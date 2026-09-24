#include "OssTutkCameraSource.hpp"
#include "obn/log.hpp"

#include <chrono>
#include <thread>

namespace obn {
namespace camera {

// Query-string parameter extractor for bambu:///tutk?... URLs.
// The key is matched only at a parameter boundary (query start or immediately
// after '&') so a short key cannot match inside a longer parameter name
// (e.g. "key" must not match the "key=" inside "authkey=").
static std::string tutk_url_param(const std::string& query,
                                   const std::string& key)
{
    const std::string needle = key + "=";
    size_t pos = 0;
    for (;;) {
        pos = query.find(needle, pos);
        if (pos == std::string::npos) return {};
        if (pos == 0 || query[pos - 1] == '&') break;
        pos += 1;
    }
    pos += needle.size();
    auto end = query.find('&', pos);
    return (end == std::string::npos)
        ? query.substr(pos)
        : query.substr(pos, end - pos);
}

bool OssTutkCameraSource::parse_url_()
{
    // bambu:///tutk?uid=...&authkey=...&passwd=...&region=...
    const std::string scheme = "bambu://";
    if (url_.compare(0, scheme.size(), scheme) != 0) return false;
    auto q = url_.find('?');
    if (q == std::string::npos) return false;
    std::string query = url_.substr(q + 1);

    tutk_uid_ = tutk_url_param(query, "uid");
    // DTLS/AV password is carried in the "passwd" parameter.
    passwd_   = tutk_url_param(query, "passwd");
    authkey_  = tutk_url_param(query, "authkey");
    channel_  = tutk_url_param(query, "channel");

    std::string region_str = tutk_url_param(query, "region");
    if (region_str == "cn")      area_code_ = 1;
    else if (region_str == "eu") area_code_ = 4;
    else if (region_str == "us") area_code_ = 2;
    else                         area_code_ = 0xFFFFFFFF;

    if (tutk_uid_.empty() || passwd_.empty()) return false;

    // Uppercase the UID (protocol requires uppercase)
    for (char& c : tutk_uid_)
        if (c >= 'a' && c <= 'z') c -= 0x20;

    // If no relay channel provided, use the UID itself
    if (channel_.empty()) channel_ = tutk_uid_;

    return true;
}

OssTutkCameraSource::OssTutkCameraSource(std::string url)
    : url_(std::move(url)) {}

OssTutkCameraSource::~OssTutkCameraSource()
{
    close();
}

static bool parse_jpeg_dimensions(const uint8_t* data, size_t size, int& width, int& height)
{
    if (size < 4 || data[0] != 0xff || data[1] != 0xd8) return false;
    size_t i = 2;
    while (i + 4 <= size) {
        if (data[i] != 0xff) {
            ++i;
            continue;
        }
        uint8_t marker = data[i + 1];
        if (marker == 0xd9 || marker == 0xda) break; // EOI or SOS
        if (marker == 0x00 || marker == 0xff) {
            i += 2;
            continue;
        }
        if (i + 4 > size) break;
        uint16_t len = (static_cast<uint16_t>(data[i + 2]) << 8) | data[i + 3];
        if (marker == 0xc0 || marker == 0xc1 || marker == 0xc2) { // SOF0, SOF1, SOF2
            if (i + 9 <= size) {
                height = (static_cast<int>(data[i + 5]) << 8) | data[i + 6];
                width  = (static_cast<int>(data[i + 7]) << 8) | data[i + 8];
                return true;
            }
        }
        if (len < 2) break;
        i += 2 + len;
    }
    return false;
}

bool OssTutkCameraSource::open()
{
    if (open_.load()) return true;

    if (!parse_url_()) {
        OBN_WARN("camera: OssTutkCameraSource: bad URL '%s'", url_.c_str());
        return false;
    }

    OBN_INFO("camera: TUTK open uid=%.20s channel=%.20s",
             tutk_uid_.c_str(), channel_.c_str());

    using namespace bambu_net::camera::oss_agora;
    AgoraJoinParams p;
    p.tutk_uid    = tutk_uid_;
    p.channel     = channel_;
    p.dtls_passwd = passwd_;
    p.av_passwd   = passwd_;
    p.authkey     = authkey_;
    p.area_code   = area_code_;
    // app_id, token, uid are unused in the direct TUTK relay path

    int rc = signaling_.join(p, [this](const uint8_t* data, int len,
                                        int64_t pts_us, bool key) {
        OssVideoFrame f;
        f.data.assign(data, data + len);
        f.pts_us      = pts_us;
        f.is_keyframe = key;
        queue_.push(std::move(f));
    });

    if (rc != 0) {
        OBN_WARN("camera: TUTK signaling join failed for uid=%.20s",
                 tutk_uid_.c_str());
        return false;
    }

    open_.store(true);

    // Wait briefly for first frame to detect stream codec and dimensions
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(2500);
    while (std::chrono::steady_clock::now() < deadline && open_.load()) {
        bambu_net::camera::oss_agora::OssVideoFrame f;
        if (queue_.pop(f)) {
            if (f.data.size() >= 2 && f.data[0] == 0xff && f.data[1] == 0xd8) {
                detected_codec_ = Codec::MotionJpeg;
                int w = 0, h = 0;
                if (parse_jpeg_dimensions(f.data.data(), f.data.size(), w, h)) {
                    detected_width_  = w;
                    detected_height_ = h;
                }
                OBN_INFO("camera: TUTK first frame detected as MotionJpeg (%zu B, %dx%d)",
                         f.data.size(), detected_width_, detected_height_);
            } else {
                detected_codec_ = Codec::H264_AnnexB;
                OBN_INFO("camera: TUTK first frame detected as H264_AnnexB (%zu B)", f.data.size());
            }
            bambu_net::camera::VideoFrame vf;
            vf.nal_data = std::move(f.data);
            vf.pts_us = f.pts_us;
            vf.is_keyframe = f.is_keyframe;
            first_frame_ = std::move(vf);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    OBN_INFO("camera: TUTK source open uid=%.20s codec=%s (%dx%d)",
             tutk_uid_.c_str(),
             detected_codec_ == Codec::MotionJpeg ? "MotionJpeg" : "H264_AnnexB",
             detected_width_, detected_height_);
    return true;
}

void OssTutkCameraSource::close()
{
    if (!open_.exchange(false)) return;
    first_frame_.reset();
    signaling_.leave();
    OBN_INFO("camera: TUTK source closed uid=%.20s", tutk_uid_.c_str());
}

bool OssTutkCameraSource::is_open() const
{
    return open_.load();
}

std::optional<bambu_net::camera::VideoFrame>
OssTutkCameraSource::next_frame(int timeout_ms)
{
    if (!open_.load()) return std::nullopt;

    if (first_frame_.has_value()) {
        auto f = std::move(*first_frame_);
        first_frame_.reset();
        return f;
    }

    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(timeout_ms);
    while (open_.load()) {
        bambu_net::camera::oss_agora::OssVideoFrame f;
        if (queue_.pop(f)) {
            bambu_net::camera::VideoFrame out;
            out.nal_data    = std::move(f.data);
            out.pts_us      = f.pts_us;
            out.is_keyframe = f.is_keyframe;
            return out;
        }
        if (std::chrono::steady_clock::now() >= deadline) return std::nullopt;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return std::nullopt;
}

bambu_net::camera::ICameraSource::StreamInfo OssTutkCameraSource::info() const
{
    StreamInfo si;
    si.width  = detected_width_;
    si.height = detected_height_;
    si.fps    = 30;
    si.codec  = detected_codec_;
    return si;
}

}  // namespace camera
}  // namespace obn
