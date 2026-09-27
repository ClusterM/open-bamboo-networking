#include "TutkCameraSource.hpp"
#include "obn/log.hpp"

#include <chrono>

namespace obn {
namespace camera {

namespace {

// Value of `key` in a query string, matched only at a parameter boundary so
// "key" does not match inside "authkey=".
std::string query_param(const std::string& query, const std::string& key)
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
    return end == std::string::npos ? query.substr(pos) : query.substr(pos, end - pos);
}

bool parse_tutk_url(const std::string& url, tutk::TutkSessionParams& p)
{
    const std::string scheme = "bambu://";
    if (url.compare(0, scheme.size(), scheme) != 0) return false;
    auto q = url.find('?');
    if (q == std::string::npos) return false;
    const std::string query = url.substr(q + 1);

    p.uid      = query_param(query, "uid");
    p.passwd   = query_param(query, "passwd");
    p.authkey  = query_param(query, "authkey");
    p.region   = query_param(query, "region");
    p.relay_id = query_param(query, "channel");
    if (p.uid.empty() || p.passwd.empty()) return false;

    for (char& c : p.uid)
        if (c >= 'a' && c <= 'z') c -= 0x20;
    if (p.region != "cn" && p.region != "eu") p.region = "us";
    if (p.relay_id.empty()) p.relay_id = p.uid;
    return true;
}

bool jpeg_dimensions(const uint8_t* data, size_t size, int& width, int& height)
{
    if (size < 4 || data[0] != 0xff || data[1] != 0xd8) return false;
    size_t i = 2;
    while (i + 4 <= size) {
        if (data[i] != 0xff) { ++i; continue; }
        uint8_t marker = data[i + 1];
        if (marker == 0xd9 || marker == 0xda) break;          // EOI, SOS
        if (marker == 0x00 || marker == 0xff) { i += 2; continue; }
        uint16_t len = (uint16_t)((data[i + 2] << 8) | data[i + 3]);
        if (marker >= 0xc0 && marker <= 0xc2) {               // SOF0..SOF2
            if (i + 9 > size) break;
            height = (data[i + 5] << 8) | data[i + 6];
            width  = (data[i + 7] << 8) | data[i + 8];
            return true;
        }
        if (len < 2) break;
        i += 2 + len;
    }
    return false;
}

// Covers the whole connect path: LAN search, relay fallback, DTLS and the
// login retries before the printer starts streaming.
constexpr auto kFirstFrameTimeout = std::chrono::seconds(15);

} // namespace

TutkCameraSource::TutkCameraSource(std::string url) : url_(std::move(url)) {}

TutkCameraSource::~TutkCameraSource() { close(); }

void TutkCameraSource::push_frame(const uint8_t* data, int len, int64_t pts_us, bool keyframe)
{
    VideoFrame f;
    f.nal_data.assign(data, data + len);
    f.pts_us      = pts_us;
    f.is_keyframe = keyframe;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!codec_known_) {
            codec_known_ = true;
            if (len >= 2 && data[0] == 0xff && data[1] == 0xd8) {
                codec_ = Codec::MotionJpeg;
                jpeg_dimensions(data, (size_t)len, width_, height_);
            }
        }
        if (frames_.size() >= kMaxQueuedFrames) frames_.pop_front();
        frames_.push_back(std::move(f));
    }
    cv_.notify_one();
}

bool TutkCameraSource::open()
{
    if (open_.load()) return true;
    if (!parse_tutk_url(url_, params_)) {
        OBN_WARN("camera: malformed TUTK URL");
        return false;
    }

    session_.join(params_, [this](const uint8_t* d, int n, int64_t pts, bool key) {
        push_frame(d, n, pts, key);
    });

    // The session gives up without notifying us, so poll its state as well.
    const auto deadline = std::chrono::steady_clock::now() + kFirstFrameTimeout;
    std::unique_lock<std::mutex> lk(mu_);
    while (frames_.empty() && session_.is_joined() &&
           std::chrono::steady_clock::now() < deadline)
        cv_.wait_for(lk, std::chrono::milliseconds(200));
    const bool got = !frames_.empty();
    lk.unlock();
    if (!got) {
        OBN_WARN("camera: TUTK stream did not start uid=%.20s", params_.uid.c_str());
        session_.leave();
        return false;
    }

    open_.store(true);
    OBN_INFO("camera: TUTK stream open uid=%.20s codec=%s",
             params_.uid.c_str(), codec_ == Codec::MotionJpeg ? "MJPEG" : "H.264");
    return true;
}

void TutkCameraSource::close()
{
    open_.store(false);
    session_.leave();
    std::lock_guard<std::mutex> lk(mu_);
    frames_.clear();
    codec_known_ = false;
}

bool TutkCameraSource::is_open() const
{
    return open_.load() && session_.is_joined();
}

std::optional<VideoFrame> TutkCameraSource::next_frame(int timeout_ms)
{
    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms), [this] {
        return !frames_.empty() || !open_.load() || !session_.is_joined();
    });
    if (frames_.empty()) return std::nullopt;
    VideoFrame f = std::move(frames_.front());
    frames_.pop_front();
    return f;
}

ICameraSource::StreamInfo TutkCameraSource::info() const
{
    std::lock_guard<std::mutex> lk(mu_);
    StreamInfo si;
    si.width  = width_;
    si.height = height_;
    si.fps    = 30;
    si.codec  = codec_;
    return si;
}

}  // namespace camera
}  // namespace obn
