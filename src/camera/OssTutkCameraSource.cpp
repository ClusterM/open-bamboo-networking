#include "OssTutkCameraSource.hpp"
#include "obn/log.hpp"

#include <chrono>
#include <thread>

namespace obn {
namespace camera {

// Query-string parameter extractor for bambu:///tutk?... URLs.
//
// Matches the key EXACTLY against each "&"-delimited "key=value" segment.
// A substring search (the previous implementation) is unsafe here: the genuine
// scheme carries both "authkey=" and no "key=", and find("key=") would grab the
// value of "authkey=" instead of returning empty.
static std::string tutk_url_param(const std::string& query,
                                   const std::string& key)
{
    size_t pos = 0;
    while (pos <= query.size()) {
        size_t amp = query.find('&', pos);
        size_t seg_end = (amp == std::string::npos) ? query.size() : amp;
        size_t eq = query.find('=', pos);
        if (eq != std::string::npos && eq < seg_end &&
            eq - pos == key.size() && query.compare(pos, key.size(), key) == 0) {
            return query.substr(eq + 1, seg_end - eq - 1);
        }
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    return {};
}

bool OssTutkCameraSource::parse_url_()
{
    // Genuine H2S scheme (from a captured LAN-direct session):
    //   bambu:///tutk?uid=<20-char-UID>&authkey=<...>&passwd=<...>&region=<cc>
    //                &device=<serial>&net_ver=...&dev_ver=...&refresh_url=1&...
    //
    //   uid      — TUTK device UID (IOTC_Connect_ByUIDEx target)
    //   authkey  — IOTC connect auth key (P2P/LAN precheck)
    //   passwd   — AV-layer / DTLS-PSK password  (PSK = SHA256(passwd))
    //   region   — master-server region for UID resolution
    //   device   — printer serial
    const std::string scheme = "bambu://";
    if (url_.compare(0, scheme.size(), scheme) != 0) return false;
    auto q = url_.find('?');
    if (q == std::string::npos) return false;
    std::string query = url_.substr(q + 1);

    tutk_uid_ = tutk_url_param(query, "uid");
    authkey_  = tutk_url_param(query, "authkey");
    passwd_   = tutk_url_param(query, "passwd");
    device_   = tutk_url_param(query, "device");

    // Legacy fallback: older minted URLs used key=<passwd> and carried no
    // authkey/passwd. Now that matching is exact, key= no longer clobbers
    // authkey=, so this only fires for the genuine legacy form.
    if (passwd_.empty()) passwd_ = tutk_url_param(query, "key");

    std::string region_str = tutk_url_param(query, "region");
    if (region_str == "cn")      area_code_ = 1;
    else if (region_str == "eu") area_code_ = 4;
    else if (region_str == "us") area_code_ = 2;
    else                         area_code_ = 0xFFFFFFFF;

    if (tutk_uid_.empty() || passwd_.empty()) return false;

    // Uppercase the UID (protocol requires uppercase)
    for (char& c : tutk_uid_)
        if (c >= 'a' && c <= 'z') c -= 0x20;

    // "channel" (relay subdomain) is not part of the genuine tutk scheme; the
    // relay fallback uses the UID when none is supplied.
    channel_ = tutk_url_param(query, "channel");
    if (channel_.empty()) channel_ = tutk_uid_;

    return true;
}

OssTutkCameraSource::OssTutkCameraSource(std::string url)
    : url_(std::move(url)) {}

OssTutkCameraSource::~OssTutkCameraSource()
{
    close();
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
    p.authkey     = authkey_;   // IOTC connect auth key (LAN/P2P precheck)
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
    OBN_INFO("camera: TUTK source open uid=%.20s", tutk_uid_.c_str());
    return true;
}

void OssTutkCameraSource::close()
{
    if (!open_.exchange(false)) return;
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
    si.width  = 1920;
    si.height = 1080;
    si.fps    = 30;
    si.codec  = Codec::H264_AnnexB;
    return si;
}

}  // namespace camera
}  // namespace obn
