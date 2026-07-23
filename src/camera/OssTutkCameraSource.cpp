#include "OssTutkCameraSource.hpp"
#include "oss_tutk/IotcClient.hpp"   // iotc_connect / oss_av_start / avRecvFrameData2
#include "obn/log.hpp"

#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

namespace obn {
namespace camera {

// First up-to-8 bytes of the authkey string, little-endian null-padded
// (matches IotcConnectCfg { authkey_lo, authkey_hi }).
static uint64_t authkey_to_u64(const std::string& s)
{
    uint64_t v = 0;
    for (size_t i = 0; i < s.size() && i < 8; ++i)
        v |= static_cast<uint64_t>(static_cast<uint8_t>(s[i])) << (8 * i);
    return v;
}

// Map the raw URL region string to the transport's TutkRegion (default US).
static bambu_net::oss_tutk::TutkRegion region_from_string(const std::string& r)
{
    using bambu_net::oss_tutk::TutkRegion;
    if (r == "cn")   return TutkRegion::CN;
    if (r == "eu")   return TutkRegion::EU;
    if (r == "asia") return TutkRegion::Asia;
    return TutkRegion::US;
}

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

    region_str_ = tutk_url_param(query, "region");
    if (region_str_ == "cn")      area_code_ = 1;
    else if (region_str_ == "eu") area_code_ = 4;
    else if (region_str_ == "us") area_code_ = 2;
    else                          area_code_ = 0xFFFFFFFF;

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

    OBN_INFO("camera: TUTK open uid=%.20s region=%s",
             tutk_uid_.c_str(), region_str_.c_str());

    // 1. LAN-direct session: UDP + LAN_SEARCH3 + DTLS-PSK.
    session_ = bambu_net::oss_tutk::iotc_connect(
        tutk_uid_, authkey_to_u64(authkey_), passwd_,
        region_from_string(region_str_));
    if (!session_) {
        OBN_WARN("camera: TUTK iotc_connect failed for uid=%.20s",
                 tutk_uid_.c_str());
        return false;
    }

    // 2. AV channel: avClientStartEx + AV LOGIN + IPCAM_START.
    av_index_ = bambu_net::oss_tutk::oss_av_start(session_, 0, "admin",
                                                  passwd_.c_str());
    if (av_index_ < 0) {
        OBN_WARN("camera: TUTK oss_av_start failed rc=%d uid=%.20s",
                 av_index_, tutk_uid_.c_str());
        bambu_net::oss_tutk::iotc_close(session_);
        session_ = nullptr;
        return false;
    }

    // 3. Reader thread pulls reassembled H.264 frames into queue_.
    running_.store(true);
    open_.store(true);
    reader_thread_ = std::thread(&OssTutkCameraSource::read_frames_, this);

    OBN_INFO("camera: TUTK source open uid=%.20s av_index=%d",
             tutk_uid_.c_str(), av_index_);
    return true;
}

void OssTutkCameraSource::read_frames_()
{
    // IDR frames can exceed 100KB; use a generous buffer like the probe.
    std::vector<char> buf(1u << 20);
    while (running_.load()) {
        int actual = 0, fcount = 0, ioc = 0;
        unsigned ts = 0;
        int rc = avRecvFrameData2(av_index_, buf.data(),
                                  static_cast<int>(buf.size()),
                                  &actual, &fcount, nullptr, 0, &ts, &ioc);
        if (rc == -20012 /*AV_ER_TIMEOUT*/) continue;
        if (rc < 0 && rc != -20014 /*AV_ER_INCOMPLETE_FRAME*/) {
            OBN_WARN("camera: TUTK avRecvFrameData2 rc=%d — stream ended", rc);
            break;
        }
        if (actual <= 0) continue;

        // A frame is a keyframe if it carries an SPS (nal type 7) or IDR
        // (nal type 5) Annex-B NAL unit.
        bool key = false;
        const uint8_t* p = reinterpret_cast<const uint8_t*>(buf.data());
        for (int i = 0; i + 4 < actual; ++i) {
            if (p[i] == 0 && p[i+1] == 0 && p[i+2] == 0 && p[i+3] == 1) {
                uint8_t nt = p[i+4] & 0x1f;
                if (nt == 7 || nt == 5) { key = true; break; }
                i += 4;
            }
        }

        bambu_net::camera::oss_agora::OssVideoFrame f;
        f.data.assign(buf.data(), buf.data() + actual);
        f.pts_us      = static_cast<int64_t>(ts) * 1000;  // ts is milliseconds
        f.is_keyframe = key;
        queue_.push(std::move(f));
    }
}

void OssTutkCameraSource::close()
{
    if (!open_.exchange(false)) return;
    running_.store(false);
    if (av_index_ >= 0) avClientStop(av_index_);
    if (reader_thread_.joinable()) reader_thread_.join();
    if (session_) {
        bambu_net::oss_tutk::iotc_close(session_);
        session_ = nullptr;
    }
    av_index_ = -1;
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
    si.width  = 1680;
    si.height = 1080;
    si.fps    = 30;
    si.codec  = Codec::H264_AnnexB;
    return si;
}

}  // namespace camera
}  // namespace obn
