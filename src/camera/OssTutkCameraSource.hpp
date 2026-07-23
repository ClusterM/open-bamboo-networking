//
// OssTutkCameraSource — ICameraSource for TUTK P2P/relay camera path.
//
// URL format (genuine H2S scheme):
//   bambu:///tutk?uid=<20-char-UID>&authkey=<...>&passwd=<...>&region=<cc>
//                [&device=<serial>][&net_ver=...][&dev_ver=...]
// Legacy form (older minted URLs): bambu:///tutk?uid=...&key=<ACCESS_CODE>
//
// Uses the clean-room TUTK LAN-direct transport (IotcClient.cpp): iotc_connect
// (UDP + LAN_SEARCH3 + DTLS-PSK) → oss_av_start (AV login + IPCAM_START) → a
// reader thread pulling one H.264 Annex-B frame per avRecvFrameData2 call.
// Frames are pushed into an OssFrameQueue and pulled by next_frame().

#pragma once

#include "ICameraSource.hpp"
#include "oss_agora/OssAgoraEngine.hpp"     // OssFrameQueue, OssVideoFrame

#include <atomic>
#include <chrono>
#include <optional>
#include <string>
#include <thread>

namespace bambu_net {
namespace oss_tutk {
struct OssSession;  // clean-room TUTK session (IotcClient.hpp)
}  // namespace oss_tutk
}  // namespace bambu_net

namespace obn {
namespace camera {

class OssTutkCameraSource : public bambu_net::camera::ICameraSource {
public:
    explicit OssTutkCameraSource(std::string url);
    ~OssTutkCameraSource() override;

    OssTutkCameraSource(const OssTutkCameraSource&) = delete;
    OssTutkCameraSource& operator=(const OssTutkCameraSource&) = delete;

    bool open()          override;
    void close()         override;
    bool is_open() const override;
    std::optional<bambu_net::camera::VideoFrame> next_frame(int timeout_ms) override;
    StreamInfo info() const override;

#ifdef OBN_TESTING
public:
    struct ParsedForTest {
        bool        ok;
        std::string uid, authkey, passwd, device, channel;
        uint32_t    area_code;
    };
    ParsedForTest parse_for_test() {
        ParsedForTest r;
        r.ok        = parse_url_();
        r.uid       = tutk_uid_;
        r.authkey   = authkey_;
        r.passwd    = passwd_;
        r.device    = device_;
        r.channel   = channel_;
        r.area_code = area_code_;
        return r;
    }
#endif

private:
    bool parse_url_();
    void read_frames_();      // reader thread body

    std::string  url_;
    std::string  tutk_uid_;   // 20-char uppercase UID
    std::string  channel_;    // relay subdomain (relay_id)
    std::string  passwd_;     // dtls_passwd + av_passwd (PSK = SHA256(passwd))
    std::string  authkey_;    // IOTC connect auth key (LAN/P2P precheck)
    std::string  device_;     // printer serial (informational)
    std::string  region_str_; // raw region param ("us"/"cn"/"eu"/"asia")
    uint32_t     area_code_ = 0xFFFFFFFF;

    bambu_net::oss_tutk::OssSession*             session_ = nullptr;
    int                                          av_index_ = -1;
    bambu_net::camera::oss_agora::OssFrameQueue  queue_;
    std::atomic<bool>                            open_{false};
    std::atomic<bool>                            running_{false};
    std::thread                                  reader_thread_;
};

}  // namespace camera
}  // namespace obn
