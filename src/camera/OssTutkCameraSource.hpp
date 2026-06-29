//
// OssTutkCameraSource — ICameraSource for TUTK P2P/relay camera path.
//
// URL format: bambu:///tutk?uid=<20-char-UID>&key=<ACCESS_CODE>
//                          [&channel=<RELAY_ID>][&region=<cn|eu|us>]
//
// Uses OssAgoraSignaling (which implements the full TUTK relay + DTLS + AV
// protocol). Frames (H.264 Annex-B) are pushed into an OssFrameQueue and
// pulled by next_frame() via a polling loop.
//
// NOTE: TUTK NAT punch-through is partially stubbed in IotcClient.cpp;
// the relay path (iotcplatform.com UDP relay with DTLS) works.

#pragma once

#include "ICameraSource.hpp"
#include "oss_agora/OssAgoraEngine.hpp"     // OssFrameQueue, OssVideoFrame
#include "oss_agora/OssAgoraSignaling.hpp"  // OssAgoraSignaling, AgoraJoinParams

#include <atomic>
#include <chrono>
#include <optional>
#include <string>

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

private:
    bool parse_url_();

    std::string  url_;
    std::string  tutk_uid_;   // 20-char uppercase UID
    std::string  channel_;    // relay subdomain (relay_id)
    std::string  passwd_;     // dtls_passwd + av_passwd
    uint32_t     area_code_ = 0xFFFFFFFF;

    bambu_net::camera::oss_agora::OssAgoraSignaling signaling_;
    bambu_net::camera::oss_agora::OssFrameQueue     queue_;
    std::atomic<bool>                                open_{false};
};

}  // namespace camera
}  // namespace obn
