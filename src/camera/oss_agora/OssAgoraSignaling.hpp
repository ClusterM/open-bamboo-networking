//
// OssAgoraSignaling — TUTK IOTC relay protocol client.
//
// Despite the "Agora" naming, this implements the TUTK IOTC relay protocol.
// See OssAgoraSignaling.cpp for connection flow and protocol details.

#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace bambu_net {
namespace camera {
namespace oss_agora {

struct OssVideoFrame {
    std::vector<uint8_t> data;
    int64_t pts_us      = 0;
    bool    is_keyframe = false;
};

struct OssFrameQueue {
    std::mutex              mu;
    std::deque<OssVideoFrame> frames;
    static constexpr size_t kMaxFrames = 120;

    void push(OssVideoFrame f) {
        std::lock_guard<std::mutex> lk(mu);
        if (frames.size() >= kMaxFrames) frames.pop_front();
        frames.push_back(std::move(f));
    }

    bool pop(OssVideoFrame& out) {
        std::lock_guard<std::mutex> lk(mu);
        if (frames.empty()) return false;
        out = std::move(frames.front());
        frames.pop_front();
        return true;
    }
};

// Connection parameters (originally Agora-named, used for TUTK relay).
struct AgoraJoinParams {
    std::string channel;    // relay_id: 20-char relay subdomain (first 16B used)
    std::string dtls_passwd; // printer passwd; PSK = SHA256(dtls_passwd) for relay DTLS
    uint32_t    area_code   = 0;  // 0xFFFFFFFF = global, 1=CN, 4=EU, 2=NA, 0x800=US
    std::string tutk_uid;   // TUTK device UID (printer serial number, uppercase)
    std::string av_passwd;  // AV-layer LOGIN password = printer access code (same value as dtls_passwd)
    std::string authkey;    // 8-char auth key from the tutk URL; used by the off-LAN rendezvous
};

using FrameCallback = std::function<void(const uint8_t* data, int len,
                                          int64_t pts_us, bool keyframe)>;

class OssAgoraSignaling {
public:
    OssAgoraSignaling();
    ~OssAgoraSignaling();

    int join(const AgoraJoinParams& params, FrameCallback cb);
    int leave();

    bool is_joined() const;

private:
    struct Impl;
    Impl* m_impl = nullptr;
};

} // namespace oss_agora
} // namespace camera
} // namespace bambu_net
