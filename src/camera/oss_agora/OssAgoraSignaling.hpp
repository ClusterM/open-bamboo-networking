//
// OssAgoraSignaling — TUTK IOTC relay protocol client.
//
// Despite the "Agora" naming, this implements the TUTK IOTC relay protocol.
// See OssAgoraSignaling.cpp for connection flow and protocol details.

#pragma once

#include <functional>
#include <string>
#include <vector>
#include <cstdint>

namespace bambu_net {
namespace camera {
namespace oss_agora {

struct OssFrameQueue;

// Connection parameters (originally Agora-named, used for TUTK relay).
struct AgoraJoinParams {
    std::string app_id;
    std::string channel;    // relay_id: 20-char relay subdomain (first 16B used)
    std::string token;       // Agora auth token
    std::string dtls_passwd; // printer passwd; PSK = SHA256(dtls_passwd) for relay DTLS
    uint32_t    uid         = 0;
    uint32_t    area_code   = 0;  // 0xFFFFFFFF = global, 1=CN, 4=EU, 2=NA, 0x800=US
    std::string stream_key; // AES-128 key material (from joinChannel args)
    std::string tutk_uid;   // TUTK device UID (printer serial number, uppercase)
    std::string av_passwd;  // AV-layer LOGIN password = printer access code (same value as dtls_passwd)
};

using FrameCallback = std::function<void(const uint8_t* data, int len,
                                          int64_t pts_us, bool keyframe)>;

class OssAgoraSignaling {
public:
    OssAgoraSignaling();
    ~OssAgoraSignaling();

    void set_test_mode(bool enabled);
    int join(const AgoraJoinParams& params, FrameCallback cb);
    int leave();

    bool is_joined() const;

private:
    struct Impl;
    Impl* m_impl = nullptr;
};

struct AgoraEdgeServer {
    std::string ip;
    uint16_t    port;
};

// Stub — not used in the TUTK relay path; always returns empty.
std::vector<AgoraEdgeServer>
agora_discover_edge_servers(const std::string& app_id, uint32_t area_code);

#ifdef OBN_TESTING
const char* region_str_from_area_code_test(uint32_t area_code);
#endif

} // namespace oss_agora
} // namespace camera
} // namespace bambu_net
