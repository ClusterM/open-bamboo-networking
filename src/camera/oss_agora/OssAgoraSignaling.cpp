#include "OssAgoraSignaling.hpp"
#include "OssAgoraEngine.hpp"
#include "../oss_tutk/IotcProtocol.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include "obn/log.hpp"
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "obn/net_compat.hpp"
#include "obn/endian_compat.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace bambu_net {
namespace camera {
namespace oss_agora {

std::vector<AgoraEdgeServer>
agora_discover_edge_servers(const std::string& /*app_id*/,
                             uint32_t /*area_code*/)
{
    return {};
}

// Map area_code to a TUTK region string for the relay DNS hostname.
//   1=CN→"cn", 4=EU→"eu", 2/0x800=NA/US→"us", default→"us"
static const char* region_str_from_area_code(uint32_t area_code)
{
    switch (area_code) {
        case 1:     return "cn";
        case 4:     return "eu";
        case 2:     return "us";
        case 0x800: return "us";
        default:    return "us";
    }
}

#ifdef OBN_TESTING
const char* region_str_from_area_code_test(uint32_t area_code)
{
    return region_str_from_area_code(area_code);
}
#endif

static std::string to_upper(const std::string& s)
{
    std::string out = s;
    for (char& c : out)
        if (c >= 'a' && c <= 'z') c -= 0x20;
    return out;
}

// Write a 16-byte AV frame header into buf (which must be pre-zeroed for seq/reserved).
// payload_len: byte count of the payload following the header.
// sub_type: kFrameSubtypeLogin, kFrameSubtypeCtrl, etc.
// dir:      kFrameDirClientToP, kFrameDirPrinterToC.
// seq:      monotonic sequence number for this frame.
// reserved: header word at [12..15] (0x0b for LOGIN, 0 otherwise).
static void write_av_frame_hdr(uint8_t* buf, uint32_t payload_len,
                                uint8_t sub_type, uint8_t dir,
                                uint32_t seq, uint32_t reserved)
{
    using namespace bambu_net::oss_tutk;
    uint32_t pl    = htole32(payload_len);
    uint32_t magic = htole32((uint32_t)kFrameMagicMarker
                              | ((uint32_t)sub_type << 16)
                              | ((uint32_t)dir      << 24));
    uint32_t sq    = htole32(seq);
    uint32_t res   = htole32(reserved);
    memcpy(buf,      &pl,    4);
    memcpy(buf + 4,  &magic, 4);
    memcpy(buf + 8,  &sq,    4);
    memcpy(buf + 12, &res,   4);
}

// =========================================================================
// OssAgoraSignaling::Impl
// =========================================================================

struct OssAgoraSignaling::Impl {
    std::atomic<bool>  joined{false};
    std::atomic<bool>  test_mode{false};
    std::thread        worker_thread;

    FrameCallback      cb;

    bambu_net::oss_tutk::RelayConn relay{};

    void run_test_mode(AgoraJoinParams params);
    int  do_join(const AgoraJoinParams& params);
    void recv_loop(const AgoraJoinParams& params);
};

void OssAgoraSignaling::Impl::run_test_mode(AgoraJoinParams /*params*/)
{
    static const uint8_t kSyntheticIDR[] = {
        // SPS NAL
        0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xC0, 0x1E,
        0xD9, 0x00, 0xA0, 0x47, 0xFE, 0xC8, 0x00,
        // PPS NAL
        0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x38, 0x80,
        // IDR slice
        0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00,
        0x33, 0xFF
    };

    while (joined.load()) {
        if (cb) {
            cb(kSyntheticIDR, sizeof(kSyntheticIDR),
               0 /*pts*/, true /*keyframe*/);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

int OssAgoraSignaling::Impl::do_join(const AgoraJoinParams& params)
{
    using namespace bambu_net::oss_tutk;

    const char* rstr = region_str_from_area_code(params.area_code);

    // params.channel is the full 20-char relay subdomain; JOIN payload uses only
    // the first 16 bytes (truncation happens inside send_relay_join).
    const std::string& channel = params.channel;

    std::string uid_upper = to_upper(params.tutk_uid);
    if (uid_upper.size() != 20) {
        OBN_ERROR("[oss-relay] invalid TUTK UID (need 20 chars): '%s'",
            uid_upper.c_str());
        return -1;
    }

    OBN_INFO("[oss-relay] do_join: region=%s relay_id=%s uid=%s",
        rstr, channel.c_str(), uid_upper.c_str());
    // PSK = SHA256(dtls_passwd); identity = "AUTHPWD_admin" — same derivation as LAN DTLS.
    OBN_INFO("[oss-relay] starting relay connect...");
    if (iotc_relay_connect(uid_upper.c_str(), channel.c_str(), rstr, &relay) != 0) {
        OBN_ERROR("[oss-relay] iotc_relay_connect failed");
        return -1;
    }

    OBN_INFO("[oss-relay] starting DTLS handshake...");
    if (iotc_relay_dtls(&relay, params.dtls_passwd.c_str(), "admin") != 0) {
        OBN_ERROR("[oss-relay] DTLS handshake failed");
        iotc_relay_close(&relay);
        return -1;
    }
    OBN_INFO("[oss-relay] DTLS handshake complete");

    // AV LOGIN: header (16B) + "admin\0" + access_code\0; reserved=0x0b.
    if (params.av_passwd.empty()) {
        OBN_ERROR("[oss-agora] av_passwd is empty — caller must supply printer access code");
        iotc_relay_close(&relay);
        return -1;
    }
    static const char kAccount[] = "admin";
    static constexpr size_t kAccLen = sizeof(kAccount) - 1;
    size_t pwd_len = params.av_passwd.size();
    uint32_t payload_len = (uint32_t)(kAccLen + 1 + pwd_len + 1);

    std::vector<uint8_t> login_pkt(16 + payload_len, 0);
    write_av_frame_hdr(login_pkt.data(), payload_len,
                       kFrameSubtypeLogin, kFrameDirClientToP,
                       /*seq=*/0, /*reserved=*/0x0b);
    uint8_t* cred = login_pkt.data() + 16;
    memcpy(cred, kAccount, kAccLen);                              // NUL from vector zero-init
    memcpy(cred + kAccLen + 1, params.av_passwd.c_str(), pwd_len); // NUL from vector zero-init

    OBN_INFO("[oss-relay] sending LOGIN frame (%zu bytes)", login_pkt.size());
    if (iotc_relay_send_app_data(&relay, login_pkt.data(), login_pkt.size()) != 0) {
        OBN_ERROR("[oss-relay] LOGIN send failed");
        iotc_relay_close(&relay);
        return -1;
    }

    {
        uint8_t ack_buf[256];
        int n = iotc_relay_recv_app_data(&relay, ack_buf, sizeof(ack_buf), 5000);
        if (n < 16) {
            OBN_ERROR("[oss-relay] LOGIN ACK timeout or too short (n=%d)", n);
            iotc_relay_close(&relay);
            return -1;
        }

        uint32_t ack_magic;
        memcpy(&ack_magic, ack_buf + 4, 4);
        ack_magic = le32toh(ack_magic);
        if ((ack_magic & 0xffff) != bambu_net::oss_tutk::kFrameMagicMarker) {
            OBN_WARN("[oss-relay] LOGIN ACK: bad magic 0x%08x", ack_magic);
            // Don't bail — may be a keepalive; continue to IPCAM_START
        } else {
            uint8_t sub = (ack_magic >> 16) & 0xff;
            if (sub == bambu_net::oss_tutk::kFrameSubtypeLogin) {
                uint32_t pl_len;
                memcpy(&pl_len, ack_buf, 4);
                pl_len = le32toh(pl_len);
                if (pl_len >= 4 && n >= 20) {
                    uint32_t result;
                    memcpy(&result, ack_buf + 16, 4);
                    result = le32toh(result);
                    if (result != 0) {
                        OBN_ERROR("[oss-relay] LOGIN rejected: result=0x%x", result);
                        iotc_relay_close(&relay);
                        return -1;
                    }
                }
                OBN_INFO("[oss-relay] LOGIN ACK: success");
            } else {
                OBN_WARN("[oss-relay] LOGIN ACK: unexpected sub=0x%02x", sub);
            }
        }
    }

    // IPCAM_START IOCtrl: header (16B) + type(4B LE=0xFF01) + data_len(4B LE=0).
    {
        std::vector<uint8_t> ioctrl(16 + 8, 0);
        write_av_frame_hdr(ioctrl.data(), /*payload_len=*/8,
                           kFrameSubtypeCtrl, kFrameDirClientToP,
                           /*seq=*/1, /*reserved=*/0);
        uint32_t iotype = htole32(IOTYPE_USER_IPCAM_START);
        memcpy(ioctrl.data() + 16, &iotype, 4);

        OBN_INFO("[oss-relay] sending IPCAM_START IOCtrl");
        if (iotc_relay_send_app_data(&relay, ioctrl.data(), ioctrl.size()) != 0) {
            OBN_ERROR("[oss-relay] IPCAM_START send failed");
            iotc_relay_close(&relay);
            return -1;
        }
    }

    OBN_INFO("[oss-relay] do_join complete — waiting for video frames");
    return 0;
}

void OssAgoraSignaling::Impl::recv_loop(const AgoraJoinParams& /*params*/)
{
    using namespace bambu_net::oss_tutk;

    OBN_INFO("[oss-relay] recv_loop started");

    while (joined.load()) {
        uint8_t plaintext[65536];
        int n = iotc_relay_recv_app_data(&relay, plaintext, sizeof(plaintext), 100);

        if (n < 0) {
            OBN_ERROR("[oss-relay] recv error — exiting recv_loop");
            break;
        }
        if (n == 0) continue;  // timeout, poll again

        if (n < 16) continue;

        uint32_t magic;
        memcpy(&magic, plaintext + 4, 4);
        magic = le32toh(magic);
        if ((magic & 0xffff) != kFrameMagicMarker) continue;

        uint8_t sub_type = (magic >> 16) & 0xff;

        // Skip LOGIN echo from printer (P→C LOGIN frames are handshake artifacts).
        uint8_t direction = (magic >> 24) & 0xff;
        if (sub_type == kFrameSubtypeLogin && direction == kFrameDirPrinterToC)
            continue;

        uint32_t payload_len;
        memcpy(&payload_len, plaintext, 4);
        payload_len = le32toh(payload_len);

        // For sub_type=CTRL (0x02): small payloads (≤8 bytes) are IOCtrl
        // responses, not video data.  H.264 Annex-B frames are always larger.
        if (sub_type == kFrameSubtypeCtrl && payload_len <= 8)
            continue;

        if (n < (int)(16 + payload_len)) continue;

        const uint8_t* h264 = plaintext + 16;

        // Detect keyframe (IDR NAL type 5, SPS type 7, or FU-A IDR)
        bool is_keyframe = false;
        if (payload_len >= 1) {
            uint8_t nal_type = h264[0] & 0x1f;
            if (nal_type == 5 || nal_type == 7) {
                is_keyframe = true;
            } else if (nal_type == 28 && payload_len >= 2) {
                // FU-A: start bit set + IDR fragment
                bool start = (h264[1] & 0x80) != 0;
                is_keyframe = start && ((h264[1] & 0x1f) == 5);
            }
        }

        if (cb && payload_len > 0) {
            // PTS from sequence number (bytes [8..11] LE), 90 kHz clock
            uint32_t seq;
            memcpy(&seq, plaintext + 8, 4);
            seq = le32toh(seq);
            int64_t pts_us = (int64_t)seq * 1000000LL / 90000LL;
            cb(h264, (int)payload_len, pts_us, is_keyframe);
        }
    }

    iotc_relay_close(&relay);
    OBN_INFO("[oss-relay] recv_loop exited");
}

OssAgoraSignaling::OssAgoraSignaling()
    : m_impl(new Impl()) {}

OssAgoraSignaling::~OssAgoraSignaling()
{
    leave();
    delete m_impl;
}

void OssAgoraSignaling::set_test_mode(bool enabled)
{
    m_impl->test_mode.store(enabled);
}

int OssAgoraSignaling::join(const AgoraJoinParams& params, FrameCallback cb)
{
    if (m_impl->joined.load()) leave();

    m_impl->cb = std::move(cb);
    m_impl->joined.store(true);

    if (m_impl->test_mode.load()) {
        OBN_INFO("[oss-relay] TEST MODE: delivering synthetic frames");
        AgoraJoinParams p = params;
        m_impl->worker_thread = std::thread([this, p]() {
            m_impl->run_test_mode(p);
        });
        return 0;
    }

    OBN_INFO("[oss-relay] join: channel=%.20s uid=%s area=0x%08X",
        params.channel.c_str(), params.tutk_uid.c_str(), params.area_code);

    AgoraJoinParams p = params;
    m_impl->worker_thread = std::thread([this, p]() {
        if (m_impl->do_join(p) == 0) {
            m_impl->recv_loop(p);
        } else {
            OBN_ERROR("[oss-relay] do_join failed");
            m_impl->joined.store(false);
        }
    });

    return 0;
}

int OssAgoraSignaling::leave()
{
    m_impl->joined.store(false);
    // Close the relay socket to unblock recvfrom in recv_loop
    bambu_net::oss_tutk::iotc_relay_close(&m_impl->relay);
    if (m_impl->worker_thread.joinable()) {
        m_impl->worker_thread.join();
    }
    return 0;
}

bool OssAgoraSignaling::is_joined() const
{
    return m_impl->joined.load();
}

} // namespace oss_agora
} // namespace camera
} // namespace bambu_net
