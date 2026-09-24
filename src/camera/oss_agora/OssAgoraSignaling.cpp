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

// Builds a 570-byte TUTK AV connect / login packet:
// 24 bytes TUTK header + 546 bytes payload
static std::vector<uint8_t> build_tutk_av_login_pkt(uint8_t type, uint32_t seq,
                                                     const std::string& account,
                                                     const std::string& passwd,
                                                     const std::string& uid_upper)
{
    std::vector<uint8_t> pkt(570, 0);

    // Header (24 bytes)
    pkt[0] = type;              // 0x00 for pkt 1, 0x20 for pkt 2
    pkt[1] = 0x00;              // sub_type
    uint16_t ver = htole16(0x000b);
    memcpy(pkt.data() + 2, &ver, 2);
    uint16_t payload_len = htole16(546); // 0x0222
    memcpy(pkt.data() + 16, &payload_len, 2);
    uint32_t sq = htole32(seq);
    memcpy(pkt.data() + 20, &sq, 4);

    // Payload (546 bytes starting at offset 24)
    uint8_t* pl = pkt.data() + 24;
    size_t acc_len = std::min(account.size(), (size_t)256);
    memcpy(pl, account.c_str(), acc_len);

    size_t pwd_len = std::min(passwd.size(), (size_t)256);
    memcpy(pl + 257, passwd.c_str(), pwd_len);

    // pl[514..517]: channel = 0 (uint32 LE, 0)
    size_t uid_len = std::min(uid_upper.size(), (size_t)20);
    memcpy(pl + 518, uid_upper.c_str(), uid_len);

    // pl[538..541]: flags2 = 0 (uint32 LE, 0)
    // pl[542..545]: flags1 = 2 (uint32 LE)
    uint32_t f1 = htole32(2);
    memcpy(pl + 542, &f1, 4);

    return pkt;
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
    if (iotc_relay_connect(uid_upper.c_str(), channel.c_str(), rstr,
                           params.authkey.c_str(), &relay) != 0) {
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

    // AV LOGIN: send TUTK 570-byte packets (type 0x00 and type 0x20)
    std::string login_pwd = params.av_passwd.empty() ? params.dtls_passwd : params.av_passwd;
    if (login_pwd.empty()) {
        OBN_ERROR("[oss-agora] av_passwd and dtls_passwd are both empty");
        iotc_relay_close(&relay);
        return -1;
    }

    std::string account = "admin";
    OBN_INFO("[oss-relay] building 570-byte TUTK AV LOGIN packets (acc='%s', uid='%s')...",
             account.c_str(), uid_upper.c_str());

    auto pkt1 = build_tutk_av_login_pkt(0x00, /*seq=*/1, account, login_pwd, uid_upper);
    auto pkt2 = build_tutk_av_login_pkt(0x20, /*seq=*/2, account, login_pwd, uid_upper);

    OBN_INFO("[oss-relay] sending LOGIN packet 1 (type=0x00, 570B)...");
    if (iotc_relay_send_app_data(&relay, pkt1.data(), pkt1.size()) != 0) {
        OBN_ERROR("[oss-relay] LOGIN packet 1 send failed");
        iotc_relay_close(&relay);
        return -1;
    }

    OBN_INFO("[oss-relay] sending LOGIN packet 2 (type=0x20, 570B)...");
    if (iotc_relay_send_app_data(&relay, pkt2.data(), pkt2.size()) != 0) {
        OBN_ERROR("[oss-relay] LOGIN packet 2 send failed");
        iotc_relay_close(&relay);
        return -1;
    }

    // Wait for LOGIN ACK from printer
    {
        uint8_t ack_buf[512];
        OBN_INFO("[oss-relay] waiting for LOGIN ACK from printer (timeout=5000ms)...");
        int n = iotc_relay_recv_app_data(&relay, ack_buf, sizeof(ack_buf), 5000);
        if (n < 0) {
            OBN_ERROR("[oss-relay] LOGIN ACK error (n=%d)", n);
            iotc_relay_close(&relay);
            return -1;
        }
        if (n == 0) {
            OBN_WARN("[oss-relay] LOGIN ACK timed out (n=0) — proceeding to IPCAM_START anyway");
        } else {
            OBN_INFO("[oss-relay] LOGIN ACK received: n=%d bytes, hex: %02x %02x %02x %02x",
                     n, ack_buf[0], n > 1 ? ack_buf[1] : 0, n > 2 ? ack_buf[2] : 0, n > 3 ? ack_buf[3] : 0);
        }
    }

    // Send IPCAM_START IOCtrl
    // In TUTK AV API, IOTYPE_USER_IPCAM_START requires SMsgAVIoctrlAVStream (channel=0, reserved=0, data_len=8).
    // 1. TUTK AV IOCtrl frame (40 bytes): 24-byte header + 16 bytes payload
    {
        std::vector<uint8_t> tutk_ioctrl(40, 0);
        tutk_ioctrl[0] = 0x08; // TUTK AV IOCtrl
        tutk_ioctrl[1] = 0x00;
        uint16_t ver = htole16(0x000b);
        memcpy(tutk_ioctrl.data() + 2, &ver, 2);
        uint16_t plen = htole16(16);
        memcpy(tutk_ioctrl.data() + 16, &plen, 2);
        uint32_t sq = htole32(3);
        memcpy(tutk_ioctrl.data() + 20, &sq, 4);
        uint32_t iotype = htole32(bambu_net::oss_tutk::IOTYPE_USER_IPCAM_START);
        memcpy(tutk_ioctrl.data() + 24, &iotype, 4);
        uint32_t dlen = htole32(8);
        memcpy(tutk_ioctrl.data() + 28, &dlen, 4);
        // channel = 0 at [32..35], reserved = 0 at [36..39]

        OBN_INFO("[oss-relay] sending TUTK IPCAM_START IOCtrl (40 bytes, iotype=0x01ff, dlen=8, ch=0)...");
        if (iotc_relay_send_app_data(&relay, tutk_ioctrl.data(), tutk_ioctrl.size()) != 0) {
            OBN_WARN("[oss-relay] TUTK IPCAM_START send failed");
        }
    }

    // 2. Also send AvFrameHeader IOCtrl frame (32 bytes):
    // 16-byte AvFrameHeader + 16 bytes payload (iotype=0x01ff, dlen=8, ch=0, res=0)
    {
        std::vector<uint8_t> ioctrl(16 + 16, 0);
        write_av_frame_hdr(ioctrl.data(), /*payload_len=*/16,
                           kFrameSubtypeCtrl, kFrameDirClientToP,
                           /*seq=*/4, /*reserved=*/0);
        uint32_t iotype = htole32(bambu_net::oss_tutk::IOTYPE_USER_IPCAM_START);
        memcpy(ioctrl.data() + 16, &iotype, 4);
        uint32_t dlen = htole32(8);
        memcpy(ioctrl.data() + 20, &dlen, 4);
        // channel = 0 at [24..27], reserved = 0 at [28..31]

        OBN_INFO("[oss-relay] sending AvFrame IPCAM_START IOCtrl (32 bytes, iotype=0x01ff, dlen=8, ch=0)...");
        if (iotc_relay_send_app_data(&relay, ioctrl.data(), ioctrl.size()) != 0) {
            OBN_WARN("[oss-relay] AvFrame IPCAM_START send failed");
        }
    }

    // 3. Fallback: also send 32-byte TUTK IOCtrl (dlen=0) and 24-byte AvFrame IOCtrl (dlen=0)
    {
        std::vector<uint8_t> tutk_ioctrl0(32, 0);
        tutk_ioctrl0[0] = 0x08;
        uint16_t ver = htole16(0x000b);
        memcpy(tutk_ioctrl0.data() + 2, &ver, 2);
        uint16_t plen = htole16(8);
        memcpy(tutk_ioctrl0.data() + 16, &plen, 2);
        uint32_t sq = htole32(5);
        memcpy(tutk_ioctrl0.data() + 20, &sq, 4);
        uint32_t iotype = htole32(bambu_net::oss_tutk::IOTYPE_USER_IPCAM_START);
        memcpy(tutk_ioctrl0.data() + 24, &iotype, 4);
        iotc_relay_send_app_data(&relay, tutk_ioctrl0.data(), tutk_ioctrl0.size());
    }

    OBN_INFO("[oss-relay] do_join complete — waiting for video frames");
    return 0;
}

void OssAgoraSignaling::Impl::recv_loop(const AgoraJoinParams& /*params*/)
{
    using namespace bambu_net::oss_tutk;

    OBN_INFO("[oss-relay] recv_loop started");
    bool first_frame = true;
    auto last_keepalive = std::chrono::steady_clock::now();

    while (joined.load()) {
        auto now = std::chrono::steady_clock::now();
        // Send periodic TUTK AV keepalive ping every 2 seconds
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_keepalive).count() >= 2) {
            last_keepalive = now;
            std::vector<uint8_t> ping(24, 0);
            ping[0] = 0x10;
            uint16_t ver = htole16(0x000b);
            memcpy(ping.data() + 2, &ver, 2);
            iotc_relay_send_app_data(&relay, ping.data(), ping.size());
        }

        uint8_t plaintext[65536];
        int n = iotc_relay_recv_app_data(&relay, plaintext, sizeof(plaintext), 100);

        if (n < 0) {
            OBN_ERROR("[oss-relay] recv error — exiting recv_loop");
            break;
        }
        if (n == 0) continue;  // timeout, poll again

        static int s_pkt_log_cnt = 0;
        if (s_pkt_log_cnt < 20) {
            s_pkt_log_cnt++;
            char hex_buf[128];
            int dump_len = std::min(n, 32);
            int pos = 0;
            for (int i = 0; i < dump_len; ++i) {
                pos += snprintf(hex_buf + pos, sizeof(hex_buf) - pos, "%02x ", plaintext[i]);
            }
            OBN_INFO("[oss-relay] PKT_DUMP #%d: n=%d hex: %s", s_pkt_log_cnt, n, hex_buf);
        }

        const uint8_t* h264 = nullptr;
        size_t payload_len = 0;
        uint32_t seq = 0;

        // Check Case 1: 16-byte AvFrameHeader
        if (n >= 16) {
            uint32_t magic;
            memcpy(&magic, plaintext + 4, 4);
            magic = le32toh(magic);
            if ((magic & 0xffff) == kFrameMagicMarker) {
                uint8_t sub_type = (magic >> 16) & 0xff;
                uint8_t direction = (magic >> 24) & 0xff;

                // Skip LOGIN echo from printer
                if (sub_type == kFrameSubtypeLogin && direction == kFrameDirPrinterToC)
                    continue;

                // All control payloads are IOCtrl responses, NOT video
                if (sub_type == kFrameSubtypeCtrl) {
                    OBN_DEBUG("[oss-relay] skipping AvFrame IOCtrl packet (n=%d)", n);
                    continue;
                }

                uint32_t pl;
                memcpy(&pl, plaintext, 4);
                pl = le32toh(pl);

                if (n >= (int)(16 + pl) && pl > 0) {
                    h264 = plaintext + 16;
                    payload_len = pl;
                    memcpy(&seq, plaintext + 8, 4);
                    seq = le32toh(seq);
                }
            }
        }

        // Check Case 2: 24-byte TUTK packet header (ver=0x000b)
        if (!h264 && n >= 24) {
            uint16_t ver;
            memcpy(&ver, plaintext + 2, 2);
            ver = le16toh(ver);
            if (ver == 0x000b) {
                uint8_t pkt_type = plaintext[0];
                uint16_t pl_len;
                memcpy(&pl_len, plaintext + 16, 2);
                pl_len = le16toh(pl_len);

                // TUTK IOCtrl responses (0x08, 0x09, 0x10) are NOT video
                if (pkt_type == 0x08 || pkt_type == 0x09 || pkt_type == 0x10) {
                    OBN_DEBUG("[oss-relay] skipping TUTK IOCtrl response (pkt_type=0x%02x, pl_len=%u)", pkt_type, pl_len);
                    continue;
                }

                // Video frames are never <= 8 bytes
                if (pl_len <= 8) {
                    OBN_INFO("[oss-relay] skipping short TUTK packet (n=%d, pkt_type=0x%02x, pl_len=%u)", n, pkt_type, pl_len);
                    continue;
                }

                if (n >= (int)(24 + pl_len) && pl_len > 0) {
                    const uint8_t* inner = plaintext + 24;
                    // Check if inner payload has 16-byte AvFrameHeader
                    if (pl_len >= 16) {
                        uint32_t inner_magic;
                        memcpy(&inner_magic, inner + 4, 4);
                        inner_magic = le32toh(inner_magic);
                        if ((inner_magic & 0xffff) == kFrameMagicMarker) {
                            uint8_t inner_sub = (inner_magic >> 16) & 0xff;
                            if (inner_sub == kFrameSubtypeCtrl) {
                                OBN_DEBUG("[oss-relay] skipping inner AvFrame IOCtrl");
                                continue;
                            }
                            uint32_t inner_pl;
                            memcpy(&inner_pl, inner, 4);
                            inner_pl = le32toh(inner_pl);
                            if (pl_len >= 16 + inner_pl && inner_pl > 0) {
                                h264 = inner + 16;
                                payload_len = inner_pl;
                                memcpy(&seq, inner + 8, 4);
                                seq = le32toh(seq);
                            }
                        }
                    }
                    if (!h264) {
                        h264 = inner;
                        payload_len = pl_len;
                        memcpy(&seq, plaintext + 20, 4);
                        seq = le32toh(seq);
                    }
                }
            }
        }

        // Check Case 3: Raw Annex-B start code
        if (!h264 && n >= 4) {
            if ((plaintext[0] == 0 && plaintext[1] == 0 && plaintext[2] == 1) ||
                (plaintext[0] == 0 && plaintext[1] == 0 && plaintext[2] == 0 && plaintext[3] == 1)) {
                h264 = plaintext;
                payload_len = (size_t)n;
            }
        }

        if (!h264 || payload_len == 0) {
            OBN_DEBUG("[oss-relay] skipping non-video packet (n=%d)", n);
            continue;
        }

        // Detect keyframe
        bool is_keyframe = false;
        size_t nal_offset = 0;
        if (payload_len >= 4 && h264[0] == 0 && h264[1] == 0 && h264[2] == 0 && h264[3] == 1) {
            nal_offset = 4;
        } else if (payload_len >= 3 && h264[0] == 0 && h264[1] == 0 && h264[2] == 1) {
            nal_offset = 3;
        } else if (payload_len >= 2 && h264[0] == 0xff && h264[1] == 0xd8) {
            // MJPEG frame (every JPEG is an intra frame)
            is_keyframe = true;
        }

        if (!is_keyframe && payload_len > nal_offset) {
            uint8_t nal_type = h264[nal_offset] & 0x1f;
            if (nal_type == 5 || nal_type == 7) {
                is_keyframe = true;
            } else if (nal_type == 28 && payload_len > nal_offset + 1) {
                bool start = (h264[nal_offset + 1] & 0x80) != 0;
                is_keyframe = start && ((h264[nal_offset + 1] & 0x1f) == 5);
            }
        }

        if (first_frame) {
            first_frame = false;
            OBN_INFO("[oss-relay] FIRST VIDEO FRAME: %zu bytes (key=%d, seq=%u)",
                     payload_len, is_keyframe ? 1 : 0, seq);
        }

        if (cb && payload_len > 0) {
            int64_t pts_us = (seq > 0) ? ((int64_t)seq * 1000000LL / 90000LL) : 0;
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
