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
#include <map>

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
    void send_ipcam_start(uint16_t ch, uint16_t& out_seq);
};

void OssAgoraSignaling::Impl::send_ipcam_start(uint16_t ch, uint16_t& out_seq)
{
    using namespace bambu_net::oss_tutk;
    OBN_INFO("[oss-relay] sending TUTK New AV API IPCAM_START (ch=%u seq=%u)...", ch, out_seq);

    // Canonical 40-byte packet as reversed from official BambuSource.dll (0x180057820 / 0x18005d5c6)
    uint8_t pkt[40] = {0};

    // Outer header (8 bytes)
    pkt[0] = 0x00; // control
    pkt[1] = 0x70; // OPCODE_AV_IOCTRL_USER
    uint16_t v = htole16(0x000b);
    memcpy(pkt + 2, &v, 2);
    uint16_t sq = htole16(out_seq++);
    memcpy(pkt + 4, &sq, 2);
    // bytes 6..7: 0

    // Inner header (20 bytes, offset 8..27)
    pkt[8] = 0x00;
    pkt[9] = 0x70;
    uint16_t in_seq = htole16(0);
    memcpy(pkt + 10, &in_seq, 2);
    uint16_t slice_cnt = htole16(1);
    memcpy(pkt + 12, &slice_cnt, 2);
    uint16_t slice_idx = htole16(0);
    memcpy(pkt + 14, &slice_idx, 2);
    uint16_t slice_len = htole16(12); // 4 (ioType) + 8 (payload)
    memcpy(pkt + 16, &slice_len, 2);
    // bytes 18..19: 0
    // bytes 20..23: ticket (0)
    // bytes 24..27: reserved (0)

    // ioType (4 bytes, offset 28..31)
    uint32_t iotype = htole32(IOTYPE_USER_IPCAM_START); // 0x000001ff = 511
    memcpy(pkt + 28, &iotype, 4);

    // payload (8 bytes, offset 32..39)
    uint32_t ch_le = htole32(ch);
    memcpy(pkt + 32, &ch_le, 4);
    // bytes 36..39: reserved (0)

    int rc = iotc_relay_send_app_data(&relay, pkt, sizeof(pkt));
    OBN_INFO("[oss-relay] IPCAM_START sent (rc=%d, len=%zu)", rc, sizeof(pkt));
}

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
            char ack_hex[256];
            int ack_dump_len = std::min(n, 64);
            int ack_pos = 0;
            for (int i = 0; i < ack_dump_len; ++i) {
                ack_pos += snprintf(ack_hex + ack_pos, sizeof(ack_hex) - ack_pos, "%02x ", ack_buf[i]);
            }
            OBN_INFO("[oss-relay] LOGIN ACK received: n=%d bytes, hex: %s", n, ack_hex);
        }
    }

    // Send IPCAM_START IOCtrl on channel 0 and channel 1
    uint16_t init_seq = 3;
    send_ipcam_start(0, init_seq);
    send_ipcam_start(1, init_seq);

    OBN_INFO("[oss-relay] do_join complete — waiting for video frames");
    return 0;
}

void OssAgoraSignaling::Impl::recv_loop(const AgoraJoinParams& /*params*/)
{
    using namespace bambu_net::oss_tutk;

    OBN_INFO("[oss-relay] recv_loop started");
    bool first_frame = true;

    struct TutkFrameAssembly {
        uint32_t frm_no = 0xFFFFFFFF;
        uint32_t timestamp = 0;
        uint16_t total_pkts = 0;
        std::map<uint16_t, std::vector<uint8_t>> chunks;

        bool add(uint32_t fno, uint32_t ts, uint16_t idx, uint16_t cnt, const uint8_t* data, size_t len) {
            if (cnt == 0) cnt = 1;

            if (fno != frm_no) {
                frm_no = fno;
                timestamp = ts;
                total_pkts = cnt;
                chunks.clear();
            }
            chunks[idx] = std::vector<uint8_t>(data, data + len);
            return (chunks.size() >= total_pkts);
        }

        std::vector<uint8_t> get_frame() {
            size_t total_len = 0;
            for (const auto& kv : chunks) total_len += kv.second.size();
            std::vector<uint8_t> out;
            out.reserve(total_len);
            for (const auto& kv : chunks) {
                out.insert(out.end(), kv.second.begin(), kv.second.end());
            }
            chunks.clear();
            total_pkts = 0;
            frm_no = 0xFFFFFFFF;
            return out;
        }
    } reassembler;

    uint16_t s_client_out_seq = 4;
    uint16_t s_ack_counter = 1;

    int received_video_frames = 0;
    int retry_start_count = 0;
    int ioc_trigger_cnt = 0;
    int frame_log_cnt = 0;
    auto last_retry_time = std::chrono::steady_clock::now();

    auto send_tutk_transport_ack = [&](uint16_t pkt_seq) {
        uint8_t ack_pkt[20] = {0};
        ack_pkt[0] = 0x0b; // dataType = TUTK BBR Transport ACK (reversed from BambuSource.dll @ 0x1800528b9)
        ack_pkt[1] = 0x00; // flag = 0
        uint16_t v = htole16(0x000b);
        memcpy(ack_pkt + 2, &v, 2);
        uint16_t c_seq = htole16(s_client_out_seq++);
        memcpy(ack_pkt + 4, &c_seq, 2);
        // bytes 6..7: 0
        uint16_t p_seq = htole16(pkt_seq);
        memcpy(ack_pkt + 8, &p_seq, 2);   // acked packet seq
        uint16_t delta = htole16(1);
        memcpy(ack_pkt + 10, &delta, 2);  // delta
        uint16_t recv_cnt = htole16(s_ack_counter++);
        memcpy(ack_pkt + 12, &recv_cnt, 2); // received packet count
        // bytes 14..19: 0
        iotc_relay_send_app_data(&relay, ack_pkt, sizeof(ack_pkt));
    };

    while (joined.load()) {
        // Periodic IPCAM_START retry if no video frames have arrived yet
        if (received_video_frames == 0 && retry_start_count < 6) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_retry_time).count() >= 1500) {
                last_retry_time = now;
                retry_start_count++;
                OBN_INFO("[oss-relay] no video yet, resending IPCAM_START (attempt %d/6)...", retry_start_count);
                send_ipcam_start(0, s_client_out_seq);
                send_ipcam_start(1, s_client_out_seq);
            }
        }

        uint8_t plaintext[65536];
        int n = iotc_relay_recv_app_data(&relay, plaintext, sizeof(plaintext), 100);

        if (n < 0) {
            OBN_ERROR("[oss-relay] recv error — exiting recv_loop");
            break;
        }
        if (n == 0) continue;  // timeout, poll again

        static int s_pkt_log_cnt = 0;
        if (s_pkt_log_cnt < 40) {
            s_pkt_log_cnt++;
            char hex_buf[256];
            int dump_len = std::min(n, 48);
            int pos = 0;
            for (int i = 0; i < dump_len; ++i) {
                pos += snprintf(hex_buf + pos, sizeof(hex_buf) - pos, "%02x ", plaintext[i]);
            }
            OBN_INFO("[oss-relay] PKT_DUMP #%d: n=%d hex: %s", s_pkt_log_cnt, n, hex_buf);
        }

        const uint8_t* h264 = nullptr;
        size_t payload_len = 0;
        uint32_t seq = 0;
        bool is_keyframe = false;
        std::vector<uint8_t> frame_buf;

        // Handle TUTK Transport Level packets (ver == 0x000b)
        if (n >= 8) {
            uint16_t ver;
            memcpy(&ver, plaintext + 2, 2);
            ver = le16toh(ver);
            if (ver == 0x000b) {
                uint8_t dataType = plaintext[0];
                uint8_t flag = plaintext[1];
                uint16_t pkt_seq;
                memcpy(&pkt_seq, plaintext + 4, 2);
                pkt_seq = le16toh(pkt_seq);

                // 1. Control packets (dataType 0x00)
                if (dataType == 0x00) {
                    if (flag == 0x10) {
                        uint16_t channel = 0;
                        if (n >= 12) {
                            memcpy(&channel, plaintext + 10, 2);
                            channel = le16toh(channel);
                        }
                        uint32_t opCode = 0;
                        if (n >= 32) {
                            memcpy(&opCode, plaintext + 28, 4);
                            opCode = le32toh(opCode);
                        }
                        OBN_INFO("[oss-relay] TUTK inner IOCtrl 0x10: seq=%u ch=%u opCode=0x%x",
                                 pkt_seq, channel, opCode);

                        // If transport ACK requested (flag & 8)
                        if (flag & 0x08) {
                            send_tutk_transport_ack(pkt_seq);
                        }

                        // OpCode 0x40 is SET_CLIENT_MAX_BUFFER_SIZE. Official binary does NOT reply with 0x11 ACK!
                        // Reply with IPCAM_START for both channels to trigger transmission
                        if (ioc_trigger_cnt++ < 3) {
                            send_ipcam_start(channel, s_client_out_seq);
                            if (channel != 0) send_ipcam_start(0, s_client_out_seq);
                            if (channel != 1) send_ipcam_start(1, s_client_out_seq);
                        }
                        continue;
                    }
                    if (flag == 0x70) {
                        OBN_INFO("[oss-relay] TUTK IOC_REQ 0x70 -> sending 0x71 ACK");
                        uint8_t ack71[24] = {0};
                        memcpy(ack71, plaintext, 24);
                        ack71[1] = 0x71;
                        ack71[16] = 0;
                        ack71[17] = 0;
                        iotc_relay_send_app_data(&relay, ack71, 24);
                        continue;
                    }
                    if (flag == 0x12) {
                        OBN_INFO("[oss-relay] TUTK RESET_BUFFER 0x12 -> sending 0x13 ACK");
                        uint8_t ack[44] = {0};
                        memcpy(ack, plaintext, 24);
                        ack[1] = 0x13;
                        ack[16] = 20;
                        if (n >= 44) memcpy(ack + 24, plaintext + 24, 20);
                        iotc_relay_send_app_data(&relay, ack, 44);
                        continue;
                    }
                    continue;
                }

                // 2. AV Stream packets (dataType 0x01 with flag 3..8, or dataType 0x03..0x08)
                bool is_stream_pkt = (dataType == 0x01) || (dataType >= 0x03 && dataType <= 0x08);
                if (is_stream_pkt) {
                    if (flag & 0x08) {
                        send_tutk_transport_ack(pkt_seq);
                    }

                    if (n < 28) continue;

                    uint8_t stream_type = (dataType == 0x01) ? flag : dataType;
                    // Audio packet (stream_type 4) -> skip
                    if (stream_type == 0x04) {
                        continue;
                    }

                    // Video packet: offsets reversed from BambuSource.dll @ 0x1800525de & 0x180052402
                    // When (flag & 8) != 0, an 8-byte transport header exists at bytes 8..15 (extra = 8)
                    // Inner header at offset 8 + extra:
                    //   [+2..3]   = slice_idx (pkt)
                    //   [+4..5]   = slice_cnt (s_count)
                    //   [+8..9]   = slice_len (payload_len)
                    //   [+12..15] = frm_no
                    //   [+16..19] = avfrm_no
                    // Slice data at offset 28 + extra
                    int extra = (flag & 0x08) ? 8 : 0;
                    if (n < 28 + extra) continue;

                    size_t hdr_off = 8 + extra;
                    uint16_t slice_idx = 0;
                    memcpy(&slice_idx, plaintext + hdr_off + 2, 2);
                    slice_idx = le16toh(slice_idx);

                    uint16_t slice_cnt = 0;
                    memcpy(&slice_cnt, plaintext + hdr_off + 4, 2);
                    slice_cnt = le16toh(slice_cnt);

                    uint16_t slice_len = 0;
                    memcpy(&slice_len, plaintext + hdr_off + 8, 2);
                    slice_len = le16toh(slice_len);

                    uint32_t frm_no = 0;
                    memcpy(&frm_no, plaintext + hdr_off + 12, 4);
                    frm_no = le32toh(frm_no);

                    uint32_t avfrm_no = 0;
                    memcpy(&avfrm_no, plaintext + hdr_off + 16, 4);
                    avfrm_no = le32toh(avfrm_no);

                    size_t payload_off = 28 + extra;
                    if (slice_cnt == 0) slice_cnt = 1;
                    if (slice_len == 0 || n < (int)(payload_off + slice_len)) {
                        slice_len = (n > (int)payload_off) ? (uint16_t)(n - payload_off) : 0;
                    }
                    if (slice_len == 0) continue;

                    const uint8_t* slice_data = plaintext + payload_off;

                    bool complete = reassembler.add(frm_no, avfrm_no, slice_idx, slice_cnt, slice_data, slice_len);
                    if (complete) {
                        frame_buf = reassembler.get_frame();
                        seq = avfrm_no;
                        received_video_frames++;

                        // Detect MJPEG directly (SOI FF D8)
                        if (frame_buf.size() >= 2 && frame_buf[0] == 0xff && frame_buf[1] == 0xd8) {
                            h264 = frame_buf.data();
                            payload_len = frame_buf.size();
                            is_keyframe = true;
                        } else {
                            // Strip 16-byte FRAMEINFO_t if present
                            if (frame_buf.size() > 16) {
                                const uint8_t* p = frame_buf.data() + 16;
                                if ((p[0] == 0 && p[1] == 0 && p[2] == 1) ||
                                    (p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 1) ||
                                    (p[0] == 0xff && p[1] == 0xd8)) {
                                    h264 = p;
                                    payload_len = frame_buf.size() - 16;
                                    uint8_t frame_flag = frame_buf.data()[2];
                                    if (frame_flag == 1) is_keyframe = true;
                                }
                            }
                            if (!h264 && !frame_buf.empty()) {
                                h264 = frame_buf.data();
                                payload_len = frame_buf.size();
                            }
                        }
                    } else {
                        // Incomplete frame, wait for next slice
                        continue;
                    }
                }
            }
        }

        // Check Case 1: 16-byte AvFrameHeader
        if (!h264 && n >= 16) {
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

        if (frame_log_cnt < 30) {
            frame_log_cnt++;
            OBN_INFO("[oss-relay] VIDEO FRAME #%d: %zu bytes (key=%d, seq=%u)",
                     frame_log_cnt, payload_len, is_keyframe ? 1 : 0, seq);
        }

        if (cb && payload_len > 0) {
            int64_t pts_us = (seq > 0) ? ((int64_t)seq * 1000LL) : 0;
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
