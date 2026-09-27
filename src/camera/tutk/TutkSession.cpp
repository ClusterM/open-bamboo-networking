#include "TutkSession.hpp"
#include "IotcProtocol.hpp"

#include "obn/endian_compat.hpp"
#include "obn/log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <map>
#include <thread>
#include <vector>

namespace obn {
namespace camera {
namespace tutk {

namespace {

constexpr const char* kAccount = "admin";

// Every AV packet starts with an 8-byte header: data type, flag, protocol
// version 0x000b (LE) and our 16-bit packet counter.
constexpr uint16_t kAvVersion = 0x000b;

void put_le16(uint8_t* p, uint16_t v) { v = htole16(v); memcpy(p, &v, 2); }
void put_le32(uint8_t* p, uint32_t v) { v = htole32(v); memcpy(p, &v, 4); }
uint16_t get_le16(const uint8_t* p) { uint16_t v; memcpy(&v, p, 2); return le16toh(v); }
uint32_t get_le32(const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return le32toh(v); }

// 570-byte AV login: 24-byte header (type 0x00 or 0x20, version, payload
// length 546, our counter at [20]) and a payload with the account at [0],
// the password at [257], the UID at [518] and 2 at [542].
//
// The stock client puts a capability block at [514..546) instead; the
// printer then switches to a different transport framing (0x0c packets with
// their own acknowledgement scheme) that this client does not implement.
std::vector<uint8_t> build_av_login(uint8_t type, uint32_t seq,
                                    const std::string& passwd,
                                    const std::string& uid_upper)
{
    std::vector<uint8_t> pkt(570, 0);
    pkt[0] = type;
    put_le16(pkt.data() + 2, kAvVersion);
    put_le16(pkt.data() + 16, 546);
    put_le32(pkt.data() + 20, seq);

    uint8_t* pl = pkt.data() + 24;
    memcpy(pl, kAccount, strlen(kAccount));
    memcpy(pl + 257, passwd.data(), std::min<size_t>(passwd.size(), 256));
    memcpy(pl + 518, uid_upper.data(), std::min<size_t>(uid_upper.size(), kUidLen));
    put_le32(pl + 542, 2);
    return pkt;
}

// 40-byte AV IOCtrl carrying io_type with the channel number as payload:
// 8-byte header (type 0x00, flag 0x70), a 20-byte IOCtrl header (single
// slice of 12 bytes), the 4-byte io type and 8 bytes of payload.
void build_ioctrl(uint8_t pkt[40], uint32_t io_type, uint32_t channel, uint16_t seq)
{
    memset(pkt, 0, 40);
    pkt[1] = 0x70;
    put_le16(pkt + 2, kAvVersion);
    put_le16(pkt + 4, seq);
    pkt[9] = 0x70;
    put_le16(pkt + 12, 1);    // slice count
    put_le16(pkt + 16, 12);   // slice length: io type + payload
    put_le32(pkt + 28, io_type);
    put_le32(pkt + 32, channel);
}

// Collects the slices of one video frame; a slice of a newer frame drops
// whatever was left of the previous one.
struct FrameAssembler {
    uint32_t frame_no = 0xffffffff;
    uint16_t total    = 0;
    std::map<uint16_t, std::vector<uint8_t>> slices;

    bool add(uint32_t fno, uint16_t idx, uint16_t cnt, const uint8_t* data, size_t len)
    {
        if (fno != frame_no) {
            frame_no = fno;
            total    = cnt ? cnt : 1;
            slices.clear();
        }
        slices[idx].assign(data, data + len);
        return slices.size() >= total;
    }

    std::vector<uint8_t> take()
    {
        std::vector<uint8_t> out;
        for (auto& kv : slices) out.insert(out.end(), kv.second.begin(), kv.second.end());
        slices.clear();
        frame_no = 0xffffffff;
        total    = 0;
        return out;
    }
};

bool starts_with_start_code(const uint8_t* p, size_t n)
{
    return (n >= 3 && p[0] == 0 && p[1] == 0 && p[2] == 1) ||
           (n >= 4 && p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 1);
}

bool is_jpeg(const uint8_t* p, size_t n) { return n >= 2 && p[0] == 0xff && p[1] == 0xd8; }

bool h264_is_keyframe(const uint8_t* p, size_t n)
{
    size_t off = (n >= 4 && p[2] == 0) ? 4 : 3;
    if (n <= off) return false;
    uint8_t nal = p[off] & 0x1f;
    return nal == 5 || nal == 7;
}

} // namespace

struct TutkSession::Impl {
    std::atomic<bool> joined{false};
    std::thread       worker;
    FrameCallback     cb;
    IotcConn          conn{};
    uint16_t          out_seq = 1;
    std::chrono::steady_clock::time_point started;

    Impl() { conn.sock = -1; }

    void run(const TutkSessionParams& p);
    int  connect(const TutkSessionParams& p);
    int  receive(const TutkSessionParams& p);

    void send(const uint8_t* data, size_t len) { iotc_send_app_data(&conn, data, len); }
    void send_login(const TutkSessionParams& p);
    void send_ioctrl(uint32_t io_type, uint32_t channel);
    void send_transport_ack(uint16_t pkt_seq, uint16_t& ack_count);
    void deliver(const uint8_t* data, size_t len, bool keyframe);
};

void TutkSession::Impl::send_login(const TutkSessionParams& p)
{
    auto a = build_av_login(0x00, out_seq++, p.passwd, p.uid);
    auto b = build_av_login(0x20, out_seq++, p.passwd, p.uid);
    send(a.data(), a.size());
    send(b.data(), b.size());
}

void TutkSession::Impl::send_ioctrl(uint32_t io_type, uint32_t channel)
{
    uint8_t pkt[40];
    build_ioctrl(pkt, io_type, channel, out_seq++);
    send(pkt, sizeof(pkt));
}

// 20-byte transport acknowledgement (type 0x0b) for a packet whose flag asks
// for one: acked counter at [8], delta 1 at [10], running count at [12].
void TutkSession::Impl::send_transport_ack(uint16_t pkt_seq, uint16_t& ack_count)
{
    uint8_t ack[20] = {0};
    ack[0] = 0x0b;
    put_le16(ack + 2, kAvVersion);
    put_le16(ack + 4, out_seq++);
    put_le16(ack + 8, pkt_seq);
    put_le16(ack + 10, 1);
    put_le16(ack + 12, ack_count++);
    send(ack, sizeof(ack));
}

void TutkSession::Impl::deliver(const uint8_t* data, size_t len, bool keyframe)
{
    if (!cb || len == 0) return;
    int64_t pts_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started).count();
    cb(data, (int)len, pts_us, keyframe);
}

int TutkSession::Impl::connect(const TutkSessionParams& p)
{
    iotc_close(&conn);
    out_seq = 1;

    for (int attempt = 1; attempt <= 3 && joined.load(); ++attempt) {
        const char* path = "lan";
        if (iotc_lan_connect(p.uid.c_str(), p.authkey.c_str(), 1500, &conn) != 0) {
            if (iotc_relay_connect(p.uid.c_str(), p.relay_id.c_str(), p.region.c_str(),
                                   p.authkey.c_str(), &conn) != 0) {
                OBN_WARN("tutk: printer unreachable over LAN and relay (attempt %d/3)", attempt);
                iotc_close(&conn);
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                continue;
            }
            path = conn.is_relay ? "relay" : "p2p";
        }
        OBN_INFO("tutk: connected via %s (attempt %d/3)", path, attempt);

        if (iotc_dtls_handshake(&conn, p.passwd.c_str(), kAccount) != 0) {
            OBN_WARN("tutk: DTLS handshake failed (attempt %d/3)", attempt);
            iotc_close(&conn);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        send_login(p);
        uint8_t ack[512];
        if (iotc_recv_app_data(&conn, ack, sizeof(ack), 800) > 0)
            OBN_DEBUG("tutk: AV login acknowledged");
        send_ioctrl(kIoTypeIpcamStart, 0);
        send_ioctrl(kIoTypeIpcamStart, 1);
        return 0;
    }
    return -1;
}

// Pumps the session until leave() or a failure. Returns 0 after leave(),
// negative when the session should be re-established.
int TutkSession::Impl::receive(const TutkSessionParams& p)
{
    FrameAssembler assembler;
    uint16_t ack_count      = 1;
    int      frames         = 0;
    int      retries        = 0;
    int      start_triggers = 0;
    auto     last_retry     = std::chrono::steady_clock::now();
    auto     last_data      = last_retry;
    std::vector<uint8_t> buf(65536);

    while (joined.load()) {
        const auto now = std::chrono::steady_clock::now();
        if (frames == 0) {
            if (now - last_retry >= std::chrono::milliseconds(1200)) {
                if (++retries > 5) {
                    OBN_WARN("tutk: no video after %d login attempts", retries - 1);
                    return -1;
                }
                last_retry = now;
                OBN_DEBUG("tutk: no video yet, repeating login (%d/5)", retries);
                send_login(p);
                send_ioctrl(kIoTypeIpcamStart, 0);
                send_ioctrl(kIoTypeIpcamStart, 1);
            }
        } else if (now - last_data >= std::chrono::seconds(5)) {
            OBN_WARN("tutk: video stalled for 5 s");
            return -4;
        }

        int n = iotc_recv_app_data(&conn, buf.data(), buf.size(), 100);
        if (n < 0) {
            OBN_WARN("tutk: session lost (%d)", n);
            return n;
        }
        if (n < 8) continue;
        last_data = std::chrono::steady_clock::now();

        const uint8_t* pkt = buf.data();
        if (get_le16(pkt + 2) != kAvVersion) continue;
        const uint8_t  type    = pkt[0];
        const uint8_t  flag    = pkt[1];
        const uint16_t pkt_seq = get_le16(pkt + 4);

        if (type == 0x00) {
            switch (flag) {
            case 0x21:  // login accepted
                send_ioctrl(kIoTypeIpcamStart, 0);
                send_ioctrl(kIoTypeIpcamStart, 1);
                break;
            case 0x10: {  // IOCtrl from the printer: echo the header as 0x11
                if (n < 24) break;
                uint16_t channel = n >= 12 ? get_le16(pkt + 10) : 0;
                OBN_DEBUG("tutk: IOCtrl 0x%x on channel %u",
                          n >= 32 ? get_le32(pkt + 28) : 0, channel);
                uint8_t reply[24];
                memcpy(reply, pkt, 24);
                reply[1] = 0x11;
                reply[9] = 0x11;
                reply[16] = reply[17] = 0;
                send(reply, sizeof(reply));
                if (start_triggers++ < 3) {
                    send_ioctrl(kIoTypeIpcamStart, 0);
                    send_ioctrl(kIoTypeIpcamStart, 1);
                }
                break;
            }
            case 0x70: {  // IOCtrl request: answer 0x71 with the same header
                if (n < 24) break;
                uint8_t reply[24];
                memcpy(reply, pkt, 24);
                reply[1] = 0x71;
                reply[16] = reply[17] = 0;
                send(reply, sizeof(reply));
                break;
            }
            case 0x12: {  // reset buffer: answer 0x13 echoing 20 bytes of body
                if (n < 24) break;
                uint8_t reply[44] = {0};
                memcpy(reply, pkt, 24);
                reply[1] = 0x13;
                reply[16] = 20;
                if (n >= 44) memcpy(reply + 24, pkt + 24, 20);
                send(reply, sizeof(reply));
                break;
            }
            default:
                break;
            }
            continue;
        }

        // Stream packets: type 0x01 with the stream kind in the flag, or the
        // kind as the type itself (0x03..0x08). Kind 4 is audio.
        if (type != 0x01 && (type < 0x03 || type > 0x08)) continue;
        if (flag & 0x08) send_transport_ack(pkt_seq, ack_count);
        const uint8_t kind = (type == 0x01) ? flag : type;
        if (kind == 0x04) continue;

        // With flag bit 3 an 8-byte transport header follows the AV header.
        // The slice header then has the slice index at [2], slice count at
        // [4], slice length at [8] and the frame number at [12]; the slice
        // data starts 20 bytes after it.
        const size_t extra = (flag & 0x08) ? 8 : 0;
        const size_t hdr   = 8 + extra;
        const size_t data  = 28 + extra;
        if ((size_t)n <= data) continue;
        uint16_t slice_idx = get_le16(pkt + hdr + 2);
        uint16_t slice_cnt = get_le16(pkt + hdr + 4);
        size_t   slice_len = get_le16(pkt + hdr + 8);
        uint32_t frame_no  = get_le32(pkt + hdr + 12);
        if (slice_len == 0 || data + slice_len > (size_t)n) slice_len = (size_t)n - data;

        if (!assembler.add(frame_no, slice_idx, slice_cnt, pkt + data, slice_len)) continue;
        std::vector<uint8_t> frame = assembler.take();

        // H.264 frames may carry a 16-byte frame info block (keyframe flag at
        // [2]) in front of the Annex-B data.
        const uint8_t* payload = frame.data();
        size_t         len     = frame.size();
        bool           key     = false;
        if (is_jpeg(payload, len)) {
            key = true;
        } else if (len > 16 && (starts_with_start_code(payload + 16, len - 16) ||
                                is_jpeg(payload + 16, len - 16))) {
            key = frame[2] == 1;
            payload += 16;
            len     -= 16;
        }
        if (!key)
            key = is_jpeg(payload, len) ||
                  (starts_with_start_code(payload, len) && h264_is_keyframe(payload, len));

        if (++frames == 1) OBN_INFO("tutk: first video frame (%zu bytes)", len);
        deliver(payload, len, key);
    }

    send_ioctrl(kIoTypeIpcamStop, 0);
    send_ioctrl(kIoTypeIpcamStop, 1);
    return 0;
}

void TutkSession::Impl::run(const TutkSessionParams& p)
{
    for (int attempt = 1; attempt <= 5 && joined.load(); ++attempt) {
        if (connect(p) == 0) {
            if (receive(p) == 0) break;
            OBN_WARN("tutk: reconnecting (%d/5)", attempt);
        } else {
            OBN_ERROR("tutk: could not establish a session (%d/5)", attempt);
        }
        iotc_close(&conn);
        if (!joined.load()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    iotc_close(&conn);
    joined.store(false);
}

TutkSession::TutkSession() : impl_(std::make_unique<Impl>()) {}

TutkSession::~TutkSession() { leave(); }

void TutkSession::join(const TutkSessionParams& params, FrameCallback cb)
{
    leave();
    impl_->cb      = std::move(cb);
    impl_->started = std::chrono::steady_clock::now();
    impl_->joined.store(true);
    OBN_INFO("tutk: starting session uid=%.20s", params.uid.c_str());
    impl_->worker = std::thread([this, params] { impl_->run(params); });
}

void TutkSession::leave()
{
    // The worker owns the connection: it notices the flag within one receive
    // step, stops the stream and closes the socket itself.
    impl_->joined.store(false);
    if (impl_->worker.joinable()) impl_->worker.join();
}

bool TutkSession::is_joined() const { return impl_->joined.load(); }

} // namespace tutk
} // namespace camera
} // namespace obn
