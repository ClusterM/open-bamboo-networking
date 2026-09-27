#include "TutkSession.hpp"
#include "Fec.hpp"
#include "IotcProtocol.hpp"

#include "obn/endian_compat.hpp"
#include "obn/log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <map>
#include <random>
#include <thread>
#include <vector>

namespace obn {
namespace camera {
namespace tutk {

namespace {

using Clock = std::chrono::steady_clock;

constexpr const char* kAccount = "admin";

// Every AV packet starts with an 8-byte header: data type, flag, protocol
// version 0x000b (LE) and the sender's 16-bit packet counter.
constexpr uint16_t kAvVersion = 0x000b;

// AV packet types of the framed transport.
constexpr uint8_t kTypeFramed    = 0x0c;  // FEC-protected stream data / IOCtrl
constexpr uint8_t kTypeHeartbeat = 0x09;
constexpr uint8_t kTypeProbe     = 0x0a;  // with flag 0x08
constexpr uint8_t kTypeProbeAck  = 0x0b;

void put_le16(uint8_t* p, uint16_t v) { v = htole16(v); memcpy(p, &v, 2); }
void put_le32(uint8_t* p, uint32_t v) { v = htole32(v); memcpy(p, &v, 4); }
uint16_t get_le16(const uint8_t* p) { uint16_t v; memcpy(&v, p, 2); return le16toh(v); }
uint32_t get_le32(const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return le32toh(v); }

uint16_t now_ms16()
{
    return (uint16_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now().time_since_epoch()).count();
}

// 570-byte AV login: 24-byte header (version, payload length 546, nonce at
// [20]) and a payload with the account at [0] and the password at [257].
// It goes out twice: `step` 0x00 and 0x20.
//
// The framed login carries the stock capability block at [514..546): the
// printer then answers with the same block and streams in the framed
// transport (0x0c packets with FEC); the step goes to the flag byte and
// [18] marks the first packet. The legacy login has the step as the type,
// the UID at [518] and 2 at [542] and gets the plain slice stream.
std::vector<uint8_t> build_av_login(uint8_t step, uint32_t nonce, bool framed,
                                    const std::string& passwd,
                                    const std::string& uid_upper)
{
    std::vector<uint8_t> pkt(570, 0);
    put_le16(pkt.data() + 2, kAvVersion);
    put_le16(pkt.data() + 16, 546);
    put_le32(pkt.data() + 20, nonce);

    uint8_t* pl = pkt.data() + 24;
    memcpy(pl, kAccount, strlen(kAccount));
    memcpy(pl + 257, passwd.data(), std::min<size_t>(passwd.size(), 256));
    if (framed) {
        pkt[1]  = step;
        pkt[18] = (step == 0x00) ? 1 : 0;
        put_le32(pl + 514, 1);
        put_le32(pl + 518, 4);
        put_le32(pl + 522, 0x001f07fb);
        put_le32(pl + 536, 3);
        put_le32(pl + 542, 1);
    } else {
        pkt[0] = step;
        memcpy(pl + 518, uid_upper.data(), std::min<size_t>(uid_upper.size(), kUidLen));
        put_le32(pl + 542, 2);
    }
    return pkt;
}

// 32-byte IOCtrl body carrying io_type with the channel number as payload:
// flag 0x70, request index, a single 12-byte slice (io type + 8 bytes).
void build_ioctrl_body(uint8_t out[32], uint32_t io_type, uint32_t channel, uint16_t index)
{
    memset(out, 0, 32);
    out[1] = 0x70;
    put_le16(out + 2, index);
    put_le32(out + 4, 1);     // slice count
    put_le32(out + 8, 12);    // slice length
    put_le32(out + 12, index);
    put_le32(out + 20, io_type);
    put_le32(out + 24, channel);
}

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

// ---------------------------------------------------------------------------
// Legacy transport
// ---------------------------------------------------------------------------

// Collects the slices of one video frame; a slice of a newer frame drops
// whatever was left of the previous one.
struct LegacyAssembler {
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

// ---------------------------------------------------------------------------
// Framed transport
// ---------------------------------------------------------------------------

// 20-byte slice header in front of every slice of a frame. The last slice
// has [1] = 1 and the length of the frame info trailer in place of its index.
constexpr size_t kSliceHeaderLen = 20;

struct SliceHeader {
    uint8_t  kind;      // 5: keyframe, 7: inter frame, 4: audio
    uint16_t count;     // slices in the frame
    uint16_t index;
    uint16_t info_len;  // frame info trailer length (last slice only)
    uint16_t len;       // payload bytes after the header
    uint32_t frame_no;
};

bool parse_slice_header(const uint8_t* p, size_t n, SliceHeader& h)
{
    if (n < kSliceHeaderLen) return false;
    const bool last = p[1] == 1;
    h.kind     = p[0];
    h.count    = get_le16(p + 4);
    h.index    = last ? (uint16_t)(h.count - 1) : get_le16(p + 6);
    h.info_len = last ? get_le16(p + 6) : 0;
    h.len      = get_le16(p + 8);
    h.frame_no = get_le32(p + 12);
    return h.count > 0 && h.index < h.count && kSliceHeaderLen + h.len <= n;
}

// Stream packets come in FEC groups: k data packets (one slice each) and m
// parity packets. A parity body starts with its own 20-byte header holding
// the coded length at [8]; the data bodies are zero-padded to that length.
class FecReceiver {
public:
    using SliceFn = std::function<void(const uint8_t*, size_t)>;

    int recovered = 0;
    int lost      = 0;

    void add(uint16_t group, uint8_t idx, uint8_t k, uint8_t m,
             const uint8_t* body, size_t n, const SliceFn& on_slice)
    {
        if (k == 0 || idx >= k + m) return;
        if (have_newest_) {
            const int16_t d = (int16_t)(group - newest_);
            if (d < -kKeepGroups) return;
            if (d > 0) advance(group);
        } else {
            have_newest_ = true;
            newest_      = group;
        }

        Group& g = groups_[group];
        if (g.blocks.empty()) {
            g.k = k;
            g.m = m;
            g.blocks.resize(k + m);
        }
        if (g.closed || g.k != k || g.m != m || !g.blocks[idx].empty() || n == 0) return;

        if (idx < k) {
            g.blocks[idx].assign(body, body + n);
            ++g.data_have;
            g.max_data = std::max<int>(g.max_data, idx);
            on_slice(body, n);
        } else {
            if (n < kSliceHeaderLen) return;
            const size_t len = get_le16(body + 8);
            if (len == 0 || kSliceHeaderLen + len > n || (g.len && g.len != len)) return;
            g.len = len;
            g.blocks[idx].assign(body + kSliceHeaderLen, body + kSliceHeaderLen + len);
            ++g.parity_have;
        }

        if (g.data_have == g.k) {
            g.closed = true;
        } else if (g.len && g.data_have + g.parity_have >= g.k) {
            recover(g, on_slice);
        } else if (idx == k + m - 1) {
            close_lost(g);
        }
    }

    // True while some group may still recover a slice that has not arrived.
    bool has_holes() const
    {
        for (const auto& kv : groups_) {
            const Group& g = kv.second;
            if (!g.closed && g.data_have < g.max_data + 1) return true;
        }
        return false;
    }

private:
    static constexpr int kKeepGroups = 8;

    struct Group {
        uint8_t k = 0;
        uint8_t m = 0;
        std::vector<std::vector<uint8_t>> blocks;
        int    data_have   = 0;
        int    parity_have = 0;
        int    max_data    = -1;
        size_t len         = 0;
        bool   closed      = false;
    };

    std::map<uint16_t, Group> groups_;
    uint16_t newest_      = 0;
    bool     have_newest_ = false;

    // A packet of a newer group means every older group is complete.
    void advance(uint16_t group)
    {
        newest_ = group;
        for (auto it = groups_.begin(); it != groups_.end();) {
            const int16_t age = (int16_t)(newest_ - it->first);
            if (age > 0 && !it->second.closed) close_lost(it->second);
            if (age > kKeepGroups || age < -kKeepGroups) it = groups_.erase(it);
            else ++it;
        }
    }

    void close_lost(Group& g)
    {
        g.closed = true;
        lost += g.k - g.data_have;
    }

    void recover(Group& g, const SliceFn& on_slice)
    {
        std::vector<bool> missing(g.k);
        auto blocks = g.blocks;
        for (int i = 0; i < g.k; ++i) {
            missing[i] = blocks[i].empty();
            if (!missing[i]) blocks[i].resize(g.len, 0);
        }
        g.closed = true;
        if (!fec::recover(blocks, g.k, g.len)) {
            lost += g.k - g.data_have;
            return;
        }
        for (int i = 0; i < g.k; ++i) {
            if (!missing[i]) continue;
            SliceHeader h;
            if (!parse_slice_header(blocks[i].data(), blocks[i].size(), h)) {
                ++lost;
                continue;
            }
            ++recovered;
            on_slice(blocks[i].data(), kSliceHeaderLen + h.len);
        }
    }
};

// Orders slices into frames. Slices may arrive late (FEC recovery happens at
// the end of a group), so an incomplete frame is held until no group can
// recover it anymore; after a lost frame inter frames are skipped until the
// next keyframe.
class FrameQueue {
public:
    using FrameFn = std::function<void(const uint8_t*, size_t, bool)>;

    int dropped = 0;

    void add(const SliceHeader& h, const uint8_t* payload)
    {
        if (have_next_ && (int32_t)(h.frame_no - next_) < 0) return;
        Frame& f = pending_[h.frame_no];
        if (f.slices.empty()) {
            f.count = h.count;
            f.first = Clock::now();
        }
        if (h.count != f.count) return;
        if (h.info_len) f.info_len = h.info_len;
        f.kind = h.kind;
        f.slices[h.index].assign(payload, payload + h.len);
    }

    void flush(bool holes, const FrameFn& emit)
    {
        while (!pending_.empty()) {
            auto it = pending_.begin();
            Frame& f = it->second;
            const bool gap      = have_next_ && it->first != next_;
            const bool complete = f.slices.size() == f.count;
            if (complete && !gap) {
                deliver(f, emit);
                next_      = it->first + 1;
                have_next_ = true;
                pending_.erase(it);
                continue;
            }
            // The missing packets are gone once a later frame has started
            // and no FEC group can bring them back.
            const bool later_started = gap || pending_.size() > 1;
            const bool expired = Clock::now() - f.first > std::chrono::milliseconds(500);
            if (!later_started || (holes && !expired)) break;
            need_key_ = true;
            if (gap) {
                dropped += (int)(it->first - next_);
                next_ = it->first;
                continue;
            }
            ++dropped;
            next_      = it->first + 1;
            have_next_ = true;
            pending_.erase(it);
        }
    }

private:
    struct Frame {
        uint16_t count    = 0;
        uint16_t info_len = 0;
        uint8_t  kind     = 0;
        Clock::time_point first;
        std::map<uint16_t, std::vector<uint8_t>> slices;
    };

    std::map<uint32_t, Frame> pending_;
    uint32_t next_      = 0;
    bool     have_next_ = false;
    bool     need_key_  = true;

    // The frame ends with a frame info trailer (codec at [0], keyframe flag
    // at [2], millisecond timestamp at [12]).
    void deliver(const Frame& f, const FrameFn& emit)
    {
        if (f.kind == 4) return;
        std::vector<uint8_t> data;
        for (const auto& kv : f.slices) data.insert(data.end(), kv.second.begin(), kv.second.end());
        size_t len = data.size();
        bool   key = f.kind == 5 || is_jpeg(data.data(), len);
        if (f.info_len && len > f.info_len) {
            len -= f.info_len;
            key = key || data[len + 2] == 1;
        }
        if (!key && starts_with_start_code(data.data(), len))
            key = h264_is_keyframe(data.data(), len);
        if (need_key_ && !key) {
            ++dropped;
            return;
        }
        need_key_ = false;
        emit(data.data(), len, key);
    }
};

// Keep-alive state of the framed transport: a heartbeat every 100 ms that
// reports the newest stream packet, a delay probe every 200 ms, and an answer
// to every probe of the printer.
struct LinkState {
    uint16_t rx_newest   = 0xffff;
    bool     rx_any      = false;
    uint16_t hb_reported = 0xffff;
    uint16_t hb_count    = 0;
    bool     hb_first    = true;
    bool     probe_first = true;
    uint16_t rx_since_ack = 0;
    uint16_t rtt_ms       = 50;
    Clock::time_point last_hb;
    Clock::time_point last_probe;

    void note_stream_packet(uint16_t counter)
    {
        if (!rx_any || (int16_t)(counter - rx_newest) > 0) rx_newest = counter;
        rx_any = true;
    }
};

} // namespace

struct TutkSession::Impl {
    std::atomic<bool> joined{false};
    std::thread       worker;
    FrameCallback     cb;
    IotcConn          conn{};
    uint16_t          out_seq       = 1;
    uint16_t          ioctrl_index  = 0;
    bool              framed        = true;
    uint32_t          login_nonce   = 0;
    LinkState         link;
    Clock::time_point started;

    Impl() { conn.sock = -1; }

    void run(const TutkSessionParams& p);
    int  connect(const TutkSessionParams& p);
    int  receive(const TutkSessionParams& p);

    void send(const uint8_t* data, size_t len) { iotc_send_app_data(&conn, data, len); }
    void put_header(uint8_t* pkt, uint8_t type, uint8_t flag);
    void send_login(const TutkSessionParams& p);
    void send_ioctrl(uint32_t io_type, uint32_t channel);
    void send_start();
    void send_stop();
    void send_transport_ack(uint16_t pkt_seq, uint16_t& ack_count);

    void send_heartbeat();
    void send_probe();
    void send_probe_ack(uint16_t echo_ts);
    void tick_link();

    void handle_legacy(const uint8_t* pkt, size_t n, LegacyAssembler& assembler,
                       uint16_t& ack_count, int& frames, int& start_triggers);
    void handle_framed(const uint8_t* pkt, size_t n, FecReceiver& fecs, FrameQueue& frames_q);
    void deliver(const uint8_t* data, size_t len, bool keyframe);
};

void TutkSession::Impl::put_header(uint8_t* pkt, uint8_t type, uint8_t flag)
{
    pkt[0] = type;
    pkt[1] = flag;
    put_le16(pkt + 2, kAvVersion);
    put_le16(pkt + 4, out_seq++);
}

void TutkSession::Impl::send_login(const TutkSessionParams& p)
{
    auto a = build_av_login(0x00, framed ? login_nonce : out_seq++, framed, p.passwd, p.uid);
    auto b = build_av_login(0x20, framed ? login_nonce + 1 : out_seq++, framed, p.passwd, p.uid);
    send(a.data(), a.size());
    send(b.data(), b.size());
}

// Framed: a 0x0c packet with an empty group header in front of the body.
// Legacy: the body follows the 8-byte AV header directly.
void TutkSession::Impl::send_ioctrl(uint32_t io_type, uint32_t channel)
{
    uint8_t pkt[48] = {0};
    const size_t hdr = framed ? 16 : 8;
    put_header(pkt, framed ? kTypeFramed : 0x00, framed ? 0 : 0x70);
    build_ioctrl_body(pkt + hdr, io_type, channel, framed ? ioctrl_index++ : 0);
    send(pkt, hdr + 32);
}

// The framed stream serves the main 1080p channel only; the legacy stream
// is requested on both channels like before.
void TutkSession::Impl::send_start()
{
    send_ioctrl(kIoTypeIpcamStart, 0);
    if (!framed) send_ioctrl(kIoTypeIpcamStart, 1);
}

void TutkSession::Impl::send_stop()
{
    send_ioctrl(kIoTypeIpcamStop, 0);
    if (!framed) send_ioctrl(kIoTypeIpcamStop, 1);
}

// Legacy 20-byte transport acknowledgement (type 0x0b) for a packet whose
// flag asks for one: acked counter at [8], delta 1 at [10], running count at
// [12].
void TutkSession::Impl::send_transport_ack(uint16_t pkt_seq, uint16_t& ack_count)
{
    uint8_t ack[20] = {0};
    put_header(ack, kTypeProbeAck, 0);
    put_le16(ack + 8, pkt_seq);
    put_le16(ack + 10, 1);
    put_le16(ack + 12, ack_count++);
    send(ack, sizeof(ack));
}

// 24-byte heartbeat: previously and currently reported newest stream packet
// counters, 1, heartbeat number at [18] and our 16-bit clock at [20]. The
// very first one has 0xff in [8..14) and 0 at [12].
void TutkSession::Impl::send_heartbeat()
{
    uint8_t pkt[24] = {0};
    put_header(pkt, kTypeHeartbeat, 0);
    if (link.hb_first) {
        memset(pkt + 8, 0xff, 6);
        link.hb_first = false;
    } else {
        const uint16_t newest = link.rx_any ? link.rx_newest : 0xffff;
        put_le16(pkt + 8, link.hb_reported);
        put_le16(pkt + 10, newest);
        put_le32(pkt + 12, 1);
        link.hb_reported = newest;
    }
    put_le16(pkt + 18, link.hb_count++);
    put_le16(pkt + 20, now_ms16());
    send(pkt, sizeof(pkt));
}

// 16-byte delay probe: our clock at [8] (echoed by the printer), the current
// round trip estimate at [10], 0x30 in the first probe and 1 afterwards.
void TutkSession::Impl::send_probe()
{
    uint8_t pkt[16] = {0};
    put_header(pkt, kTypeProbe, 0x08);
    put_le16(pkt + 8, now_ms16());
    put_le16(pkt + 10, link.rtt_ms);
    put_le32(pkt + 12, link.probe_first ? 0x30 : 1);
    link.probe_first = false;
    send(pkt, sizeof(pkt));
}

// 20-byte answer to a printer probe: not counted, 0x1f at [6], the echoed
// clock and the number of packets received since the previous answer.
void TutkSession::Impl::send_probe_ack(uint16_t echo_ts)
{
    uint8_t pkt[20] = {0};
    pkt[0] = kTypeProbeAck;
    put_le16(pkt + 2, kAvVersion);
    pkt[6] = 0x1f;
    put_le16(pkt + 8, echo_ts);
    put_le16(pkt + 10, link.rx_since_ack);
    put_le16(pkt + 12, link.rx_since_ack);
    link.rx_since_ack = 0;
    send(pkt, sizeof(pkt));
}

void TutkSession::Impl::tick_link()
{
    const auto now = Clock::now();
    if (now - link.last_hb >= std::chrono::milliseconds(100)) {
        link.last_hb = now;
        send_heartbeat();
    }
    if (now - link.last_probe >= std::chrono::milliseconds(200)) {
        link.last_probe = now;
        send_probe();
    }
}

void TutkSession::Impl::deliver(const uint8_t* data, size_t len, bool keyframe)
{
    if (!cb || len == 0) return;
    int64_t pts_us = std::chrono::duration_cast<std::chrono::microseconds>(
        Clock::now() - started).count();
    cb(data, (int)len, pts_us, keyframe);
}

int TutkSession::Impl::connect(const TutkSessionParams& p)
{
    iotc_close(&conn);

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

        out_seq      = 1;
        ioctrl_index = 0;
        link         = LinkState{};
        login_nonce  = std::random_device{}();
        send_login(p);

        // The printer echoes our capability block when it speaks the framed
        // transport; anything else means the legacy stream.
        uint8_t resp[512];
        int n = iotc_recv_app_data(&conn, resp, sizeof(resp), 800);
        if (n >= 40 && resp[0] == 0x00 && resp[1] == 0x21) {
            if (framed && get_le32(resp + 36) == 0) {
                OBN_INFO("tutk: printer has no framed transport, using the legacy stream");
                framed = false;
                send_login(p);
            } else {
                OBN_DEBUG("tutk: AV login accepted (%s)", framed ? "framed" : "legacy");
            }
        }
        if (framed) {
            send_probe();
            send_start();
            send_heartbeat();
            link.last_hb = link.last_probe = Clock::now();
        } else {
            send_start();
        }
        return 0;
    }
    return -1;
}

void TutkSession::Impl::handle_legacy(const uint8_t* pkt, size_t n, LegacyAssembler& assembler,
                                      uint16_t& ack_count, int& frames, int& start_triggers)
{
    const uint8_t  type    = pkt[0];
    const uint8_t  flag    = pkt[1];
    const uint16_t pkt_seq = get_le16(pkt + 4);

    if (type == 0x00) {
        switch (flag) {
        case 0x21:  // login accepted
            send_start();
            break;
        case 0x10: {  // IOCtrl from the printer: echo the header as 0x11
            if (n < 24) break;
            OBN_DEBUG("tutk: IOCtrl 0x%x on channel %u",
                      n >= 32 ? get_le32(pkt + 28) : 0, get_le16(pkt + 10));
            uint8_t reply[24];
            memcpy(reply, pkt, 24);
            reply[1] = 0x11;
            reply[9] = 0x11;
            reply[16] = reply[17] = 0;
            send(reply, sizeof(reply));
            if (start_triggers++ < 3) send_start();
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
        return;
    }

    // Stream packets: type 0x01 with the stream kind in the flag, or the
    // kind as the type itself (0x03..0x08). Kind 4 is audio.
    if (type != 0x01 && (type < 0x03 || type > 0x08)) return;
    if (flag & 0x08) send_transport_ack(pkt_seq, ack_count);
    const uint8_t kind = (type == 0x01) ? flag : type;
    if (kind == 0x04) return;

    // With flag bit 3 an 8-byte transport header follows the AV header.
    // The slice header then has the slice index at [2], slice count at
    // [4], slice length at [8] and the frame number at [12]; the slice
    // data starts 20 bytes after it.
    const size_t extra = (flag & 0x08) ? 8 : 0;
    const size_t hdr   = 8 + extra;
    const size_t data  = 28 + extra;
    if (n <= data) return;
    uint16_t slice_idx = get_le16(pkt + hdr + 2);
    uint16_t slice_cnt = get_le16(pkt + hdr + 4);
    size_t   slice_len = get_le16(pkt + hdr + 8);
    uint32_t frame_no  = get_le32(pkt + hdr + 12);
    if (slice_len == 0 || data + slice_len > n) slice_len = n - data;

    if (!assembler.add(frame_no, slice_idx, slice_cnt, pkt + data, slice_len)) return;
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

// A 0x0c packet: AV header, with flag bit 3 an embedded printer probe (8
// bytes, clock at [0]), then an 8-byte group header (group number, index,
// k data packets, m parity packets) and the body. k == 0 marks control
// traffic such as IOCtrl notifications, which need no answer.
void TutkSession::Impl::handle_framed(const uint8_t* pkt, size_t n, FecReceiver& fecs,
                                      FrameQueue& frames_q)
{
    size_t off = 8;
    if (pkt[1] & 0x08) {
        if (n < 16) return;
        send_probe_ack(get_le16(pkt + 8));
        off = 16;
    }
    if (n < off + 8) return;
    const uint16_t group = get_le16(pkt + off);
    const uint8_t  idx   = pkt[off + 2];
    const uint8_t  k     = pkt[off + 3];
    const uint32_t m     = get_le32(pkt + off + 4);
    const uint8_t* body  = pkt + off + 8;
    const size_t   blen  = n - off - 8;

    if (k == 0) {
        if (blen >= 24 && body[1] == 0x10)
            OBN_DEBUG("tutk: IOCtrl 0x%x from printer", get_le32(body + 20));
        return;
    }
    if (m > 255u - k) return;
    link.note_stream_packet(get_le16(pkt + 4));

    fecs.add(group, idx, k, (uint8_t)m, body, blen, [&](const uint8_t* s, size_t sn) {
        SliceHeader h;
        if (parse_slice_header(s, sn, h)) frames_q.add(h, s + kSliceHeaderLen);
    });
}

// Pumps the session until leave() or a failure. Returns 0 after leave(),
// negative when the session should be re-established.
int TutkSession::Impl::receive(const TutkSessionParams& p)
{
    LegacyAssembler legacy;
    FecReceiver     fecs;
    FrameQueue      frames_q;
    uint16_t ack_count      = 1;
    int      frames         = 0;
    int      retries        = 0;
    int      start_triggers = 0;
    auto     last_retry     = Clock::now();
    auto     last_data      = last_retry;
    auto     last_stats     = last_retry;
    std::vector<uint8_t> buf(65536);

    auto emit = [&](const uint8_t* data, size_t len, bool key) {
        if (++frames == 1) OBN_INFO("tutk: first video frame (%zu bytes)", len);
        deliver(data, len, key);
    };

    while (joined.load()) {
        const auto now = Clock::now();
        if (frames == 0) {
            if (now - last_retry >= std::chrono::milliseconds(1500)) {
                if (++retries > 5) {
                    OBN_WARN("tutk: no video after %d login attempts", retries - 1);
                    return -1;
                }
                last_retry = now;
                OBN_DEBUG("tutk: no video yet, repeating login (%d/5)", retries);
                send_login(p);
                send_start();
            }
        } else if (now - last_data >= std::chrono::seconds(5)) {
            OBN_WARN("tutk: video stalled for 5 s");
            return -4;
        }
        if (framed) tick_link();
        if (now - last_stats >= std::chrono::seconds(10)) {
            last_stats = now;
            OBN_DEBUG("tutk: %d frames, %d packets recovered, %d lost, %d frames dropped",
                      frames, fecs.recovered, fecs.lost, frames_q.dropped);
        }

        int n = iotc_recv_app_data(&conn, buf.data(), buf.size(), 20);
        if (n < 0) {
            OBN_WARN("tutk: session lost (%d)", n);
            return n;
        }
        if (n < 8) continue;
        last_data = Clock::now();

        const uint8_t* pkt = buf.data();
        if (get_le16(pkt + 2) != kAvVersion) continue;

        if (!framed) {
            handle_legacy(pkt, (size_t)n, legacy, ack_count, frames, start_triggers);
            continue;
        }

        ++link.rx_since_ack;
        switch (pkt[0]) {
        case kTypeFramed:
            handle_framed(pkt, (size_t)n, fecs, frames_q);
            frames_q.flush(fecs.has_holes(), emit);
            break;
        case kTypeProbe:
            if (n >= 16) send_probe_ack(get_le16(pkt + 8));
            break;
        case kTypeProbeAck:
            if (n >= 10) {
                const uint16_t rtt = (uint16_t)(now_ms16() - get_le16(pkt + 8));
                if (rtt < 5000) link.rtt_ms = (uint16_t)((link.rtt_ms * 7 + rtt) / 8);
            }
            break;
        default:
            break;
        }
    }

    OBN_INFO("tutk: session end: %d frames, %d packets recovered, %d lost, %d frames dropped",
             frames, fecs.recovered, fecs.lost, frames_q.dropped);
    send_stop();
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
    impl_->started = Clock::now();
    impl_->framed  = true;
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
