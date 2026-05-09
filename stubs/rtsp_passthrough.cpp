#include "rtsp_passthrough.hpp"

#include "rtsp_client.hpp"
#include "source_log.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

namespace obn::rtsp {

namespace {

using obn::source::log_fmt;
using obn::source::Logger;

// gstbambusrc.c uses `Bambu_SampleFlag::f_sync == 1` to flag access
// units that start a fresh GOP. We mirror that on every IDR.
constexpr int kFlagSync = 1;

// Cap the ready queue so a slow consumer cannot grow memory without
// bound. gstbambusrc polls every 33 ms (30 Hz); a queue of 8 access
// units gives ~250 ms of headroom which is plenty.
constexpr std::size_t kMaxReadyQueue = 8;

// One Annex-B encoded access unit ready to be handed to the caller.
struct Sample {
    std::vector<std::uint8_t> bytes;
    std::uint64_t             dt_100ns = 0;
    int                       flags    = 0;
};

inline void append_annexb(std::vector<std::uint8_t>& out,
                          const std::uint8_t* nal, std::size_t n)
{
    static constexpr std::uint8_t kStartCode[4] = {0x00, 0x00, 0x00, 0x01};
    out.insert(out.end(), kStartCode, kStartCode + 4);
    out.insert(out.end(), nal, nal + n);
}

inline bool nal_is_sps(std::uint8_t nal0) { return (nal0 & 0x1f) == 7; }
inline bool nal_is_pps(std::uint8_t nal0) { return (nal0 & 0x1f) == 8; }

} // namespace

struct Passthrough::Impl {
    Logger logger;
    void*  log_ctx;

    Client client;

    std::thread             worker;
    std::atomic<bool>       stop_flag{false};

    std::mutex              q_mu;
    std::condition_variable q_cv;
    std::deque<Sample>      ready;

    Sample                  current;            // borrowed by last try_pull
    std::chrono::steady_clock::time_point t0;

    Impl(Logger l, void* c)
        : logger(l ? l : obn::source::noop_logger),
          log_ctx(c),
          client(l, c) {}
};

Passthrough::Passthrough(Logger logger, void* log_ctx)
    : impl_(std::make_unique<Impl>(logger, log_ctx)) {}

Passthrough::~Passthrough()
{
    stop();
}

int Passthrough::start(const std::string& host,
                       int                port,
                       const std::string& user,
                       const std::string& passwd,
                       const std::string& path,
                       bool               tls,
                       int                connect_timeout_ms)
{
    auto& I = *impl_;

    Url u;
    u.host    = host;
    u.port    = port;
    u.user    = user;
    u.passwd  = passwd;
    u.path    = path;
    u.tls     = tls;

    if (I.client.start(u, connect_timeout_ms) != 0) {
        // rtsp::Client already filled set_last_error.
        return -1;
    }

    const auto& tr = I.client.track();
    log_fmt(I.logger, I.log_ctx,
            "rtsp_passthrough: start ok (sps=%zuB pps=%zuB pt=%d)",
            tr.sps.size(), tr.pps.size(), tr.rtp_pt);

    I.t0 = std::chrono::steady_clock::now();
    I.stop_flag.store(false, std::memory_order_release);
    I.worker = std::thread([this] {
        auto& I = *impl_;

        // Annex-B accumulator for the current access unit. Flushed
        // when we either see a NAL with a different RTP timestamp
        // than what we are currently building, or when the M-bit on
        // the last RTP packet of a NAL marks the AU end.
        std::vector<std::uint8_t> au;
        au.reserve(64 * 1024);
        std::uint32_t au_ts        = 0;
        bool          au_open      = false;
        bool          au_has_idr   = false;
        const auto&   tr           = I.client.track();

        auto flush_au = [&]() {
            if (!au_open || au.empty()) {
                au.clear();
                au_open    = false;
                au_has_idr = false;
                return;
            }
            // Stamp DTS as wall-clock since start() (in 100 ns units),
            // matching what the MJPG path in BambuSource.cpp does.
            // Using wall-clock instead of the upstream RTP timestamp
            // sidesteps wrap-around handling and lines up with how
            // gstbambusrc's downstream sink treats live sources.
            auto now = std::chrono::steady_clock::now();
            auto ns  = std::chrono::duration_cast<std::chrono::nanoseconds>(
                          now - I.t0).count();

            Sample s;
            s.bytes    = std::move(au);
            s.dt_100ns = static_cast<std::uint64_t>(ns / 100);
            s.flags    = au_has_idr ? kFlagSync : 0;

            au.clear();
            au_open    = false;
            au_has_idr = false;

            std::unique_lock<std::mutex> lk(I.q_mu);
            // Drop oldest if backlogged - liveness over completeness.
            while (I.ready.size() >= kMaxReadyQueue) {
                I.ready.pop_front();
            }
            I.ready.emplace_back(std::move(s));
            lk.unlock();
            I.q_cv.notify_all();
        };

        while (!I.stop_flag.load(std::memory_order_acquire)) {
            Nalu n;
            int rc = I.client.read_nalu(&n);
            if (rc != 0) {
                // stop() races with read_nalu(): cancel() shuts the
                // socket down so SSL_read returns rc=-1 with no
                // last_error set. Treat that as a graceful shutdown
                // rather than a stream error.
                bool stopping = I.stop_flag.load(std::memory_order_acquire);
                if (rc == 1) {
                    log_fmt(I.logger, I.log_ctx,
                            "rtsp_passthrough: stream end");
                } else if (stopping) {
                    log_fmt(I.logger, I.log_ctx,
                            "rtsp_passthrough: read_nalu interrupted by stop()");
                } else {
                    const char* err = obn::source::get_last_error();
                    log_fmt(I.logger, I.log_ctx,
                            "rtsp_passthrough: read_nalu error: %s",
                            (err && *err) ? err : "(no detail)");
                }
                // Mark stream end via an empty, error-flag sample so
                // the consumer can bubble it up as Pull_StreamEnd /
                // Pull_Error. We use an empty sample with flags|=2
                // to distinguish from a normal IDR (flags=1).
                std::unique_lock<std::mutex> lk(I.q_mu);
                Sample marker;
                marker.dt_100ns = 0;
                marker.flags    = (rc == 1 || stopping)
                                    ? 0x100 /*EOS*/ : 0x200 /*ERR*/;
                I.ready.emplace_back(std::move(marker));
                lk.unlock();
                I.q_cv.notify_all();
                break;
            }

            if (n.data.empty()) continue;
            std::uint8_t nal0     = n.data[0];
            int          nal_type = nal0 & 0x1f;
            // Drop SPS / PPS coming in-band on the wire: we synthesise
            // them from the SDP cache before every IDR ourselves, so
            // honouring the in-band copies as well would just cost
            // bandwidth without changing the output.
            if (nal_is_sps(nal0) || nal_is_pps(nal0)) continue;

            if (au_open && n.rtp_ts_90khz != au_ts) {
                // Boundary by RTP timestamp change (in case the M-bit
                // got dropped or arrived out of order).
                flush_au();
            }

            if (!au_open) {
                au_open = true;
                au_ts   = n.rtp_ts_90khz;
            }

            if (nal_type == 5 /*IDR*/) {
                // Prefix SPS + PPS in front of every IDR so a decoder
                // that joins late (or an Orca reconnect after a brief
                // network hiccup) recovers without needing the next
                // SDP fetch.
                if (!tr.sps.empty()) append_annexb(au, tr.sps.data(), tr.sps.size());
                if (!tr.pps.empty()) append_annexb(au, tr.pps.data(), tr.pps.size());
                au_has_idr = true;
            }
            append_annexb(au, n.data.data(), n.data.size());

            if (n.au_end) {
                flush_au();
            }
        }
    });

    return 0;
}

Passthrough::PullResult Passthrough::try_pull(const std::uint8_t** out_buf,
                                              std::size_t*         out_size,
                                              std::uint64_t*       out_dt_100ns,
                                              int*                 out_flags)
{
    auto& I = *impl_;
    std::unique_lock<std::mutex> lk(I.q_mu);
    if (I.ready.empty()) return Pull_WouldBlock;

    I.current = std::move(I.ready.front());
    I.ready.pop_front();
    lk.unlock();

    if (I.current.flags & 0x100) return Pull_StreamEnd;
    if (I.current.flags & 0x200) return Pull_Error;

    *out_buf      = I.current.bytes.data();
    *out_size     = I.current.bytes.size();
    *out_dt_100ns = I.current.dt_100ns;
    *out_flags    = I.current.flags;
    return Pull_Ok;
}

void Passthrough::stop()
{
    if (!impl_) return;
    auto& I = *impl_;
    if (I.stop_flag.exchange(true)) return;

    // Wake the worker if it is blocked inside read_nalu(): cancel()
    // shuts the SSL socket down so SSL_read returns immediately.
    I.client.cancel();
    if (I.worker.joinable()) I.worker.join();
    I.client.stop();
}

} // namespace obn::rtsp
