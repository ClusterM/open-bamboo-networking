// Minimal RTSP / RTSPS client for Bambu Lab printers.
//
// Bambu's X1 / P1S / P2S firmware exposes the camera as an RTSP-over-TLS
// stream on port 322 with H.264 inside RTP/TCP-interleaved packets.
// The official libBambuSource ships an embedded live555 client to read
// it; we replace that with a hand-rolled client small enough to live
// next to the rest of libBambuSource and free of the version-skew
// problems we hit when trying to dlopen system libavformat (whose
// DT_NEEDED libavutil clashed with the older libavutil that Studio's
// AppImage already had loaded -- see README).
//
// What this client does *not* do, on purpose:
//   - UDP transport. Bambu always negotiates TCP-interleaved; offering
//     UDP would just add a fallback path no real printer takes.
//   - Plain RTSP without TLS. The URL parser still accepts rtsp:// for
//     symmetry / test fixtures, but Bambu never serves it.
//   - Digest authentication. Every printer firmware we have looked at
//     speaks Basic; if a future revision returns 401, start() reports
//     an error and the caller's "could not authenticate" surface fires
//     (we did not want to ship a half-tested Digest path that nobody
//     can actually exercise today).
//   - Random RTSP servers. The SDP parser is good enough for Bambu's
//     output but is not a general-purpose SDP implementation; in
//     particular it expects a single H.264 video track, payload type
//     advertised via `a=rtpmap`, parameter sets via `sprop-parameter-sets`,
//     and a track URL given by `a=control:`.
//
// Threading: start() / read_nalu() / stop() are *not* thread-safe with
// each other. The intended pattern is one producer thread driving
// read_nalu() in a loop and another thread calling stop() exactly
// once. cancel() is the only call that may be made from any thread:
// it shuts the socket down to break the producer out of an in-flight
// SSL_read. The RTSP keepalive and the RTCP receiver reports run on
// one internal thread that the client owns.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "source_log.hpp"

namespace obn::rtsp {

// Parsed RTSP URL. host/port/path are the minimum required to dial;
// user/passwd flow into Basic auth on every request.
struct Url {
    std::string host;
    int         port    = 322;
    std::string user    = "bblp";
    std::string passwd;
    std::string path    = "/streaming/live/1";
    // Printer serial from ?device= (SNI + CN verify for RTSPS TLS).
    std::string device;
    // True for rtsps:// (TLS on top of TCP). Always true for Bambu;
    // settable for unit tests and the rare custom firmware that opts
    // out.
    bool        tls     = true;
};

// What the SDP told us about the H.264 video track. Filled in by
// start() and stable across the lifetime of the client.
struct H264Track {
    // Out-of-band parameter sets, raw NAL bytes (no Annex-B start
    // code). Either or both may be empty if the printer chose to send
    // them in-band only; the decoder catches up with the first IDR.
    std::vector<std::uint8_t> sps;
    std::vector<std::uint8_t> pps;

    // Always 90000 for H.264; kept as a field so the timestamp math
    // upstream is explicit instead of relying on a magic number.
    std::uint32_t clock_rate = 90000;

    // RTP payload type from `m=video <port> RTP/AVP <pt>`. We only
    // emit NAL units originating from this PT; others (RTCP, audio)
    // are dropped before reaching read_nalu().
    int           rtp_pt     = 96;

    // Geometry and frame rate decoded from the SDP's SPS, cropping
    // applied. Zero when the SDP carried no SPS or it did not parse,
    // in which case the caller keeps its own default.
    int           width      = 0;
    int           height     = 0;
    // Rounded frames per second from the SPS VUI timing info; 0 when
    // the SPS omits it (VUI timing is optional).
    int           fps        = 0;
};

// One NAL unit handed back to the caller. `data` is *raw NAL bytes*:
// no Annex-B `00 00 00 01` prefix. The decoder side will add it (or
// the AVCC-style 4-byte big-endian length) as needed.
struct Nalu {
    std::vector<std::uint8_t> data;
    // RTP timestamp in the track's 90 kHz clock at the moment the
    // first packet of this NALU was emitted.
    std::uint32_t             rtp_ts_90khz = 0;
    // True when the M-bit on the last RTP packet was set, i.e. this
    // NAL unit terminates an access unit. The decoder uses it to
    // flush any pending reorder buffer.
    bool                      au_end       = false;
};

class Client {
public:
    // logger / log_ctx are forwarded as-is to obn::source::log_at, so
    // Studio's per-tunnel callback receives the same trace we mirror
    // into obn-bambusource.log.
    Client(obn::source::Logger logger, void* log_ctx);
    ~Client();

    // Synchronous: TCP-connect, TLS handshake, OPTIONS, DESCRIBE,
    // parse SDP, SETUP, PLAY. On success returns 0 with track()
    // populated. On failure returns -1 with set_last_error(...) and
    // any partial state already torn down (idempotent stop()).
    //
    // connect_timeout_ms applies to the TCP connect *and* to each
    // subsequent control-plane SSL_read; the worker thread is
    // started by start() and runs until stop() is called, so the
    // timeout does not affect the data plane.
    int start(const Url& url, int connect_timeout_ms = 5000);

    // Pulls the next NAL unit. Blocks the calling thread until one
    // is available, the peer hangs up, or cancel()/stop() unblocks
    // it. Return codes:
    //    0 - NAL written into *out
    //    1 - clean end-of-stream (server sent TEARDOWN or closed TCP)
    //   -1 - protocol or transport error (see get_last_error())
    int read_nalu(Nalu* out);

    // Snapshot of the H.264 parameters parsed during start(). Result
    // is valid only between a successful start() and stop().
    const H264Track& track() const noexcept;

    // Idempotent. After stop() the client is dead -- the keepalive
    // thread is joined, TLS is shut down, and read_nalu() returns -1.
    void stop();

    // Thread-safe wake-up for a producer parked in SSL_read. Calls
    // shutdown(fd, SHUT_RDWR) on the underlying socket so the read
    // returns immediately. Safe to call multiple times. Does NOT
    // free the SSL session -- stop() does that under a mutex.
    void cancel();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace obn::rtsp
