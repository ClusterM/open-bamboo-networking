// RTSP/RTSPS H.264 byte-stream passthrough.
//
// gstbambusrc.c (vendored verbatim by both Bambu Studio and Orca
// Slicer on Linux) takes whatever Bambu_ReadSample hands it and
// pushes it straight at a GStreamer pipeline whose first element is
// `h264parse ! avdec_h264 / openh264dec / vaapih264dec`. The slicer
// side is responsible for decoding; the plugin side only needs to
// deliver Annex-B byte-stream H.264.
//
// Passthrough wires obn::rtsp::Client (which already does the
// RTSP/RTSPS handshake + RTP depacketisation) up to that contract:
//
//    SDP                 ->  cached SPS / PPS, hand-prefixed before
//                            every IDR access unit so the decoder
//                            can recover after reconnects.
//    interleaved RTP/TCP ->  rtsp::Client::read_nalu() (background
//                            worker thread).
//    Annex-B emit        ->  worker assembles one access unit at a
//                            time, prepends `00 00 00 01` to each
//                            NAL, copies into a small ring of
//                            shared_ptr<vector<uint8_t>> samples.
//    Bambu_ReadSample    ->  try_pull() pops the head of the ring;
//                            buffer pointer is borrowed (valid until
//                            the next try_pull()).
//
// The class deliberately exposes the same enum shape (Ok / WouldBlock
// / StreamEnd / Error) the C-ABI expects so BambuSource.cpp can map
// 1:1 onto Bambu_success / Bambu_would_block / Bambu_stream_end / -1.
//
// Threading: start() / try_pull() / stop() are called from the same
// thread (BambuSource's per-tunnel call site). The worker thread is
// internal and is joined inside stop(); start() spawns it once.
#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "source_log.hpp"

namespace obn::rtsp {

class Passthrough {
public:
    enum PullResult {
        Pull_Ok         =  0,  // Bambu_success
        Pull_StreamEnd  =  1,  // Bambu_stream_end
        Pull_WouldBlock =  2,  // Bambu_would_block
        Pull_Error      = -1,
    };

    // Geometry the SDP's SPS advertised, zeroed when it did not parse.
    struct StreamParams {
        int width  = 0;
        int height = 0;
        int fps    = 0;
    };

    Passthrough(obn::source::Logger logger, void* log_ctx);
    ~Passthrough();

    // Synchronous: dial + TLS + OPTIONS/DESCRIBE/SETUP/PLAY. Spawns
    // the worker thread once handshake succeeds. Returns 0 on
    // success, -1 on any failure (set_last_error has the detail).
    int start(const std::string& host,
              int                port,
              const std::string& user,
              const std::string& passwd,
              const std::string& path,
              bool               tls,
              const std::string& device = {},
              int                connect_timeout_ms = 5000);

    // Valid after a successful start().
    StreamParams params() const;

    // Non-blocking pop of the next ready Annex-B sample. The caller
    // gets a borrowed pointer; it remains valid until the next
    // try_pull() call (or stop()). dt_100ns is wall-clock since
    // start() in 100 ns units (matches the existing MJPG path so
    // gstbambusrc's `decode_time * 100ULL` does the right thing).
    // flags carries Bambu_SampleFlag::f_sync (1) on access units
    // containing an IDR slice.
    //
    // Never answers Pull_WouldBlock forever: once no access unit has
    // been produced for the stall timeout, every call returns
    // Pull_Error. gstbambusrc polls "would block" in a usleep loop
    // while holding the pad's stream lock and has no unlock() handler,
    // so an endlessly blocked source deadlocks the slicer's teardown
    // (issue #54) -- reporting the dead stream is what breaks the loop.
    PullResult try_pull(const std::uint8_t** out_buf,
                        std::size_t*         out_size,
                        std::uint64_t*       out_dt_100ns,
                        int*                 out_flags);

    // Idempotent. Joins the worker, tears down the RTSP client.
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace obn::rtsp
