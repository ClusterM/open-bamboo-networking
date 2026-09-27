//
// JpegCameraSource — ICameraSource for A1/P1/N1/N2S/C13/C14 TLS-MJPEG stream.
//
// Implements ICameraSource (pull model) over an internal push-model reader
// thread that maintains a TLS connection to the printer's port 6000.
//
// Thread model:
//   reader_thread_   owns the TLS connection; pushes frames to queue_.
//   next_frame()     called from MjpegServer's per-client threads; pops.
//   close() / mu_    closes the raw socket to interrupt blocking TLS reads.

#pragma once

#include "ICameraSource.hpp"
#include "obn/camera.hpp"     // JpegConfig, is_jpeg_model

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

typedef struct ssl_st     SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace obn {
namespace camera {

// Internal frame queue (push/blocking-pop) shared between reader thread and
// multiple serve_client_ threads.
class JpegFrameQueue {
public:
    static constexpr int kMaxFrames = 10;

    void push(std::vector<uint8_t> frame) {
        std::lock_guard<std::mutex> lk(mu_);
        if (closed_) return;
        while (static_cast<int>(frames_.size()) >= kMaxFrames)
            frames_.pop_front();
        frames_.push_back(std::move(frame));
        cv_.notify_one();
    }

    // Block up to timeout_ms. Returns true + fills `out` on success.
    bool pop(std::vector<uint8_t>& out, int timeout_ms) {
        std::unique_lock<std::mutex> lk(mu_);
        bool ready = cv_.wait_for(
            lk, std::chrono::milliseconds(timeout_ms),
            [this] { return !frames_.empty() || closed_; });
        if (!ready || frames_.empty()) return false;
        out = std::move(frames_.front());
        frames_.pop_front();
        return true;
    }

    void close() {
        std::lock_guard<std::mutex> lk(mu_);
        closed_ = true;
        frames_.clear();
        cv_.notify_all();
    }

    bool closed() const {
        std::lock_guard<std::mutex> lk(mu_);
        return closed_;
    }

private:
    mutable std::mutex               mu_;
    std::condition_variable          cv_;
    std::deque<std::vector<uint8_t>> frames_;
    bool                             closed_ = false;
};

class JpegCameraSource : public bambu_net::camera::ICameraSource {
public:
    explicit JpegCameraSource(const JpegConfig& cfg);
    ~JpegCameraSource() override;

    JpegCameraSource(const JpegCameraSource&) = delete;
    JpegCameraSource& operator=(const JpegCameraSource&) = delete;

    // ICameraSource interface
    bool open()          override;
    void close()         override;
    bool is_open() const override;
    std::optional<bambu_net::camera::VideoFrame> next_frame(int timeout_ms) override;
    StreamInfo info() const override;

private:
    void reader_loop_();
    bool connect_and_auth_();
    void read_frames_();
    void cleanup_tls_();
    void close_fd_locked_();

    int  ssl_read_full_(uint8_t* dst, std::size_t n, int timeout_ms);
    int  ssl_write_full_(const uint8_t* src, std::size_t n, int timeout_ms);
    int  poll_read_(int timeout_ms);
    int  poll_write_(int timeout_ms);

    JpegConfig                        cfg_;
    std::shared_ptr<JpegFrameQueue>   queue_;
    std::atomic<bool>                 open_{false};
    std::atomic<bool>                 running_{false};
    mutable std::mutex                mu_;       // guards fd_
    int                               fd_ = -1; // protected by mu_
    SSL_CTX*                          ssl_ctx_ = nullptr; // reader thread only
    SSL*                              ssl_     = nullptr;  // reader thread only
    std::thread                       reader_thread_;
};

}  // namespace camera
}  // namespace obn
