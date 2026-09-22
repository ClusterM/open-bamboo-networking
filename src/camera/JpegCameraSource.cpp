#include "JpegCameraSource.hpp"
#include "obn/log.hpp"
#include "obn/os_compat.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <vector>

namespace obn {
namespace camera {

// ── wire protocol constants ──────────────────────────────────────────────────

static constexpr uint32_t    kAuthPayloadSize = 0x40;
static constexpr uint32_t    kAuthTypeJpeg    = 0x3000;
static constexpr std::size_t kAuthPacketLen   = 80;
static constexpr std::size_t kFrameHeaderLen  = 16;
static constexpr uint8_t     kJpegSoi[2]      = {0xFF, 0xD8};
static constexpr uint32_t    kMaxPayloadBytes = 8u * 1024u * 1024u;

static void write_u32_le(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>(v);
    out[1] = static_cast<uint8_t>(v >> 8);
    out[2] = static_cast<uint8_t>(v >> 16);
    out[3] = static_cast<uint8_t>(v >> 24);
}

static uint32_t read_u32_le(const uint8_t* in) {
    return  static_cast<uint32_t>(in[0])
         | (static_cast<uint32_t>(in[1]) <<  8)
         | (static_cast<uint32_t>(in[2]) << 16)
         | (static_cast<uint32_t>(in[3]) << 24);
}

// ── TCP connect helper ───────────────────────────────────────────────────────

static int jpeg_tcp_connect(const std::string& host, int port, int timeout_ms)
{
    obn::os::winsock_init_once();

    addrinfo hints{};
    addrinfo* res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    std::snprintf(port_str, sizeof(port_str), "%d", port);
    if (::getaddrinfo(host.c_str(), port_str, &hints, &res) != 0 || !res)
        return -1;

    obn::os::socket_t best = obn::os::kInvalidSocket;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
#if defined(_WIN32)
        obn::os::socket_t fd = static_cast<obn::os::socket_t>(
            ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
#else
        obn::os::socket_t fd = ::socket(ai->ai_family,
                                         ai->ai_socktype, ai->ai_protocol);
#endif
        if (!obn::os::socket_valid(fd)) continue;
        {
            int yes = 1;
#if defined(_WIN32)
            ::setsockopt(static_cast<SOCKET>(fd), IPPROTO_TCP, TCP_NODELAY,
                         reinterpret_cast<const char*>(&yes), sizeof(yes));
#else
            ::setsockopt(static_cast<int>(fd), IPPROTO_TCP, TCP_NODELAY,
                         &yes, sizeof(yes));
#endif
        }
        obn::os::set_nonblocking(fd);
#if defined(_WIN32)
        int rc = ::connect(static_cast<SOCKET>(fd), ai->ai_addr,
                           static_cast<int>(ai->ai_addrlen));
#else
        int rc = ::connect(static_cast<int>(fd), ai->ai_addr, ai->ai_addrlen);
#endif
        if (rc == 0) { best = fd; break; }

        int err = obn::os::last_socket_error();
        if (obn::os::socket_in_progress(err)) {
            short rev = 0;
            int pr = obn::os::poll_one(fd, POLLOUT, timeout_ms, &rev);
            if (pr > 0 && (rev & POLLOUT)) {
                int so_err = 0;
#if defined(_WIN32)
                int sl = sizeof(so_err);
                ::getsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_ERROR,
                             reinterpret_cast<char*>(&so_err), &sl);
#else
                socklen_t sl = sizeof(so_err);
                ::getsockopt(static_cast<int>(fd), SOL_SOCKET, SO_ERROR,
                             &so_err, &sl);
#endif
                if (so_err == 0) { best = fd; break; }
            }
        }
        obn::os::close_socket(fd);
    }
    ::freeaddrinfo(res);
    return obn::os::socket_valid(best) ? static_cast<int>(best) : -1;
}

// ── JpegCameraSource ─────────────────────────────────────────────────────────

JpegCameraSource::JpegCameraSource(const JpegConfig& cfg)
    : cfg_(cfg)
    , queue_(std::make_shared<JpegFrameQueue>())
{}

JpegCameraSource::~JpegCameraSource()
{
    close();
}

bool JpegCameraSource::open()
{
    if (open_.load()) return true;
    running_.store(true);
    open_.store(true);
    reader_thread_ = std::thread(&JpegCameraSource::reader_loop_, this);
    return true;
}

void JpegCameraSource::close()
{
    if (!open_.exchange(false)) return;
    running_.store(false);
    {
        std::lock_guard<std::mutex> lk(mu_);
        close_fd_locked_();
    }
    if (reader_thread_.joinable()) reader_thread_.join();
}

bool JpegCameraSource::is_open() const
{
    return open_.load();
}

std::optional<bambu_net::camera::VideoFrame>
JpegCameraSource::next_frame(int timeout_ms)
{
    std::vector<uint8_t> raw;
    if (!queue_->pop(raw, timeout_ms)) {
        if (queue_->closed()) {
            // Reader exited — source is done
            open_.store(false);
        }
        return std::nullopt;
    }
    bambu_net::camera::VideoFrame f;
    f.nal_data    = std::move(raw);
    f.is_keyframe = true;   // every JPEG is a keyframe
    f.pts_us      = 0;
    return f;
}

bambu_net::camera::ICameraSource::StreamInfo JpegCameraSource::info() const
{
    StreamInfo si;
    si.width  = 1280;
    si.height = 720;
    si.fps    = 10;
    si.codec  = Codec::MotionJpeg;
    return si;
}

// ── Reader thread ─────────────────────────────────────────────────────────────

void JpegCameraSource::reader_loop_()
{
    while (running_.load()) {
        try {
            if (!connect_and_auth_()) {
                for (int i = 0; i < 30 && running_.load(); ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            OBN_INFO("camera: %s port-6000 connected", cfg_.dev_id.c_str());
            read_frames_();
            OBN_INFO("camera: %s stream ended", cfg_.dev_id.c_str());
        } catch (...) {
            OBN_WARN("camera: %s reader exception", cfg_.dev_id.c_str());
        }
        cleanup_tls_();
    }
    cleanup_tls_();
    queue_->close();
}

bool JpegCameraSource::connect_and_auth_()
{
    int fd = jpeg_tcp_connect(cfg_.ip, cfg_.port, cfg_.connect_timeout_ms);
    if (fd < 0) {
        OBN_WARN("camera: %s tcp_connect %s:%d failed",
                 cfg_.dev_id.c_str(), cfg_.ip.c_str(), cfg_.port);
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!running_.load()) {
            obn::os::close_socket(static_cast<obn::os::socket_t>(fd));
            return false;
        }
        fd_ = fd;
    }

    ssl_ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx_) { cleanup_tls_(); return false; }
    SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx_, TLS1_2_VERSION);
    SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_cipher_list(ssl_ctx_, "AES256-GCM-SHA384");

    ssl_ = SSL_new(ssl_ctx_);
    if (!ssl_) { cleanup_tls_(); return false; }
    SSL_set_fd(ssl_, fd_);

    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(cfg_.connect_timeout_ms);
    while (true) {
        if (!running_.load()) { cleanup_tls_(); return false; }
        int r = SSL_connect(ssl_);
        if (r == 1) break;
        int e = SSL_get_error(ssl_, r);
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) { cleanup_tls_(); return false; }
        int rem = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now).count());
        if (e == SSL_ERROR_WANT_READ) {
            if (poll_read_(rem) <= 0) { cleanup_tls_(); return false; }
        } else if (e == SSL_ERROR_WANT_WRITE) {
            if (poll_write_(rem) <= 0) { cleanup_tls_(); return false; }
        } else {
            OBN_WARN("camera: %s TLS error %d", cfg_.dev_id.c_str(), e);
            cleanup_tls_(); return false;
        }
    }

    // Build 80-byte auth packet
    std::vector<uint8_t> pkt(kAuthPacketLen, 0);
    write_u32_le(&pkt[0], kAuthPayloadSize);
    write_u32_le(&pkt[4], kAuthTypeJpeg);
    std::memcpy(&pkt[16], "bblp", 4);
    std::size_t pass_n = std::min<std::size_t>(32, cfg_.access_code.size());
    std::memcpy(&pkt[48], cfg_.access_code.data(), pass_n);
    if (ssl_write_full_(pkt.data(), pkt.size(), cfg_.connect_timeout_ms) != 0) {
        OBN_WARN("camera: %s auth write failed", cfg_.dev_id.c_str());
        cleanup_tls_(); return false;
    }
    return true;
}

void JpegCameraSource::read_frames_()
{
    std::vector<uint8_t> scratch;
    scratch.reserve(256 * 1024);
    while (running_.load()) {
        uint8_t hdr[kFrameHeaderLen];
        if (ssl_read_full_(hdr, kFrameHeaderLen, cfg_.read_timeout_ms) != 0)
            break;
        uint32_t payload = read_u32_le(hdr);
        if (payload == 0 || payload > kMaxPayloadBytes) {
            OBN_WARN("camera: %s bad payload=%u", cfg_.dev_id.c_str(), payload);
            break;
        }
        if (scratch.size() < payload) scratch.resize(payload);
        if (ssl_read_full_(scratch.data(), payload, cfg_.read_timeout_ms) != 0)
            break;
        if (payload < 2 ||
            scratch[0] != kJpegSoi[0] ||
            scratch[1] != kJpegSoi[1]) {
            OBN_WARN("camera: %s frame missing SOI", cfg_.dev_id.c_str());
            break;
        }
        queue_->push(std::vector<uint8_t>(scratch.begin(),
                                           scratch.begin() + payload));
    }
}

// ── TLS I/O ──────────────────────────────────────────────────────────────────

int JpegCameraSource::ssl_read_full_(uint8_t* dst, std::size_t n, int timeout_ms)
{
    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(timeout_ms);
    std::size_t off = 0;
    while (off < n) {
        if (!running_.load()) return -1;
        int r = SSL_read(ssl_, dst + off, static_cast<int>(n - off));
        if (r > 0) { off += static_cast<std::size_t>(r); continue; }
        int e = SSL_get_error(ssl_, r);
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return -1;
        int rem = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now).count());
        if (e == SSL_ERROR_WANT_READ) {
            if (poll_read_(rem) <= 0) return -1;
        } else if (e == SSL_ERROR_WANT_WRITE) {
            if (poll_write_(rem) <= 0) return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

int JpegCameraSource::ssl_write_full_(const uint8_t* src, std::size_t n, int timeout_ms)
{
    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(timeout_ms);
    std::size_t off = 0;
    while (off < n) {
        int r = SSL_write(ssl_, src + off, static_cast<int>(n - off));
        if (r > 0) { off += static_cast<std::size_t>(r); continue; }
        int e = SSL_get_error(ssl_, r);
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return -1;
        int rem = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now).count());
        if (e == SSL_ERROR_WANT_READ) {
            if (poll_read_(rem) <= 0) return -1;
        } else if (e == SSL_ERROR_WANT_WRITE) {
            if (poll_write_(rem) <= 0) return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

int JpegCameraSource::poll_read_(int timeout_ms)
{
    int fd; { std::lock_guard<std::mutex> lk(mu_); fd = fd_; }
    if (fd < 0) return -1;
    short rev = 0;
    return obn::os::poll_one(static_cast<obn::os::socket_t>(fd),
                              POLLIN, timeout_ms, &rev);
}

int JpegCameraSource::poll_write_(int timeout_ms)
{
    int fd; { std::lock_guard<std::mutex> lk(mu_); fd = fd_; }
    if (fd < 0) return -1;
    short rev = 0;
    return obn::os::poll_one(static_cast<obn::os::socket_t>(fd),
                              POLLOUT, timeout_ms, &rev);
}

void JpegCameraSource::close_fd_locked_()
{
    if (fd_ >= 0) {
        obn::os::close_socket(static_cast<obn::os::socket_t>(fd_));
        fd_ = -1;
    }
}

void JpegCameraSource::cleanup_tls_()
{
    if (ssl_) {
        SSL_set_shutdown(ssl_, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (ssl_ctx_) {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }
    std::lock_guard<std::mutex> lk(mu_);
    close_fd_locked_();
}

}  // namespace camera
}  // namespace obn
