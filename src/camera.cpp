//
// camera.cpp — camera session lifecycle and MJPEG HTTP server.
//
// Each printer camera session is managed by CameraRegistry.  The right
// ICameraSource is created by CameraSourceFactory:
//
//   bambu:///agora?...  → AgoraCameraSource  (H.264 relay via OssAgoraSignaling)
//   bambu:///tutk?...   → OssTutkCameraSource (H.264 relay via OssAgoraSignaling)
//   JPEG model + LAN IP → JpegCameraSource   (MJPEG served locally over HTTP)
//
// Only JPEG sources (Codec::MotionJpeg) get a local MJPEG HTTP server whose
// URL is handed to Studio.  H.264 relay sources return the original camera_url
// so Studio's BambuSource handles playback directly.

#include "obn/camera.hpp"
#include "obn/log.hpp"
#include "obn/os_compat.hpp"
#include "camera/ICameraSource.hpp"
#include "camera/CameraSourceFactory.hpp"

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
#  include <poll.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace obn::camera {

namespace {

// ── model classification ──────────────────────────────────────────────────────

std::string to_upper_(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

// ── socket send helpers ───────────────────────────────────────────────────────

bool send_raw_(obn::os::socket_t fd, const void* data, std::size_t n) {
    const char* p = static_cast<const char*>(data);
    std::size_t off = 0;
    while (off < n) {
#if defined(_WIN32)
        int sent = ::send(static_cast<SOCKET>(fd), p + off,
                          static_cast<int>(n - off), 0);
#else
        ssize_t sent = ::send(static_cast<int>(fd), p + off, n - off, 0);
#endif
        if (sent <= 0) return false;
        off += static_cast<std::size_t>(sent);
    }
    return true;
}

bool send_str_(obn::os::socket_t fd, const std::string& s) {
    return send_raw_(fd, s.data(), s.size());
}

bool send_vec_(obn::os::socket_t fd, const std::vector<uint8_t>& v) {
    return send_raw_(fd, v.data(), v.size());
}

// ── MjpegServer ───────────────────────────────────────────────────────────────
//
// Listens on 127.0.0.1:0 and serves a multipart/x-mixed-replace MJPEG stream.
// Each client gets its own detached thread that calls source->next_frame().
// Used only for JpegCameraSource (MotionJpeg codec).

class MjpegServer {
public:
    MjpegServer() = default;
    ~MjpegServer() { stop(); }
    MjpegServer(const MjpegServer&) = delete;
    MjpegServer& operator=(const MjpegServer&) = delete;

    int start(std::shared_ptr<bambu_net::camera::ICameraSource> source) {
        obn::os::winsock_init_once();
        source_ = std::move(source);

#if defined(_WIN32)
        obn::os::socket_t fd = static_cast<obn::os::socket_t>(
            ::socket(AF_INET, SOCK_STREAM, 0));
#else
        obn::os::socket_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
#endif
        if (!obn::os::socket_valid(fd)) return -1;

        {
            int on = 1;
#if defined(_WIN32)
            ::setsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_REUSEADDR,
                         reinterpret_cast<const char*>(&on), sizeof(on));
#else
            ::setsockopt(static_cast<int>(fd), SOL_SOCKET, SO_REUSEADDR,
                         &on, sizeof(on));
#endif
        }

        sockaddr_in sa{};
        sa.sin_family      = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port        = 0;

#if defined(_WIN32)
        if (::bind(static_cast<SOCKET>(fd),
                   reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0 ||
            ::listen(static_cast<SOCKET>(fd), 4) != 0) {
            obn::os::close_socket(fd); return -1;
        }
        int sl = sizeof(sa);
        if (::getsockname(static_cast<SOCKET>(fd),
                          reinterpret_cast<sockaddr*>(&sa), &sl) != 0) {
            obn::os::close_socket(fd); return -1;
        }
#else
        if (::bind(static_cast<int>(fd),
                   reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0 ||
            ::listen(static_cast<int>(fd), 4) != 0) {
            obn::os::close_socket(fd); return -1;
        }
        socklen_t sl = sizeof(sa);
        if (::getsockname(static_cast<int>(fd),
                          reinterpret_cast<sockaddr*>(&sa), &sl) != 0) {
            obn::os::close_socket(fd); return -1;
        }
#endif

        listen_fd_ = static_cast<std::uintptr_t>(fd);
        port_      = ntohs(sa.sin_port);
        running_.store(true);
        accept_thread_ = std::thread(&MjpegServer::accept_loop_, this);
        OBN_INFO("camera: MJPEG HTTP server on 127.0.0.1:%d", port_);
        return port_;
    }

    void stop() {
        if (!running_.exchange(false)) return;
        auto fd = static_cast<obn::os::socket_t>(listen_fd_);
        listen_fd_ = static_cast<std::uintptr_t>(obn::os::kInvalidSocket);
        if (obn::os::socket_valid(fd)) {
            obn::os::shutdown_both(fd);
            obn::os::close_socket(fd);
        }
        if (accept_thread_.joinable()) accept_thread_.join();
    }

    int port() const { return port_; }

private:
    void accept_loop_() {
        while (running_.load()) {
            sockaddr_in ca{};
#if defined(_WIN32)
            int cl = sizeof(ca);
            obn::os::socket_t c = static_cast<obn::os::socket_t>(
                ::accept(static_cast<SOCKET>(listen_fd_),
                         reinterpret_cast<sockaddr*>(&ca), &cl));
#else
            socklen_t cl = sizeof(ca);
            obn::os::socket_t c = ::accept(
                static_cast<int>(listen_fd_),
                reinterpret_cast<sockaddr*>(&ca), &cl);
#endif
            if (!obn::os::socket_valid(c)) {
                if (!running_.load()) break;
                if (obn::os::last_socket_error() == EINTR) continue;
                break;
            }
            auto src = source_;  // shared_ptr copy
            std::thread([c, src]() mutable {
                serve_client_(c, std::move(src));
                obn::os::close_socket(c);
            }).detach();
        }
    }

    static void serve_client_(
        obn::os::socket_t fd,
        std::shared_ptr<bambu_net::camera::ICameraSource> source)
    {
        // Drain HTTP request headers (we don't inspect them).
        char req[4096];
        std::size_t got = 0;
        while (got < sizeof(req) - 1) {
#if defined(_WIN32)
            int n = ::recv(static_cast<SOCKET>(fd), req + got,
                           static_cast<int>(sizeof(req) - 1 - got), 0);
#else
            ssize_t n = ::recv(static_cast<int>(fd), req + got,
                               sizeof(req) - 1 - got, 0);
#endif
            if (n <= 0) return;
            got += static_cast<std::size_t>(n);
            req[got] = '\0';
            if (std::strstr(req, "\r\n\r\n")) break;
        }

        const std::string stream_hdr =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: multipart/x-mixed-replace; boundary=frame\r\n"
            "Cache-Control: no-cache, no-store\r\n"
            "Connection: close\r\n"
            "\r\n";
        if (!send_str_(fd, stream_hdr)) return;

        while (source->is_open()) {
            auto frame_opt = source->next_frame(2000);
            if (!frame_opt) continue;  // timeout or EOS

            const auto& data = frame_opt->nal_data;
            if (data.empty()) continue;

            std::string part_hdr =
                "--frame\r\n"
                "Content-Type: image/jpeg\r\n"
                "Content-Length: " + std::to_string(data.size()) + "\r\n"
                "\r\n";
            if (!send_str_(fd, part_hdr)) break;
            if (!send_vec_(fd, data))     break;
            if (!send_str_(fd, "\r\n"))   break;
        }
    }

    std::shared_ptr<bambu_net::camera::ICameraSource> source_;
    std::uintptr_t  listen_fd_{static_cast<std::uintptr_t>(-1)};
    int             port_{0};
    std::atomic<bool> running_{false};
    std::thread     accept_thread_;
};

// ── CameraRegistry ─────────────────────────────────────────────────────────────

struct CameraEntry {
    std::shared_ptr<bambu_net::camera::ICameraSource> source;
    std::unique_ptr<MjpegServer>                       server;  // nullptr for H.264
    std::string                                         url;
};

class CameraRegistry {
public:
    static CameraRegistry& instance() {
        static CameraRegistry inst;
        return inst;
    }

    std::string start(const CameraSpec& spec) {
        stop(spec.dev_id);

        auto source = CameraSourceFactory().make(spec);

        if (!source) {
            // No local source — if there's an explicit camera_url, return it
            // so Studio's BambuSource handles playback natively.
            if (!spec.camera_url.empty()) {
                std::lock_guard<std::mutex> lk(mu_);
                entries_[spec.dev_id].url = spec.camera_url;
                return spec.camera_url;
            }
            OBN_DEBUG("camera: no source for %s (model=%s url=%s)",
                      spec.dev_id.c_str(), spec.model.c_str(),
                      spec.camera_url.c_str());
            return {};
        }

        if (!source->open()) {
            OBN_WARN("camera: source open() failed for %s", spec.dev_id.c_str());
            return {};
        }

        auto si = source->info();

        if (si.codec == bambu_net::camera::ICameraSource::Codec::MotionJpeg) {
            // JPEG camera: start local MJPEG HTTP server
            auto server = std::make_unique<MjpegServer>();
            int port = server->start(source);
            if (port < 0) {
                OBN_ERROR("camera: MJPEG server bind failed for %s",
                          spec.dev_id.c_str());
                source->close();
                return {};
            }
            std::string url = "http://127.0.0.1:" + std::to_string(port) + "/cam";
            {
                std::lock_guard<std::mutex> lk(mu_);
                entries_[spec.dev_id] = {source, std::move(server), url};
            }
            OBN_INFO("camera: JPEG session %s → %s",
                     spec.dev_id.c_str(), url.c_str());
            return url;
        }

        // H.264 relay source: keep running, return original camera_url for Studio
        std::string url = spec.camera_url;
        {
            std::lock_guard<std::mutex> lk(mu_);
            entries_[spec.dev_id] = {source, nullptr, url};
        }
        OBN_INFO("camera: H.264 session %s → %s",
                 spec.dev_id.c_str(), url.c_str());
        return url;
    }

    std::string start(const JpegConfig& cfg) {
        CameraSpec spec;
        spec.dev_id      = cfg.dev_id;
        spec.lan_ip      = cfg.ip;
        spec.access_code = cfg.access_code;
        return start(spec);
    }

    void stop(const std::string& dev_id) {
        std::shared_ptr<bambu_net::camera::ICameraSource> source;
        std::unique_ptr<MjpegServer>                       server;
        {
            std::lock_guard<std::mutex> lk(mu_);
            auto it = entries_.find(dev_id);
            if (it == entries_.end()) return;
            source = std::move(it->second.source);
            server = std::move(it->second.server);
            entries_.erase(it);
        }
        if (server) server->stop();
        if (source) source->close();
    }

    std::string get_url(const std::string& dev_id) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = entries_.find(dev_id);
        return it != entries_.end() ? it->second.url : std::string{};
    }

private:
    CameraRegistry() = default;
    std::mutex                         mu_;
    std::map<std::string, CameraEntry> entries_;
};

} // anonymous namespace

// ── Public API ────────────────────────────────────────────────────────────────

bool is_jpeg_model(const std::string& model) {
    if (model.empty()) return false;
    const std::string up = to_upper_(model);
    if (up.find("X1")  != std::string::npos) return false;
    if (up.find("H2")  != std::string::npos) return false;
    if (up.find("C11") != std::string::npos) return false;
    if (up.find("C12") != std::string::npos) return false;
    if (up.find("C16") != std::string::npos) return false;
    if (up.find("C18") != std::string::npos) return false;
    if (up.find("A1")  != std::string::npos) return true;
    if (up.find("N1")  != std::string::npos) return true;
    if (up.find("N2S") != std::string::npos) return true;
    if (up.find("P1")  != std::string::npos) return true;
    if (up.find("C13") != std::string::npos) return true;
    if (up.find("C14") != std::string::npos) return true;
    return false;
}

std::string start_camera(const CameraSpec& spec) {
    return CameraRegistry::instance().start(spec);
}

std::string start_camera(const JpegConfig& cfg) {
    return CameraRegistry::instance().start(cfg);
}

void stop_camera(const std::string& dev_id) {
    CameraRegistry::instance().stop(dev_id);
}

std::string get_url(const std::string& dev_id) {
    return CameraRegistry::instance().get_url(dev_id);
}

} // namespace obn::camera
