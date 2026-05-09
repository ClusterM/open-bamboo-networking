#include "obn/cover_server.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <sys/types.h>
#endif

#include "obn/cover_cache.hpp"
#include "obn/log.hpp"
#include "obn/os_compat.hpp"

namespace fs = std::filesystem;

namespace obn::cover_server {

namespace {

using obn::os::socket_t;
using obn::os::kInvalidSocket;

// Cheap containment check: the requested filename must live under
// cover_cache::temp_dir() and must match the "cover-XXXXXXXX-pN.png"
// pattern that cover_cache::path_for produces. We deliberately reject
// anything with path separators or "..".
bool safe_basename(const std::string& s)
{
    if (s.empty() || s.size() > 64) return false;
    if (s.find('/') != std::string::npos) return false;
    if (s.find('\\') != std::string::npos) return false;
    if (s.find("..") != std::string::npos) return false;
    // Must start with "cover-" and end with ".png" - anything else is
    // not a file we produced.
    if (s.rfind("cover-", 0) != 0) return false;
    if (s.size() < 4 || s.substr(s.size() - 4) != ".png") return false;
    return true;
}

std::string read_file(const fs::path& p)
{
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    std::string body((std::istreambuf_iterator<char>(f)), {});
    return body;
}

void send_all(socket_t fd, const std::string& data)
{
    std::size_t off = 0;
    while (off < data.size()) {
#if defined(_WIN32)
        int n = ::send(static_cast<SOCKET>(fd), data.data() + off,
                       static_cast<int>(data.size() - off), 0);
#else
        ssize_t n = ::send(static_cast<int>(fd), data.data() + off,
                           data.size() - off, 0);
#endif
        if (n <= 0) return;
        off += static_cast<std::size_t>(n);
    }
}

void send_status(socket_t fd, int code, const std::string& reason)
{
    std::string r = "HTTP/1.1 " + std::to_string(code) + " " + reason +
                    "\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    send_all(fd, r);
}

void handle_one(socket_t fd)
{
    // Read request header into a bounded buffer. 4 KB is plenty for a
    // line like "GET /cover/cover-XXXXXXXX-p1.png HTTP/1.1".
    char  buf[4096];
    std::size_t got = 0;
    while (got < sizeof(buf) - 1) {
#if defined(_WIN32)
        int n = ::recv(static_cast<SOCKET>(fd), buf + got,
                       static_cast<int>(sizeof(buf) - 1 - got), 0);
#else
        ssize_t n = ::recv(static_cast<int>(fd), buf + got,
                           sizeof(buf) - 1 - got, 0);
#endif
        if (n <= 0) break;
        got += static_cast<std::size_t>(n);
        buf[got] = 0;
        if (std::strstr(buf, "\r\n\r\n")) break;
    }
    buf[got < sizeof(buf) ? got : sizeof(buf) - 1] = 0;

    // Parse request line: METHOD SP TARGET SP VERSION.
    const char* sp1 = std::strchr(buf, ' ');
    if (!sp1) { send_status(fd, 400, "Bad Request"); return; }
    const char* sp2 = std::strchr(sp1 + 1, ' ');
    if (!sp2) { send_status(fd, 400, "Bad Request"); return; }
    std::string method(buf, sp1 - buf);
    std::string target(sp1 + 1, sp2 - sp1 - 1);
    OBN_DEBUG("cover_server: %s %s (got %zu header bytes)",
              method.c_str(), target.c_str(), got);
    if (method != "GET" && method != "HEAD") {
        send_status(fd, 405, "Method Not Allowed");
        return;
    }
    // Strip any query string - we don't use one, but wxWebRequest
    // sometimes appends cache-busting parameters.
    if (auto q = target.find('?'); q != std::string::npos) target.resize(q);

    static const std::string kPrefix = "/cover/";
    if (target.rfind(kPrefix, 0) != 0) {
        send_status(fd, 404, "Not Found");
        return;
    }
    std::string base = target.substr(kPrefix.size());
    if (!safe_basename(base)) {
        send_status(fd, 404, "Not Found");
        return;
    }
    fs::path full = fs::path(cover_cache::temp_dir()) / base;
    // Debug hook: allow pinning a single file to be served instead of
    // the FTPS cache, which lets us test what Studio's wxImage accepts
    // without reprinting.
    if (const char* o = std::getenv("OBN_COVER_DEBUG_FILE")) {
        if (*o) full = o;
    }
    std::error_code ec;
    // Studio fires a single wxWebRequest per subtask id and caches the
    // response (StatusPanel::update_cloud_subtask / img_list), so we
    // only get one shot to hand it a useable image. If the cover_cache
    // FTPS worker is still chugging, hold the connection open for up
    // to kWaitMs: a 20 MB .3mf takes ~2s over LAN FTPS.
    constexpr int kWaitMs = 15000;
    constexpr int kPollMs = 100;
    for (int waited = 0;
         waited < kWaitMs && (!fs::exists(full, ec) || ec);
         waited += kPollMs)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(kPollMs));
    }
    if (!fs::exists(full, ec) || ec) {
        // Return 503 so wxWebRequest goes into State_Failed and Studio
        // paints its "broken image" placeholder. refresh_thumbnail_
        // webrequest (triggered by a user click on the thumbnail) will
        // retry us - by which point the FTPS worker should have
        // finished.
        std::string r = "HTTP/1.1 503 Service Unavailable\r\n"
                        "Connection: close\r\nContent-Length: 0\r\n\r\n";
        send_all(fd, r);
        return;
    }
    std::string body = read_file(full);
    std::string hdr =
        "HTTP/1.1 200 OK\r\n"
        "Connection: close\r\n"
        "Content-Type: image/png\r\n"
        "Cache-Control: no-store\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
    send_all(fd, hdr);
    if (method == "GET") send_all(fd, body);
    OBN_DEBUG("cover_server: served %s %zu bytes",
              base.c_str(), body.size());
}

} // namespace

Server::Server() = default;

Server::~Server() { stop(); }

int Server::start()
{
    if (running_.load()) return 0;

    obn::os::winsock_init_once();
    socket_t fd = static_cast<socket_t>(::socket(AF_INET, SOCK_STREAM, 0));
    if (!obn::os::socket_valid(fd)) {
        int e = obn::os::last_socket_error();
        return e ? e : -1;
    }
    int on = 1;
    ::setsockopt(static_cast<int>(fd), SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&on), sizeof(on));

    sockaddr_in sa{};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port        = 0;
    if (::bind(static_cast<int>(fd), reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
        int e = obn::os::last_socket_error();
        obn::os::close_socket(fd);
        return e ? e : -1;
    }
    if (::listen(static_cast<int>(fd), 8) != 0) {
        int e = obn::os::last_socket_error();
        obn::os::close_socket(fd);
        return e ? e : -1;
    }
#if defined(_WIN32)
    int sl = sizeof(sa);
#else
    socklen_t sl = sizeof(sa);
#endif
    if (::getsockname(static_cast<int>(fd), reinterpret_cast<sockaddr*>(&sa), &sl) != 0) {
        int e = obn::os::last_socket_error();
        obn::os::close_socket(fd);
        return e ? e : -1;
    }
    listen_fd_ = static_cast<std::uintptr_t>(fd);
    port_.store(ntohs(sa.sin_port));
    running_.store(true);
    accept_thread_ = std::thread(&Server::accept_loop, this);
    OBN_INFO("cover_server: listening on 127.0.0.1:%d", port_.load());
    return 0;
}

void Server::stop()
{
    if (!running_.exchange(false)) return;
    socket_t fd = static_cast<socket_t>(listen_fd_);
    listen_fd_ = static_cast<std::uintptr_t>(kInvalidSocket);
    if (obn::os::socket_valid(fd)) {
        obn::os::shutdown_both(fd);
        obn::os::close_socket(fd);
    }
    if (accept_thread_.joinable()) accept_thread_.join();
}

void Server::accept_loop()
{
    while (running_.load()) {
        sockaddr_in ca{};
#if defined(_WIN32)
        int cl = sizeof(ca);
#else
        socklen_t cl = sizeof(ca);
#endif
        socket_t c = static_cast<socket_t>(
            ::accept(static_cast<int>(listen_fd_),
                     reinterpret_cast<sockaddr*>(&ca), &cl));
        if (!obn::os::socket_valid(c)) {
            if (!running_.load()) break;
            if (obn::os::last_socket_error() == EINTR) continue;
            break;
        }
        char ip[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));
        OBN_DEBUG("cover_server: accept from %s:%d", ip, ntohs(ca.sin_port));
        std::thread([c]() {
            handle_one(c);
            // Graceful HTTP close: send FIN (shutdown(WR)) so libsoup gets
            // the full body, then drain any trailing bytes the client
            // might send (RST-on-close otherwise eats the last segments).
            // SO_LINGER as a safety net caps the wait at 2s per connection.
            linger lo{1, 2};
            ::setsockopt(static_cast<int>(c), SOL_SOCKET, SO_LINGER,
                         reinterpret_cast<const char*>(&lo), sizeof(lo));
#if defined(_WIN32)
            ::shutdown(static_cast<SOCKET>(c), SD_SEND);
            DWORD tv = 2000;  // ms on Winsock
            ::setsockopt(static_cast<SOCKET>(c), SOL_SOCKET, SO_RCVTIMEO,
                         reinterpret_cast<const char*>(&tv), sizeof(tv));
            char sink[256];
            while (::recv(static_cast<SOCKET>(c), sink, sizeof(sink), 0) > 0) { /* drain */ }
#else
            ::shutdown(static_cast<int>(c), SHUT_WR);
            char  sink[256];
            timeval tv{2, 0};
            ::setsockopt(static_cast<int>(c), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            while (::recv(static_cast<int>(c), sink, sizeof(sink), 0) > 0) { /* drain */ }
#endif
            obn::os::close_socket(c);
        }).detach();
    }
}

std::string Server::url_for(const std::string& subtask_name,
                            int                plate_idx,
                            const std::string& version) const
{
    int p = port_.load();
    if (p <= 0 || subtask_name.empty()) return {};
    fs::path path = cover_cache::path_for(subtask_name, plate_idx, version);
    if (path.empty()) return {};
    return "http://127.0.0.1:" + std::to_string(p) + "/cover/" +
           path.filename().string();
}

} // namespace obn::cover_server
