#pragma once

// Ultra-light HTTP server used solely to hand print cover PNGs back to
// Studio's wxWebRequest (which, on Linux, runs on libsoup and therefore
// doesn't accept file:// URLs).
//
// Lifetime is managed by Agent: one singleton per process, started lazily
// the first time a synthetic subtask id needs a URL and torn down when
// the Agent is destroyed. Listens on 127.0.0.1:<random> so nothing from
// the network side can reach it.
//
// The server is a single-threaded accept loop spawning a short-lived
// handler thread per connection - we're serving at most a handful of
// requests over the lifetime of a print, so a thread pool would be
// overkill.

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

namespace obn::cover_server {

class Server {
public:
    Server();
    ~Server();

    Server(const Server&)            = delete;
    Server& operator=(const Server&) = delete;

    // Binds to 127.0.0.1:0 and starts the accept loop. Idempotent -
    // further calls are no-ops while the server is up. Returns 0 on
    // success, errno on failure.
    int start();

    void stop();

    // 0 if not running yet.
    int port() const { return port_.load(); }

    // http://127.0.0.1:<port>/cover/cover-XXXXXXXX-pN.png - matches the
    // basename produced by cover_cache::path_for. `version` is forwarded
    // verbatim to path_for so the URL changes whenever the per-print
    // token changes (typically gcode_start_time), which is what stops
    // Studio's wxImage / StatusPanel::img_list from serving a stale
    // thumbnail for a same-named .3mf reprinted with new content.
    std::string url_for(const std::string& subtask_name,
                        int                plate_idx,
                        const std::string& version = {}) const;

private:
    void accept_loop();

    // Stored as uintptr_t to fit both POSIX `int` and Winsock `SOCKET`
    // without dragging <winsock2.h> into a public header. cover_server.cpp
    // casts through obn::os::socket_t at use sites.
    std::uintptr_t   listen_fd_ = static_cast<std::uintptr_t>(-1);
    std::atomic<int> port_{0};
    std::atomic<bool> running_{false};
    std::thread      accept_thread_;
};

} // namespace obn::cover_server
