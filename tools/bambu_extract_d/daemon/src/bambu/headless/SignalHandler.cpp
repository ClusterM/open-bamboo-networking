#include "SignalHandler.hpp"

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <stdexcept>
#include <thread>

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

namespace Slic3r {
namespace bambu {
namespace headless {

namespace {

std::atomic<int>  g_write_fd{-1};
int               g_read_fd  = -1;
std::thread       g_worker;
std::atomic<bool> g_running{false};

struct sigaction g_prior_sigint{};
struct sigaction g_prior_sigterm{};
bool             g_installed = false;

extern "C" void on_signal(int ) {
    const int fd = g_write_fd.load(std::memory_order_acquire);
    if (fd < 0) return;
    const char b = 1;

    ssize_t r = ::write(fd, &b, 1);
    (void) r;
}

void worker_loop(std::function<void()> cb) {
    char buf;
    while (g_running.load(std::memory_order_acquire)) {
        ssize_t n = ::read(g_read_fd, &buf, 1);
        if (n <= 0) {

            if (n == 0) return;
            if (errno == EINTR) continue;
            return;
        }
        if (cb) {
            try { cb(); }
            catch (const std::exception& ex) {
            }
        }
    }
}

}

SignalHandler::SignalHandler(std::function<void()> cb) {
    if (g_installed) {
        throw std::runtime_error(
            "SignalHandler: already installed (process-global)");
    }

    int fds[2];
    if (::pipe(fds) != 0) {
        throw std::runtime_error("SignalHandler: pipe() failed");
    }

    int flags = ::fcntl(fds[1], F_GETFL, 0);
    ::fcntl(fds[1], F_SETFL, flags | O_NONBLOCK);

    g_read_fd = fds[0];
    g_write_fd.store(fds[1], std::memory_order_release);
    g_running.store(true, std::memory_order_release);
    g_worker = std::thread(worker_loop, std::move(cb));

    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (::sigaction(SIGINT,  &sa, &g_prior_sigint)  != 0 ||
        ::sigaction(SIGTERM, &sa, &g_prior_sigterm) != 0) {
        g_running.store(false);
        ::close(fds[1]);
        ::close(fds[0]);
        g_write_fd.store(-1);
        g_read_fd = -1;
        if (g_worker.joinable()) g_worker.join();
        throw std::runtime_error("SignalHandler: sigaction() failed");
    }
    g_installed = true;
}

SignalHandler::~SignalHandler() {
    if (!g_installed) return;
    ::sigaction(SIGINT,  &g_prior_sigint,  nullptr);
    ::sigaction(SIGTERM, &g_prior_sigterm, nullptr);

    g_running.store(false, std::memory_order_release);

    const int wfd = g_write_fd.exchange(-1, std::memory_order_acq_rel);
    if (wfd >= 0) ::close(wfd);
    if (g_worker.joinable()) g_worker.join();
    if (g_read_fd >= 0) { ::close(g_read_fd); g_read_fd = -1; }
    g_installed = false;
}

}
}
}
