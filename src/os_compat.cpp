#include "obn/os_compat.hpp"

#include <cerrno>
#include <cstring>
#include <mutex>

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
#  include <fcntl.h>
#  include <poll.h>
#  include <pthread.h>
#  include <strings.h>
#  include <sys/socket.h>
#  include <sys/syscall.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

namespace obn::os {

long thread_id()
{
#if defined(_WIN32)
    return static_cast<long>(::GetCurrentThreadId());
#elif defined(__linux__)
    return static_cast<long>(::syscall(SYS_gettid));
#else
    // BSDs / macOS: pthread_self() returns an opaque type. We just want
    // a stable per-thread number for log lines, so cast the address.
    return static_cast<long>(reinterpret_cast<std::uintptr_t>(
        reinterpret_cast<void*>(::pthread_self())));
#endif
}

bool localtime_safe(std::time_t t, std::tm* out)
{
    if (!out) return false;
#if defined(_WIN32)
    return ::localtime_s(out, &t) == 0;
#else
    return ::localtime_r(&t, out) != nullptr;
#endif
}

bool gmtime_safe(std::time_t t, std::tm* out)
{
    if (!out) return false;
#if defined(_WIN32)
    return ::gmtime_s(out, &t) == 0;
#else
    return ::gmtime_r(&t, out) != nullptr;
#endif
}

std::time_t timegm_safe(std::tm* tm)
{
    if (!tm) return static_cast<std::time_t>(-1);
#if defined(_WIN32)
    return ::_mkgmtime(tm);
#else
    return ::timegm(tm);
#endif
}

int strcasecmp_portable(const char* a, const char* b)
{
    if (!a || !b) return a == b ? 0 : (a ? 1 : -1);
#if defined(_WIN32)
    return ::_stricmp(a, b);
#else
    return ::strcasecmp(a, b);
#endif
}

// ---------- Sockets ----------

void winsock_init_once()
{
#if defined(_WIN32)
    static std::once_flag once;
    std::call_once(once, []{
        WSADATA wsa{};
        // 2.2 is what every modern Windows ships; failure here is
        // catastrophic (no networking) so we just fail loud rather
        // than try to recover.
        ::WSAStartup(MAKEWORD(2, 2), &wsa);
        // We deliberately do not call WSACleanup at process exit: the
        // plugin DLL stays loaded for the life of Studio, and any cleanup
        // race with a still-running socket thread would be worse than
        // letting the OS reclaim the Winsock state on exit.
    });
#endif
}

bool socket_valid(socket_t s)
{
#if defined(_WIN32)
    return s != kInvalidSocket;
#else
    return s >= 0;
#endif
}

void close_socket(socket_t s)
{
    if (!socket_valid(s)) return;
#if defined(_WIN32)
    ::closesocket(static_cast<SOCKET>(s));
#else
    ::close(static_cast<int>(s));
#endif
}

int last_socket_error()
{
#if defined(_WIN32)
    int e = ::WSAGetLastError();
    // Translate the most common ones into POSIX errno values so the
    // existing call sites that compare against EINPROGRESS / EWOULDBLOCK
    // / EINTR / EBADF keep working unchanged.
    switch (e) {
    case WSAEWOULDBLOCK:  return EWOULDBLOCK;
    case WSAEINPROGRESS:  return EINPROGRESS;
    case WSAEALREADY:     return EALREADY;
    case WSAEINTR:        return EINTR;
    case WSAEBADF:        return EBADF;
    case WSAECONNREFUSED: return ECONNREFUSED;
    case WSAECONNRESET:   return ECONNRESET;
    case WSAETIMEDOUT:    return ETIMEDOUT;
    case WSAENOTCONN:     return ENOTCONN;
    case WSAENETDOWN:     return ENETDOWN;
    case WSAENETUNREACH:  return ENETUNREACH;
    case WSAEHOSTUNREACH: return EHOSTUNREACH;
    case WSAEADDRINUSE:   return EADDRINUSE;
    case WSAEACCES:       return EACCES;
    case WSAEINVAL:       return EINVAL;
    default:              return e;
    }
#else
    return errno;
#endif
}

bool socket_in_progress(int err)
{
    return err == EINPROGRESS || err == EWOULDBLOCK
#ifdef EAGAIN
        || err == EAGAIN
#endif
        ;
}

int set_nonblocking(socket_t s)
{
    if (!socket_valid(s)) return -1;
#if defined(_WIN32)
    u_long nb = 1;
    return ::ioctlsocket(static_cast<SOCKET>(s), FIONBIO, &nb) == 0 ? 0 : -1;
#else
    int fd = static_cast<int>(s);
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

int poll_one(socket_t s, short events, int timeout_ms, short* out_revents)
{
    if (out_revents) *out_revents = 0;
    if (!socket_valid(s)) return -1;
#if defined(_WIN32)
    WSAPOLLFD pfd{};
    pfd.fd = static_cast<SOCKET>(s);
    pfd.events = events;
    int rc = ::WSAPoll(&pfd, 1, timeout_ms);
    if (rc > 0 && out_revents) *out_revents = pfd.revents;
    return rc;
#else
    pollfd pfd{};
    pfd.fd = static_cast<int>(s);
    pfd.events = events;
    int rc = ::poll(&pfd, 1, timeout_ms);
    if (rc > 0 && out_revents) *out_revents = pfd.revents;
    return rc;
#endif
}

void shutdown_both(socket_t s)
{
    if (!socket_valid(s)) return;
#if defined(_WIN32)
    ::shutdown(static_cast<SOCKET>(s), SD_BOTH);
#else
    ::shutdown(static_cast<int>(s), SHUT_RDWR);
#endif
}

} // namespace obn::os
