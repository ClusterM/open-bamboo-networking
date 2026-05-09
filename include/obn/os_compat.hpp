// Tiny POSIX-vs-Win32 portability shim used everywhere the rest of the
// plugin would otherwise reach for unistd.h / sys/socket.h / strings.h.
//
// The plugin started life as a Linux-only port (libstdc++ new C++11 ABI,
// gcc, POSIX sockets); when we added a Windows MSVC build for Bambu Studio
// the cleanest move was to keep the bulk of the source unchanged and
// funnel every Linux-only call through this tiny abstraction layer.
//
// Goals:
//   * Provide a single `socket_t` type that aliases SOCKET on Windows and
//     int on POSIX so socket-handling code can stop sprinkling #ifdefs.
//   * Wrap a handful of small POSIX/Win32 differences (close vs
//     closesocket, poll vs WSAPoll, fcntl O_NONBLOCK vs ioctlsocket
//     FIONBIO, errno vs WSAGetLastError, gmtime_r vs gmtime_s, etc.).
//   * Make sure WSAStartup is called exactly once before any socket call,
//     idempotent across multiple Agent lifetimes inside the same Studio
//     process. WSACleanup is intentionally not called -- the cost of a
//     no-op cleanup at process exit is zero, and the cost of forgetting
//     to re-init across an Agent restart is extremely confusing socket
//     errors (WSANOTINITIALISED).
//
// On POSIX every call here resolves to a one-liner over the existing
// system function -- the wrapper is free. On Windows we go through the
// Winsock equivalents and translate select error codes back to POSIX
// values (EWOULDBLOCK, EINPROGRESS, EBADF) so existing call sites that
// already check `errno == EINPROGRESS` keep working.

#pragma once

#include <cstdint>
#include <ctime>

namespace obn::os {

// Linux/macOS thread id ~= gettid() / pthread_self() lower bits;
// Windows ~= GetCurrentThreadId(). Returned as long for printf("%ld").
long thread_id();

// Race-free thread-safe variants of the C standard time helpers. POSIX
// has localtime_r/gmtime_r; MSVC has localtime_s/gmtime_s with swapped
// argument order. We wrap both so callers don't have to think about it.
// Returns true on success.
bool localtime_safe(std::time_t t, std::tm* out);
bool gmtime_safe(std::time_t t, std::tm* out);

// timegm(struct tm*) -- POSIX, not C standard. MSVC equivalent is
// _mkgmtime. Behaviour matches: tm is interpreted as UTC, no DST fixup,
// returns time_t or (time_t)-1 on failure.
std::time_t timegm_safe(std::tm* tm);

// strcasecmp / _stricmp.
int strcasecmp_portable(const char* a, const char* b);

// ---------- Sockets ----------

// SOCKET on Windows is unsigned (uintptr_t-shaped, with ~0 == invalid);
// POSIX sockets are plain ints, with -1 == invalid. Use this typedef
// when storing a socket; cast to the native type only at the boundary
// of an OS call we don't wrap.
#if defined(_WIN32)
using socket_t = std::uintptr_t;
constexpr socket_t kInvalidSocket = static_cast<socket_t>(~static_cast<std::uintptr_t>(0));
#else
using socket_t = int;
constexpr socket_t kInvalidSocket = static_cast<socket_t>(-1);
#endif

// Idempotent WSAStartup wrapper. No-op on POSIX. Must be called before
// any socket() call on Windows, but calling it twice or from multiple
// threads is safe.
void winsock_init_once();

// True if `s` refers to a real, currently-open socket. Use to test the
// result of socket()/accept(): on POSIX `s >= 0`, on Windows `s !=
// INVALID_SOCKET`.
bool socket_valid(socket_t s);

// closesocket() on Windows, close() on POSIX. Safe on kInvalidSocket.
void close_socket(socket_t s);

// Last error from a socket call. WSAGetLastError on Windows, errno on
// POSIX. Translated so the caller can still compare against
// EWOULDBLOCK / EINPROGRESS / EBADF / EINTR -- on Windows we map
// WSAEWOULDBLOCK and WSAEINPROGRESS both to EINPROGRESS (the more
// common check), WSAEINTR to EINTR, WSAEBADF to EBADF.
int last_socket_error();

// True if `err` (as returned by last_socket_error) is the "operation
// would block / connect in progress" condition for non-blocking I/O.
// Hides the Windows-vs-POSIX naming mess behind a single predicate.
bool socket_in_progress(int err);

// Put a socket into non-blocking mode. Returns 0 on success, -1 on
// failure (see last_socket_error). POSIX: fcntl O_NONBLOCK; Windows:
// ioctlsocket FIONBIO 1.
int set_nonblocking(socket_t s);

// poll() / WSAPoll() with a single fd. `events` and `revents` use the
// usual POLLIN / POLLOUT / POLLHUP names. Returns 0 on timeout,
// >0 with revents written to *out_revents on activity, -1 on error
// (see last_socket_error).
int poll_one(socket_t s, short events, int timeout_ms, short* out_revents = nullptr);

// shutdown(SD_BOTH) / shutdown(SHUT_RDWR). No-op on kInvalidSocket.
void shutdown_both(socket_t s);

} // namespace obn::os
