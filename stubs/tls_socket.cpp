#include "tls_socket.hpp"

#include "source_log.hpp"

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
#  include <windows.h>
#else
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>

namespace obn::tls {
namespace {

std::once_flag g_init_flag;
SSL_CTX*       g_ctx = nullptr;

void init_once()
{
    std::call_once(g_init_flag, []() {
        // Winsock must be initialised before getaddrinfo() and friends.
        // No-op on POSIX. Idempotent and thread-safe on Windows.
        obn::os::winsock_init_once();

        // OpenSSL 1.1 made these no-ops, but they remain harmless on
        // older libcrypto versions Studio sometimes pins.
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        g_ctx = SSL_CTX_new(TLS_client_method());
        if (!g_ctx) {
            obn::source::set_last_error("SSL_CTX_new failed");
            return;
        }
        // TLS 1.0 floor: Bambu firmware is happy with anything from
        // 1.0 upwards; pinning higher would lock out older A1 mini
        // firmware that still negotiates TLS 1.1.
        SSL_CTX_set_min_proto_version(g_ctx, TLS1_VERSION);
        // No verify: every printer ships its own self-signed cert
        // with no published CA chain. We have no anchor to verify
        // against, so the best we can do is rely on the auth packet /
        // RTSP credentials inside the encrypted tunnel.
        SSL_CTX_set_verify(g_ctx, SSL_VERIFY_NONE, nullptr);
    });
}

void store_openssl_error(const char* prefix)
{
    char errbuf[256];
    ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
    char composed[320];
    std::snprintf(composed, sizeof(composed), "%s: %s", prefix, errbuf);
    obn::source::set_last_error(composed);
}

#if defined(_WIN32)
// Windows uses gai_strerrorA from <ws2tcpip.h>; it is safe to call but
// not thread-safe across calls. For our error-reporting purposes we
// copy out immediately into set_last_error, so racing is fine.
const char* gai_strerror_portable(int rc)
{
    return ::gai_strerrorA(rc);
}
#else
const char* gai_strerror_portable(int rc) { return ::gai_strerror(rc); }
#endif

} // namespace

SSL_CTX* shared_ctx()
{
    init_once();
    return g_ctx;
}

obn::os::socket_t dial(const std::string& host, int port, int timeout_ms)
{
    init_once();

    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    char port_s[16];
    std::snprintf(port_s, sizeof(port_s), "%d", port);
    int gai = ::getaddrinfo(host.c_str(), port_s, &hints, &res);
    if (gai != 0 || !res) {
        obn::source::set_last_error(gai_strerror_portable(gai));
        return obn::os::kInvalidSocket;
    }

    obn::os::socket_t fd = obn::os::kInvalidSocket;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    for (auto* ai = res; ai; ai = ai->ai_next) {
        // socket() returns int on POSIX and SOCKET (uintptr_t) on Win;
        // both fit our socket_t alias. Failure value is -1 on POSIX and
        // INVALID_SOCKET on Win, both of which compare unequal to a
        // valid socket via socket_valid().
        auto raw = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        fd = static_cast<obn::os::socket_t>(raw);
        if (!obn::os::socket_valid(fd)) { fd = obn::os::kInvalidSocket; continue; }

        // Same coarse send/recv timeout drives both the connect attempt
        // and downstream blocking reads; OpenSSL inherits it. Windows'
        // SO_SNDTIMEO/SO_RCVTIMEO take a DWORD millisecond count; POSIX
        // takes a struct timeval -- different ABI, so split here.
#if defined(_WIN32)
        DWORD tv_ms = static_cast<DWORD>(timeout_ms);
        ::setsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_SNDTIMEO,
                     reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
        ::setsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
        BOOL one_b = TRUE;
        ::setsockopt(static_cast<SOCKET>(fd), IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&one_b), sizeof(one_b));
        if (::connect(static_cast<SOCKET>(fd), ai->ai_addr,
                      static_cast<int>(ai->ai_addrlen)) == 0) break;
#else
        timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        int one = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
#endif
        obn::os::close_socket(fd);
        fd = obn::os::kInvalidSocket;
        if (std::chrono::steady_clock::now() > deadline) break;
    }
    freeaddrinfo(res);
    if (!obn::os::socket_valid(fd)) obn::source::set_last_error("connect failed");
    return fd;
}

int dial_tls(const std::string& host, int port, int timeout_ms,
             obn::os::socket_t* out_fd, SSL** out_ssl)
{
    *out_fd  = obn::os::kInvalidSocket;
    *out_ssl = nullptr;

    SSL_CTX* ctx = shared_ctx();
    if (!ctx) return -1;

    obn::os::socket_t fd = dial(host, port, timeout_ms);
    if (!obn::os::socket_valid(fd)) return -1;

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        store_openssl_error("SSL_new");
        obn::os::close_socket(fd);
        return -1;
    }
    // SSL_set_fd takes int. Windows SOCKETs always fit in 32 bits in
    // practice (Microsoft documents the limit) so the truncating cast
    // here is safe; on POSIX socket_t IS int so the cast is a no-op.
    SSL_set_fd(ssl, static_cast<int>(fd));
    // SNI is required by some Bambu firmware revisions even though they
    // never actually swap certs based on it. Setting it unconditionally
    // is harmless and matches what OrcaSlicer's RTSP code does.
    SSL_set_tlsext_host_name(ssl, host.c_str());
    if (SSL_connect(ssl) != 1) {
        store_openssl_error("SSL_connect");
        SSL_free(ssl);
        obn::os::close_socket(fd);
        return -1;
    }

    *out_fd  = fd;
    *out_ssl = ssl;
    return 0;
}

void close_tls(obn::os::socket_t* fd, SSL** ssl)
{
    if (ssl && *ssl) {
        // SSL_shutdown returns 0 on partial close, 1 on full close, -1
        // on error. We don't care about a graceful shutdown here -- the
        // peer is fine with a TCP RST.
        SSL_shutdown(*ssl);
        SSL_free(*ssl);
        *ssl = nullptr;
    }
    if (fd && obn::os::socket_valid(*fd)) {
        obn::os::close_socket(*fd);
        *fd = obn::os::kInvalidSocket;
    }
}

int ssl_write_all(SSL* ssl, const void* buf, std::size_t len)
{
    const auto* p = static_cast<const std::uint8_t*>(buf);
    std::size_t sent = 0;
    while (sent < len) {
        int n = SSL_write(ssl, p + sent, static_cast<int>(len - sent));
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            // WANT_READ during a write means the underlying handshake
            // wants to renegotiate; loop back and OpenSSL will drive
            // the read leg internally on the next SSL_write().
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue;
            return -1;
        }
        sent += static_cast<std::size_t>(n);
    }
    return 0;
}

int ssl_read_full(SSL* ssl, void* buf, std::size_t len)
{
    auto*       p   = static_cast<std::uint8_t*>(buf);
    std::size_t got = 0;
    while (got < len) {
        int n = SSL_read(ssl, p + got, static_cast<int>(len - got));
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue;
            // ZERO_RETURN is a clean TLS close-notify; treat it as EOF
            // only when we have at least the previous bytes intact.
            if (err == SSL_ERROR_ZERO_RETURN) return 1;
            return -1;
        }
        got += static_cast<std::size_t>(n);
    }
    return 0;
}

int ssl_read_line(SSL* ssl, std::string* out, std::size_t max_len)
{
    out->clear();
    out->reserve(128);
    // Two-byte sliding window (last char + current char) so we can
    // detect CRLF without a second buffer or lookahead.
    char prev = '\0';
    while (out->size() < max_len) {
        char c = '\0';
        int  n = SSL_read(ssl, &c, 1);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue;
            if (err == SSL_ERROR_ZERO_RETURN) return 1;
            return -1;
        }
        if (prev == '\r' && c == '\n') {
            // Strip the trailing CR we already pushed.
            if (!out->empty()) out->pop_back();
            return 0;
        }
        out->push_back(c);
        prev = c;
    }
    obn::source::set_last_error("ssl_read_line: line exceeded max_len");
    return -1;
}

} // namespace obn::tls
