#include "obn/tls_dial.hpp"

#include "obn/lan_tls.hpp"
#include "obn/lan_tls_env.hpp"
#include "obn/net_compat.hpp"
#include "obn/os_compat.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

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
#include <string>

namespace obn::tls {
namespace {

std::once_flag g_init_flag;
SSL_CTX*       g_ctx_insecure = nullptr;
LastErrorFn    g_error_sink   = nullptr;
thread_local std::string g_last_error;

void set_error(const char* msg)
{
    if (g_error_sink) {
        g_error_sink(msg ? msg : "");
        return;
    }
    g_last_error = msg ? msg : "";
}

void init_once()
{
    std::call_once(g_init_flag, []() {
        obn::os::winsock_init_once();

        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        g_ctx_insecure = SSL_CTX_new(TLS_client_method());
        if (!g_ctx_insecure) {
            set_error("SSL_CTX_new failed");
            return;
        }
        SSL_CTX_set_min_proto_version(g_ctx_insecure, TLS1_VERSION);
        SSL_CTX_set_verify(g_ctx_insecure, SSL_VERIFY_NONE, nullptr);
    });
}

void store_openssl_error(const char* prefix)
{
    char errbuf[256];
    ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
    char composed[320];
    std::snprintf(composed, sizeof(composed), "%s: %s", prefix, errbuf);
    set_error(composed);
}

#if defined(_WIN32)
const char* gai_strerror_portable(int rc) { return ::gai_strerrorA(rc); }
#else
const char* gai_strerror_portable(int rc) { return ::gai_strerror(rc); }
#endif

SSL_CTX* make_verify_ctx(const char* ca_file, const char* peer_cert,
                         std::string& err)
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        err = "SSL_CTX_new failed";
        return nullptr;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    std::string peer_path = peer_cert ? peer_cert : "";
    if (!obn::lan_tls::configure_lan_ssl_verify(ctx, ca_file, peer_path, &err)) {
        SSL_CTX_free(ctx);
        return nullptr;
    }
    return ctx;
}

bool verify_peer_cn(SSL* ssl, const char* expected_cn)
{
    if (!expected_cn || !*expected_cn) return false;
    X509* cert = SSL_get1_peer_certificate(ssl);
    if (!cert) return false;
    const int ok = X509_check_host(cert, expected_cn, std::strlen(expected_cn), 0, nullptr);
    X509_free(cert);
    return ok == 1;
}

} // namespace

void set_socket_io_timeout(obn::os::socket_t fd, int timeout_ms)
{
    if (!obn::os::socket_valid(fd)) return;
#if defined(_WIN32)
    DWORD tv_ms = static_cast<DWORD>(timeout_ms);
    ::setsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_SNDTIMEO,
                 reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
    ::setsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
#else
    timeval tv{};
    if (timeout_ms > 0) {
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
    }
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

void clear_socket_io_timeout(obn::os::socket_t fd)
{
    set_socket_io_timeout(fd, 0);
}

void set_last_error_sink(LastErrorFn fn) { g_error_sink = fn; }

const char* last_error() { return g_last_error.c_str(); }

SSL_CTX* shared_ctx()
{
    init_once();
    return g_ctx_insecure;
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
        set_error(gai_strerror_portable(gai));
        return obn::os::kInvalidSocket;
    }

    obn::os::socket_t fd = obn::os::kInvalidSocket;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    for (auto* ai = res; ai; ai = ai->ai_next) {
        auto raw = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        fd = static_cast<obn::os::socket_t>(raw);
        if (!obn::os::socket_valid(fd)) { fd = obn::os::kInvalidSocket; continue; }

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
    if (!obn::os::socket_valid(fd)) set_error("connect failed");
    return fd;
}

int dial_tls(const std::string& host, int port, int timeout_ms,
             obn::os::socket_t* out_fd, SSL** out_ssl,
             const char* expected_serial)
{
    *out_fd  = obn::os::kInvalidSocket;
    *out_ssl = nullptr;

    init_once();

    const bool want_verify = !obn::lan_tls::skip_verify_from_env();
    std::string ca_path;
    std::string serial_str;
    if (want_verify) {
        if (const char* ca = obn::lan_tls::resolve_lan_ca_file()) {
            ca_path = ca;
        }
        if (expected_serial && *expected_serial) {
            serial_str = expected_serial;
        } else if (const char* s = obn::lan_tls::wait_env_serial(
                       host.c_str(), obn::lan_tls::serial_env_wait_ms())) {
            serial_str = s;
        }
        if (ca_path.empty()) {
            set_error(
                "OBN_LAN_TLS_CA_FILE not set (check obn.lan_tls.env in config dir)");
            return -1;
        }
        if (serial_str.empty()) {
            char msg[256];
            std::snprintf(msg, sizeof(msg),
                          "no serial for %s after %dms (key=%s)",
                          host.c_str(), obn::lan_tls::serial_env_wait_ms(),
                          obn::lan_tls::env_key_for_ip(host).c_str());
            set_error(msg);
            return -1;
        }
    }
    std::string peer_path;
    if (want_verify) {
        if (const char* peer = obn::lan_tls::resolve_lan_peer_cert(
                host.c_str(), serial_str.c_str())) {
            peer_path = peer;
        }
    }

    SSL_CTX* ctx = nullptr;
    bool     owned_ctx = false;
    if (want_verify) {
        std::string err;
        ctx = make_verify_ctx(ca_path.c_str(),
                              peer_path.empty() ? nullptr : peer_path.c_str(),
                              err);
        if (!ctx) {
            set_error(err.c_str());
            return -1;
        }
        owned_ctx = true;
    } else {
        ctx = g_ctx_insecure;
        if (!ctx) {
            set_error("SSL_CTX not initialized");
            return -1;
        }
    }

    obn::os::socket_t fd = dial(host, port, timeout_ms);
    if (!obn::os::socket_valid(fd)) {
        if (owned_ctx) SSL_CTX_free(ctx);
        return -1;
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        store_openssl_error("SSL_new");
        obn::os::close_socket(fd);
        if (owned_ctx) SSL_CTX_free(ctx);
        return -1;
    }

    const char* sni = want_verify ? serial_str.c_str() : host.c_str();
    SSL_set_fd(ssl, static_cast<int>(fd));
    SSL_set_tlsext_host_name(ssl, sni);
    if (SSL_connect(ssl) != 1) {
        store_openssl_error("SSL_connect");
        SSL_free(ssl);
        obn::os::close_socket(fd);
        if (owned_ctx) SSL_CTX_free(ctx);
        return -1;
    }

    if (want_verify && !verify_peer_cn(ssl, serial_str.c_str())) {
        set_error("TLS hostname verify failed");
        SSL_free(ssl);
        obn::os::close_socket(fd);
        if (owned_ctx) SSL_CTX_free(ctx);
        return -1;
    }

    clear_socket_io_timeout(fd);

    if (owned_ctx) SSL_CTX_free(ctx);

    *out_fd  = fd;
    *out_ssl = ssl;
    return 0;
}

void close_tls(obn::os::socket_t* fd, SSL** ssl)
{
    if (ssl && *ssl) {
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
    if (!ssl) return -1;
    const auto* p = static_cast<const std::uint8_t*>(buf);
    const obn::os::socket_t fd =
        static_cast<obn::os::socket_t>(SSL_get_fd(ssl));
    std::size_t sent = 0;
    while (sent < len) {
        const int n = SSL_write(ssl, p + sent, static_cast<int>(len - sent));
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
            continue;
        }
        const int err = SSL_get_error(ssl, n);
        short ev = 0;
        if (err == SSL_ERROR_WANT_READ) ev = obn::net::poll_event::in;
        else if (err == SSL_ERROR_WANT_WRITE) ev = obn::net::poll_event::out;
        else return -1;
        if (!obn::os::socket_valid(fd)) return -1;
        short revents = 0;
        if (obn::os::poll_one(fd, ev, 120000, &revents) <= 0 ||
            !(revents & ev)) {
            return -1;
        }
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
            if (!out->empty()) out->pop_back();
            return 0;
        }
        out->push_back(c);
        prev = c;
    }
    set_error("ssl_read_line: line exceeded max_len");
    return -1;
}

} // namespace obn::tls
