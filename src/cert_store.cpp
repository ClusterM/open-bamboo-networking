#include "obn/cert_store.hpp"

#include "obn/log.hpp"
#include "obn/os_compat.hpp"

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
#  include <netdb.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#endif

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <mutex>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace obn::cert_store {

namespace {

using obn::os::socket_t;
using obn::os::kInvalidSocket;

// OpenSSL 1.1+ initializes itself, but we still guard the per-process setup
// so we can be sure SSL_library_init/ERR_load_crypto_strings-style state is
// idempotent across repeat Agent lifecycles.
std::once_flag g_ssl_init;

void init_openssl_once()
{
    std::call_once(g_ssl_init, []() {
        ::SSL_load_error_strings();
        ::OpenSSL_add_ssl_algorithms();
    });
}

// Waits for `s` to become readable or writable (depending on `want_write`)
// with a timeout expressed in milliseconds. Returns 1 on ready, 0 on timeout,
// -1 on error.
int wait_fd(socket_t s, bool want_write, int timeout_ms)
{
    short events = want_write ? POLLOUT : POLLIN;
    return obn::os::poll_one(s, events, timeout_ms);
}

socket_t connect_with_timeout(const std::string& host, int port, int timeout_ms)
{
    obn::os::winsock_init_once();
    // getaddrinfo handles both IPv4 literals and hostnames. Printers are
    // typically reached by IPv4 literal, but we accept hostnames for parity
    // with the rest of the plugin.
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    char port_buf[16];
    std::snprintf(port_buf, sizeof(port_buf), "%d", port);
    int gai = ::getaddrinfo(host.c_str(), port_buf, &hints, &res);
    if (gai != 0 || !res) {
        OBN_WARN("cert_store: getaddrinfo(%s) failed: %s", host.c_str(),
                 ::gai_strerror(gai));
        return kInvalidSocket;
    }

    socket_t fd = kInvalidSocket;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = static_cast<socket_t>(::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
        if (!obn::os::socket_valid(fd)) { fd = kInvalidSocket; continue; }
        if (obn::os::set_nonblocking(fd) < 0) { obn::os::close_socket(fd); fd = kInvalidSocket; continue; }
        int rc = ::connect(static_cast<int>(fd), ai->ai_addr,
                           static_cast<int>(ai->ai_addrlen));
        if (rc == 0) break;
        int e = obn::os::last_socket_error();
        if (!obn::os::socket_in_progress(e)) {
            obn::os::close_socket(fd); fd = kInvalidSocket; continue;
        }
        int w = wait_fd(fd, /*want_write=*/true, timeout_ms);
        if (w <= 0) { obn::os::close_socket(fd); fd = kInvalidSocket; continue; }
        int       so_err = 0;
#if defined(_WIN32)
        int so_len = sizeof(so_err);
        if (::getsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_ERROR,
                         reinterpret_cast<char*>(&so_err), &so_len) < 0 || so_err != 0) {
            obn::os::close_socket(fd); fd = kInvalidSocket; continue;
        }
#else
        socklen_t so_len = sizeof(so_err);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len) < 0 || so_err != 0) {
            obn::os::close_socket(fd); fd = kInvalidSocket; continue;
        }
#endif
        break;
    }
    ::freeaddrinfo(res);
    return fd;
}

bool drive_ssl_connect(SSL* ssl, socket_t fd, int timeout_ms)
{
    for (;;) {
        int rc = ::SSL_connect(ssl);
        if (rc == 1) return true;
        int err = ::SSL_get_error(ssl, rc);
        if (err == SSL_ERROR_WANT_READ) {
            if (wait_fd(fd, /*want_write=*/false, timeout_ms) <= 0) return false;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (wait_fd(fd, /*want_write=*/true, timeout_ms) <= 0) return false;
        } else {
            return false;
        }
    }
}

} // namespace

std::string device_cert_path(const std::string& config_dir, const std::string& dev_id)
{
    std::string base = config_dir;
    if (!base.empty() && base.back() == '/') base.pop_back();
    return base + "/certs/" + dev_id + ".pem";
}

bool ensure_parent_dir(const std::string& file_path)
{
    namespace fs = std::filesystem;
    fs::path p(file_path);
    fs::path parent = p.parent_path();
    if (parent.empty()) return true;
    std::error_code ec;
    fs::create_directories(parent, ec);
    if (ec) {
        OBN_WARN("cert_store: create_directories(%s) failed: %s",
                 parent.string().c_str(), ec.message().c_str());
        return false;
    }
    return true;
}

bool capture_peer_cert_pem(const std::string& host,
                           int                port,
                           int                timeout_ms,
                           const std::string& out_pem_path)
{
    init_openssl_once();

    socket_t fd = connect_with_timeout(host, port, timeout_ms);
    if (!obn::os::socket_valid(fd)) {
        OBN_WARN("cert_store: TCP connect %s:%d failed", host.c_str(), port);
        return false;
    }

    SSL_CTX* ctx = ::SSL_CTX_new(::TLS_client_method());
    if (!ctx) {
        OBN_ERROR("cert_store: SSL_CTX_new failed");
        obn::os::close_socket(fd);
        return false;
    }
    // We deliberately do not set VERIFY_PEER here: the whole point is to
    // capture the self-signed cert even though it won't validate against any
    // CA we know yet.
    ::SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    SSL* ssl = ::SSL_new(ctx);
    if (!ssl) {
        ::SSL_CTX_free(ctx);
        obn::os::close_socket(fd);
        return false;
    }
    // Set SNI so that servers multiplexing on IP route correctly. Printers
    // ignore it but Studio's own plugin sends the dev_ip as SNI, so we match.
    ::SSL_set_tlsext_host_name(ssl, host.c_str());
    // SSL_set_fd takes the native int handle; on Windows SOCKET is wider than
    // int, but the socket numbers vcpkg's Winsock hands out always fit in 32
    // bits in practice. Cast through the typedef to keep the warning level
    // happy.
    ::SSL_set_fd(ssl, static_cast<int>(fd));

    bool ok = drive_ssl_connect(ssl, fd, timeout_ms);
    if (!ok) {
        unsigned long ecode = ::ERR_peek_last_error();
        char ebuf[256];
        ::ERR_error_string_n(ecode, ebuf, sizeof(ebuf));
        OBN_WARN("cert_store: SSL_connect %s:%d failed (%s)",
                 host.c_str(), port, ebuf);
        ::SSL_shutdown(ssl);
        ::SSL_free(ssl);
        ::SSL_CTX_free(ctx);
        obn::os::close_socket(fd);
        return false;
    }

    // OpenSSL 3.0+ returns a reffed cert, which the caller must free. The 1.x
    // equivalent (SSL_get_peer_certificate) is a macro for the same thing in
    // modern headers.
    X509* cert = ::SSL_get1_peer_certificate(ssl);
    bool  wrote = false;
    if (cert) {
        if (!ensure_parent_dir(out_pem_path)) {
            ::X509_free(cert);
        } else {
            FILE* f = std::fopen(out_pem_path.c_str(), "wb");
            if (!f) {
                OBN_WARN("cert_store: open(%s) failed: %s",
                         out_pem_path.c_str(), std::strerror(errno));
            } else {
                if (::PEM_write_X509(f, cert) == 1) wrote = true;
                else OBN_WARN("cert_store: PEM_write_X509 failed for %s",
                              out_pem_path.c_str());
                std::fclose(f);
            }
            ::X509_free(cert);
        }
    } else {
        OBN_WARN("cert_store: SSL_get1_peer_certificate returned null");
    }

    ::SSL_shutdown(ssl);
    ::SSL_free(ssl);
    ::SSL_CTX_free(ctx);
    obn::os::close_socket(fd);
    return wrote;
}

} // namespace obn::cert_store
