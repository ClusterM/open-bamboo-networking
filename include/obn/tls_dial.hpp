#pragma once

// Shared TLS+TCP dial helpers for libbambu_networking and libBambuSource.
// LAN verify via printer.cer + serial (registry / env); OBN_SKIP_TLS_VERIFY
// falls back to SSL_VERIFY_NONE.

#include <cstddef>
#include <string>

#include "obn/os_compat.hpp"

typedef struct ssl_st     SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace obn::tls {

using LastErrorFn = void (*)(const char* msg);

void set_last_error_sink(LastErrorFn fn);
const char* last_error();

SSL_CTX* shared_ctx();

obn::os::socket_t dial(const std::string& host, int port, int timeout_ms);

int dial_tls(const std::string& host, int port, int timeout_ms,
             obn::os::socket_t* out_fd, SSL** out_ssl,
             const char* expected_serial = nullptr);

void close_tls(obn::os::socket_t* fd, SSL** ssl);

// Temporary per-socket I/O timeouts (milliseconds). clear_* restores blocking.
void set_socket_io_timeout(obn::os::socket_t fd, int timeout_ms);
void clear_socket_io_timeout(obn::os::socket_t fd);

int ssl_write_all(SSL* ssl, const void* buf, std::size_t len);

int ssl_read_full(SSL* ssl, void* buf, std::size_t len);

int ssl_read_line(SSL* ssl, std::string* out, std::size_t max_len = 8192);

} // namespace obn::tls
