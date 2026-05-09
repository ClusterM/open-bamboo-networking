// Shared TLS+TCP primitives for libBambuSource.
//
// The MJPG camera reader (port 6000), RTSP client (port 322), and FTPS
// file-browser bridge in this plugin all need the same dance:
// TCP-connect with a timeout, hand the fd to OpenSSL, complete a TLS
// handshake against a Bambu self-signed cert, and then send/receive
// bytes. Repeating that across BambuSource.cpp and rtsp_client.cpp is
// how we ended up with slightly different timeout policies and SNI
// bugs in the past, hence this consolidation.
//
// Design:
//   * One process-wide SSL_CTX, configured TLS 1.0+ with SSL_VERIFY_NONE
//     (Bambu burns a different per-batch self-signed CA into every
//     printer; verifying would just be theatre).
//   * dial() uses SO_SNDTIMEO/SO_RCVTIMEO on the socket so subsequent
//     SSL_read/SSL_write also honour the timeout without us having to
//     drive a second select() loop on top of OpenSSL.
//   * ssl_read_full / ssl_read_line are blocking helpers tuned for
//     RTSP-style framing -- read exactly N bytes for binary payloads,
//     read up to CRLF for headers. Single-byte SSL_read is fine here
//     because RTSP control traffic is small and infrequent; the
//     hot path (interleaved RTP) goes through ssl_read_full on the
//     full RTP packet length.
//
// Everything here is plain blocking I/O. Callers that need to break a
// blocked SSL_read from another thread do it the standard way:
// shutdown(fd, SHUT_RDWR) on the underlying socket, which causes
// SSL_read to return error promptly. rtsp_client relies on that for
// its stop() path.
#pragma once

#include <cstddef>
#include <string>

#include "obn/os_compat.hpp"

// Forward declarations so callers in headers don't need to pull in the
// OpenSSL umbrella -- only the .cpp side needs <openssl/ssl.h>.
typedef struct ssl_st     SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace obn::tls {

// Returns a process-wide shared SSL_CTX. The first call also runs
// SSL_library_init / SSL_load_error_strings under a std::call_once.
// Returns nullptr only if OpenSSL itself failed to allocate the CTX,
// in which case obn::source::set_last_error has been populated.
SSL_CTX* shared_ctx();

// TCP-connect to host:port. Uses getaddrinfo (AF_UNSPEC), iterates
// candidates, applies SO_SNDTIMEO/SO_RCVTIMEO + TCP_NODELAY to each
// socket, returns the first one that connects. Returns a valid socket
// on success, obn::os::kInvalidSocket on failure (and sets
// obn::source::set_last_error). Use obn::os::socket_valid() to test
// the result; the underlying type is plain int on POSIX and SOCKET on
// Windows, which is why we no longer return -1 directly.
obn::os::socket_t dial(const std::string& host, int port, int timeout_ms);

// One-shot TLS dial: dial() + SSL_new + SSL_set_tlsext_host_name + SSL_connect.
// On success: returns 0, *out_fd holds the connected socket, *out_ssl
// holds the established SSL session.
// On failure: returns -1, both out-params get cleaned up to
// kInvalidSocket / nullptr, and obn::source::set_last_error carries
// an OpenSSL error string.
int dial_tls(const std::string& host, int port, int timeout_ms,
             obn::os::socket_t* out_fd, SSL** out_ssl);

// Tear down a TLS session and the underlying socket. Safe to call with
// already-closed values; sets *fd to kInvalidSocket and *ssl to nullptr
// on return.
void close_tls(obn::os::socket_t* fd, SSL** ssl);

// Blocking write-all over the TLS layer. Loops on partial writes and
// retries on SSL_ERROR_WANT_{READ,WRITE} (which can happen during a
// renegotiation). Returns 0 on full delivery, -1 on hard failure.
int ssl_write_all(SSL* ssl, const void* buf, std::size_t len);

// Blocking read-exact `len` bytes into `buf`. Loops until either all
// bytes are in or the peer closes / errors out.
//
// Return codes:
//    0 - all `len` bytes received
//    1 - clean EOF before the buffer was filled (peer closed gracefully)
//   -1 - protocol or socket error
int ssl_read_full(SSL* ssl, void* buf, std::size_t len);

// Read one CRLF-terminated line from the TLS stream into *out (CRLF
// stripped, *out is cleared first). One SSL_read per byte; that is
// fine for RTSP/HTTP-shaped headers since they are short and rare.
// `max_len` caps the line at a sane size so a malicious server can't
// stuff us into a 4 GiB allocation.
//
// Return codes mirror ssl_read_full(); a -1 also covers the case
// where the peer sent more than `max_len` bytes without a CRLF.
int ssl_read_line(SSL* ssl, std::string* out, std::size_t max_len = 8192);

} // namespace obn::tls
