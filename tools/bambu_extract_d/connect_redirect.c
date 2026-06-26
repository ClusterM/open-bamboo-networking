#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

/*
 * Redirect connect() calls targeting 127.0.0.1:8883 to FAKE_PRINTER_PORT.
 * When FAKE_PRINTER_PORT is unset or equals 8883, the redirect is a no-op.
 *
 * Always overrides SSL_CTX_set_verify / SSL_set_verify to SSL_VERIFY_NONE
 * so the daemon accepts the fake broker's ephemeral self-signed certificate.
 */

static int (*real_connect)(int, const struct sockaddr *, socklen_t);

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    if (!real_connect)
        real_connect = (int (*)(int, const struct sockaddr *, socklen_t))
                       dlsym(RTLD_NEXT, "connect");

    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        if (ntohl(sin->sin_addr.s_addr) == 0x7f000001 &&
            ntohs(sin->sin_port) == 8883) {
            const char *redir = getenv("FAKE_PRINTER_PORT");
            if (redir && redir[0]) {
                struct sockaddr_in sa2;
                memcpy(&sa2, sin, sizeof(sa2));
                sa2.sin_port = htons((unsigned short)atoi(redir));
                return real_connect(fd, (const struct sockaddr *)&sa2, len);
            }
        }
    }
    return real_connect(fd, addr, len);
}

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb cb)
{
    typedef void (*fn_t)(SSL_CTX *, int, SSL_verify_cb);
    fn_t real = (fn_t)dlsym(RTLD_NEXT, "SSL_CTX_set_verify");
    if (real) real(ctx, SSL_VERIFY_NONE, NULL);
}

void SSL_set_verify(SSL *ssl, int mode, SSL_verify_cb cb)
{
    typedef void (*fn_t)(SSL *, int, SSL_verify_cb);
    fn_t real = (fn_t)dlsym(RTLD_NEXT, "SSL_set_verify");
    if (real) real(ssl, SSL_VERIFY_NONE, NULL);
}
