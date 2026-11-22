// Tests the verification policy configure_lan_ssl_verify() installs.
//
// Printer leaves are CN=<serial> with no subjectAltName, so the LAN contexts
// must ask OpenSSL to consult the subject DN: since 4.1 it no longer does so
// on its own and every LAN TLS path failed the hostname check (#157).

#include "obn/lan_tls.hpp"

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#define CHECK(cond) do {                                                    \
    if (!(cond)) {                                                          \
        std::cerr << "FAIL " << __FILE__ << ":" << __LINE__                 \
                  << ": " #cond "\n";                                       \
        ++fail_count;                                                       \
    }                                                                       \
} while (0)

static int fail_count = 0;

// Any parseable certificate will do: SSL_CTX_load_verify_locations() only has
// to accept the file, nothing in this test builds a chain.
static const char kCaPem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDbTCCAlWgAwIBAgIUF7xZo/pQ7C81ZTs5n+0mDnlDPa4wDQYJKoZIhvcNAQEL\n"
    "BQAwRjELMAkGA1UEBhMCQ04xITAfBgNVBAoMGEJCTCBUZWNobm9sb2dpZXMgQ28u\n"
    "IEx0ZDEUMBIGA1UEAwwLQkJMIFRlc3QgQ0EwHhcNMjYxMTIyMDExOTM4WhcNNDYx\n"
    "MTE3MDExOTM4WjBGMQswCQYDVQQGEwJDTjEhMB8GA1UECgwYQkJMIFRlY2hub2xv\n"
    "Z2llcyBDby4gTHRkMRQwEgYDVQQDDAtCQkwgVGVzdCBDQTCCASIwDQYJKoZIhvcN\n"
    "AQEBBQADggEPADCCAQoCggEBANQv+20hltnxzmMjAP4nQeUXV99Wc3BQYi3tlgqb\n"
    "RvNpEp37fC5X3ALg/icI+CNcD7YMF06kOccfGR6MKElEjl8lu0cdaf9WwbCwdxKB\n"
    "1XX4qo8d0umI22MFwdsBEQiizjAOJmG4N/uWODDT7ATAxThxG94SJ4v7omibCAaV\n"
    "+boRtwfY7RzZIUGb7Y3rt49WrUjp5dvV0xMsMDGCdsXFql7krspy0RjMMl8/AAoB\n"
    "+cCKuG7BoDpUcaNo2zI3c6FS0/y2MLW1TGizJJnrm51SwDxS4MGdKJfzqv2CPJys\n"
    "C6R/Bt8Oz3XPEkpiUIahOfXmVc2IwRkdr0Y64qX4zlFqoj0CAwEAAaNTMFEwHQYD\n"
    "VR0OBBYEFI81zQm4EFzcx/5O6N7NaAQupXvgMB8GA1UdIwQYMBaAFI81zQm4EFzc\n"
    "x/5O6N7NaAQupXvgMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\n"
    "AHFg7NxKUvLJyeR1OQUUjCqPlik+efH3MI1zYfovuldfbxz7Ou6ZwKcM+VqNCwMR\n"
    "gcis6GWnKH1DWDYsBzUV/4Z8z/b1As5c0slQn9reozU4hUVM3NxNLdc3Kimd+vKe\n"
    "n0aKUYuJo6NHHUnD9MCxehCOONzOQXJ2vfJ+tJkzyukN6g5d8pcWUr/sj+Y8DhK1\n"
    "0w8wP9O16+vcRyAGQnlM/0paEZ/FfMnuyLlznVFsrykcZ+C5GBAupv6zMONBTWUO\n"
    "pilSO980e7j1YC/rqamBqqcdjQ4cAriG89VgfEem28BoJ1fUWXRN+PXjusYsktzE\n"
    "OT+oL9ORNddesAnJEvpbYWQ=\n"
    "-----END CERTIFICATE-----\n";

int main()
{
    const auto ca_path = std::filesystem::temp_directory_path()
                       / "obn-lan-tls-verify-test-ca.pem";
    {
        std::ofstream out(ca_path, std::ios::binary);
        out << kCaPem;
    }

    SSL_CTX* ctx = ::SSL_CTX_new(::TLS_client_method());
    CHECK(ctx != nullptr);
    if (!ctx) return 1;

    // Default policy: SAN only. The flag has to be asked for.
    X509_VERIFY_PARAM* vpm = ::SSL_CTX_get0_param(ctx);
    CHECK(vpm != nullptr);
    CHECK((::X509_VERIFY_PARAM_get_hostflags(vpm)
           & X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT) == 0);

    std::string err;
    CHECK(obn::lan_tls::configure_lan_ssl_verify(ctx, ca_path.string(), "", &err));
    CHECK(err.empty());

    vpm = ::SSL_CTX_get0_param(ctx);
    CHECK(vpm != nullptr);
    CHECK((::X509_VERIFY_PARAM_get_hostflags(vpm)
           & X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT) != 0);
    CHECK((::X509_VERIFY_PARAM_get_hostflags(vpm)
           & X509_CHECK_FLAG_NEVER_CHECK_SUBJECT) == 0);
    CHECK((::X509_VERIFY_PARAM_get_flags(vpm) & X509_V_FLAG_PARTIAL_CHAIN) != 0);

    // Each connection gets the policy from the context, which is what makes
    // setting it there (and in the vendored mosquitto patch) work at all.
    SSL* ssl = ::SSL_new(ctx);
    CHECK(ssl != nullptr);
    if (ssl) {
        X509_VERIFY_PARAM* sp = ::SSL_get0_param(ssl);
        CHECK((::X509_VERIFY_PARAM_get_hostflags(sp)
               & X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT) != 0);
        // Setting the expected name must not drop it: mosquitto configures the
        // context first and calls X509_VERIFY_PARAM_set1_host() per connection.
        CHECK(::X509_VERIFY_PARAM_set1_host(sp, "00M00A000000001", 0) == 1);
        CHECK((::X509_VERIFY_PARAM_get_hostflags(sp)
               & X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT) != 0);
        ::SSL_free(ssl);
    }

    ::SSL_CTX_free(ctx);
    std::filesystem::remove(ca_path);

    if (fail_count) {
        std::fprintf(stderr, "%d test(s) failed\n", fail_count);
        return 1;
    }
    std::printf("lan_tls_verify_test: ok\n");
    return 0;
}
