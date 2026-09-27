#include "obn/http_client.hpp"

#include <cstdio>
#include <string>

static int fail_count = 0;

#define CHECK_EQ(got, want)                                                  \
    do {                                                                     \
        const std::string g_ = (got), w_ = (want);                           \
        if (g_ != w_) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d:\n  got:  %s\n  want: %s\n",    \
                         __FILE__, __LINE__, g_.c_str(), w_.c_str());        \
            ++fail_count;                                                    \
        }                                                                    \
    } while (0)

using obn::http::redact_secret_headers;

int main()
{
    // A request header block the way libcurl hands it to the debug callback.
    CHECK_EQ(redact_secret_headers("GET /v1/user-service/my/profile HTTP/2\r\n"
                                   "Host: api.bambulab.com\r\n"
                                   "Authorization: Bearer eyJhbGciOi.secret.token\r\n"
                                   "Accept: application/json\r\n"
                                   "\r\n"),
             "GET /v1/user-service/my/profile HTTP/2\r\n"
             "Host: api.bambulab.com\r\n"
             "Authorization: Bearer <redacted 23 bytes>\r\n"
             "Accept: application/json\r\n"
             "\r\n");

    // Header names are case-insensitive; the scheme word survives.
    CHECK_EQ(redact_secret_headers("authorization: AWS4-HMAC-SHA256 Credential=AKIA/x, Signature=abc"),
             "authorization: AWS4-HMAC-SHA256 <redacted 32 bytes>");

    // Headers without a scheme are masked whole.
    CHECK_EQ(redact_secret_headers("x-amz-security-token: FQoGZXIvYXdzEJr\n"
                                   "X-OSS-Security-Token: CAIS8gF1q6Ft5B2y\n"
                                   "Cookie: token=abc; other=1\n"
                                   "Set-Cookie: sid=xyz; HttpOnly\n"
                                   "x-bbl-device-security-sign: c2lnbmF0dXJl\n"),
             "x-amz-security-token: <redacted 15 bytes>\n"
             "X-OSS-Security-Token: <redacted 16 bytes>\n"
             "Cookie: <redacted 18 bytes>\n"
             "Set-Cookie: <redacted 17 bytes>\n"
             "x-bbl-device-security-sign: <redacted 12 bytes>\n");

    // Everything else, including look-alike names, is untouched.
    const std::string benign = "Content-Type: application/json\r\n"
                               "X-BBL-Client-Name: OrcaSlicer\r\n"
                               "X-Authorization-Hint: none\r\n"
                               "HTTP/2 200\r\n";
    CHECK_EQ(redact_secret_headers(benign), benign);

    // Degenerate input.
    CHECK_EQ(redact_secret_headers(""), "");
    CHECK_EQ(redact_secret_headers("Authorization:"), "Authorization:");
    CHECK_EQ(redact_secret_headers("Authorization: Bearer"), "Authorization: <redacted 6 bytes>");

    if (fail_count) {
        std::fprintf(stderr, "%d test(s) failed\n", fail_count);
        return 1;
    }
    std::printf("http_redact_test: all passed\n");
    return 0;
}
