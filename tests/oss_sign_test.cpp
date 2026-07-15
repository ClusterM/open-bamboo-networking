#include "obn/oss_sign.hpp"

#include <cstdio>
#include <string>

static int fail_count = 0;

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, \
                         #cond);                                        \
            ++fail_count;                                               \
        }                                                               \
    } while (0)

// FIPS 180-2 SHA-256 vectors.
static void test_sha256()
{
    CHECK(obn::oss::sha256_hex("") ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(obn::oss::sha256_hex("abc") ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

// RFC 4231 test case 2 (SHA-256) and RFC 2202 test case 2 (SHA-1).
static void test_hmac()
{
    const std::string mac = obn::oss::hmac_sha256(
        "Jefe", "what do ya want for nothing?");
    CHECK(obn::oss::hex_lower(mac) ==
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    const std::string mac1 = obn::oss::hmac_sha1(
        "Jefe", "what do ya want for nothing?");
    CHECK(obn::oss::hex_lower(mac1) ==
          "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
}

// AWS's published "deriving the signing key" example
// (secret/date/region/service -> known key bytes).
static void test_sigv4_signing_key()
{
    const std::string key = obn::oss::aws_sigv4_signing_key(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "20120215", "us-east-1", "iam");
    CHECK(obn::oss::hex_lower(key) ==
          "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d");
}

static void test_base64()
{
    CHECK(obn::oss::base64("") == "");
    CHECK(obn::oss::base64("f") == "Zg==");
    CHECK(obn::oss::base64("foobar") == "Zm9vYmFy");
}

static void test_parse_config()
{
    const std::string json = R"({
        "endpoint": "https://bucket.s3.us-east-1.amazonaws.com",
        "accessKeyId": "AKIDEXAMPLE",
        "accessKeySecret": "SECRET",
        "securityToken": "TOKEN",
        "expiration": "2026-01-01T00:00:00Z",
        "bucketName": "bucket",
        "cdnUrl": "https://cdn.example.com"
    })";
    const auto c = obn::oss::parse_config(json);
    CHECK(c.ok);
    CHECK(c.endpoint == "https://bucket.s3.us-east-1.amazonaws.com");
    CHECK(c.access_key_id == "AKIDEXAMPLE");
    CHECK(c.access_key_secret == "SECRET");
    CHECK(c.security_token == "TOKEN");
    CHECK(c.bucket == "bucket");
    CHECK(c.cdn_url == "https://cdn.example.com");
    CHECK(!obn::oss::is_aliyun(c));

    const auto bad = obn::oss::parse_config("{}");
    CHECK(!bad.ok);

    const auto ali = obn::oss::parse_config(
        R"({"endpoint":"https://b.oss-cn-hangzhou.aliyuncs.com",)"
        R"("accessKeyId":"A","accessKeySecret":"S"})");
    CHECK(ali.ok);
    CHECK(obn::oss::is_aliyun(ali));
}

static void test_sigv4_put_headers()
{
    obn::oss::Credentials c;
    c.access_key_id     = "AKIDEXAMPLE";
    c.access_key_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    c.security_token    = "TOKEN";
    c.region            = "us-east-1";
    c.ok                = true;

    const std::string payload = "hello";
    const auto h = obn::oss::aws_sigv4_put_headers(
        c, "bucket.s3.us-east-1.amazonaws.com", "/rating/1/2/pic.jpg",
        "image/jpeg", payload, "20260712T000000Z", "20260712");

    CHECK(h.count("Authorization") == 1);
    const std::string& auth = h.at("Authorization");
    CHECK(auth.rfind("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"
                     "20260712/us-east-1/s3/aws4_request", 0) == 0);
    CHECK(auth.find("SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
                    "x-amz-security-token") != std::string::npos);
    CHECK(auth.find("Signature=") != std::string::npos);
    CHECK(h.at("x-amz-content-sha256") == obn::oss::sha256_hex(payload));
    CHECK(h.at("x-amz-date") == "20260712T000000Z");
    CHECK(h.at("x-amz-security-token") == "TOKEN");
    CHECK(h.at("Content-Type") == "image/jpeg");

    // Same input signs identically (determinism), different payload doesn't.
    const auto h2 = obn::oss::aws_sigv4_put_headers(
        c, "bucket.s3.us-east-1.amazonaws.com", "/rating/1/2/pic.jpg",
        "image/jpeg", payload, "20260712T000000Z", "20260712");
    CHECK(h2.at("Authorization") == auth);
    const auto h3 = obn::oss::aws_sigv4_put_headers(
        c, "bucket.s3.us-east-1.amazonaws.com", "/rating/1/2/pic.jpg",
        "image/jpeg", "other", "20260712T000000Z", "20260712");
    CHECK(h3.at("Authorization") != auth);
}

static void test_aliyun_put_headers()
{
    obn::oss::Credentials c;
    c.endpoint          = "https://b.oss-cn-hangzhou.aliyuncs.com";
    c.access_key_id     = "AKID";
    c.access_key_secret = "SECRET";
    c.security_token    = "STS";
    c.bucket            = "b";
    c.ok                = true;

    const auto h = obn::oss::aliyun_oss_put_headers(
        c, "/b/rating/1/2/pic.jpg", "image/jpeg",
        "Sun, 12 Jul 2026 00:00:00 GMT");
    CHECK(h.count("Authorization") == 1);
    CHECK(h.at("Authorization").rfind("OSS AKID:", 0) == 0);
    CHECK(h.at("Date") == "Sun, 12 Jul 2026 00:00:00 GMT");
    CHECK(h.at("Content-Type") == "image/jpeg");
    CHECK(h.at("x-oss-security-token") == "STS");
}

int main()
{
    test_sha256();
    test_hmac();
    test_sigv4_signing_key();
    test_base64();
    test_parse_config();
    test_sigv4_put_headers();
    test_aliyun_put_headers();

    if (fail_count) {
        std::fprintf(stderr, "%d check(s) failed\n", fail_count);
        return 1;
    }
    std::puts("oss_sign_test: all checks passed");
    return 0;
}
