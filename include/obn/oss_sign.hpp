#pragma once

// Client-side object-storage request signing for the credential-based
// upload leg (rating pictures / MakerWorld publish). Distinct from the
// server-presigned print-upload PUT (see src/cloud_print.cpp), which is
// already signed by the cloud and needs no client-side crypto.
//
// Two schemes are supported:
//   * AWS Signature V4 (global region, S3-compatible endpoints).
//   * Aliyun OSS V1 `Authorization: OSS <AKID>:<sig>` (CN region).
//
// The low-level primitives are exposed so signing_test/oss_sign_test can
// pin them against the vendors' published test vectors.

#include <map>
#include <string>

namespace obn::oss {

// Credential blob returned by GET /v1/user-service/my/{oss,s3}config?useType=1.
struct Credentials {
    std::string endpoint;           // scheme+host, e.g. "https://bucket.oss-cn-hangzhou.aliyuncs.com"
    std::string access_key_id;
    std::string access_key_secret;
    std::string security_token;     // STS token (may be empty)
    std::string bucket;
    std::string region;             // SigV4 scope region ("" -> "us-east-1")
    std::string cdn_url;            // public base for the stored object
    bool        ok = false;
};

// Parse the config JSON handed back to Studio by get_oss_config. Accepts
// both AWS-style (accessKeyId/accessKeySecret/securityToken/bucketName)
// and generic key spellings. `ok` is false when required fields are absent.
Credentials parse_config(const std::string& json);

// True when the endpoint host looks like Aliyun OSS ("aliyuncs.com").
bool is_aliyun(const Credentials& c);

// --- primitives (deterministic; covered by tests) ------------------------

std::string sha256_hex(const std::string& data);
std::string hmac_sha256(const std::string& key, const std::string& data); // raw bytes
std::string hmac_sha1(const std::string& key, const std::string& data);   // raw bytes (Aliyun V1)
std::string hex_lower(const std::string& raw);
std::string base64(const std::string& raw);

// AWS SigV4 signing key: HMAC chain over date/region/service. Raw bytes.
std::string aws_sigv4_signing_key(const std::string& secret,
                                  const std::string& date_stamp,   // YYYYMMDD
                                  const std::string& region,
                                  const std::string& service);

// --- high-level: build headers for a single-shot PUT of `payload` --------

// Returns the full set of request headers (including Authorization) for an
// S3 PUT to `host`/`canonical_uri`. `amz_date` is "YYYYMMDDTHHMMSSZ"; that
// UTC value's date part must equal `date_stamp` ("YYYYMMDD").
std::map<std::string, std::string>
aws_sigv4_put_headers(const Credentials& c,
                      const std::string& host,
                      const std::string& canonical_uri,
                      const std::string& content_type,
                      const std::string& payload,
                      const std::string& amz_date,
                      const std::string& date_stamp);

// Returns headers for an Aliyun OSS PUT. `canonical_resource` is
// "/<bucket>/<object>"; `date_rfc1123` is the GMT Date header value.
std::map<std::string, std::string>
aliyun_oss_put_headers(const Credentials& c,
                       const std::string& canonical_resource,
                       const std::string& content_type,
                       const std::string& date_rfc1123);

} // namespace obn::oss
