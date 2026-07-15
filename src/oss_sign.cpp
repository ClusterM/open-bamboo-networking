#include "obn/oss_sign.hpp"

#include "obn/json_lite.hpp"

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <initializer_list>

namespace obn::oss {
namespace {

const char* kB64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string first_nonempty(const obn::json::Value& obj,
                           std::initializer_list<const char*> keys)
{
    for (const char* k : keys) {
        const std::string v = obj.find(k).as_string();
        if (!v.empty()) return v;
    }
    return {};
}

} // namespace

std::string sha256_hex(const std::string& data)
{
    unsigned char md[SHA256_DIGEST_LENGTH];
    ::SHA256(reinterpret_cast<const unsigned char*>(data.data()),
             data.size(), md);
    return hex_lower(std::string(reinterpret_cast<char*>(md),
                                 SHA256_DIGEST_LENGTH));
}

std::string hmac_sha256(const std::string& key, const std::string& data)
{
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int  out_len = 0;
    ::HMAC(::EVP_sha256(),
           key.data(), static_cast<int>(key.size()),
           reinterpret_cast<const unsigned char*>(data.data()), data.size(),
           out, &out_len);
    return std::string(reinterpret_cast<char*>(out), out_len);
}

std::string hmac_sha1(const std::string& key, const std::string& data)
{
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int  out_len = 0;
    ::HMAC(::EVP_sha1(),
           key.data(), static_cast<int>(key.size()),
           reinterpret_cast<const unsigned char*>(data.data()), data.size(),
           out, &out_len);
    return std::string(reinterpret_cast<char*>(out), out_len);
}

std::string hex_lower(const std::string& raw)
{
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(raw.size() * 2);
    for (unsigned char c : raw) {
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0x0f]);
    }
    return out;
}

std::string base64(const std::string& raw)
{
    std::string out;
    out.reserve(((raw.size() + 2) / 3) * 4);
    const auto* d = reinterpret_cast<const unsigned char*>(raw.data());
    for (std::size_t i = 0; i < raw.size(); i += 3) {
        unsigned int w = static_cast<unsigned int>(d[i]) << 16;
        if (i + 1 < raw.size()) w |= static_cast<unsigned int>(d[i + 1]) << 8;
        if (i + 2 < raw.size()) w |= static_cast<unsigned int>(d[i + 2]);
        out.push_back(kB64[(w >> 18) & 63]);
        out.push_back(kB64[(w >> 12) & 63]);
        out.push_back(i + 1 < raw.size() ? kB64[(w >> 6) & 63] : '=');
        out.push_back(i + 2 < raw.size() ? kB64[w & 63] : '=');
    }
    return out;
}

std::string aws_sigv4_signing_key(const std::string& secret,
                                  const std::string& date_stamp,
                                  const std::string& region,
                                  const std::string& service)
{
    const std::string k_date    = hmac_sha256("AWS4" + secret, date_stamp);
    const std::string k_region  = hmac_sha256(k_date, region);
    const std::string k_service = hmac_sha256(k_region, service);
    return hmac_sha256(k_service, "aws4_request");
}

Credentials parse_config(const std::string& json)
{
    Credentials c;
    auto root = obn::json::parse(json);
    if (!root || !root->is_object()) return c;

    // The fields may live at the top level or under a "data" wrapper.
    obn::json::Value obj = *root;
    if (obj.find("accessKeyId").as_string().empty() &&
        obj.find("data").is_object())
        obj = obj.find("data");

    c.endpoint          = first_nonempty(obj, {"endpoint", "Endpoint", "host"});
    c.access_key_id     = first_nonempty(obj, {"accessKeyId", "AccessKeyId", "access_key_id"});
    c.access_key_secret = first_nonempty(obj, {"accessKeySecret", "AccessKeySecret", "access_key_secret"});
    c.security_token    = first_nonempty(obj, {"securityToken", "SecurityToken", "security_token"});
    c.bucket            = first_nonempty(obj, {"bucketName", "BucketName", "bucket"});
    c.region            = first_nonempty(obj, {"region", "Region"});
    c.cdn_url           = first_nonempty(obj, {"cdnUrl", "CdnUrl", "cdn_url"});

    c.ok = !c.endpoint.empty() && !c.access_key_id.empty() &&
           !c.access_key_secret.empty();
    return c;
}

bool is_aliyun(const Credentials& c)
{
    return c.endpoint.find("aliyuncs.com") != std::string::npos;
}

std::map<std::string, std::string>
aws_sigv4_put_headers(const Credentials& c,
                      const std::string& host,
                      const std::string& canonical_uri,
                      const std::string& content_type,
                      const std::string& payload,
                      const std::string& amz_date,
                      const std::string& date_stamp)
{
    const std::string region  = c.region.empty() ? "us-east-1" : c.region;
    const std::string service = "s3";
    const std::string payload_hash = sha256_hex(payload);

    // Signed headers, in the sorted order SigV4 requires. content-type is
    // sent but left unsigned (S3 only mandates signing x-amz-* headers).
    std::string canonical_headers =
        "host:" + host + "\n" +
        "x-amz-content-sha256:" + payload_hash + "\n" +
        "x-amz-date:" + amz_date + "\n";
    std::string signed_headers = "host;x-amz-content-sha256;x-amz-date";
    if (!c.security_token.empty()) {
        canonical_headers += "x-amz-security-token:" + c.security_token + "\n";
        signed_headers    += ";x-amz-security-token";
    }

    const std::string canonical_request =
        "PUT\n" + canonical_uri + "\n" + /*query*/ "\n" +
        canonical_headers + "\n" + signed_headers + "\n" + payload_hash;

    const std::string scope =
        date_stamp + "/" + region + "/" + service + "/aws4_request";
    const std::string string_to_sign =
        "AWS4-HMAC-SHA256\n" + amz_date + "\n" + scope + "\n" +
        sha256_hex(canonical_request);

    const std::string signing_key =
        aws_sigv4_signing_key(c.access_key_secret, date_stamp, region, service);
    const std::string signature = hex_lower(hmac_sha256(signing_key, string_to_sign));

    const std::string authorization =
        "AWS4-HMAC-SHA256 Credential=" + c.access_key_id + "/" + scope +
        ", SignedHeaders=" + signed_headers +
        ", Signature=" + signature;

    std::map<std::string, std::string> h;
    h["Authorization"]        = authorization;
    h["x-amz-content-sha256"] = payload_hash;
    h["x-amz-date"]           = amz_date;
    if (!c.security_token.empty()) h["x-amz-security-token"] = c.security_token;
    if (!content_type.empty())     h["Content-Type"]         = content_type;
    return h;
}

std::map<std::string, std::string>
aliyun_oss_put_headers(const Credentials& c,
                       const std::string& canonical_resource,
                       const std::string& content_type,
                       const std::string& date_rfc1123)
{
    // Aliyun OSS V1: StringToSign = VERB\nCONTENT-MD5\nCONTENT-TYPE\nDATE\n
    // CanonicalizedOSSHeaders + CanonicalizedResource, HMAC-SHA1 signed and
    // base64-encoded. We send no Content-MD5 and only the
    // x-oss-security-token canonicalized header (when present).
    std::string canonical_oss_headers;
    if (!c.security_token.empty())
        canonical_oss_headers = "x-oss-security-token:" + c.security_token + "\n";

    const std::string string_to_sign =
        "PUT\n" + std::string("") + "\n" + content_type + "\n" +
        date_rfc1123 + "\n" + canonical_oss_headers + canonical_resource;

    const std::string signature =
        base64(hmac_sha1(c.access_key_secret, string_to_sign));

    std::map<std::string, std::string> h;
    h["Authorization"] = "OSS " + c.access_key_id + ":" + signature;
    h["Date"]          = date_rfc1123;
    if (!content_type.empty())     h["Content-Type"]          = content_type;
    if (!c.security_token.empty()) h["x-oss-security-token"]   = c.security_token;
    return h;
}

} // namespace obn::oss
