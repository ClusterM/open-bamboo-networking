#pragma once

// A small wrapper around libcurl that covers the subset of HTTP we need
// to talk to Bambu's cloud (`api.bambulab.com`) and the printer's web
// endpoints where relevant.
//
// Design notes:
//   * Synchronous, single-threaded per call. Each Request::send() uses
//     its own CURL handle, so callers can freely use them across
//     threads.
//   * TLS is delegated to libcurl's TLS backend (OpenSSL on our build).
//     api.bambulab.com sits behind Cloudflare which is picky about TLS
//     fingerprints; we don't yet attempt to mimic a full browser JA3.
//     Default User-Agent is `OBN/<plugin version>` unless overridden per
//     request or merged from Studio via bambu_network_set_extra_http_header.
//   * Responses are delivered as a plain struct with status + body +
//     a subset of headers (`Set-Cookie`, `Content-Type`). Callers do
//     the JSON parsing themselves (we keep a zero-dep JSON reader
//     helper in `json_lite.hpp`).

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace obn::http {

struct Response {
    long        status_code = 0; // 0 if the request did not complete
    std::string body;
    std::string content_type;
    std::vector<std::string> set_cookies;
    std::string error; // non-empty if the transport failed
};

enum class Method { GET, POST, PUT, DEL, PATCH };

struct Request {
    Method                                method = Method::GET;
    std::string                           url;
    std::map<std::string, std::string>    headers;
    std::string                           body;   // for POST/PUT/PATCH; also DELETE when set
    std::string                           ca_file;
    bool                                  insecure = false;
    int                                   connect_timeout_s = 10;
    int                                   timeout_s         = 30;
    // When true, we do NOT inject a default `Content-Type` / `Accept`
    // even if the body is non-empty. Required for PUTs to S3 presigned
    // URLs: the V2 signature covers `Content-Type`, so any mismatch
    // yields SignatureDoesNotMatch.
    bool                                  no_default_content_type = false;
    bool                                  no_default_accept       = false;
};

// Process-wide libcurl init (idempotent). Safe to call repeatedly.
void global_init();

// Execute the request and return the response. Never throws.
Response perform(const Request& req);

// Convenience: GET with JSON Accept header.
Response get_json(const std::string& url,
                  const std::map<std::string, std::string>& headers = {},
                  const std::string& ca_file = {});

// Convenience: POST application/json.
Response post_json(const std::string& url,
                   const std::string& body,
                   const std::map<std::string, std::string>& headers = {},
                   const std::string& ca_file = {});

// URL-encode a single component (RFC 3986 unreserved + percent).
std::string url_encode(const std::string& in);

} // namespace obn::http
