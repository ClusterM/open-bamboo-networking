#pragma once

#include <string>
#include <vector>

namespace obn::camera {

struct PackedDevKey {
    std::string serial;
    std::string dev_version;
    std::vector<std::string> protocols;
};

// Parses Studio's packed "serial|dev_ver|protocols[|channel]" string.
PackedDevKey parse_packed_dev_key(const std::string& raw);

// Constructs JSON body for POST /v1/iot-service/api/user/ttcode.
std::string build_ttcode_request_body(const std::string& serial,
                                      const std::string& dev_version,
                                      const std::vector<std::string>& protocols);

struct TtcodeResponse {
    std::string uid;
    std::string authkey;
    std::string passwd;
    std::string region;
    std::string type;
};

// Parses flat JSON response from /v1/iot-service/api/user/ttcode.
bool parse_ttcode_response(const std::string& json,
                           TtcodeResponse& out,
                           std::string* err = nullptr);

// Formats "bambu:///tutk?uid=...&authkey=...&passwd=...&region=..." with URL encoding.
std::string build_tutk_url(const std::string& uid,
                           const std::string& authkey,
                           const std::string& passwd,
                           const std::string& region);

// URL-encodes a string according to RFC 3986 unreserved character rules.
std::string url_encode(const std::string& in);

} // namespace obn::camera
