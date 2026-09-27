#include "obn/camera_url.hpp"
#include "obn/json_lite.hpp"

#include <sstream>

namespace obn::camera {

std::string url_encode(const std::string& in)
{
    static const char HEX[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size() * 3);
    for (unsigned char c : in) {
        bool unreserved = (c >= 'A' && c <= 'Z') ||
                          (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') ||
                          c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(HEX[(c >> 4) & 0xF]);
            out.push_back(HEX[c & 0xF]);
        }
    }
    return out;
}

PackedDevKey parse_packed_dev_key(const std::string& raw)
{
    PackedDevKey result;
    if (raw.empty()) return result;

    const auto b1 = raw.find('|');
    if (b1 == std::string::npos) {
        result.serial = raw;
        result.protocols = {"tutk", "agora"};
        return result;
    }

    result.serial = raw.substr(0, b1);

    const auto b2 = raw.find('|', b1 + 1);
    if (b2 == std::string::npos) {
        result.dev_version = raw.substr(b1 + 1);
        result.protocols = {"tutk", "agora"};
        return result;
    }

    result.dev_version = raw.substr(b1 + 1, b2 - (b1 + 1));

    const auto b3 = raw.find('|', b2 + 1);
    const std::string protos_spec = raw.substr(b2 + 1, b3 == std::string::npos ? std::string::npos : b3 - (b2 + 1));

    std::stringstream ss(protos_spec);
    std::string item;
    while (std::getline(ss, item, ',')) {
        while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.erase(item.begin());
        while (!item.empty() && (item.back() == ' ' || item.back() == '\t')) item.pop_back();
        if (!item.empty()) {
            result.protocols.push_back(item);
        }
    }

    if (result.protocols.empty()) {
        result.protocols = {"tutk", "agora"};
    }

    return result;
}

std::string build_ttcode_request_body(const std::string& serial,
                                      const std::string& dev_version,
                                      const std::vector<std::string>& protocols)
{
    std::string protos_json = "[";
    for (size_t i = 0; i < protocols.size(); ++i) {
        if (i > 0) protos_json += ",";
        protos_json += obn::json::escape(protocols[i]);
    }
    protos_json += "]";

    std::string req = "{\"dev_id\":" + obn::json::escape(serial);
    if (!dev_version.empty()) {
        req += ",\"dev_version\":" + obn::json::escape(dev_version);
    }
    req += ",\"protocols\":" + protos_json + "}";
    return req;
}

bool parse_ttcode_response(const std::string& json,
                           TtcodeResponse& out,
                           std::string* err)
{
    out = TtcodeResponse{};
    auto root = obn::json::parse(json, err);
    if (!root) return false;

    auto get = [](const obn::json::Value& v, const char* k) -> std::string {
        auto f = v.find(k);
        return f.is_null() ? std::string{} : f.as_string();
    };

    out.uid     = get(*root, "ttcode");
    if (out.uid.empty()) out.uid = get(*root, "uid");
    out.authkey = get(*root, "authkey");
    out.passwd  = get(*root, "passwd");
    out.region  = get(*root, "region");
    out.type    = get(*root, "type");

    return !out.uid.empty();
}

std::string build_tutk_url(const std::string& uid,
                           const std::string& authkey,
                           const std::string& passwd,
                           const std::string& region)
{
    return "bambu:///tutk?uid=" + url_encode(uid)
         + "&authkey=" + url_encode(authkey)
         + "&passwd=" + url_encode(passwd)
         + "&region=" + url_encode(region);
}

} // namespace obn::camera
