// AgoraUrl.cpp — parser for the bambu:///agora?... camera URL.

#include "AgoraUrl.hpp"

#include <string>
#include <unordered_map>

namespace bambu_net {
namespace camera {

// ---------------------------------------------------------------------------
// URL parsing helpers
// ---------------------------------------------------------------------------

static std::string url_decode(const std::string& in)
{
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ) {
        if (in[i] == '%' && i + 2 < in.size()) {
            char hi = in[i+1], lo = in[i+2];
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int h = hex(hi), l = hex(lo);
            if (h >= 0 && l >= 0) {
                out.push_back(static_cast<char>((h << 4) | l));
                i += 3;
                continue;
            }
        } else if (in[i] == '+') {
            out.push_back(' ');
            ++i;
            continue;
        }
        out.push_back(in[i++]);
    }
    return out;
}

static std::unordered_map<std::string, std::string>
parse_query(const std::string& q)
{
    std::unordered_map<std::string, std::string> m;
    size_t pos = 0;
    while (pos < q.size()) {
        size_t amp = q.find('&', pos);
        if (amp == std::string::npos) amp = q.size();
        size_t eq = q.find('=', pos);
        if (eq != std::string::npos && eq < amp) {
            m[url_decode(q.substr(pos, eq - pos))] =
                url_decode(q.substr(eq + 1, amp - eq - 1));
        }
        pos = amp + 1;
    }
    return m;
}

AgoraRegion agora_region_from_string(const std::string& s)
{
    if (s == "cn") return AgoraRegion::CN;
    if (s == "eu") return AgoraRegion::EU;
    if (s == "na") return AgoraRegion::NA;
    if (s == "us") return AgoraRegion::US;
    return AgoraRegion::Default;
}

bool AgoraUrl::parse(const std::string& url, AgoraUrl& out, std::string& err)
{
    const std::string scheme = "bambu://";
    if (url.compare(0, scheme.size(), scheme) != 0) {
        err = "not a bambu:// URL";
        return false;
    }
    size_t path_start = scheme.size();
    while (path_start < url.size() && url[path_start] == '/') ++path_start;

    size_t q = url.find('?', path_start);
    std::string path  = (q == std::string::npos)
                        ? url.substr(path_start)
                        : url.substr(path_start, q - path_start);
    std::string query = (q == std::string::npos) ? "" : url.substr(q + 1);

    if (path != "agora") {
        err = "path is not 'agora': " + path;
        return false;
    }

    auto params = parse_query(query);
    auto get = [&](const std::string& k, const std::string& def = "") {
        auto it = params.find(k);
        return it != params.end() ? it->second : def;
    };

    out.app_id   = get("app");
    out.channel  = get("channel");
    out.token    = get("token");
    out.passwd   = get("passwd");
    out.device   = get("device");
    out.tutk_uid = get("tutk_uid");
    out.dev_ver  = get("dev_ver");
    out.net_ver  = get("net_ver");
    out.cli_id   = get("cli_id");
    out.cli_ver  = get("cli_ver");
    out.region   = agora_region_from_string(get("region", ""));
    out.auxiliary = get("auxiliary_enable", "0") != "0";

    std::string user_str = get("user", "0");
    try { out.uid = static_cast<uint32_t>(std::stoul(user_str)); }
    catch (...) { out.uid = 0; }

    std::string refresh_str = get("refresh_url", "0");
    try { out.refresh_fn = static_cast<uintptr_t>(std::stoull(refresh_str, nullptr, 16)); }
    catch (...) { out.refresh_fn = 0; }

    if (out.app_id.empty())   { err = "missing 'app' param";     return false; }
    if (out.channel.empty())  { err = "missing 'channel' param"; return false; }
    return true;
}

}  // namespace camera
}  // namespace bambu_net
