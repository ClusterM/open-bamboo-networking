#include "obn/cloud_presets.hpp"

#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/cloud_auth.hpp"
#include "obn/http_client.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"
#include "obn/os_compat.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <sstream>

namespace obn::cloud_presets {

namespace {

std::string api_base(Agent* a)
{
    return obn::cloud::api_host(a->cloud_region());
}

std::string settings_base(Agent* a)
{
    return api_base(a) + "/v1/iot-service/api/slicer/setting";
}

// Stringify any json value back to a flat scalar string, matching the
// way PresetCollection::get_differed_values_to_update stored options
// (serialize()). Arrays/objects fall back to compact JSON text so we
// don't lose information (e.g. if the server ever starts returning
// typed values instead of pre-stringified ones).
std::string json_scalar_to_string(const obn::json::Value& v)
{
    using K = obn::json::Value::Kind;
    switch (v.kind()) {
        case K::Null:   return {};
        case K::Bool:   return v.as_bool() ? "1" : "0";
        case K::String: return v.as_string();
        case K::Number: {
            double d = v.as_number();
            // Prefer integer rendering when the value has no fractional
            // part: Bambu's config options are overwhelmingly ints.
            long long as_int = static_cast<long long>(d);
            if (static_cast<double>(as_int) == d) {
                return std::to_string(as_int);
            }
            std::ostringstream os;
            os.precision(17);
            os << d;
            return os.str();
        }
        case K::Array:
        case K::Object:
            return v.dump();
    }
    return {};
}

// "2026-04-21 17:11:27" (UTC) -> unix seconds. Returns 0 on parse fail.
std::int64_t parse_iso_utc(const std::string& s)
{
    if (s.empty()) return 0;
    // strptime is POSIX-only; MSVC has no equivalent. The format is fixed
    // ("YYYY-MM-DD HH:MM:SS"), so a tiny sscanf does the job and is more
    // portable than dragging in std::get_time / strptime polyfills.
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0;
    if (std::sscanf(s.c_str(), "%4d-%2d-%2d %2d:%2d:%2d",
                    &y, &mo, &d, &h, &mi, &se) != 6) {
        return 0;
    }
    std::tm t{};
    t.tm_year = y - 1900;
    t.tm_mon  = mo - 1;
    t.tm_mday = d;
    t.tm_hour = h;
    t.tm_min  = mi;
    t.tm_sec  = se;
    // The struct is interpreted as UTC; timegm()/_mkgmtime() do not apply
    // a TZ offset. obn::os::timegm_safe maps to the right one per platform.
    auto tt = obn::os::timegm_safe(&t);
    if (tt == static_cast<std::time_t>(-1)) return 0;
    return static_cast<std::int64_t>(tt);
}

// Parse a server JSON body. Empty / unparseable bodies become an empty
// object, so callers can still call `.find(...)` without null checks.
obn::json::Value parse_body(const std::string& body)
{
    std::string err;
    auto v = obn::json::parse(body, &err);
    if (!v) return obn::json::Value{obn::json::Object{}};
    return *v;
}

// Copy a server-side error code (if any) into values_map["code"] so
// Studio's `values_map["code"] == "14"` preset-limit check keeps
// working even on our workaround path.
void propagate_error_code(const obn::json::Value& root,
                          std::map<std::string, std::string>& values_map)
{
    auto c = root.find("code");
    if (c.is_number()) {
        long long n = c.as_int();
        if (n != 0) values_map["code"] = std::to_string(n);
    } else if (c.is_string() && !c.as_string().empty()) {
        values_map["code"] = c.as_string();
    }
}

// Build the top-level POST/PATCH body. Envelope fields "version",
// "type", "base_id" are lifted out of `values_map`; everything else
// (including **`filament_id`**) stays inside the `setting` object.
//
// Important: stock `POST /setting` for a *filament* preset places
// `filament_id` **only** inside `setting` (e.g. `"filament_id":"P1ec9c9c"`)
// and does **not** duplicate it as a top-level key. Sending a top-level
// `filament_id` without the same field inside `setting` yields HTTP 200
// but the server stores `filament_id: null` in GET /setting/<id> and
// printer-side catalogue sync never picks up the material ID.
//
// Also match stock for: `"public":false` on create; omit empty top-level
// `base_id` (never send ""); PATCH print presets lead with `base_id`
// when non-empty.
std::string build_upload_body(const std::string& name,
                              const std::map<std::string, std::string>& values_map,
                              bool is_create)
{
    static const char* const top_keys[] = {
        IOT_JSON_KEY_VERSION, IOT_JSON_KEY_TYPE, IOT_JSON_KEY_BASE_ID,
    };
    auto is_top = [&](const std::string& k) {
        for (auto* tk : top_keys) if (k == tk) return true;
        return false;
    };

    auto get_or = [&](const char* k) -> std::string {
        auto it = values_map.find(k);
        return it == values_map.end() ? std::string{} : it->second;
    };

    const std::string bid    = get_or(IOT_JSON_KEY_BASE_ID);
    const std::string typ    = get_or(IOT_JSON_KEY_TYPE);
    const std::string ver    = get_or(IOT_JSON_KEY_VERSION);

    std::ostringstream os;
    os << '{';

    if (!is_create && !bid.empty()) {
        os << "\"base_id\":" << obn::json::escape(bid) << ',';
    }
    os << "\"name\":" << obn::json::escape(name);
    if (is_create) {
        os << ",\"public\":false";
    }

    os << ",\"setting\":{";
    bool first = true;
    for (const auto& [k, v] : values_map) {
        if (is_top(k)) continue;
        // "code" is an error-reporting slot we write back in-place; it
        // must not be uploaded as part of the preset.
        if (k == "code") continue;
        // Envelope-only / session metadata Studio sometimes leaves in the map.
        if (k == IOT_JSON_KEY_NAME || k == IOT_JSON_KEY_SETTING_ID ||
            k == IOT_JSON_KEY_USER_ID || k == "public") {
            continue;
        }
        if (!first) os << ',';
        first = false;
        os << obn::json::escape(k) << ':' << obn::json::escape(v);
    }
    os << '}';

    if (is_create) {
        // Stock POST always includes these keys; keep them even when empty
        // so we do not regress servers that validate presence, not just MITM
        // shapes with non-empty bundles.
        os << ",\"type\":" << obn::json::escape(typ);
        os << ",\"version\":" << obn::json::escape(ver);
    } else {
        if (!typ.empty()) {
            os << ",\"type\":" << obn::json::escape(typ);
        }
        if (!ver.empty()) {
            os << ",\"version\":" << obn::json::escape(ver);
        }
    }
    if (is_create && !bid.empty()) {
        os << ",\"base_id\":" << obn::json::escape(bid);
    }
    os << '}';
    return os.str();
}

// Turn the server response for GET /setting/<id> into the flat
// values_map Studio's loader expects. `user_id` is injected from the
// authenticated session (the server doesn't include it in the
// response).
void fill_values_from_full(const obn::json::Value& root,
                           const std::string& user_id,
                           std::map<std::string, std::string>& out)
{
    out.clear();
    // Metadata from the envelope first, so if a same-named key is
    // also inside `setting` the envelope wins.
    auto copy_str = [&](const char* key) {
        auto v = root.find(key);
        if (v.is_string()) out[key] = v.as_string();
        else if (v.is_number()) out[key] = std::to_string(v.as_int());
    };
    copy_str(IOT_JSON_KEY_NAME);
    copy_str(IOT_JSON_KEY_TYPE);
    copy_str(IOT_JSON_KEY_VERSION);
    copy_str(IOT_JSON_KEY_SETTING_ID);
    copy_str(IOT_JSON_KEY_BASE_ID);
    copy_str(IOT_JSON_KEY_FILAMENT_ID);

    // `setting` is a flat {key: string-ish value} map.
    const auto& setting = root.find("setting");
    if (setting.is_object()) {
        for (const auto& [k, v] : setting.as_object()) {
            out[k] = json_scalar_to_string(v);
        }
    }

    // Convert "YYYY-MM-DD HH:MM:SS" into the unix-seconds string
    // Studio's load_user_preset() wants (std::atoll on the value).
    std::string iso = root.find(IOT_JSON_KEY_UPDATE_TIME).as_string();
    if (iso.empty()) iso = root.find(IOT_JSON_KEY_UPDATED_TIME).as_string();
    std::int64_t unix_ts = parse_iso_utc(iso);
    if (unix_ts == 0) {
        // If the server ever returns a pre-epoch string or we fail to
        // parse, avoid emitting "0" (it triggers Studio's "always
        // overwrite" branch). Use 1 as a harmless sentinel.
        unix_ts = 1;
    }
    out[IOT_JSON_KEY_UPDATED_TIME] = std::to_string(unix_ts);

    // Studio's load_user_preset() requires base_id to be present in the
    // flat map (Preset.cpp). copy_str() skips JSON null; many cloud
    // filament rows have base_id null at the envelope and omit it from
    // `setting`, so the key is missing and every such preset is dropped
    // without surfacing an error through the plugin.
    if (out.find(IOT_JSON_KEY_BASE_ID) == out.end()) {
        out[IOT_JSON_KEY_BASE_ID] = "";
    }

    // Studio's loader rejects presets without user_id. The server
    // doesn't echo it, so inject our authenticated user_id here.
    if (!user_id.empty()) {
        out[IOT_JSON_KEY_USER_ID] = user_id;
    }
}

} // namespace

int list(Agent* a, const std::string& bundle_version, std::vector<Meta>* out)
{
    if (!a || !out) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    out->clear();

    auto hdrs = a->cloud_api_http_headers();
    if (hdrs.find("Authorization") == hdrs.end()) {
        return BAMBU_NETWORK_ERR_GET_SETTING_LIST_FAILED;
    }
    // GET doesn't need Content-Type; some backends 415 if present.
    hdrs.erase("Content-Type");

    std::string url = settings_base(a) + "?public=false";
    if (!bundle_version.empty()) {
        url += "&version=" + obn::http::url_encode(bundle_version);
    }

    auto resp = obn::http::get_json(url, hdrs);
    OBN_INFO("cloud_presets::list http=%ld bytes=%zu",
             resp.status_code, resp.body.size());
    if (!resp.error.empty() || resp.status_code < 200 || resp.status_code >= 300) {
        OBN_WARN("cloud_presets::list failed: %s", resp.error.c_str());
        return BAMBU_NETWORK_ERR_GET_SETTING_LIST_FAILED;
    }

    obn::json::Value root = parse_body(resp.body);

    // Response:
    //   { "message":"success", ..., "print":{"private":[...],"public":[...]},
    //     "printer":{...}, "filament":{...} }
    static const char* const types[] = { IOT_PRINT_TYPE_STRING,
                                         IOT_PRINTER_TYPE_STRING,
                                         IOT_FILAMENT_STRING };
    int total = 0;
    for (const char* type : types) {
        auto priv = root.find(std::string{type} + ".private");
        if (!priv.is_array()) continue;
        for (const auto& item : priv.as_array()) {
            Meta m;
            m.type         = type;
            m.setting_id   = item.find(IOT_JSON_KEY_SETTING_ID).as_string();
            m.name         = item.find(IOT_JSON_KEY_NAME).as_string();
            m.version      = item.find(IOT_JSON_KEY_VERSION).as_string();
            m.base_id      = item.find(IOT_JSON_KEY_BASE_ID).as_string();
            m.filament_id  = item.find(IOT_JSON_KEY_FILAMENT_ID).as_string();
            m.inherits     = item.find("inherits").as_string();
            m.update_time  = item.find(IOT_JSON_KEY_UPDATE_TIME).as_string();
            m.updated_time_unix = parse_iso_utc(m.update_time);
            m.is_public    = false;
            if (m.setting_id.empty() || m.name.empty()) continue;
            out->push_back(std::move(m));
            ++total;
        }
    }
    OBN_INFO("cloud_presets::list -> %d user presets", total);
    return BAMBU_NETWORK_SUCCESS;
}

int get_full(Agent* a,
             const std::string&                  setting_id,
             std::map<std::string, std::string>* values_map)
{
    if (!a || !values_map || setting_id.empty())
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;

    auto hdrs = a->cloud_api_http_headers();
    if (hdrs.find("Authorization") == hdrs.end())
        return BAMBU_NETWORK_ERR_GET_SETTING_LIST_FAILED;
    hdrs.erase("Content-Type");

    const std::string url = settings_base(a) + "/"
                          + obn::http::url_encode(setting_id);
    auto resp = obn::http::get_json(url, hdrs);
    OBN_DEBUG("cloud_presets::get_full id=%s http=%ld bytes=%zu",
              setting_id.c_str(), resp.status_code, resp.body.size());

    if (resp.status_code == 400) {
        // Server shape: {"message":"missing","code":2,"error":"..."}
        OBN_INFO("cloud_presets::get_full %s: not found on server",
                 setting_id.c_str());
        return BAMBU_NETWORK_ERR_GET_SETTING_LIST_FAILED;
    }
    if (!resp.error.empty() || resp.status_code < 200 || resp.status_code >= 300) {
        OBN_WARN("cloud_presets::get_full %s failed: http=%ld err=%s",
                 setting_id.c_str(), resp.status_code, resp.error.c_str());
        return BAMBU_NETWORK_ERR_GET_SETTING_LIST_FAILED;
    }

    obn::json::Value root = parse_body(resp.body);
    fill_values_from_full(root, a->cloud_user_id(), *values_map);
    return BAMBU_NETWORK_SUCCESS;
}

std::string create(Agent*                              a,
                   const std::string&                  name,
                   std::map<std::string, std::string>& values_map,
                   unsigned int*                       http_code)
{
    if (http_code) *http_code = 0;
    if (!a) return {};

    auto hdrs = a->cloud_api_http_headers();
    if (hdrs.find("Authorization") == hdrs.end()) {
        OBN_WARN("cloud_presets::create: not logged in");
        return {};
    }

    std::string body = build_upload_body(name, values_map, /*is_create=*/true);
    auto resp = obn::http::post_json(settings_base(a), body, hdrs);
    if (http_code) *http_code = static_cast<unsigned int>(resp.status_code);
    OBN_INFO("cloud_presets::create name='%s' http=%ld bytes=%zu",
             name.c_str(), resp.status_code, resp.body.size());

    obn::json::Value root = parse_body(resp.body);
    propagate_error_code(root, values_map);

    if (!resp.error.empty() || resp.status_code < 200 || resp.status_code >= 300) {
        return {};
    }

    std::string new_id = root.find(IOT_JSON_KEY_SETTING_ID).as_string();
    std::string iso    = root.find(IOT_JSON_KEY_UPDATE_TIME).as_string();
    if (iso.empty()) iso = root.find(IOT_JSON_KEY_UPDATED_TIME).as_string();
    std::int64_t ts = parse_iso_utc(iso);
    if (ts > 0) values_map[IOT_JSON_KEY_UPDATED_TIME] = std::to_string(ts);
    return new_id;
}

int update(Agent*                              a,
           const std::string&                  setting_id,
           const std::string&                  name,
           std::map<std::string, std::string>& values_map,
           unsigned int*                       http_code)
{
    if (http_code) *http_code = 0;
    if (!a || setting_id.empty()) return BAMBU_NETWORK_ERR_PUT_SETTING_FAILED;

    auto hdrs = a->cloud_api_http_headers();
    if (hdrs.find("Authorization") == hdrs.end()) {
        OBN_WARN("cloud_presets::update: not logged in");
        return BAMBU_NETWORK_ERR_PUT_SETTING_FAILED;
    }

    std::string body = build_upload_body(name, values_map, /*is_create=*/false);
    obn::http::Request req;
    req.method  = obn::http::Method::PATCH;
    req.url     = settings_base(a) + "/" + obn::http::url_encode(setting_id);
    req.body    = body;
    req.headers = hdrs;
    auto resp   = obn::http::perform(req);
    if (http_code) *http_code = static_cast<unsigned int>(resp.status_code);
    OBN_INFO("cloud_presets::update id=%s http=%ld bytes=%zu",
             setting_id.c_str(), resp.status_code, resp.body.size());

    obn::json::Value root = parse_body(resp.body);
    propagate_error_code(root, values_map);

    if (!resp.error.empty() || resp.status_code < 200 || resp.status_code >= 300) {
        return BAMBU_NETWORK_ERR_PUT_SETTING_FAILED;
    }

    std::string iso = root.find(IOT_JSON_KEY_UPDATE_TIME).as_string();
    if (iso.empty()) iso = root.find(IOT_JSON_KEY_UPDATED_TIME).as_string();
    std::int64_t ts = parse_iso_utc(iso);
    if (ts > 0) values_map[IOT_JSON_KEY_UPDATED_TIME] = std::to_string(ts);
    return BAMBU_NETWORK_SUCCESS;
}

int del(Agent* a, const std::string& setting_id)
{
    if (!a || setting_id.empty()) return BAMBU_NETWORK_ERR_DEL_SETTING_FAILED;

    auto hdrs = a->cloud_api_http_headers();
    if (hdrs.find("Authorization") == hdrs.end()) {
        OBN_WARN("cloud_presets::del: not logged in");
        return BAMBU_NETWORK_ERR_DEL_SETTING_FAILED;
    }
    hdrs.erase("Content-Type");

    obn::http::Request req;
    req.method  = obn::http::Method::DEL;
    req.url     = settings_base(a) + "/" + obn::http::url_encode(setting_id);
    req.headers = hdrs;
    auto resp   = obn::http::perform(req);
    OBN_INFO("cloud_presets::del id=%s http=%ld", setting_id.c_str(), resp.status_code);

    if (!resp.error.empty() || resp.status_code < 200 || resp.status_code >= 300) {
        return BAMBU_NETWORK_ERR_DEL_SETTING_FAILED;
    }
    // Server is idempotent: DELETE on a missing id also returns 200.
    return BAMBU_NETWORK_SUCCESS;
}

} // namespace obn::cloud_presets
