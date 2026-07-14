#include "obn/cloud_filament.hpp"

#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/cloud_auth.hpp"
#include "obn/http_client.hpp"
#include "obn/log.hpp"

#include <sstream>
#include <string>

namespace obn::cloud_filament {

namespace {

std::string base_v2(Agent* a)
{
    return obn::cloud::api_host(a->cloud_region())
         + "/v1/design-user-service/my/filament/v2";
}

std::string base_config(Agent* a)
{
    return obn::cloud::api_host(a->cloud_region())
         + "/v1/design-user-service/filament/config";
}

// Build "?k1=v1&k2=v2" out of <key, value> pairs, skipping empties.
// We mirror Studio's ListFilamentV2Req schema: offset / limit are always
// emitted (server defaults differ from local defaults), the rest only
// when non-empty.
std::string build_list_query(const BBL::FilamentQueryParams& p)
{
    std::ostringstream os;
    char sep = '?';
    auto append = [&](const char* k, const std::string& v) {
        if (v.empty()) return;
        os << sep << k << '=' << obn::http::url_encode(v);
        sep = '&';
    };
    auto append_int = [&](const char* k, int v) {
        os << sep << k << '=' << v;
        sep = '&';
    };
    append_int("offset", p.offset);
    append_int("limit",  p.limit);
    append("category",   p.category);
    append("status",     p.status);
    // Studio's CloudClient maps three local key spellings (ids /
    // spoolId / spool_id) into FilamentQueryParams::spool_id, then
    // forwards a single comma-separated string. The cloud's swagger
    // calls the field `ids`.
    append("ids",        p.spool_id);
    append("RFIDs",      p.rfid);
    return os.str();
}

// JSON-escape `s` into a quoted string literal. Keeps the implementation
// dependency-free; we only need the small subset of escapes that string
// ids / RFIDs may contain.
std::string json_str(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(c);
                }
        }
    }
    out.push_back('"');
    return out;
}

// Build {"ids":[...],"RFIDs":[...]} from a FilamentDeleteParams. We send
// ids as JSON strings (matches the live MITM trace and the way
// wgtFilaManagerCloudClient::batch_delete forwards them); the Studio
// dispatcher upstream converts numeric-looking ids to int64 before
// re-stringifying so the server accepts both forms.
std::string build_delete_body(const BBL::FilamentDeleteParams& p)
{
    std::ostringstream os;
    os << '{';
    bool first = true;
    auto emit_arr = [&](const char* key, const std::vector<std::string>& v) {
        if (v.empty()) return;
        if (!first) os << ',';
        first = false;
        os << '"' << key << "\":[";
        for (size_t i = 0; i < v.size(); ++i) {
            if (i) os << ',';
            os << json_str(v[i]);
        }
        os << ']';
    };
    emit_arr("ids",   p.ids);
    emit_arr("RFIDs", p.rfids);
    os << '}';
    return os.str();
}

#if ABI_VERSION >= 0x020801

std::string build_ams_sync_item(const BBL::AmsSyncItem& item)
{
    std::ostringstream os;
    os << '{';
    bool first = true;
    auto comma = [&]() {
        if (!first) os << ',';
        first = false;
    };
    auto emit_str = [&](const char* key, const std::string& v) {
        comma();
        os << '"' << key << "\":" << json_str(v);
    };
    auto emit_int = [&](const char* key, int v) {
        comma();
        os << '"' << key << "\":" << v;
    };
    auto emit_bool = [&](const char* key, bool v) {
        comma();
        os << '"' << key << "\":" << (v ? "true" : "false");
    };

    emit_str("RFID", item.RFID);
    emit_int("amsId", item.amsId);
    emit_str("amsSn", item.amsSn);
    emit_int("amsType", item.amsType);
    emit_str("color", item.color);
    emit_int("colorType", item.colorType);
    comma();
    os << "\"colors\":[";
    for (size_t i = 0; i < item.colors.size(); ++i) {
        if (i) os << ',';
        os << json_str(item.colors[i]);
    }
    os << ']';
    emit_bool("createNew", item.createNew);
    emit_str("filamentId", item.filamentId);
    emit_str("filamentName", item.filamentName);
    emit_str("filamentType", item.filamentType);
    emit_str("filamentVendor", item.filamentVendor);
    emit_bool("isSupport", item.isSupport);
    emit_int("netWeight", item.netWeight);
    emit_str("note", item.note);
    emit_str("slotId", item.slotId);
    emit_int("totalNetWeight", item.totalNetWeight);
    emit_str("trayIdName", item.trayIdName);
    os << '}';
    return os.str();
}

std::string build_ams_sync_body(const BBL::AmsSyncParams& params)
{
    std::ostringstream os;
    os << "{\"devId\":" << json_str(params.devId) << ",\"items\":[";
    for (size_t i = 0; i < params.items.size(); ++i) {
        if (i) os << ',';
        os << build_ams_sync_item(params.items[i]);
    }
    os << "]}";
    return os.str();
}

#endif

// Common prologue: ensure we're logged in and grab the auth headers.
// Returns false (and stamps an empty body) when no session is available
// so callers can short-circuit with the right BAMBU_NETWORK_* code.
bool prepare(Agent* a,
             std::string* out_body,
             std::map<std::string, std::string>* hdrs)
{
    if (out_body) out_body->clear();
    if (!a) return false;
    *hdrs = a->cloud_api_http_headers();
    return hdrs->find("Authorization") != hdrs->end();
}

} // namespace

int list(Agent* a, const BBL::FilamentQueryParams& params, std::string* out_body)
{
    std::map<std::string, std::string> hdrs;
    if (!prepare(a, out_body, &hdrs)) {
        OBN_WARN("cloud_filament::list: not logged in");
        return BAMBU_NETWORK_ERR_GET_FILAMENTS_FAILED;
    }
    // GET: avoid Content-Type so picky backends don't 415.
    hdrs.erase("Content-Type");

    const std::string url = base_v2(a) + build_list_query(params);
    auto resp = obn::http::get_json(url, hdrs);
    OBN_INFO("cloud_filament::list http=%ld bytes=%zu (offset=%d limit=%d cat='%s' status='%s' ids='%s' rfid='%s')",
             resp.status_code, resp.body.size(),
             params.offset, params.limit,
             params.category.c_str(), params.status.c_str(),
             params.spool_id.c_str(), params.rfid.c_str());

    if (out_body) *out_body = resp.body;
    if (!resp.error.empty() || resp.status_code < 200 || resp.status_code >= 300) {
        OBN_WARN("cloud_filament::list failed: http=%ld err=%s",
                 resp.status_code, resp.error.c_str());
        return BAMBU_NETWORK_ERR_GET_FILAMENTS_FAILED;
    }
    return BAMBU_NETWORK_SUCCESS;
}

int create(Agent* a, const std::string& request_body, std::string* out_body)
{
    std::map<std::string, std::string> hdrs;
    if (!prepare(a, out_body, &hdrs)) {
        OBN_WARN("cloud_filament::create: not logged in");
        return BAMBU_NETWORK_ERR_CREATE_FILAMENT_FAILED;
    }

    auto resp = obn::http::post_json(base_v2(a), request_body, hdrs);
    OBN_INFO("cloud_filament::create http=%ld bytes=%zu req_len=%zu",
             resp.status_code, resp.body.size(), request_body.size());

    if (out_body) *out_body = resp.body;
    if (!resp.error.empty() || resp.status_code < 200 || resp.status_code >= 300) {
        OBN_WARN("cloud_filament::create failed: http=%ld err=%s body=%s",
                 resp.status_code, resp.error.c_str(), resp.body.c_str());
        return BAMBU_NETWORK_ERR_CREATE_FILAMENT_FAILED;
    }
    return BAMBU_NETWORK_SUCCESS;
}

int update(Agent* a, const std::string& spool_id,
           const std::string& request_body, std::string* out_body)
{
    std::map<std::string, std::string> hdrs;
    if (!prepare(a, out_body, &hdrs)) {
        OBN_WARN("cloud_filament::update: not logged in");
        return BAMBU_NETWORK_ERR_UPDATE_FILAMENT_FAILED;
    }

    obn::http::Request req;
    req.method  = obn::http::Method::PUT;
    req.url     = base_v2(a);
    req.headers = hdrs;
    req.body    = request_body;
    auto resp   = obn::http::perform(req);
    OBN_INFO("cloud_filament::update id='%s' http=%ld bytes=%zu req_len=%zu",
             spool_id.c_str(), resp.status_code, resp.body.size(),
             request_body.size());

    if (out_body) *out_body = resp.body;
    if (!resp.error.empty() || resp.status_code < 200 || resp.status_code >= 300) {
        OBN_WARN("cloud_filament::update failed: http=%ld err=%s body=%s",
                 resp.status_code, resp.error.c_str(), resp.body.c_str());
        return BAMBU_NETWORK_ERR_UPDATE_FILAMENT_FAILED;
    }
    return BAMBU_NETWORK_SUCCESS;
}

int batch_delete(Agent* a, const BBL::FilamentDeleteParams& params,
                 std::string* out_body)
{
    std::map<std::string, std::string> hdrs;
    if (!prepare(a, out_body, &hdrs)) {
        OBN_WARN("cloud_filament::batch_delete: not logged in");
        return BAMBU_NETWORK_ERR_DELETE_FILAMENT_FAILED;
    }

    if (params.ids.empty() && params.rfids.empty()) {
        OBN_WARN("cloud_filament::batch_delete: nothing to delete");
        return BAMBU_NETWORK_ERR_DELETE_FILAMENT_FAILED;
    }

    obn::http::Request req;
    req.method  = obn::http::Method::DEL;
    req.url     = base_v2(a) + "/batch";
    req.headers = hdrs;
    req.body    = build_delete_body(params);
    auto resp   = obn::http::perform(req);
    OBN_INFO("cloud_filament::batch_delete http=%ld ids=%zu rfids=%zu",
             resp.status_code, params.ids.size(), params.rfids.size());

    if (out_body) *out_body = resp.body;
    if (!resp.error.empty() || resp.status_code < 200 || resp.status_code >= 300) {
        OBN_WARN("cloud_filament::batch_delete failed: http=%ld err=%s body=%s",
                 resp.status_code, resp.error.c_str(), resp.body.c_str());
        return BAMBU_NETWORK_ERR_DELETE_FILAMENT_FAILED;
    }
    return BAMBU_NETWORK_SUCCESS;
}

int config(Agent* a, std::string* out_body)
{
    std::map<std::string, std::string> hdrs;
    if (!prepare(a, out_body, &hdrs)) {
        OBN_WARN("cloud_filament::config: not logged in");
        return BAMBU_NETWORK_ERR_GET_FILAMENT_CONFIG_FAILED;
    }
    hdrs.erase("Content-Type");

    auto resp = obn::http::get_json(base_config(a), hdrs);
    OBN_INFO("cloud_filament::config http=%ld bytes=%zu",
             resp.status_code, resp.body.size());

    if (out_body) *out_body = resp.body;
    if (!resp.error.empty() || resp.status_code < 200 || resp.status_code >= 300) {
        OBN_WARN("cloud_filament::config failed: http=%ld err=%s",
                 resp.status_code, resp.error.c_str());
        return BAMBU_NETWORK_ERR_GET_FILAMENT_CONFIG_FAILED;
    }
    return BAMBU_NETWORK_SUCCESS;
}

#if ABI_VERSION >= 0x020801

int sync_ams(Agent* a, const BBL::AmsSyncParams& params, std::string* out_body)
{
    std::map<std::string, std::string> hdrs;
    if (!prepare(a, out_body, &hdrs)) {
        OBN_WARN("cloud_filament::sync_ams: not logged in");
        return BAMBU_NETWORK_ERR_UPDATE_FILAMENT_FAILED;
    }
    if (params.devId.empty() || params.items.empty()) {
        OBN_WARN("cloud_filament::sync_ams: empty devId or items");
        return BAMBU_NETWORK_ERR_UPDATE_FILAMENT_FAILED;
    }

    const std::string body = build_ams_sync_body(params);
    auto resp = obn::http::post_json(base_v2(a) + "/ams/sync", body, hdrs);
    OBN_INFO("cloud_filament::sync_ams dev='%s' items=%zu http=%ld bytes=%zu",
             params.devId.c_str(), params.items.size(),
             resp.status_code, resp.body.size());

    if (out_body) *out_body = resp.body;
    if (!resp.error.empty() || resp.status_code < 200 || resp.status_code >= 300) {
        OBN_WARN("cloud_filament::sync_ams failed: http=%ld err=%s body=%s",
                 resp.status_code, resp.error.c_str(), resp.body.c_str());
        return BAMBU_NETWORK_ERR_UPDATE_FILAMENT_FAILED;
    }
    return BAMBU_NETWORK_SUCCESS;
}

#endif

} // namespace obn::cloud_filament
