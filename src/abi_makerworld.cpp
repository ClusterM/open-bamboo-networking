#include <ctime>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <string>
#include <vector>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/cloud_auth.hpp"
#include "obn/http_client.hpp"
#include "obn/log.hpp"
#include "obn/oss_sign.hpp"

// Forward declaration only: BBLModelTask is defined in Bambu Studio's
// DeviceManager.hpp. We never dereference the pointer; we just need the type
// name to match Studio's std::function<void(BBLModelTask*)> template
// instantiation exactly. Getting the template parameter wrong is NOT merely
// a style issue - std::function's type-erased invoker expects arguments at
// specific offsets/layouts, and a mismatched instantiation silently
// reinterprets (e.g.) an int as a pointer, which is how PID 459153 died
// with SIGBUS inside StatusPanel::update_model_info.
class BBLModelTask;

using obn::as_agent;

// MakerWorld / model mall / OSS: no open specification exists. Most of
// these return success with empty payloads so Studio's UI degrades
// gracefully instead of crashing. The OSS credential/upload leg
// (get_oss_config + put_rating_picture_oss) is implemented per issue #49.

namespace {

// Split "https://host/..." into (host, scheme+host base). Returns false
// when the endpoint has no recognisable scheme.
bool split_endpoint(const std::string& endpoint, std::string* host,
                    std::string* base)
{
    const auto p = endpoint.find("://");
    if (p == std::string::npos) return false;
    const std::string rest = endpoint.substr(p + 3);
    const auto slash = rest.find('/');
    *host = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    *base = endpoint.substr(0, p + 3) + *host;
    return !host->empty();
}

// UTC now formatted as SigV4 "YYYYMMDDTHHMMSSZ" plus the "YYYYMMDD" stamp
// and an RFC 1123 date for Aliyun.
struct UtcNow {
    std::string amz_date;
    std::string date_stamp;
    std::string rfc1123;
};

UtcNow utc_now()
{
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char amz[32], stamp[16], rfc[48];
    std::strftime(amz, sizeof(amz), "%Y%m%dT%H%M%SZ", &tm);
    std::strftime(stamp, sizeof(stamp), "%Y%m%d", &tm);
    std::strftime(rfc, sizeof(rfc), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    return {amz, stamp, rfc};
}

} // namespace

OBN_ABI int bambu_network_get_design_staffpick(void* /*agent*/,
                                               int /*offset*/, int /*limit*/,
                                               std::function<void(std::string)> cb)
{
    if (cb) cb("{\"list\":[],\"total\":0}");
    return BAMBU_NETWORK_SUCCESS;
}

// The real plugin spells this `start_publish` when resolved (NetworkAgent.cpp
// uses the typo `start_pubilsh` only on the Studio side for the function
// pointer name), so we export the canonical name.
OBN_ABI int bambu_network_start_publish(void* /*agent*/,
                                        BBL::PublishParams     /*params*/,
                                        BBL::OnUpdateStatusFn  /*update_fn*/,
                                        BBL::WasCancelledFn    /*cancel_fn*/,
                                        std::string*           out)
{
    if (out) out->clear();
    return BAMBU_NETWORK_ERR_INVALID_RESULT;
}

OBN_ABI int bambu_network_get_model_publish_url(void* /*agent*/, std::string* url)
{
    if (url) *url = "https://makerworld.com/";
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_subtask(void*          /*agent*/,
                                      BBLModelTask*  task,
                                      std::function<void(BBLModelTask*)> cb)
{
    // Studio owns `task` (a heap BBLModelTask it just new'd, with task_id
    // pre-filled) and expects the plugin to enrich it with the cloud
    // model/design record for that task_id, then hand it back through `cb`.
    // The callback (StatusPanel::update_model_info -> get_subtask_fn) matches
    // subtask->task_id against the active print and calls set_modeltask(subtask),
    // taking ownership of the very pointer we echo back.
    //
    // We have no MakerWorld model/design metadata to add for user-uploaded
    // prints (there is no published model behind them), so we echo the caller's
    // object back unchanged. This is what completes Studio's request: skipping
    // the callback leaves StatusPanel::request_model_info_flag latched forever
    // and leaks the freshly-new'd BBLModelTask. It is ABI-safe precisely because
    // we return the SAME valid pointer Studio handed us - never a fabricated one
    // (the callback dereferences subtask->task_id, so a bad pointer would crash).
    OBN_DEBUG("get_subtask task=%p cb=%d -> echo", (void*)task, cb ? 1 : 0);
    if (task && cb) cb(task);
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_model_mall_home_url(void* /*agent*/, std::string* url)
{
    if (url) *url = "https://makerworld.com/";
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_model_mall_detail_url(void* /*agent*/,
                                                    std::string* url,
                                                    std::string  id)
{
    if (url) *url = std::string("https://makerworld.com/models/") + id;
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_put_model_mall_rating(void* /*agent*/,
                                                int /*rating_id*/, int /*score*/,
                                                std::string /*content*/,
                                                std::vector<std::string> /*images*/,
                                                unsigned int& http_code,
                                                std::string&  http_error)
{
    http_code = 0;
    http_error.clear();
    return BAMBU_NETWORK_ERR_INVALID_RESULT;
}

// Fetch the STS-scoped object-storage credentials Studio then feeds back
// into put_rating_picture_oss. Endpoint per issue #49:
//   GET /v1/user-service/my/ossconfig?useType=1  (S3 global)
//   GET /v1/user-service/my/s3config?useType=1   (fallback)
// We return the server JSON verbatim in `config`; Studio treats it as an
// opaque blob and hands it straight back to us.
OBN_ABI int bambu_network_get_oss_config(void* agent,
                                         std::string& config,
                                         std::string  /*country_code*/,
                                         unsigned int& http_code,
                                         std::string&  http_error)
{
    config.clear();
    http_code = 0;
    http_error.clear();

    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;

    auto session = a->user_session_snapshot();
    if (session.access_token.empty()) {
        http_error = "not logged in";
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }

    const std::string api = obn::cloud::api_host(a->cloud_region());
    std::map<std::string, std::string> hdrs;
    hdrs["Authorization"] = "Bearer " + session.access_token;
    hdrs["Accept"]        = "application/json";

    for (const char* path : {"/v1/user-service/my/ossconfig?useType=1",
                             "/v1/user-service/my/s3config?useType=1"}) {
        auto resp = obn::http::get_json(api + path, hdrs);
        http_code = static_cast<unsigned int>(resp.status_code);
        if (!resp.error.empty()) { http_error = resp.error; continue; }
        if (resp.status_code == 200 && !resp.body.empty()) {
            config = resp.body;
            return BAMBU_NETWORK_SUCCESS;
        }
    }
    if (http_error.empty()) http_error = "oss config unavailable";
    OBN_WARN("get_oss_config: no usable credentials (http=%u)", http_code);
    return BAMBU_NETWORK_ERR_INVALID_RESULT;
}

// Upload a rating picture to object storage using the credentials Studio
// obtained via get_oss_config, signing the PUT client-side (AWS SigV4 for
// the global S3 endpoint, Aliyun OSS V1 for CN). On success `pic_oss_path`
// is rewritten to the stored object key so Studio records the reference.
// TODO(verify-on-hardware): the object-key convention and the exact value
// Studio expects back in pic_oss_path are not wire-confirmed (issue #49);
// this fails closed (returns an error, never a fake success).
OBN_ABI int bambu_network_put_rating_picture_oss(void* agent,
                                                 std::string& config,
                                                 std::string& pic_oss_path,
                                                 std::string  model_id,
                                                 int          profile_id,
                                                 unsigned int& http_code,
                                                 std::string&  http_error)
{
    http_code = 0;
    http_error.clear();

    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;

    const obn::oss::Credentials c = obn::oss::parse_config(config);
    if (!c.ok) {
        http_error = "bad oss config";
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }

    // Read the local picture file (pic_oss_path is the source path on entry).
    std::ifstream f(pic_oss_path, std::ios::binary);
    if (!f) {
        http_error = "cannot open picture " + pic_oss_path;
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }
    std::string body((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());
    if (body.empty()) {
        http_error = "empty picture";
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }

    std::string host, base;
    if (!split_endpoint(c.endpoint, &host, &base)) {
        http_error = "bad oss endpoint";
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }

    // Derive a deterministic object key under the user's rating namespace.
    const auto slash = pic_oss_path.find_last_of("/\\");
    const std::string basename = (slash == std::string::npos)
                                     ? pic_oss_path
                                     : pic_oss_path.substr(slash + 1);
    const std::string object_key = "rating/" + model_id + "/" +
                                   std::to_string(profile_id) + "/" + basename;
    const std::string canonical_uri = "/" + object_key;

    const UtcNow now = utc_now();
    const std::string content_type = "image/jpeg";

    obn::http::Request req;
    req.method                  = obn::http::Method::PUT;
    req.url                     = base + canonical_uri;
    req.body                    = body;
    req.no_default_content_type = true;
    req.no_default_accept       = true;
    req.timeout_s               = 60;

    if (obn::oss::is_aliyun(c)) {
        const std::string canonical_resource = "/" + c.bucket + canonical_uri;
        req.headers = obn::oss::aliyun_oss_put_headers(
            c, canonical_resource, content_type, now.rfc1123);
    } else {
        req.headers = obn::oss::aws_sigv4_put_headers(
            c, host, canonical_uri, content_type, body,
            now.amz_date, now.date_stamp);
    }

    auto resp   = obn::http::perform(req);
    http_code   = static_cast<unsigned int>(resp.status_code);
    if (!resp.error.empty()) {
        http_error = resp.error;
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }
    if (resp.status_code < 200 || resp.status_code >= 300) {
        http_error = "oss PUT HTTP " + std::to_string(resp.status_code);
        OBN_WARN("put_rating_picture_oss: %s body=%.500s",
                 http_error.c_str(), resp.body.c_str());
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }

    pic_oss_path = object_key;
    OBN_INFO("put_rating_picture_oss: uploaded %zu bytes -> %s",
             body.size(), object_key.c_str());
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_model_mall_rating(void* /*agent*/,
                                                int /*job_id*/,
                                                std::string&  rating_result,
                                                unsigned int& http_code,
                                                std::string&  http_error)
{
    rating_result.clear();
    http_code = 0;
    http_error.clear();
    return BAMBU_NETWORK_ERR_INVALID_RESULT;
}

OBN_ABI int bambu_network_get_mw_user_preference(void* /*agent*/,
                                                 std::function<void(std::string)> cb)
{
    // CRITICAL: Studio expects a JSON with a numeric `recommendStatus`
    // field. It reads it as `int nRecommendStatus = jPrefer["recommendStatus"]`
    // inside a CallAfter lambda (WebViewDialog.cpp, SendDesignStaffpick).
    // If the field is missing, nlohmann::json converts null -> int and
    // throws type_error, which propagates out of the queued lambda
    // (past Studio's outer try/catch) and aborts the whole process via
    // wxApp::OnUnhandledException. We answer with 0 so Studio takes the
    // "default staff pick" branch and never looks at a null.
    if (cb) cb("{\"recommendStatus\":0}");
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_mw_user_4ulist(void* /*agent*/,
                                             int /*seed*/, int /*limit*/,
                                             std::function<void(std::string)> cb)
{
    if (cb) cb("{\"list\":[],\"total\":0}");
    return BAMBU_NETWORK_SUCCESS;
}

// -----------------------------------------------------------------------
// Additional symbols exported by the real plugin. Bambu Studio's current
// NetworkAgent.cpp does not resolve them, but newer Studio builds might; we
// export them as no-ops to stay binary-compatible.
// -----------------------------------------------------------------------

OBN_ABI int bambu_network_check_user_report(void* /*agent*/, int* /*id*/, bool* printable)
{
    if (printable) *printable = false;
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_del_rating_picture_oss(void* /*agent*/,
                                                 std::string& /*config*/,
                                                 std::string& pic_oss_path,
                                                 std::string  /*model_id*/,
                                                 int          /*profile_id*/,
                                                 unsigned int& http_code,
                                                 std::string&  http_error)
{
    pic_oss_path.clear();
    http_code = 0;
    http_error.clear();
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_model_instance_id(void* /*agent*/,
                                                std::string /*model_id*/,
                                                std::string* instance_id,
                                                unsigned int& http_code,
                                                std::string&  http_error)
{
    if (instance_id) instance_id->clear();
    http_code = 0;
    http_error.clear();
    return BAMBU_NETWORK_ERR_GET_INSTANCE_ID_FAILED;
}

OBN_ABI int bambu_network_get_model_rating_id(void* /*agent*/,
                                              std::string  /*model_id*/,
                                              int          /*profile_id*/,
                                              int*         rating_id,
                                              unsigned int& http_code,
                                              std::string&  http_error)
{
    if (rating_id) *rating_id = 0;
    http_code = 0;
    http_error.clear();
    return BAMBU_NETWORK_ERR_GET_RATING_ID_FAILED;
}
