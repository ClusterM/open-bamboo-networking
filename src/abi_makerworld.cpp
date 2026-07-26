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
#include "obn/json_lite.hpp"
#include "obn/log.hpp"
#include "obn/oss_sign.hpp"

// Layout must match BambuStudio ProjectTask.hpp::BBLModelTask (non-virtual:
// 4 ints + 4 strings). Studio allocates; we only fill fields. The type name
// must also match Studio's std::function<void(BBLModelTask*)> instantiation
// exactly — a mismatched template parameter caused SIGBUS in
// StatusPanel::update_model_info (wrong invoker / argument layout).
class BBLModelTask {
public:
    int         job_id      = 0;
    int         design_id   = 0;
    int         profile_id  = 0;
    int         instance_id = 0;
    std::string task_id;
    std::string model_id;
    std::string model_name;
    std::string profile_name;
};

using obn::as_agent;

// MakerWorld / model mall / OSS. Wire confirmed via stock MITM
// (plugin_runner --action mw_probe) + research/08.12-makerworld.md.
// Dead ABIs (staffpick / publish / home_url) stay stubs — Studio GUI
// no longer calls them (ba049f6a2).

namespace {

// MakerWorld site host (not the REST api host). Mirrors Studio
// GUI_App::get_model_http_url for US / CN production.
std::string makerworld_host(const std::string& region)
{
    if (region == "CN") return "https://makerworld.com.cn/";
    return "https://makerworld.com/";
}

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

// Stock: GET /v1/user-service/my/task/<task_id> (Bearer). Distinct from
// get_subtask_info (iot-service). Not gated on block_cloud — read of an
// already-created cloud task record (same rationale as cover fetch).
OBN_ABI int bambu_network_get_subtask(void* agent,
                                      BBLModelTask* task,
                                      std::function<void(BBLModelTask*)> cb)
{
    auto echo = [&]() {
        if (task && cb) cb(task);
        return BAMBU_NETWORK_SUCCESS;
    };
    if (!task) return BAMBU_NETWORK_SUCCESS;

    const std::string& tid = task->task_id;
    if (tid.empty() || tid == "0" || tid.rfind("lan-", 0) == 0) {
        OBN_DEBUG("get_subtask: skip synthetic/empty id=%s", tid.c_str());
        return echo();
    }

    auto* a = as_agent(agent);
    if (!a) return echo();
    auto s = a->user_session_snapshot();
    if (s.access_token.empty()) {
        OBN_WARN("get_subtask: no access token (id=%s)", tid.c_str());
        return echo();
    }

    const std::string url = obn::cloud::api_host(a->cloud_region())
        + "/v1/user-service/my/task/"
        + obn::http::url_encode(tid);
    auto hdrs = a->cloud_api_http_headers();
    OBN_INFO("get_subtask: cloud id=%s", tid.c_str());
    auto resp = obn::http::get_json(url, hdrs);
    if (!resp.error.empty() || resp.status_code != 200) {
        OBN_WARN("get_subtask: HTTP %ld err=%s",
                 resp.status_code, resp.error.c_str());
        return echo();
    }

    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root) {
        OBN_WARN("get_subtask: JSON parse: %s", perr.c_str());
        return echo();
    }
    // Map MakerWorld camelCase → BBLModelTask (see research/07.12).
    task->job_id      = static_cast<int>(root->find("id").as_int(0));
    task->design_id   = static_cast<int>(root->find("designId").as_int(0));
    task->instance_id = static_cast<int>(root->find("instanceId").as_int(0));
    task->profile_id  = static_cast<int>(root->find("profileId").as_int(0));
    {
        auto v = root->find("modelId");
        if (v.is_string()) task->model_id = v.as_string();
        else if (v.is_number()) task->model_id = std::to_string(v.as_int());
    }
    task->model_name   = root->find("designTitle").as_string();
    task->profile_name = root->find("title").as_string();
    OBN_INFO("get_subtask: ok id=%s design=%d instance=%d",
             tid.c_str(), task->design_id, task->instance_id);
    if (cb) cb(task);
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_model_mall_home_url(void* /*agent*/, std::string* url)
{
    if (url) *url = "https://makerworld.com/";
    return BAMBU_NETWORK_SUCCESS;
}

// StatusPanel::market_model_scoring_page expects a URL containing
// "/models/<design_id>" then rewrites to …/u/<uid>/rating…. Stock returns
// a short-lived SSO ticket path; absolute regional models URL is enough
// for the rewrite + browser launch.
OBN_ABI int bambu_network_get_model_mall_detail_url(void* agent,
                                                    std::string* url,
                                                    std::string  id)
{
    if (!url) return BAMBU_NETWORK_SUCCESS;
    std::string region = "US";
    if (auto* a = as_agent(agent)) region = a->cloud_region();
    *url = makerworld_host(region) + "models/" + id;
    return BAMBU_NETWORK_SUCCESS;
}

// Stock: PUT /v1/comment-service/rating/<rating_id>
// body {"content":"...","images":[...],"score":N}
OBN_ABI int bambu_network_put_model_mall_rating(void* agent,
                                                int rating_id, int score,
                                                std::string content,
                                                std::vector<std::string> images,
                                                unsigned int& http_code,
                                                std::string&  http_error)
{
    http_code = 0;
    http_error.clear();
    if (rating_id <= 0) return BAMBU_NETWORK_ERR_GET_RATING_ID_FAILED;

    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    auto s = a->user_session_snapshot();
    if (s.access_token.empty()) {
        http_error = "not logged in";
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }

    using obn::json::Value;
    using obn::json::Object;
    using obn::json::Array;
    Array imgs;
    for (const auto& im : images) imgs.push_back(Value(im));
    Object body{
        {"content", Value(std::move(content))},
        {"images",  Value(std::move(imgs))},
        {"score",   Value(static_cast<double>(score))},
    };
    const std::string url = obn::cloud::api_host(a->cloud_region())
        + "/v1/comment-service/rating/"
        + std::to_string(rating_id);
    obn::http::Request req;
    req.method  = obn::http::Method::PUT;
    req.url     = url;
    req.headers = a->cloud_api_http_headers();
    req.body    = Value(std::move(body)).dump();
    OBN_INFO("put_model_mall_rating: id=%d score=%d images=%zu",
             rating_id, score, images.size());
    auto resp = obn::http::perform(req);
    http_code = static_cast<unsigned int>(resp.status_code);
    if (!resp.error.empty()) {
        http_error = resp.error;
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }
    if (resp.status_code < 200 || resp.status_code >= 300) {
        http_error = resp.body.empty()
            ? ("HTTP " + std::to_string(resp.status_code))
            : resp.body;
        OBN_WARN("put_model_mall_rating: HTTP %ld", resp.status_code);
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }
    return BAMBU_NETWORK_SUCCESS;
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

// Stock: GET /v1/comment-service/rating/inst/<instance_id>
// Studio passes instance_id (misnamed job_id). 404 when no rating yet.
OBN_ABI int bambu_network_get_model_mall_rating(void* agent,
                                                int job_id,
                                                std::string&  rating_result,
                                                unsigned int& http_code,
                                                std::string&  http_error)
{
    rating_result.clear();
    http_code = 0;
    http_error.clear();

    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    if (job_id <= 0) return BAMBU_NETWORK_ERR_INVALID_RESULT;

    auto s = a->user_session_snapshot();
    if (s.access_token.empty()) {
        http_error = "not logged in";
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }

    const std::string url = obn::cloud::api_host(a->cloud_region())
        + "/v1/comment-service/rating/inst/"
        + std::to_string(job_id);
    auto hdrs = a->cloud_api_http_headers();
    OBN_INFO("get_model_mall_rating: instance_id=%d", job_id);
    auto resp = obn::http::get_json(url, hdrs);
    http_code = static_cast<unsigned int>(resp.status_code);
    if (!resp.error.empty()) {
        http_error = resp.error;
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }
    if (resp.status_code != 200) {
        http_error = resp.body.empty()
            ? ("HTTP " + std::to_string(resp.status_code))
            : resp.body;
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }
    rating_result = std::move(resp.body);
    return BAMBU_NETWORK_SUCCESS;
}

// Stock: GET /v1/design-user-service/my/preference
// Body includes numeric recommendStatus (1|3 → For-You). On failure keep
// the crash-safe stub — missing/null recommendStatus aborts Studio.
OBN_ABI int bambu_network_get_mw_user_preference(void* agent,
                                                 std::function<void(std::string)> cb)
{
    const char* k_safe = "{\"recommendStatus\":0}";
    auto* a = as_agent(agent);
    if (!a || !cb) {
        if (cb) cb(k_safe);
        return BAMBU_NETWORK_SUCCESS;
    }
    auto s = a->user_session_snapshot();
    if (s.access_token.empty()) {
        cb(k_safe);
        return BAMBU_NETWORK_SUCCESS;
    }

    const std::string url = obn::cloud::api_host(a->cloud_region())
        + "/v1/design-user-service/my/preference";
    auto resp = obn::http::get_json(url, a->cloud_api_http_headers());
    if (!resp.error.empty() || resp.status_code != 200 || resp.body.empty()) {
        OBN_WARN("get_mw_user_preference: HTTP %ld — using safe stub",
                 resp.status_code);
        cb(k_safe);
        return BAMBU_NETWORK_SUCCESS;
    }
    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root || !root->find("recommendStatus").is_number()) {
        OBN_WARN("get_mw_user_preference: missing recommendStatus — stub");
        cb(k_safe);
        return BAMBU_NETWORK_SUCCESS;
    }
    cb(resp.body);
    return BAMBU_NETWORK_SUCCESS;
}

// Stock: GET /v1/design-service/my/design/recommend?seed=&limit=
// Response {hits, seed, surplus}; Studio injects command before postMessage.
OBN_ABI int bambu_network_get_mw_user_4ulist(void* agent,
                                             int seed, int limit,
                                             std::function<void(std::string)> cb)
{
    const char* k_empty = "{\"hits\":[],\"seed\":0,\"surplus\":0}";
    auto* a = as_agent(agent);
    if (!a || !cb) {
        if (cb) cb(k_empty);
        return BAMBU_NETWORK_SUCCESS;
    }
    auto s = a->user_session_snapshot();
    if (s.access_token.empty()) {
        cb(k_empty);
        return BAMBU_NETWORK_SUCCESS;
    }
    if (limit <= 0) limit = 10;

    const std::string url = obn::cloud::api_host(a->cloud_region())
        + "/v1/design-service/my/design/recommend?seed="
        + std::to_string(seed) + "&limit=" + std::to_string(limit);
    auto resp = obn::http::get_json(url, a->cloud_api_http_headers());
    if (!resp.error.empty() || resp.status_code != 200 || resp.body.empty()) {
        OBN_WARN("get_mw_user_4ulist: HTTP %ld — empty list",
                 resp.status_code);
        cb(k_empty);
        return BAMBU_NETWORK_SUCCESS;
    }
    cb(resp.body);
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
