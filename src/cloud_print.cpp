// Cloud print pipeline (start_print / start_local_print_with_record).
//
// Shared cloud bookkeeping for both ABI entry points, then a delivery
// fork that intentionally diverges from current stock hybrid behaviour
// (stock uploads the main .3mf to S3 even on "LAN+record" and the
// printer re-downloads it — see NETWORK_PLUGIN.md §6.8.1.2):
//
//   [A]  POST   /v1/iot-service/api/user/project
//   [B]  PUT    <presigned>                                       config 3mf
//   [C]  PUT    /v1/iot-service/api/user/notification
//   [D]  GET    /v1/iot-service/api/user/notification?action=upload&ticket=..
//
//   use_lan_channel=true  (_with_record):
//   [E]  FTPS STOR main .3mf to printer (PrintParams.ftp_folder)
//   [F]  PATCH  /v1/iot-service/api/user/project/<pid>            url=ftp://...
//   [G]  POST   /v1/user-service/my/task                          mode=lan_file
//
//   use_lan_channel=false (start_print):
//   [E]  GET    /v1/iot-service/api/user/upload?models=...
//   [F]  PUT    <presigned>                                       main 3mf
//   [G]  PATCH  /v1/iot-service/api/user/project/<pid>            url=S3
//   [H]  POST   /v1/user-service/my/task                          mode=cloud_file
//
// Config upload [B]/[D] is required for Print History thumbnails.
// Print start is cloud /my/task dispatch — the plugin does not publish
// MQTT project_file (would double-fire). On LAN failure the plugin
// returns < 0 so Studio can fall back to start_print.

#include "obn/agent.hpp"

#include "obn/bambu_networking.hpp"
#include "obn/signing.hpp"
#include "obn/cloud_auth.hpp"
#include "obn/config.hpp"
#include "obn/http_client.hpp"
#include "obn/identity_headers.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"
#include "obn/print_job.hpp"
#include "obn/print_params_ftp_prefs.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

namespace obn {

namespace {

// Compact JSON array escape helper reused from the LAN path.
std::string json_escape(const std::string& in)
{
    return obn::json::escape(in);
}

// Redacts a presigned URL for logging: keeps scheme://host/path and the
// query-parameter *names* (so we can tell a SigV4 PUT-presign apart from a
// GET-presign, spot an expiry, etc.) but drops every query *value* — the
// AWS signature and any embedded token must never hit the log. A trailing
// "?<k1>=…&<k2>=…" summary is appended so the shape stays diagnosable.
std::string redact_url(const std::string& url)
{
    const auto q = url.find('?');
    if (q == std::string::npos) return url;
    std::string out = url.substr(0, q);
    out += " ?[";
    std::size_t i = q + 1;
    bool first = true;
    while (i < url.size()) {
        std::size_t amp = url.find('&', i);
        std::size_t end = (amp == std::string::npos) ? url.size() : amp;
        std::size_t eq  = url.find('=', i);
        std::string key = (eq != std::string::npos && eq < end)
                              ? url.substr(i, eq - i)
                              : url.substr(i, end - i);
        if (!first) out += ',';
        out += key;
        first = false;
        if (amp == std::string::npos) break;
        i = amp + 1;
    }
    out += ']';
    return out;
}

// Reads the whole file into memory. The print-ready 3mf is typically
// a few MB up to ~100 MB; config 3mf is always <200KB. We keep a
// single buffer in memory for both because libcurl's PUT path wants
// the data in one shot (CURLOPT_POSTFIELDS). If we ever need to
// stream multi-GB uploads, the right fix is a read-callback variant
// of obn::http::Request, not chunking here.
std::string slurp_file(const std::string& path, std::string* err)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        if (err) *err = "open failed";
        return {};
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    if (!ifs && !ifs.eof()) {
        if (err) *err = "read failed";
        return {};
    }
    return oss.str();
}

// AMS mapping helpers. Studio hands us the mapping as a JSON array
// string in params.ams_mapping ("[0,-1,-1,-1]") and richer info in
// params.ams_mapping2 / ams_mapping_info. We pass them through
// verbatim when they look like valid JSON; otherwise fall back to
// a conservative empty mapping.

std::string trim(std::string s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' ||
                          s.front() == '\r' || s.front() == '\n'))
        s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' ||
                          s.back() == '\r' || s.back() == '\n'))
        s.pop_back();
    return s;
}

std::string json_or_default(const std::string& raw, const char* fallback)
{
    std::string s = trim(raw);
    if (s.empty()) return fallback;
    // Cheap validator: accept only strings that look like a JSON
    // array/object (first char). json::parse would be stricter but
    // also much slower; the mapping strings come from Studio's own
    // serializer, so a sniff is enough.
    if (s.front() == '[' || s.front() == '{') return s;
    return fallback;
}

// Build a single amsMapping2 element as the server expects it:
// `{"amsId":N,"slotId":M}` (camelCase). The convention observed in
// the MITM dump is:
//   -1   -> amsId=255, slotId=0 (unset / "external spool" sentinel)
//   >=0  -> amsId=i/4, slotId=i%4 (linear index over AMS slot 0..3)
// The external-spool sentinel is `{amsId:255,slotId:0}`, NOT
// `{...,slotId:255}`: a genuine no-AMS /my/task body carries slotId 0
// and the endpoint 400s on the wrong shape (cross-validated in #48).
std::string ams_slot_pair(int ams_id, int slot_id)
{
    return "{\"amsId\":" + std::to_string(ams_id) +
           ",\"slotId\":" + std::to_string(slot_id) + "}";
}

// Produce the amsMapping2 JSON array for /my/task.
//
// Studio *does* hand us a p.ams_mapping2 string, but it's serialized
// with snake_case keys (`ams_id`, `slot_id`) as used by the printer's
// internal MQTT schema. The cloud `/my/task` endpoint only accepts
// camelCase (`amsId`, `slotId`) and 400s with
// `field "amsMapping2[0].amsId" is not set` otherwise.
//
// We therefore parse Studio's JSON ourselves and re-serialize into the
// camelCase shape. If that fails or Studio gave us nothing usable, we
// fall back to deriving the mapping from the flat p.ams_mapping array
// (`[0,-1,2,-1]`).
std::string ams_mapping2_for_cloud(const BBL::PrintParams& p)
{
    auto derived_from_flat = [&]() {
        auto root = obn::json::parse(p.ams_mapping);
        if (!root || !root->is_array()) return std::string("[]");
        std::string out = "[";
        bool first = true;
        for (const auto& v : root->as_array()) {
            if (!v.is_number()) continue;
            int idx = static_cast<int>(v.as_number());
            int ams_id, slot_id;
            if (idx < 0) { ams_id = 255; slot_id = 0; }
            else         { ams_id = idx / 4; slot_id = idx % 4; }
            if (!first) out.push_back(',');
            first = false;
            out += ams_slot_pair(ams_id, slot_id);
        }
        out.push_back(']');
        return out;
    };

    std::string raw = trim(p.ams_mapping2);
    if (raw.empty() || raw == "[]") return derived_from_flat();

    auto root = obn::json::parse(raw);
    if (!root || !root->is_array()) return derived_from_flat();

    std::string out = "[";
    bool first = true;
    for (const auto& item : root->as_array()) {
        // Accept either schema. Prefer camelCase if present (future-
        // proof against Studio catching up), otherwise snake_case.
        auto ams_v  = item.find("amsId");
        if (!ams_v.is_number())  ams_v  = item.find("ams_id");
        auto slot_v = item.find("slotId");
        if (!slot_v.is_number()) slot_v = item.find("slot_id");
        int ams_id  = ams_v.is_number()  ? static_cast<int>(ams_v.as_number())  : 255;
        // Missing slot defaults to 0 to match the external-spool sentinel
        // {amsId:255,slotId:0} (see ams_slot_pair note; #48).
        int slot_id = slot_v.is_number() ? static_cast<int>(slot_v.as_number()) : 0;
        if (!first) out.push_back(',');
        first = false;
        out += ams_slot_pair(ams_id, slot_id);
    }
    out.push_back(']');
    return out;
}

std::string to_bool(bool v) { return v ? "true" : "false"; }

// ---------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------

// Full stock X-BBL identity block for the print-pipeline endpoints. Delegates
// to the shared helper so the header set, values, casing and wire order match
// the closed-source plugin exactly (Cloudflare fingerprints the request). POST
// /my/task enforces two by VALUE: X-BBL-Client-Name (must be "BambuStudio" to
// reach the uploaded content) and X-BBL-OS-Type (must match the uploader's OS).
// identity_headers() defaults the name to "BambuStudio" (overridable via
// config::client_name / BBL_CLIENT_NAME) and detects the OS type, so both hold.
// POST /my/task and POST /project require X-BBL-Client-ID; GET stages erase
// Content-Type at the call site.
std::map<std::string, std::string> bbl_headers(const std::string& access_token,
                                               const std::string& user_id)
{
    return obn::bbl::identity_headers(access_token, user_id,
                                      /*include_client_id*/true,
                                      /*with_content_type*/true);
}

bool status_ok(long code) { return code >= 200 && code < 300; }

// Reports a transport or HTTP error through Studio's update_fn and
// stashes the server message where our log scraper can see it.
int fail_stage(BBL::OnUpdateStatusFn update_fn, int code, const std::string& what,
               const obn::http::Response& resp)
{
    std::string detail = what;
    if (!resp.error.empty()) detail += ": " + resp.error;
    else if (resp.status_code != 0)
        detail += ": HTTP " + std::to_string(resp.status_code);
    OBN_ERROR("cloud_print: %s (body=%.2000s)", detail.c_str(), resp.body.c_str());
    if (update_fn) update_fn(BBL::PrintingStageERROR, code, detail);
    return code;
}

// ---------------------------------------------------------------
// Per-step HTTP calls
// ---------------------------------------------------------------

struct ProjectInfo {
    std::string project_id;
    std::string model_id;
    std::string profile_id;
    std::string upload_url;     // presigned S3 PUT for the config 3mf (step B)
    std::string upload_ticket;  // fed back into the notification endpoint
};

int create_project(const std::string& api, const std::string& token,
                   const std::string& user_id,
                   const std::string& name, ProjectInfo* out,
                   BBL::OnUpdateStatusFn update_fn)
{
    obn::http::Request req;
    req.method  = obn::http::Method::POST;
    req.url     = api + "/v1/iot-service/api/user/project";
    req.headers = bbl_headers(token, user_id);
    req.body    = std::string("{\"name\":") + json_escape(name) + "}";
    req.timeout_s = 30;

    auto resp = obn::http::perform(req);
    if (!resp.error.empty() || !status_ok(resp.status_code))
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_REQUEST_PROJECT_ID_FAILED,
                          "create_project", resp);

    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root) {
        OBN_ERROR("cloud_print: create_project bad JSON: %s (body=%s)",
                  perr.c_str(), resp.body.c_str());
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_PRINT_WR_REQUEST_PROJECT_ID_FAILED,
                                 "bad JSON");
        return BAMBU_NETWORK_ERR_PRINT_WR_REQUEST_PROJECT_ID_FAILED;
    }
    out->project_id    = root->find("project_id").as_string();
    out->model_id      = root->find("model_id").as_string();
    out->profile_id    = root->find("profile_id").as_string();
    out->upload_url    = root->find("upload_url").as_string();
    out->upload_ticket = root->find("upload_ticket").as_string();

    if (out->project_id.empty() || out->upload_url.empty()) {
        OBN_ERROR("cloud_print: create_project missing fields: body=%s",
                  resp.body.c_str());
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_PRINT_WR_REQUEST_PROJECT_ID_FAILED,
                                 "missing fields");
        return BAMBU_NETWORK_ERR_PRINT_WR_REQUEST_PROJECT_ID_FAILED;
    }
    OBN_INFO("cloud_print: project pid=%s mid=%s prof=%s",
             out->project_id.c_str(), out->model_id.c_str(), out->profile_id.c_str());
    OBN_DEBUG("cloud_print: config upload_url=%s", redact_url(out->upload_url).c_str());
    return 0;
}

// PUT bytes to a presigned S3 URL. Amazon's signature covers only the
// method + resource + expiry + AWS key; query-string presigned URLs
// are forgiving of extra headers, which is why the original plugin
// blithely sends its X-BBL-* set on them too. We mimic that.
int s3_put(const std::string& url, const std::string& body,
           BBL::OnUpdateStatusFn update_fn,
           BBL::WasCancelledFn   cancel_fn,
           int                   stage_start_pct,
           int                   stage_end_pct,
           int                   err_code)
{
    (void)cancel_fn; // libcurl synchronous path: we observe cancel on the
                     // next major step boundary.
    obn::http::Request req;
    req.method  = obn::http::Method::PUT;
    req.url     = url;
    // The Bambu cloud presigner returns an S3 signature-V2 query-auth URL
    // (`?AWSAccessKeyId=…&Expires=…&Signature=…`), confirmed on-wire
    // against genuine POST /user/project traffic (us-west-2, 2026-07).
    // NOT SigV4 — there is no X-Amz-Algorithm / X-Amz-Signature. The V2
    // StringToSign covers Content-Type, and the presigner signs with an
    // empty one, so we MUST send the PUT without a Content-Type or the
    // signature will not match. Two catches:
    //   * libcurl, when doing a PUT via CUSTOMREQUEST+POSTFIELDS, silently
    //     injects `Content-Type: application/x-www-form-urlencoded`. The
    //     idiomatic way to tell libcurl to drop a header is to append
    //     the header name followed by a colon and NO value.
    //   * libcurl also auto-adds `Expect: 100-continue` for bodies > 1 KiB;
    //     Studio's original plugin omits it, so we do the same.
    req.no_default_content_type = true; // don't add our own application/json
    req.no_default_accept       = true; // don't add our own Accept: application/json
    req.headers["Content-Type"] = "";   // REMOVE libcurl's auto Content-Type
    req.headers["Expect"]       = "";   // REMOVE libcurl's auto Expect: 100-continue
    req.body      = body;
    req.timeout_s = 120;

    if (update_fn && stage_start_pct >= 0)
        update_fn(BBL::PrintingStageUpload, stage_start_pct,
                  std::to_string(stage_start_pct) + "%");

    auto resp = obn::http::perform(req);
    if (!resp.error.empty() || !status_ok(resp.status_code))
        return fail_stage(update_fn, err_code, "s3 PUT", resp);

    OBN_DEBUG("cloud_print: s3 PUT ok http=%ld bytes=%zu url=%s",
              resp.status_code, body.size(), redact_url(url).c_str());

    if (update_fn && stage_end_pct >= 0)
        update_fn(BBL::PrintingStageUpload, stage_end_pct,
                  std::to_string(stage_end_pct) + "%");
    return 0;
}

int notify_upload(const std::string& api, const std::string& token,
                  const std::string& user_id,
                  const std::string& ticket, const std::string& origin_name,
                  BBL::OnUpdateStatusFn update_fn)
{
    obn::http::Request req;
    req.method  = obn::http::Method::PUT;
    req.url     = api + "/v1/iot-service/api/user/notification";
    req.headers = bbl_headers(token, user_id);
    std::ostringstream os;
    os << "{\"upload\":{\"origin_file_name\":" << json_escape(origin_name)
       << ",\"ticket\":" << json_escape(ticket) << "}}";
    req.body    = os.str();
    req.timeout_s = 30;
    auto resp = obn::http::perform(req);
    if (!resp.error.empty() || !status_ok(resp.status_code))
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_PUT_NOTIFICATION_FAILED,
                          "notify_upload", resp);
    return 0;
}

// Polls /notification?action=upload until the async upload settles.
// HTTP is always 200; the body is {"message":"running"|"success", ...}.
// Keep polling while message=="running"; "success" ends the wait. Any
// other message is a hard failure.
int poll_upload(const std::string& api, const std::string& token,
                const std::string& user_id,
                const std::string& ticket,
                BBL::OnUpdateStatusFn update_fn,
                BBL::WasCancelledFn cancel_fn)
{
    std::map<std::string, std::string> hdrs = bbl_headers(token, user_id);
    hdrs.erase("Content-Type"); // GET
    const std::string url = api
        + "/v1/iot-service/api/user/notification?action=upload&ticket="
        + obn::http::url_encode(ticket);

    for (int attempt = 0; attempt < 20; ++attempt) {
        if (cancel_fn && cancel_fn()) return BAMBU_NETWORK_ERR_CANCELED;
        auto resp = obn::http::get_json(url, hdrs);
        if (!resp.error.empty() || !status_ok(resp.status_code)) {
            OBN_DEBUG("cloud_print: poll_upload attempt=%d status=%ld err=%s",
                      attempt, resp.status_code, resp.error.c_str());
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        auto root = obn::json::parse(resp.body);
        const std::string msg = root ? root->find("message").as_string()
                                     : std::string{};
        if (msg == "running") {
            OBN_DEBUG("cloud_print: poll_upload running attempt=%d", attempt);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }
        if (msg == "success") {
            OBN_DEBUG("cloud_print: poll_upload OK attempt=%d", attempt);
            return 0;
        }
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_GET_NOTIFICATION_FAILED,
                          "poll_upload", resp);
    }
    if (update_fn) update_fn(BBL::PrintingStageERROR,
                             BAMBU_NETWORK_ERR_PRINT_WR_GET_NOTIFICATION_TIMEOUT,
                             "upload poll timeout");
    return BAMBU_NETWORK_ERR_PRINT_WR_GET_NOTIFICATION_TIMEOUT;
}

// PATCH /project/<pid> with the profile_print_3mf descriptor that
// points at where the print-ready 3mf now lives. Studio issues this
// twice - once with a throw-away ftp:// placeholder before the real
// OSS upload, once more with the real URL afterwards. We copy that
// pattern because the server-side state machine seems to care about
// the first call being present.
int patch_project(const std::string& api, const std::string& token,
                  const std::string& user_id,
                  const std::string& project_id,
                  const std::string& profile_id,
                  const std::string& md5, int plate_idx,
                  const std::string& url,
                  BBL::OnUpdateStatusFn update_fn)
{
    obn::http::Request req;
    req.method    = obn::http::Method::PATCH;
    req.url       = api + "/v1/iot-service/api/user/project/" + project_id;
    req.headers   = bbl_headers(token, user_id);
    req.timeout_s = 30;
    std::ostringstream os;
    os << "{\"profile_id\":" << json_escape(profile_id)
       << ",\"profile_print_3mf\":[{"
       << "\"md5\":" << json_escape(md5)
       << ",\"plate_idx\":" << (plate_idx <= 0 ? 1 : plate_idx)
       << ",\"url\":" << json_escape(url)
       << "}]}";
    req.body = os.str();

    auto resp = obn::http::perform(req);
    if (!resp.error.empty() || !status_ok(resp.status_code))
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_PATCH_PROJECT_FAILED,
                          "patch_project", resp);
    return 0;
}

int get_upload_url(const std::string& api, const std::string& token,
                   const std::string& user_id,
                   const std::string& model_slot,
                   std::string* out_url,
                   BBL::OnUpdateStatusFn update_fn)
{
    std::map<std::string, std::string> hdrs = bbl_headers(token, user_id);
    hdrs.erase("Content-Type"); // GET
    std::string url = api + "/v1/iot-service/api/user/upload?models="
                    + obn::http::url_encode(model_slot);
    auto resp = obn::http::get_json(url, hdrs);
    if (!resp.error.empty() || !status_ok(resp.status_code))
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_GET_USER_UPLOAD_FAILED,
                          "get_upload_url", resp);
    // Raw body holds only presigned URLs + object keys (no account secrets);
    // kept at DEBUG for diagnosing endpoint shape changes.
    OBN_DEBUG("cloud_print: get_upload_url raw body=%s", resp.body.c_str());
    auto root = obn::json::parse(resp.body);
    if (!root) return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_GET_USER_UPLOAD_FAILED,
                                 "bad get_upload_url JSON", resp);
    auto arr_v = root->find("urls");
    const auto& arr = arr_v.as_array();
    if (arr.empty())
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_GET_USER_UPLOAD_FAILED,
                          "get_upload_url empty", resp);
    auto url_v = arr.front().find("url");
    *out_url = url_v.as_string();
    if (out_url->empty())
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_GET_USER_UPLOAD_FAILED,
                          "get_upload_url missing url", resp);
    OBN_DEBUG("cloud_print: get_upload_url -> %s", redact_url(*out_url).c_str());
    return 0;
}

// Studio fetches the user's cloud print settings mid-pipeline (after the
// first project PATCH, before the second presigned URL). The response tunes
// client-side print prefs; we fetch it for wire parity and ignore the body 
// -- a failur is non-fatal to the print.
void fetch_my_setting(const std::string& api, const std::string& token,
                      const std::string& user_id)
{
    auto hdrs = bbl_headers(token, user_id);   // CID + Content-Type retained
    auto resp = obn::http::get_json(api + "/v1/user-service/my/setting", hdrs);
    OBN_DEBUG("cloud_print: GET /my/setting http=%ld", resp.status_code);
}

// The body of POST /my/task is the single biggest surface we have to
// mimic from Studio. The MITM baseline is ~30 fields; most of them
// map 1:1 to PrintParams. Anything we can't sensibly provide (custom
// filament mappings from MakerWorld, nozzle_info for multi-nozzle
// printers) we default to an empty array, which the server accepts.
std::string build_task_body(const BBL::PrintParams& p,
                            const std::string& project_id,
                            const std::string& model_id,
                            const std::string& profile_id,
                            bool use_lan_channel)
{
    (void)project_id;
    std::ostringstream os;
    os << "{";
    os << "\"amsDetailMapping\":"
       << json_or_default(p.ams_mapping_info, "[]");
    os << ",\"amsMapping\":"  << json_or_default(p.ams_mapping, "[-1]");
    os << ",\"amsMapping2\":" << ams_mapping2_for_cloud(p);
    if (!p.nozzle_mapping.empty()) {
        os << ",\"nozzleMapping\":" << p.nozzle_mapping;
    }
    os << ",\"autoBedLeveling\":"     << p.auto_bed_leveling;
    os << ",\"bedLeveling\":"         << to_bool(p.task_bed_leveling);
    os << ",\"bedType\":" << json_escape(p.task_bed_type.empty()
                                         ? std::string{"auto"} : p.task_bed_type);

    int cfg_bits = 0;
    #if ABI_VERSION >= 0x020503
        if (p.task_timelapse_use_internal &&
            !obn::config::current().force_timelapse_external)
            cfg_bits |= 4;
    #endif
    os << ",\"cfg\":\"" << cfg_bits << "\"";
    os << ",\"cover\":\"\""; // TODO: investigate 
    os << ",\"deviceId\":"     << json_escape(p.dev_id);
    os << ",\"extrudeCaliFlag\":"         << p.auto_flow_cali;
    #if ABI_VERSION >= 0x020400
        os << ",\"extrudeCaliManualMode\":"   << p.extruder_cali_manual_mode;
    #endif
    os << ",\"filamentSettingIds\":[]"; // TODO: investigate 
    os << ",\"flowCali\":"            << to_bool(p.task_flow_cali);
    os << ",\"layerInspect\":"        << to_bool(p.task_layer_inspect);
    os << ",\"mode\":"
       << (use_lan_channel ? std::string{"\"lan_file\""}
                           : std::string{"\"cloud_file\""});
    os << ",\"modelId\":"     << json_escape(model_id);
    os << ",\"nozzleInfos\":" << json_or_default(p.nozzles_info, "[]");
    os << ",\"nozzleOffsetCali\":"    << p.auto_offset_cali;
    os << ",\"oriModelId\":"  << json_escape(p.origin_model_id);
    os << ",\"oriProfileId\":" << p.origin_profile_id;
    os << ",\"plateIndex\":"  << (p.plate_index <= 0 ? 1 : p.plate_index);
    // profileId must be a number in the MITM baseline.
    os << ",\"profileId\":"   << (profile_id.empty() ? std::string{"0"} : profile_id);
    os << ",\"sequence_id\":\"20000\""; // TODO: is it always 20000?
    os << ",\"timelapse\":"   << to_bool(p.task_record_timelapse);
    os << ",\"title\":"       << json_escape(p.project_name.empty()
                                             ? p.task_name : p.project_name);
    os << ",\"useAms\":"      << to_bool(p.task_use_ams);
    os << ",\"vibrationCali\":" << to_bool(p.task_vibration_cali);
    os << "}";
    return os.str();
}

int create_task(const std::string& api, const std::string& token,
                const std::string& user_id,
                const std::string& body, std::string* out_task_id,
                BBL::OnUpdateStatusFn update_fn)
{
    // MakerWorld's /my/task endpoint is picky about amsMapping2 /
    // amsDetailMapping field shape; log the full body so we can diff
    // against the MITM dump when it 400s.
    OBN_DEBUG("cloud_print: create_task body=%s", body.c_str());
    obn::http::Request req;
    req.method  = obn::http::Method::POST;
    req.url     = api + "/v1/user-service/my/task";
    auto hdrs = bbl_headers(token, user_id);
    OBN_DEBUG("cloud_print: create_task hdr X-BBL-Client-Name=%s X-BBL-OS-Type=%s "
              "(config client_name=%s) uid=%s",
              hdrs["X-BBL-Client-Name"].c_str(), hdrs["X-BBL-OS-Type"].c_str(),
              obn::config::current().client_name.c_str(), user_id.c_str());
    // Signing headers are best-effort: when no slicer key/cert is configured
    // these come back empty, and we omit them rather than send blanks. The
    // cloud verifies x-bbl-device-security-sign by recovering a recent
    // timestamp from the signature (current time in ms, raw PKCS#1 v1.5, not
    // the body); it is only enforced on signed writes.
    // The HTTP header uses `issuer:serial.lower()`, a DIFFERENT serialization
    // from the MQTT envelope cert_id (`serial+issuer`). Sending the MQTT form
    // here gets the write rejected with 403.
    const std::string cert_id  = obn::signing::app_certification_id();
    const std::string sec_sign = obn::signing::device_security_sign();
    OBN_DEBUG("cloud_print: create_task sign hdrs cert_id='%s' (len=%zu) "
              "sec_sign_len=%zu",
              cert_id.c_str(), cert_id.size(), sec_sign.size());
    if (!cert_id.empty())  hdrs["x-bbl-app-certification-id"] = cert_id;
    if (!sec_sign.empty()) hdrs["x-bbl-device-security-sign"] = sec_sign;
    req.headers   = std::move(hdrs);
    req.body      = body;
    req.timeout_s = 60;

    auto resp = obn::http::perform(req);

    // Hard-fail on any transport error or non-2xx: POST /my/task registers the
    // print with MakerWorld and, for cloud prints, is what actually authorizes
    // the printer to fetch the uploaded content. Swallowing its failure led to
    // silent breakage (the job would proceed with task_id=0 and then stall on
    // the printer with "failed to download"), so surface it instead.
    // The most common cause of a 403 here is X-BBL-Client-Name != "BambuStudio"
    // (see config::client_name) or an X-BBL-OS-Type / uploader-OS mismatch.
    // Note: this path is only reached for cloud prints (bambu_network_start_print)
    // and "local print with record" (start_local_print_with_record); block_cloud
    // stops run_cloud_print_job before we ever get here, and pure LAN printing
    // (start_local_print -> run_local_print_job) never calls /my/task.
    if (!resp.error.empty() || resp.status_code < 200 || resp.status_code >= 300)
        return fail_stage(update_fn, BAMBU_NETWORK_ERR_PRINT_WR_POST_TASK_FAILED,
                          "create_task", resp);

    auto root = obn::json::parse(resp.body);
    if (!root) {
        OBN_WARN("cloud_print: create_task bad JSON; continuing with task_id=0");
        *out_task_id = "0";
        return 0;
    }
    *out_task_id = root->find("id").as_string();
    if (out_task_id->empty()) {
        // Some builds return id as an integer; json_lite as_string()
        // returns empty for numeric values.
        const auto& rbody = resp.body;
        auto pos = rbody.find("\"id\"");
        if (pos != std::string::npos) {
            pos = rbody.find_first_of("0123456789", pos);
            if (pos != std::string::npos) {
                auto end = rbody.find_first_not_of("0123456789", pos);
                *out_task_id = rbody.substr(pos, end == std::string::npos
                                                 ? std::string::npos
                                                 : end - pos);
            }
        }
    }
    if (out_task_id->empty()) {
        OBN_WARN("cloud_print: create_task missing task_id; continuing with task_id=0");
        *out_task_id = "0";
    }
    OBN_INFO("cloud_print: task_id=%s", out_task_id->c_str());
    return 0;
}

} // namespace

#ifdef OBN_TESTING
// Thin wrappers that give anonymous-namespace functions external linkage
// so cloud_print_test can exercise them without extracting them.
namespace cloud_print {
std::string test_ams_mapping2(const BBL::PrintParams& p)
    { return ams_mapping2_for_cloud(p); }
std::string test_build_task_body(const BBL::PrintParams& p,
                                 const std::string& project_id,
                                 const std::string& model_id,
                                 const std::string& profile_id,
                                 bool use_lan_channel)
    { return build_task_body(p, project_id, model_id, profile_id, use_lan_channel); }
} // namespace cloud_print
#endif

int Agent::run_cloud_print_job(const BBL::PrintParams& p,
                               BBL::OnUpdateStatusFn   update_fn,
                               BBL::WasCancelledFn     cancel_fn,
                               bool                    use_lan_channel)
{
    OBN_INFO("cloud_print dev=%s ip=%s plate=%d file=%s config=%s project=%s chan=%s",
             p.dev_id.c_str(), p.dev_ip.c_str(), p.plate_index,
             p.filename.c_str(), p.config_filename.c_str(),
             p.project_name.c_str(),
             use_lan_channel ? "lan" : "cloud");

    // Studio's PrintJob::process picks the ABI entry point:
    //   start_local_print_with_record -> use_lan_channel=true
    //   start_print                   -> use_lan_channel=false
    // On LAN failure we return < 0 so Studio can fall back to start_print.

    if (p.filename.empty()) {
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_FILE_NOT_EXIST,
                                 "empty filename");
        return BAMBU_NETWORK_ERR_FILE_NOT_EXIST;
    }

    // Hard stop: never push a print file through Bambu's cloud when the
    // user has opted out. Studio normally avoids this path because the
    // printer is never marked cloud-online under block_cloud, but a future
    // Studio update or unexpected dispatch must not be able to upload to
    // S3 behind the user's back. See issue #41.
    if (obn::config::current().block_cloud) {
        OBN_WARN("run_cloud_print_job: blocked by block_cloud");
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_INVALID_HANDLE,
                                 "cloud print blocked by config");
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }

    auto session = user_session_snapshot();
    if (session.access_token.empty() || session.user_id.empty()) {
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_INVALID_HANDLE,
                                 "not logged in");
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }
    const std::string api   = obn::cloud::api_host(cloud_region());
    const std::string token = session.access_token;
    const std::string uid   = session.user_id;

    if (update_fn) update_fn(BBL::PrintingStageCreate, 0, "");
    if (cancel_fn && cancel_fn()) return BAMBU_NETWORK_ERR_CANCELED;

    // -------------------------------------------------------------
    // [A] Create the cloud project and get the first presigned URL
    // -------------------------------------------------------------
    std::string project_name = p.project_name.empty() ? p.task_name : p.project_name;
    if (project_name.empty()) project_name = "untitled";
    ProjectInfo info{};
    if (int rc = create_project(api, token, uid, project_name, &info, update_fn);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [B] Upload the config 3mf (small). Required for Print History
    // thumbnails even when the main model is delivered over FTPS.
    // -------------------------------------------------------------
    std::string config_path = p.config_filename;
    if (p.config_filename.empty()) {
        OBN_WARN("cloud_print: config_filename is empty, uploading the main file (%s) instead",
                 p.filename.c_str());
        config_path = p.filename;
    }
    std::string slurp_err;
    std::string config_bytes = slurp_file(config_path, &slurp_err);
    if (config_bytes.empty()) {
        OBN_ERROR("cloud_print: config read %s: %s",
                  config_path.c_str(), slurp_err.c_str());
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_FILE_NOT_EXIST,
                                 "config_filename not readable");
        return BAMBU_NETWORK_ERR_FILE_NOT_EXIST;
    }
    OBN_INFO("cloud_print: uploading config %s to S3", config_path.c_str());
    if (int rc = s3_put(info.upload_url, config_bytes, update_fn, cancel_fn,
                        /*stage_start_pct=*/0, /*stage_end_pct=*/10,
                        BAMBU_NETWORK_ERR_PRINT_WR_UPLOAD_3MF_CONFIG_TO_OSS_FAILED);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [C/D] Notify + poll.
    // -------------------------------------------------------------
    std::string origin_cfg = std::filesystem::path(config_path).filename().string();
    if (int rc = notify_upload(api, token, uid, info.upload_ticket,
                               origin_cfg, update_fn);
        rc != 0) return rc;
    if (int rc = poll_upload(api, token, uid, info.upload_ticket,
                             update_fn, cancel_fn);
        rc != 0) return rc;

    std::string remote_name = print_job::pick_remote_name(p);
    std::string md5         = p.ftp_file_md5;
    // Schema placeholder when Studio left ftp_file_md5 empty.
    if (md5.empty()) md5 = "00000000000000000000000000000000"; // TODO: compute real md5

    std::string project_url; // ftp://… or S3 https — registered via PATCH

    // Stock plugin fetches user print settings here, before the upload
    // branch. Wire-parity only; response is unused and a failure is
    // non-fatal.
    fetch_my_setting(api, token, uid);

    if (use_lan_channel) {
        // ---------------------------------------------------------
        // LAN delivery: FTPS STOR + PATCH ftp:// (no main S3 upload).
        // ---------------------------------------------------------
        if (p.dev_ip.empty() || p.password.empty()) {
            OBN_ERROR("cloud_print: lan channel requested but no dev_ip/access_code");
            if (update_fn) update_fn(BBL::PrintingStageERROR,
                                     BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED,
                                     "no dev_ip/access_code for LAN print");
            return BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED;
        }

        // Peer pin for FTPS TLS hostname verify when no prior connect_printer.
        publish_peer_cert_pin(p.dev_ip, p.dev_id);

        std::string lan_remote_path =
            print_job::build_ftp_remote_path(p, remote_name);
        OBN_INFO("cloud_print: upload path=ftps :990 remote=%s ftp_folder='%s'",
                 lan_remote_path.c_str(), p.ftp_folder.c_str());

        print_params_set_use_ssl_for_ftp(p.use_ssl_for_ftp);

        std::uint64_t total = 0;
        std::string ca_file = bambu_ca_bundle_path();
        std::string stored_path;
        if (int rc = print_job::ftp_upload(p, lan_remote_path, ca_file,
                                           update_fn, cancel_fn,
                                           BAMBU_NETWORK_ERR_PRINT_LP_UPLOAD_FTP_FAILED,
                                           total, &stored_path);
            rc != 0) return rc;
        if (!stored_path.empty()) lan_remote_path = stored_path;
        project_url = print_job::build_ftp_url(lan_remote_path);
        OBN_INFO("cloud_print: lan-ftps uploaded %llu bytes to %s (url=%s)",
                 static_cast<unsigned long long>(total),
                 lan_remote_path.c_str(), project_url.c_str());

        if (int rc = patch_project(api, token, uid, info.project_id, info.profile_id,
                                   md5, p.plate_index, project_url, update_fn);
            rc != 0) return rc;
    } else {
        // ---------------------------------------------------------
        // Cloud delivery: main .3mf to S3 + PATCH S3 URL.
        // ---------------------------------------------------------
        std::string main_upload_url;
        std::string plate_tag =
            std::to_string(p.plate_index <= 0 ? 1 : p.plate_index);
        std::string model_slot =
            info.model_id + "_" + info.profile_id + "_" + plate_tag + ".3mf";
        if (int rc = get_upload_url(api, token, uid, model_slot,
                                    &main_upload_url, update_fn);
            rc != 0) return rc;

        std::string main_bytes = slurp_file(p.filename, &slurp_err);
        if (main_bytes.empty()) {
            OBN_ERROR("cloud_print: main read %s: %s",
                      p.filename.c_str(), slurp_err.c_str());
            if (update_fn) update_fn(BBL::PrintingStageERROR,
                                    BAMBU_NETWORK_ERR_FILE_NOT_EXIST,
                                    "filename not readable");
            return BAMBU_NETWORK_ERR_FILE_NOT_EXIST;
        }
        if (int rc = s3_put(main_upload_url, main_bytes, update_fn, cancel_fn,
                            /*stage_start_pct=*/10, /*stage_end_pct=*/95,
                            BAMBU_NETWORK_ERR_PRINT_WR_UPLOAD_3MF_TO_OSS_FAILED);
            rc != 0) return rc;

        project_url = main_upload_url;
        if (int rc = patch_project(api, token, uid, info.project_id, info.profile_id,
                                   md5, p.plate_index, project_url, update_fn);
            rc != 0) return rc;
    }

    // -------------------------------------------------------------
    // POST /my/task — cloud dispatches the print (no plugin MQTT).
    // -------------------------------------------------------------
    if (update_fn) update_fn(BBL::PrintingStageSending, 0, "");

    std::string task_body = build_task_body(p, info.project_id, info.model_id,
                                            info.profile_id, use_lan_channel);
    std::string task_id;
    if (int rc = create_task(api, token, uid, task_body, &task_id, update_fn);
        rc != 0) return rc;

    if (update_fn) update_fn(BBL::PrintingStageFinished, 0, "3");
    OBN_INFO("cloud_print dev=%s: queued (project=%s task=%s delivery=%s url=%s)",
             p.dev_id.c_str(), info.project_id.c_str(), task_id.c_str(),
             use_lan_channel ? "ftps" : "s3",
             use_lan_channel ? project_url.c_str()
                             : redact_url(project_url).c_str());
    return 0;
}

} // namespace obn
