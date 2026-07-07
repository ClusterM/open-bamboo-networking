// Cloud print pipeline.
//
// Reverse-engineered from a MITM capture of Studio 02.05.02.51 + the
// original closed-source Bambu plugin pushing a job through
// "start_local_print_with_record" (which is what Studio picks whenever
// the printer is reachable on the LAN and an access code is known -
// the bare "start_print" path we still share all the HTTP plumbing
// with, only the final delivery channel changes).
//
// End-to-end sequence for a single plate:
//
//   [A]  POST   /v1/iot-service/api/user/project                body {"name":"<job>"}
//        -> { project_id, model_id, profile_id, upload_url,
//             upload_ticket }                                     << [A1]
//   [B]  PUT    <upload_url from A1>                              config 3mf
//   [C]  PUT    /v1/iot-service/api/user/notification             notify
//   [D]  GET    /v1/iot-service/api/user/notification?action=upload&ticket=..
//   [E]  PATCH  /v1/iot-service/api/user/project/<pid>            {"profile_id","profile_print_3mf":[{..,"url":"ftp://..."}]}
//   [F]  GET    /v1/iot-service/api/user/upload?models=<mid>_<plate>.3mf
//        -> { urls: [{ url }] }                                   << [F1]
//   [G]  PUT    <F1 url>                                          full 3mf with gcode
//   [H]  PATCH  /v1/iot-service/api/user/project/<pid>            register real url
//   [I]  POST   /v1/user-service/my/task                          {..,"mode":"lan_file"/"cloud_file"}
//        -> { id: <task_id> }                                     << [I1]
//   [J]  MQTT publish project_file on the appropriate channel.
//
// In the LAN-channel ("start_local_print_with_record") variant we also
// push the .3mf to the printer (:6000 emmc cache on brtc hardware, else
// FTPS STOR); the cloud record exists for MakerWorld task history.
//
// Anything that needs to be kept in sync with Studio's internal
// format is commented inline rather than factored out, because small
// field-name drifts here break the flow silently (the printer either
// refuses the MQTT, or the cloud server 500s the create_task call,
// and neither surface a helpful error to the user).

#include "obn/agent.hpp"

#include "obn/bambu_networking.hpp"
#include "obn/cert_store.hpp"
#include "obn/signing.hpp"
#include "obn/cloud_auth.hpp"
#include "obn/config.hpp"
#include "obn/http_client.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"
#include "obn/print_job.hpp"
#include "obn/print_params_ftp_prefs.hpp"
#include "obn/tunnel_upload.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

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

// ---------------------------------------------------------------------------
// RSA field encryption helpers (cloud project_file url_enc / param_enc).
// ---------------------------------------------------------------------------

// Encrypts `plaintext` with RSA-PKCS#1 v1.5 using `pkey`. The caller retains
// ownership of `pkey`. Returns base64-encoded ciphertext, or "" on failure.
static std::string rsa_pkcs1v15_encrypt_b64(EVP_PKEY*          pkey,
                                             const std::string& plaintext,
                                             std::string*       err)
{
    if (!pkey) {
        if (err) *err = "null public key";
        return {};
    }

    EVP_PKEY_CTX* ctx = ::EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        if (err) *err = "EVP_PKEY_CTX_new failed";
        return {};
    }

    bool setup_ok = (::EVP_PKEY_encrypt_init(ctx) > 0) &&
                    (::EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0);
    if (!setup_ok) {
        ::EVP_PKEY_CTX_free(ctx);
        unsigned long ecode = ::ERR_peek_last_error();
        char ebuf[256];
        ::ERR_error_string_n(ecode, ebuf, sizeof(ebuf));
        if (err) *err = std::string("encrypt init/padding failed: ") + ebuf;
        return {};
    }

    const auto* pt    = reinterpret_cast<const unsigned char*>(plaintext.data());
    std::size_t ptlen = plaintext.size();

    std::size_t outlen = 0;
    if (::EVP_PKEY_encrypt(ctx, nullptr, &outlen, pt, ptlen) <= 0) {
        ::EVP_PKEY_CTX_free(ctx);
        unsigned long ecode = ::ERR_peek_last_error();
        char ebuf[256];
        ::ERR_error_string_n(ecode, ebuf, sizeof(ebuf));
        if (err) *err = std::string("EVP_PKEY_encrypt size query failed: ") + ebuf;
        return {};
    }

    std::vector<unsigned char> ct(outlen);
    if (::EVP_PKEY_encrypt(ctx, ct.data(), &outlen, pt, ptlen) <= 0) {
        ::EVP_PKEY_CTX_free(ctx);
        unsigned long ecode = ::ERR_peek_last_error();
        char ebuf[256];
        ::ERR_error_string_n(ecode, ebuf, sizeof(ebuf));
        if (err) *err = std::string("EVP_PKEY_encrypt failed: ") + ebuf;
        return {};
    }
    ::EVP_PKEY_CTX_free(ctx);

    return obn::signing::base64_encode(ct.data(), outlen);
}

// Loads the printer's public key from its PEM certificate on disk.
// Returns a ref-bumped EVP_PKEY* (caller must free), or nullptr on failure.
static EVP_PKEY* load_printer_pub_key_from_pem(const std::string& pem_path)
{
    FILE* f = std::fopen(pem_path.c_str(), "r");
    if (!f) return nullptr;
    X509* cert = ::PEM_read_X509(f, nullptr, nullptr, nullptr);
    std::fclose(f);
    if (!cert) return nullptr;
    EVP_PKEY* pk = ::X509_get_pubkey(cert);
    ::X509_free(cert);
    return pk;
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
//   -1   -> amsId=255, slotId=255 (unset / "external spool" sentinel)
//   >=0  -> amsId=i/4, slotId=i%4 (linear index over AMS slot 0..3)
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
            if (idx < 0) { ams_id = 255; slot_id = 255; }
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
        int slot_id = slot_v.is_number() ? static_cast<int>(slot_v.as_number()) : 255;
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

// Shared X-BBL headers captured from the stock plugin. Cloudflare
// in front of api.bambulab.com is lenient about missing X-BBL
// fields, but a couple of endpoints (notably POST /my/task) can
// reject calls without X-BBL-Client-ID. We always set a client id
// derived from the user id; the rest is cosmetic telemetry.
std::map<std::string, std::string> bbl_headers(const std::string& access_token,
                                               const std::string& user_id)
{
    std::map<std::string, std::string> h;
    h["Authorization"]        = "Bearer " + access_token;
    h["Content-Type"]         = "application/json";
    h["Accept"]               = "application/json";
    h["X-BBL-Client-Name"]    = "OpenBambooNetworking";
    h["X-BBL-Client-Type"]    = "slicer";
    h["X-BBL-OS-Type"]        = "linux";
    h["X-BBL-Agent-OS-Type"]  = "linux";
    h["X-BBL-Language"]       = "en-US";
    h["X-BBL-Executable-info"]= "{}";
    if (!user_id.empty())
        h["X-BBL-Client-ID"] = "slicer:" + user_id + ":obn0";
    return h;
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
    // S3 V2 presigned URLs include Content-Type in the canonical
    // StringToSign. The presigner (bambulab cloud) signs with an empty
    // Content-Type, so we MUST send the request without one. Two catches:
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

// Polls /notification?action=upload until the server acknowledges.
// In our MITM trace the first GET already returns {"message":"success"}
// right away, but the original plugin polls for a few seconds; we mirror
// that with a short retry loop to stay compatible with slower backends.
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
        if (resp.error.empty() && status_ok(resp.status_code)) {
            OBN_DEBUG("cloud_print: poll_upload OK attempt=%d", attempt);
            return 0;
        }
        OBN_DEBUG("cloud_print: poll_upload attempt=%d status=%ld err=%s",
                  attempt, resp.status_code, resp.error.c_str());
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
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
    return 0;
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
        os << ",\"nozzleMapping\":" << p.nozzle_mapping; // TODO: test
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
    os << ",\"cover\":\"\"";
    os << ",\"deviceId\":"     << json_escape(p.dev_id);
    os << ",\"extrudeCaliFlag\":"         << p.auto_flow_cali;
    #if ABI_VERSION >= 0x020400
        os << ",\"extrudeCaliManualMode\":"   << p.extruder_cali_manual_mode;
    #endif
    os << ",\"filamentSettingIds\":[]";
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
    os << ",\"sequence_id\":\"20000\"";
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
    // Signing headers are best-effort: when no slicer key/cert is configured
    // these come back empty, and we omit them rather than send blanks. The
    // cloud verifies x-bbl-device-security-sign by recovering a recent
    // timestamp from the signature (current time in ms, raw PKCS#1 v1.5, not
    // the body); it is only enforced on signed writes.
    const std::string cert_id  = obn::signing::slicer_cert_id();
    const std::string sec_sign = obn::signing::device_security_sign();
    if (!cert_id.empty())  hdrs["x-bbl-app-certification-id"] = cert_id;
    if (!sec_sign.empty()) hdrs["x-bbl-device-security-sign"] = sec_sign;
    req.headers   = std::move(hdrs);
    req.body      = body;
    req.timeout_s = 60;

    auto resp = obn::http::perform(req);

    // Soft-fail: the /my/task endpoint records the print in MakerWorld but is
    // not required for the actual print to start (the printer is triggered by
    // the MQTT project_file command). If the HTTP request fails (network error,
    // non-2xx, missing signing key, etc.) we log and continue with task_id "0".
    if (!resp.error.empty() || resp.status_code < 200 || resp.status_code >= 300) {
        OBN_WARN("cloud_print: create_task soft-fail (http %ld, err=%s); "
                 "continuing with task_id=0",
                 resp.status_code, resp.error.c_str());
        *out_task_id = "0";
        return 0;
    }

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
    // [B] Upload the config 3mf (small). Studio generates it next to
    // the main 3mf; if it's missing we fall back to the main file so
    // we at least have *something* for the archive.
    // -------------------------------------------------------------
    std::string config_path = p.config_filename.empty() ? p.filename : p.config_filename;
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
    // Upload progress for the config file is tiny and confusing in the
    // UI; we report 0% at start and 10% after. The big file (step G)
    // owns 10..95%.
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

    // -------------------------------------------------------------
    // [E] First PATCH - placeholder ftp:// url. Studio always does
    // this before uploading the real 3mf.
    // -------------------------------------------------------------
    std::string remote_name = print_job::pick_remote_name(p);
    std::string ftp_url     = "ftp://" + remote_name;
    std::string md5         = p.ftp_file_md5;
    // The printer will re-compute md5 on download; if Studio didn't
    // give us one, keep the field so the server schema stays happy.
    if (md5.empty()) md5 = "00000000000000000000000000000000";

    if (int rc = patch_project(api, token, uid, info.project_id, info.profile_id,
                               md5, p.plate_index, ftp_url, update_fn);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [F] Get the second presigned URL (for the main 3mf).
    // Studio composes model_slot = "<model_id>_<profile_id>_<plate>.3mf".
    // -------------------------------------------------------------
    std::string plate_tag = std::to_string(p.plate_index <= 0 ? 1 : p.plate_index);
    std::string model_slot = info.model_id + "_" + info.profile_id + "_" + plate_tag + ".3mf";
    std::string main_upload_url;
    if (int rc = get_upload_url(api, token, uid, model_slot, &main_upload_url, update_fn);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [G] Upload the print-ready 3mf (big).
    // -------------------------------------------------------------
    std::string main_bytes = slurp_file(p.filename, &slurp_err);
    if (main_bytes.empty()) {
        OBN_ERROR("cloud_print: main read %s: %s", p.filename.c_str(), slurp_err.c_str());
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_FILE_NOT_EXIST,
                                 "filename not readable");
        return BAMBU_NETWORK_ERR_FILE_NOT_EXIST;
    }
    if (int rc = s3_put(main_upload_url, main_bytes, update_fn, cancel_fn,
                        /*stage_start_pct=*/10, /*stage_end_pct=*/95,
                        BAMBU_NETWORK_ERR_PRINT_WR_UPLOAD_3MF_TO_OSS_FAILED);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [H] Second PATCH with the real URL.
    // -------------------------------------------------------------
    if (int rc = patch_project(api, token, uid, info.project_id, info.profile_id,
                               md5, p.plate_index, main_upload_url, update_fn);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [9/I] LAN-only: upload to printer storage, then POST task with
    // mode=lan_file. Cloud variant skips local upload.
    // -------------------------------------------------------------
    std::string lan_remote_path; // wire path / basename for MQTT
    if (use_lan_channel) {
        if (p.dev_ip.empty() || p.password.empty()) {
            OBN_WARN("cloud_print: lan channel requested but no dev_ip/access_code "
                     "-> degrading to cloud channel");
            use_lan_channel = false;
        } else if (print_job::use_brtc_cache_upload(p)) {
            OBN_INFO("cloud_print: upload path=brtc :6000 (try_emmc_print=%d, force_ftps=%d)",
                     p.try_emmc_print ? 1 : 0,
                     obn::config::current().force_ftps ? 1 : 0);
            obn::tunnel_upload::ConnectParams cp =
                obn::tunnel_upload::connect_params_from_print(
                    p.dev_ip, p.dev_id, p.password);
            obn::tunnel_upload::UploadRequest ureq;
            ureq.local_path   = p.filename;
            ureq.dest_storage = "emmc";
            ureq.dest_name    = remote_name;

            obn::tunnel_upload::UploadCallbacks cb;
            cb.cancelled = [&]() { return cancel_fn && cancel_fn(); };
            cb.progress = [&](int pct) {
                if (update_fn) update_fn(BBL::PrintingStageUpload, pct, "");
            };

            obn::tunnel_upload::UploadOutcome outcome;
            if (int rc = obn::tunnel_upload::upload_file(
                    cp, ureq, cb, &outcome,
                    BAMBU_NETWORK_ERR_PRINT_LP_UPLOAD_FTP_FAILED);
                rc != 0) return rc;
            lan_remote_path = remote_name;
            OBN_INFO("cloud_print: brtc upload %llu bytes to emmc/%s",
                     static_cast<unsigned long long>(outcome.bytes),
                     remote_name.c_str());
        } else {
            OBN_INFO("cloud_print: upload path=ftps :990 (try_emmc_print=%d, force_ftps=%d)",
                     p.try_emmc_print ? 1 : 0,
                     obn::config::current().force_ftps ? 1 : 0);
            std::string folder = p.ftp_folder;
            if (!folder.empty() && folder.back() != '/') folder += '/';
            if (!folder.empty() && folder.front() == '/') folder.erase(0, 1);
            lan_remote_path = "/" + folder + remote_name;

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
            OBN_INFO("cloud_print: lan-ftps uploaded %llu bytes to %s",
                     static_cast<unsigned long long>(total), lan_remote_path.c_str());
        }
    }

    if (update_fn) update_fn(BBL::PrintingStageSending, 0, "");

    std::string task_body = build_task_body(p, info.project_id, info.model_id,
                                            info.profile_id, use_lan_channel);
    std::string task_id;
    if (int rc = create_task(api, token, uid, task_body, &task_id, update_fn);
        rc != 0) return rc;

    // -------------------------------------------------------------
    // [J] MQTT publish the project_file command. The printer watches
    // for this on its report/request channel and starts the job the
    // moment it lands.
    // -------------------------------------------------------------
    print_job::ProjectFileOpts opts;
    opts.project_id = info.project_id;
    opts.profile_id = info.profile_id;
    opts.task_id    = task_id;
    opts.subtask_id = "0";
    opts.md5        = md5;
    if (use_lan_channel) {
        opts.file_path = lan_remote_path;
        if (print_job::use_brtc_cache_upload(p)) {
            opts.url = print_job::build_brtc_emmc_url(remote_name);
        } else {
            opts.url = print_job::build_ftp_url(lan_remote_path);
        }
    } else {
        // Cloud: the printer fetches directly from S3 over HTTPS.
        opts.file_path = remote_name;
        opts.url       = main_upload_url;
    }

    // Build the MQTT project_file payload. Cloud prints (both LAN-channel and
    // cloud-channel) require url_enc / param_enc — RSA-PKCS#1 v1.5 encrypted
    // to the printer's public key — instead of plaintext url / param. Without
    // this the firmware rejects the command with "mqtt message verify failed".
    std::string mqtt_json;
    {
        // Obtain the printer's RSA public key: prefer the in-memory cache
        // (populated by install_device_cert / capture_peer_cert_pem), fall
        // back to reading the PEM from disk if the cache is empty.
        EVP_PKEY* printer_pk = cert_store::get_printer_pub_key(p.dev_id);
        if (!printer_pk) {
            std::string pem_path = cert_store::device_cert_path(config_dir(), p.dev_id);
            printer_pk = load_printer_pub_key_from_pem(pem_path);
            if (printer_pk) {
                cert_store::set_printer_pub_key(p.dev_id, printer_pk);
            }
        }
        if (!printer_pk) {
            OBN_ERROR("cloud_print: no public key for dev=%s; "
                      "ensure install_device_cert() has run", p.dev_id.c_str());
            if (update_fn) update_fn(BBL::PrintingStageERROR,
                                     BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED,
                                     "no printer public key for RSA encryption");
            return BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED;
        }

        std::string plate_param = "Metadata/plate_" +
            std::to_string(p.plate_index <= 0 ? 1 : p.plate_index) + ".gcode";

        std::string enc_err;
        std::string url_enc   = rsa_pkcs1v15_encrypt_b64(printer_pk, opts.url,   &enc_err);
        std::string param_enc = rsa_pkcs1v15_encrypt_b64(printer_pk, plate_param, &enc_err);
        ::EVP_PKEY_free(printer_pk);

        if (url_enc.empty() || param_enc.empty()) {
            OBN_ERROR("cloud_print: RSA field encryption failed: %s", enc_err.c_str());
            if (update_fn) update_fn(BBL::PrintingStageERROR,
                                     BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED,
                                     "RSA field encryption failed: " + enc_err);
            return BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED;
        }

        print_job::CloudProjectFileOpts cloud_opts;
        cloud_opts.url_enc    = std::move(url_enc);
        cloud_opts.param_enc  = std::move(param_enc);
        cloud_opts.file_path  = opts.file_path;
        cloud_opts.md5        = opts.md5;
        cloud_opts.project_id = opts.project_id;
        cloud_opts.profile_id = opts.profile_id;
        cloud_opts.task_id    = opts.task_id;
        cloud_opts.subtask_id = opts.subtask_id;

        mqtt_json = print_job::build_cloud_project_file_json(p, cloud_opts);
    }
    OBN_DEBUG("cloud_print mqtt: %s", mqtt_json.c_str());

    int pub_rc = 0;
    if (use_lan_channel) {
        pub_rc = send_message_to_printer(p.dev_id, mqtt_json, /*qos=*/0);
    } else {
        pub_rc = cloud_send_message(p.dev_id, mqtt_json, /*qos=*/0);
    }
    if (pub_rc != 0) {
        OBN_ERROR("cloud_print: mqtt publish failed rc=%d", pub_rc);
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_PRINT_LP_PUBLISH_MSG_FAILED,
                                 "MQTT publish failed");
        return BAMBU_NETWORK_ERR_PRINT_LP_PUBLISH_MSG_FAILED;
    }

    if (update_fn) update_fn(BBL::PrintingStageFinished, 0, "3");
    OBN_INFO("cloud_print dev=%s: queued (project=%s task=%s chan=%s)",
             p.dev_id.c_str(), info.project_id.c_str(), task_id.c_str(),
             use_lan_channel ? "lan" : "cloud");
    return 0;
}

} // namespace obn
