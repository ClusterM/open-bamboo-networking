#include "obn/cloud_auth.hpp"

#include "obn/config.hpp"
#include "obn/http_client.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"

#include <map>
#include <sstream>

namespace obn::cloud {

namespace {

std::string refresh_body(const std::string& refresh)
{
    std::ostringstream os;
    os << '{'
       << "\"refreshToken\":" << obn::json::escape(refresh)
       << '}';
    return os.str();
}

// Stock logout body uses the all-lowercase key `refreshtoken` (not
// camelCase) and always sends an empty string; Bearer alone is enough
// (research/08.05-auth.md gap_probe --do-logout).
std::string logout_body()
{
    return "{\"refreshtoken\":\"\"}";
}

// Extract the common "accessToken" shape. Fields that are absent stay
// empty; callers check `ok` first.
void fill_auth_fields(const obn::json::Value& root, AuthResult& r)
{
    r.access_token  = root.find("accessToken").as_string();
    r.refresh_token = root.find("refreshToken").as_string();
    r.expires_in    = root.find("expiresIn").as_int(0);
    r.refresh_expires_in = root.find("refreshExpiresIn").as_int(0);
    r.login_type    = root.find("loginType").as_string();
    // tfaKey is sometimes called "tfa_key"; check both.
    auto tfa1 = root.find("tfaKey").as_string();
    auto tfa2 = root.find("tfa_key").as_string();
    r.tfa_key = !tfa1.empty() ? tfa1 : tfa2;
}

std::string api_error(const obn::json::Value& root, long status)
{
    auto msg = root.find("message").as_string();
    if (msg.empty()) msg = root.find("error").as_string();
    if (msg.empty()) msg = "http " + std::to_string(status);
    return msg;
}

} // namespace

std::string api_host(const std::string& region)
{
    return obn::config::cloud_api_host_for(obn::config::current(), region);
}

std::string web_host(const std::string& region)
{
    return obn::config::cloud_web_host_for(obn::config::current(), region);
}

const char* os_type()
{
    // POST /my/task rejects an OS mismatch with the uploader with HTTP 403,
    // so this must reflect the real platform.
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#else
    return "linux";
#endif
}

std::map<std::string, std::string> bbl_headers(const std::string& access_token,
                                               const std::string& user_id)
{
    const auto& cfg_client_name = obn::config::current().client_name;
    std::map<std::string, std::string> h;
    h["Authorization"]        = "Bearer " + access_token;
    h["Content-Type"]         = "application/json";
    h["Accept"]               = "application/json";
    h["X-BBL-Client-Name"]    = cfg_client_name.empty() ? std::string{"OpenBambooNetworking"}
                                                        : cfg_client_name;
    h["X-BBL-Client-Type"]    = "slicer";
    h["X-BBL-OS-Type"]        = os_type();
    h["X-BBL-Agent-OS-Type"]  = os_type();
    h["X-BBL-Language"]       = "en-US";
    h["X-BBL-Executable-info"]= R"({"cert_end_date":"2029-03-12","cert_start_date":"2025-12-23","hash_value":"3dca1e74c49cdcd6b6f551500f6f7667af28d8db","issue_name":"GlobalSign GCC R45 EV CodeSigning CA 2020","serial_number":"23009bd87d891a5405b02fbc","sign_date":"2026-08-14T09:50:51Z","subject_name":"Shanghai Lunkuo Technology Co., Ltd","verify_result":"0"})";
    if (!user_id.empty())
        h["X-BBL-Client-ID"] = "slicer:" + user_id + ":obn0";
    return h;
}

AuthResult login_with_ticket(const std::string& region,
                             const std::string& ticket)
{
    AuthResult r;
    if (ticket.empty()) {
        r.error_message = "empty ticket";
        return r;
    }
    // Endpoint confirmed from the original plugin's traffic:
    //   POST https://api.bambulab.com/v1/user-service/user/ticket/<TICKET>
    //   body: {"ticket":"<TICKET>"}
    // Response on success (HTTP 200):
    //   {"accessToken":"...","refreshToken":"...","expiresIn":31536000,
    //    "refreshExpiresIn":...,"tfaKey":"","accessMethod":"ticket",
    //    "loginType":"","firstAppLogin":false}
    // The ticket is single-use and short-lived; any failure here means
    // Studio will re-open the login dialog.
    std::string url  = api_host(region) + "/v1/user-service/user/ticket/" + ticket;
    std::string body = std::string("{\"ticket\":") + obn::json::escape(ticket) + "}";
    auto resp = obn::http::post_json(url, body);
    r.http_status = resp.status_code;
    r.raw_body    = resp.body;
    if (!resp.error.empty()) {
        r.error_message = resp.error;
        return r;
    }
    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root) {
        r.error_message = "bad JSON: " + perr;
        return r;
    }
    fill_auth_fields(*root, r);
    r.ok = !r.access_token.empty();
    if (!r.ok) r.error_message = api_error(*root, resp.status_code);
    return r;
}

AuthResult refresh_token(const std::string& region,
                         const std::string& access,
                         const std::string& refresh)
{
    AuthResult r;
    std::map<std::string, std::string> hdrs;
    if (!access.empty())
        hdrs["Authorization"] = "Bearer " + access;
    // Stock: POST /v1/user-service/user/refreshtoken + Bearer + refreshToken body.
    auto resp = obn::http::post_json(
        api_host(region) + "/v1/user-service/user/refreshtoken",
        refresh_body(refresh),
        hdrs);
    r.http_status = resp.status_code;
    r.raw_body    = resp.body;
    if (!resp.error.empty()) {
        r.error_message = resp.error;
        return r;
    }
    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root) {
        r.error_message = "bad JSON: " + perr;
        return r;
    }
    fill_auth_fields(*root, r);
    r.ok = !r.access_token.empty();
    if (!r.ok) r.error_message = api_error(*root, resp.status_code);
    return r;
}

bool logout(const std::string& region,
            const std::string& access_token,
            const std::string& /*refresh*/)
{
    if (access_token.empty()) return true;
    std::map<std::string, std::string> hdrs{
        {"Authorization", "Bearer " + access_token},
    };
    // Evidence: MITM stock agent 02.08.01.53 — POST …/my/logout → 200
    // empty body. Failure must not block local session clear.
    auto resp = obn::http::post_json(
        api_host(region) + "/v1/user-service/my/logout",
        logout_body(),
        hdrs);
    if (!resp.error.empty()) {
        OBN_WARN("cloud logout: transport %s", resp.error.c_str());
        return false;
    }
    if (resp.status_code < 200 || resp.status_code >= 300) {
        OBN_WARN("cloud logout: http %ld", resp.status_code);
        return false;
    }
    return true;
}

ProfileResult get_profile(const std::string& region,
                          const std::string& access_token)
{
    ProfileResult r;
    std::map<std::string, std::string> hdrs{
        {"Authorization", "Bearer " + access_token},
    };
    auto resp = obn::http::get_json(api_host(region) + "/v1/user-service/my/profile", hdrs);
    r.http_status = resp.status_code;
    r.raw_body    = resp.body;
    if (!resp.error.empty()) {
        r.error_message = resp.error;
        return r;
    }
    if (resp.status_code != 200) {
        r.error_message = "http " + std::to_string(resp.status_code);
        return r;
    }
    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root) { r.error_message = "bad JSON: " + perr; return r; }
    // The profile response looks like:
    //   {"uidStr":"...","name":"...","avatar":"...","account":"...","nickname":"..."}
    // (field names vary slightly across account regions; we accept a few
    // common spellings).
    r.user_id   = root->find("uidStr").as_string();
    if (r.user_id.empty()) {
        auto uid = root->find("uid").as_int(0);
        if (uid != 0) r.user_id = std::to_string(uid);
    }
    r.user_name = root->find("name").as_string();
    r.nick_name = root->find("nickname").as_string();
    if (r.nick_name.empty()) r.nick_name = root->find("nickName").as_string();
    r.avatar    = root->find("avatar").as_string();
    r.account   = root->find("account").as_string();
    // setting.isFirmwareBetaOpen controls whether the cloud firmware
    // endpoint returns beta firmware entries for this user's devices.
    r.firmware_beta_open = root->find("setting.isFirmwareBetaOpen").as_bool();
    r.ok = true;
    return r;
}

} // namespace obn::cloud
