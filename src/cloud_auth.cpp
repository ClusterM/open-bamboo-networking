#include "obn/cloud_auth.hpp"

#include "obn/config.hpp"
#include "obn/http_client.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"

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
                         const std::string& refresh)
{
    AuthResult r;
    // Note: the endpoint name varies between Studio versions and the HA
    // community docs (`/v1/user-service/user/refreshtoken` or
    // `/v1/user-service/user/refresh-token`). We try the more common
    // dash-less form; if it 404s we'll iterate later.
    auto resp = obn::http::post_json(api_host(region) + "/v1/user-service/user/refreshtoken",
                                     refresh_body(refresh));
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

#if 0 // NOT YET WIRED - kept as documentation; application_token derivation unconfirmed
DeviceCertResult fetch_device_cert(const std::string& region,
                                   const std::string& access_token,
                                   const std::string& application_token,
                                   const std::string& aes256_key)
{
    DeviceCertResult r;
    if (application_token.empty()) {
        r.error_message = "application_token required (see cloud_auth.hpp comment)";
        return r;
    }
    // Endpoint confirmed from MITM capture of the stock plugin:
    //   GET /v1/iot-service/api/user/applications/{token}/cert?aes256={key}&ver=1
    // The client generates a random 32-byte AES key, base64url-encodes it, and
    // passes it here so the server can encrypt the returned private key with it.
    const std::string encoded_token = obn::http::url_encode(application_token);
    const std::string encoded_key   = obn::http::url_encode(aes256_key);
    std::string url = api_host(region)
        + "/v1/iot-service/api/user/applications/"
        + encoded_token
        + "/cert?aes256="
        + encoded_key
        + "&ver=1";
    std::map<std::string, std::string> hdrs{
        {"Authorization", "Bearer " + access_token},
    };
    auto resp = obn::http::get_json(url, hdrs);
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
    if (!root) {
        r.error_message = "bad JSON: " + perr;
        return r;
    }
    // Response shape (from MITM capture):
    //   {"cert": "<3-cert PEM chain>", "crl": ["<PEM CRL>"],
    //    "key": "<AES-256-CBC encrypted private key, base64>"}
    // Chain order: device leaf -> per-device intermediate CA
    // ("{dev_uid}.bambulab.com") -> Bambu root CA.
    // CRL is valid ~30 days; refresh before expiry to maintain MQTT auth.
    // Decrypt `key` with AES-256-CBC using the caller's base64url-decoded
    // aes256_key before passing it to mosquitto.
    r.cert = root->find("cert").as_string();
    // crl is an array of PEM strings; take the first entry.
    {
        auto crl_v = root->find("crl");
        const auto& crl_arr = crl_v.as_array();
        if (!crl_arr.empty()) r.crl = crl_arr[0].as_string();
    }
    r.key  = root->find("key").as_string();
    r.ok   = !r.cert.empty();
    if (!r.ok) r.error_message = "cert field missing in response";
    return r;
}
#endif // NOT YET WIRED

} // namespace obn::cloud
