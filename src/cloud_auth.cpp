#include "obn/cloud_auth.hpp"

#include "obn/config.hpp"
#include "obn/http_client.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#if !defined(_WIN32)
#  include <sys/stat.h>
#endif

namespace obn::cloud {

namespace {

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

int64_t now_epoch_seconds()
{
    return static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

// Create the directory tree up to (not including) the filename in `path`.
void mkdirs_for_file_(const std::string& path)
{
    std::error_code ec;
    auto parent = std::filesystem::path(path).parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent, ec);
}

// Serialise the session as a compact JSON object into `out`.
void encode_session_json_(const SessionData& d, std::string& out)
{
    out.clear();
    out += "{\n";
    auto add_str = [&](const char* k, const std::string& v, bool last = false) {
        out += "  \""; out += k; out += "\": ";
        out += obn::json::escape(v);
        if (!last) out += ',';
        out += '\n';
    };
    auto add_i64 = [&](const char* k, int64_t v, bool last = false) {
        out += "  \""; out += k; out += "\": ";
        out += std::to_string(v);
        if (!last) out += ',';
        out += '\n';
    };
    add_str("access_token",       d.access_token);
    add_str("refresh_token",      d.refresh_token);
    add_i64("access_expires_at",  d.access_expires_at);
    add_i64("refresh_expires_at", d.refresh_expires_at);
    add_str("user_id",            d.user_id);
    add_str("region",             d.region);
    add_str("user_email",         d.user_email, /*last=*/true);
    out += "}\n";
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// SessionData members
// ---------------------------------------------------------------------------

bool SessionData::access_valid(int slack_seconds) const noexcept
{
    if (access_token.empty()) return false;
    if (access_expires_at <= 0) return false;  // unknown → treat as expired
    return (access_expires_at - now_epoch_seconds()) > static_cast<int64_t>(slack_seconds);
}

bool SessionData::refresh_valid(int slack_seconds) const noexcept
{
    if (refresh_token.empty()) return false;
    if (refresh_expires_at <= 0) return true;  // unknown → assume still good
    return (refresh_expires_at - now_epoch_seconds()) > static_cast<int64_t>(slack_seconds);
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

std::string default_session_path()
{
    const auto& cfg = obn::config::current().session_path;
    if (!cfg.empty()) return cfg;
    const auto& dir = obn::config::dir();
    if (!dir.empty()) return dir + "/session.json";
    return {};
}

SessionData session_from_auth(const AuthResult& r,
                              const std::string& region,
                              const std::string& user_id,
                              const std::string& user_email)
{
    SessionData d;
    d.access_token        = r.access_token;
    d.refresh_token       = r.refresh_token;
    const int64_t now     = now_epoch_seconds();
    d.access_expires_at   = (r.expires_in > 0) ? now + r.expires_in : 0;
    d.refresh_expires_at  = 0;   // AuthResult does not carry refresh_expires_in
    d.user_id             = user_id;
    d.region              = region;
    d.user_email          = user_email;
    return d;
}

bool save_session(const SessionData& data, const std::string& path_in)
{
    const std::string path = path_in.empty() ? default_session_path() : path_in;
    mkdirs_for_file_(path);
    const std::string tmp = path + ".tmp";

    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            OBN_ERROR("session: open(%s) failed: %s", tmp.c_str(), std::strerror(errno));
            return false;
        }
        std::string body;
        encode_session_json_(data, body);
        out.write(body.data(), static_cast<std::streamsize>(body.size()));
        out.flush();
        if (!out.good()) {
            OBN_ERROR("session: write to %s failed", tmp.c_str());
            out.close();
            std::error_code ec;
            std::filesystem::remove(tmp, ec);
            return false;
        }
    }

#if !defined(_WIN32)
    if (::chmod(tmp.c_str(), S_IRUSR | S_IWUSR) != 0)
        OBN_WARN("session: chmod(0600) on %s failed: %s",
                 tmp.c_str(), std::strerror(errno));
#endif

    std::error_code ec;
#if defined(_WIN32)
    // Windows rename does not overwrite; remove the destination first.
    std::filesystem::remove(path, ec);
#endif
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        OBN_ERROR("session: rename(%s -> %s) failed: %s",
                  tmp.c_str(), path.c_str(), ec.message().c_str());
        std::error_code rmec;
        std::filesystem::remove(tmp, rmec);
        return false;
    }
#if !defined(_WIN32)
    if (::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0)
        OBN_WARN("session: chmod(0600) on %s failed: %s",
                 path.c_str(), std::strerror(errno));
#endif
    OBN_INFO("session: saved to %s (access_expires_at=%lld user_id=%s region=%s)",
             path.c_str(), (long long)data.access_expires_at,
             data.user_id.c_str(), data.region.c_str());
    return true;
}

SessionData load_session(const std::string& path_in)
{
    const std::string path = path_in.empty() ? default_session_path() : path_in;
    SessionData d;
    std::ifstream in(path);
    if (!in) {
        OBN_INFO("session: no session file at %s", path.c_str());
        return d;
    }
    std::string text((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    std::string perr;
    auto root = obn::json::parse(text, &perr);
    if (!root) {
        OBN_WARN("session: parse error in %s: %s", path.c_str(), perr.c_str());
        return d;
    }
    d.access_token       = root->find("access_token").as_string();
    d.refresh_token      = root->find("refresh_token").as_string();
    d.access_expires_at  = root->find("access_expires_at").as_int(0);
    d.refresh_expires_at = root->find("refresh_expires_at").as_int(0);
    d.user_id            = root->find("user_id").as_string();
    d.region             = root->find("region").as_string();
    d.user_email         = root->find("user_email").as_string();
    OBN_INFO("session: loaded from %s (user_id=%s access_expires_at=%lld)",
             path.c_str(), d.user_id.c_str(), (long long)d.access_expires_at);
    return d;
}

SessionData load_and_refresh_if_needed(const std::string& path, int slack_seconds)
{
    SessionData d = load_session(path);
    if (!d.has_tokens()) {
        OBN_INFO("session: no valid tokens on disk");
        return d;
    }

    if (d.access_valid(slack_seconds)) {
        OBN_INFO("session: access_token still valid for user_id=%s", d.user_id.c_str());
        return d;
    }

    if (!d.refresh_valid(slack_seconds)) {
        OBN_WARN("session: refresh_token expired for user_id=%s", d.user_id.c_str());
        return SessionData{};
    }

    OBN_INFO("session: access_token near/past expiry for user_id=%s, refreshing",
             d.user_id.c_str());

    AuthResult r = obn::cloud::refresh_token(d.region, d.refresh_token);
    if (!r.ok) {
        OBN_WARN("session: refresh call failed: %s", r.error_message.c_str());
        return SessionData{};
    }

    const int64_t now   = now_epoch_seconds();
    d.access_token      = r.access_token;
    if (!r.refresh_token.empty()) d.refresh_token = r.refresh_token;
    d.access_expires_at = (r.expires_in > 0) ? now + r.expires_in : 0;
    // refresh_expires_at: not in AuthResult, leave unchanged

    if (!save_session(d, path)) {
        OBN_WARN("session: refresh succeeded but save failed; "
                 "next boot will refresh again");
    }
    return d;
}

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
