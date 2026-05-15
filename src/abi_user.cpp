#include <sstream>
#include <string>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/cloud_auth.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"

using obn::as_agent;

OBN_IGNORE_RETURN_CXX_IN_EXTERN_C_BEGIN

OBN_ABI int bambu_network_change_user(void* agent, std::string user_info)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    OBN_INFO("change_user info_len=%zu", user_info.size());
    if (user_info.empty() || user_info == "{}") {
        // Studio calls change_user("") on startup / logout.
        a->clear_session();
        return BAMBU_NETWORK_SUCCESS;
    }
    return a->apply_login_info(user_info);
}

OBN_ABI bool bambu_network_is_user_login(void* agent)
{
    // Studio polls this ~5 ms apart from its main timer, so even DEBUG
    // drowns the rest of the log. Demote to TRACE; flip OBN_LOG_LEVEL=
    // trace to see it.
    if (auto* a = as_agent(agent)) {
        bool v = a->user_logged_in();
        OBN_TRACE("is_user_login -> %s", v ? "true" : "false");
        return v;
    }
    OBN_TRACE("is_user_login -> false (no agent)");
    return false;
}

OBN_ABI int bambu_network_user_logout(void* agent, bool request)
{
    // Polled by Studio every ~2 s as a safety-net even when the user
    // isn't logged in. Keep this off the default log to avoid noise.
    OBN_TRACE("user_logout request=%d", request);
    if (auto* a = as_agent(agent)) a->clear_session();
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI std::string bambu_network_get_user_id(void* agent)
{
    if (auto* a = as_agent(agent)) {
        auto v = a->user_session_snapshot().user_id;
        OBN_INFO("get_user_id -> '%s'", v.c_str());
        return v;
    }
    return {};
}

OBN_ABI std::string bambu_network_get_user_name(void* agent)
{
    if (auto* a = as_agent(agent)) {
        auto v = a->user_session_snapshot().user_name;
        OBN_INFO("get_user_name -> '%s'", v.c_str());
        return v;
    }
    return {};
}

OBN_ABI std::string bambu_network_get_user_avatar(void* agent)
{
    if (auto* a = as_agent(agent)) {
        auto v = a->user_session_snapshot().avatar;
        OBN_INFO("get_user_avatar -> len=%zu", v.size());
        return v;
    }
    return {};
}

OBN_ABI std::string bambu_network_get_user_nickanme(void* agent)
{
    if (auto* a = as_agent(agent)) {
        auto s = a->user_session_snapshot();
        auto& v = s.nick_name.empty() ? s.user_name : s.nick_name;
        OBN_INFO("get_user_nickanme -> '%s'", v.c_str());
        return v;
    }
    return {};
}

namespace {

// The original plugin replies to Studio's get_login_info with a
// postMessage envelope whose command is studio_userlogin (or
// studio_useroffline on logout). The sidebar JS in
// resources/web/homepage3/js/left.js and the login WebView in
// resources/web/login/js/login.js both dispatch on those exact
// command names and read data.avatar / data.name to drive the
// "logged in" UI (hide the Login/Register button, show the avatar
// and nickname). We mirror that shape verbatim; extra fields are
// harmless but name+avatar are the ones Studio actually looks at.
std::string build_session_cmd(const obn::Agent* a, bool logout)
{
    if (!a) return "{\"sequence_id\":\"0\",\"command\":\"studio_useroffline\",\"data\":{}}";
    auto s = a->user_session_snapshot();
    const std::string& display_name = s.nick_name.empty() ? s.user_name : s.nick_name;
    std::ostringstream os;
    os << '{';
    os << "\"sequence_id\":\"0\",";
    os << "\"command\":" << (logout
        ? "\"studio_useroffline\""
        : "\"studio_userlogin\"") << ',';
    os << "\"data\":{";
    os << "\"avatar\":"    << obn::json::escape(s.avatar) << ',';
    os << "\"name\":"      << obn::json::escape(display_name) << ',';
    os << "\"user_id\":"   << obn::json::escape(s.user_id) << ',';
    os << "\"user_name\":" << obn::json::escape(s.user_name) << ',';
    os << "\"nickname\":"  << obn::json::escape(s.nick_name) << ',';
    os << "\"account\":"   << obn::json::escape(s.account) << ',';
    os << "\"token\":"     << obn::json::escape(s.access_token) << ',';
    os << "\"refresh\":"   << obn::json::escape(s.refresh_token);
    os << "}}";
    return os.str();
}

} // namespace

// Studio calls build_login_cmd / build_logout_cmd from
// WebViewPanel::OnFreshLoginStatus, which is driven by a 2-second
// wxTimer that starts as soon as the HomePage WebView posts its first
// script message, and keeps running for the lifetime of that panel.
// The sidebar uses the returned JSON to keep its avatar / login
// status widget in sync. That means we get called roughly every two
// seconds even when nothing about the session has changed; logging
// at INFO would drown out everything else, so we stay at DEBUG.
OBN_ABI std::string bambu_network_build_login_cmd(void* agent)
{
    auto r = build_session_cmd(as_agent(agent), /*logout=*/false);
    OBN_DEBUG("build_login_cmd -> len=%zu", r.size());
    return r;
}

OBN_ABI std::string bambu_network_build_logout_cmd(void* agent)
{
    // Mirrors user_logout polling cadence (~2 s); demote to TRACE for
    // the same reason.
    auto r = build_session_cmd(as_agent(agent), /*logout=*/true);
    OBN_TRACE("build_logout_cmd -> len=%zu", r.size());
    return r;
}

OBN_ABI std::string bambu_network_build_login_info(void* agent)
{
    // WebViewPanel::SendLoginInfo() wraps this string in
    // window.postMessage(...) and forwards it to the currently
    // visible WebView panel. Studio's JS dispatches on command,
    // same as build_login_cmd, so we reuse the envelope.
    auto r = build_session_cmd(as_agent(agent), /*logout=*/false);
    OBN_INFO("build_login_info -> len=%zu", r.size());
    return r;
}

OBN_ABI int bambu_network_get_my_profile(void* agent,
                                         std::string  token,
                                         unsigned int* http_code,
                                         std::string*  http_body)
{
    if (http_code) *http_code = 0;
    if (http_body) http_body->clear();
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    if (token.empty()) token = a->user_session_snapshot().access_token;
    if (token.empty()) return BAMBU_NETWORK_ERR_INVALID_RESULT;

    auto r = obn::cloud::get_profile(a->cloud_region(), token);
    if (http_code) *http_code = static_cast<unsigned int>(r.http_status);
    if (http_body) *http_body = r.raw_body;
    return r.ok ? BAMBU_NETWORK_SUCCESS : BAMBU_NETWORK_ERR_INVALID_RESULT;
}

OBN_ABI int bambu_network_get_my_token(void* agent,
                                       std::string  ticket,
                                       unsigned int* http_code,
                                       std::string*  http_body)
{
    if (http_code) *http_code = 0;
    if (http_body) http_body->clear();
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    OBN_INFO("get_my_token: ticket len=%zu", ticket.size());
    auto r = obn::cloud::login_with_ticket(a->cloud_region(), ticket);
    if (http_code) *http_code = static_cast<unsigned int>(r.http_status);
    if (http_body) *http_body = r.raw_body;
    if (r.ok) return BAMBU_NETWORK_SUCCESS;
    OBN_WARN("get_my_token: %s", r.error_message.c_str());
    return BAMBU_NETWORK_ERR_INVALID_RESULT;
}

OBN_ABI int bambu_network_get_user_info(void* agent, int* identifier)
{
    if (identifier) *identifier = 0;
    if (auto* a = as_agent(agent)) {
        if (a->user_logged_in()) {
            if (identifier) {
                // Studio uses `int` but Bambu user_ids are 32-bit unsigned
                // values on the wire (e.g. 3575315859 > INT_MAX). std::stoi
                // would throw out_of_range there, which unwinds through the
                // ABI boundary and aborts. Use stoll and bit-cast.
                try {
                    long long v = std::stoll(a->user_session_snapshot().user_id);
                    *identifier = static_cast<int>(static_cast<unsigned int>(v));
                } catch (...) { *identifier = 0; }
            }
        }
    }
    OBN_INFO("get_user_info -> id=%d", identifier ? *identifier : 0);
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI std::string bambu_network_get_bambulab_host(void* agent)
{
    // Studio uses this as the web-portal base (WebView loads
    // host + "/sign-in"; bind-ticket builds host + "api/sign-in/ticket?...").
    // Must be the PORTAL host, not the API host, and must end with '/'.
    if (auto* a = as_agent(agent))
        return obn::cloud::web_host(a->cloud_region());
    return "https://bambulab.com/";
}

OBN_ABI std::string bambu_network_get_user_selected_machine(void* agent)
{
    auto* a = as_agent(agent);
    return a ? a->user_selected_machine() : std::string{};
}

OBN_ABI int bambu_network_set_user_selected_machine(void* agent, std::string dev_id)
{
    if (auto* a = as_agent(agent)) {
        a->set_user_selected_machine(std::move(dev_id));
        return BAMBU_NETWORK_SUCCESS;
    }
    return BAMBU_NETWORK_ERR_INVALID_HANDLE;
}

OBN_IGNORE_RETURN_CXX_IN_EXTERN_C_END
