#include "obn/bind_cloud.hpp"

#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/cloud_auth.hpp"
#include "obn/http_client.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"

#include <map>
#include <sstream>

namespace obn::cloud_bind {
namespace {

std::string api_base(Agent* a)
{
    return obn::cloud::api_host(a->cloud_region());
}

obn::http::Response http_patch(const std::string& url,
                                const std::string& body,
                                const std::map<std::string, std::string>& hdrs)
{
    obn::http::Request r;
    r.method = obn::http::Method::PATCH;
    r.url    = url;
    r.body   = body;
    r.headers = hdrs;
    return obn::http::perform(r);
}

obn::http::Response http_delete(const std::string& url,
                                 const std::map<std::string, std::string>& hdrs)
{
    obn::http::Request r;
    r.method = obn::http::Method::DEL;
    r.url    = url;
    r.headers = hdrs;
    return obn::http::perform(r);
}

void emit(BBL::OnUpdateStatusFn& fn, BBL::BindJobStage st, int code, const std::string& msg)
{
    if (fn) fn(static_cast<int>(st), code, msg);
}

// Stock cloud responses usually carry message=="success" and code:null or 0.
bool http_json_success(const std::string& body, long http_status)
{
    if (http_status < 200 || http_status >= 300) return false;
    if (body.empty()) return true;
    std::string perr;
    auto root = obn::json::parse(body, &perr);
    if (!root) return http_status == 200;
    if (root->find("message").as_string() == "success") return true;
    const auto c = root->find("code");
    if (!c.is_null() && c.is_number() && c.as_int() == 0) return true;
    if (!c.is_null() && c.is_string() && c.as_string() == "0") return true;
    // Some endpoints return { "devices": [...] } without message.
    if (!root->find("devices").is_null()) return true;
    return false;
}

std::string extract_ticket_from_json(const std::string& body)
{
    std::string perr;
    auto root = obn::json::parse(body, &perr);
    if (!root) return {};
    // Common shapes: {"ticket":"..."} {"data":{"ticket":"..."}}
    std::string t = root->find("ticket").as_string();
    if (!t.empty()) return t;
    t = root->find("data.ticket").as_string();
    if (!t.empty()) return t;
    return root->find("data.bind_ticket").as_string();
}

} // namespace

int ping_bind(Agent* agent, const std::string& ping_code)
{
    if (!agent || !agent->user_logged_in()) return BAMBU_NETWORK_ERR_BIND_FAILED;
    auto hdrs = agent->cloud_api_http_headers();
    if (hdrs.find("Authorization") == hdrs.end()) {
        OBN_WARN("ping_bind: not logged in");
        return BAMBU_NETWORK_ERR_BIND_FAILED;
    }

    const std::string base = api_base(agent) + "/v1/iot-service/api/user/bind";
    // The slicer plugin tries a handful of payload shapes; the cloud keeps
    // changing field names between regions/firmware generations.
    const char* keys[] = {"ping", "pin_code", "bind_pin", "code", "bind_code"};
    for (const char* k : keys) {
        std::ostringstream body;
        body << "{\"" << k << "\":" << obn::json::escape(ping_code) << "}";
        auto resp = obn::http::post_json(base, body.str(), hdrs);
        OBN_INFO("ping_bind try key=%s http=%ld body.len=%zu",
                 k,
                 resp.status_code,
                 resp.body.size());
        if (!resp.error.empty()) continue;
        if (http_json_success(resp.body, resp.status_code)) return BAMBU_NETWORK_SUCCESS;
    }
    OBN_WARN("ping_bind: all payload variants failed");
    return BAMBU_NETWORK_ERR_BIND_FAILED;
}

int bind_lan_to_account(Agent* agent,
                        const std::string& dev_ip,
                        const std::string& dev_id,
                        const std::string& /*sec_link*/,
                        const std::string& timezone,
                        bool               improved,
                        BBL::OnUpdateStatusFn update_fn)
{
    if (!agent) return BAMBU_NETWORK_ERR_BIND_FAILED;

    emit(update_fn, BBL::LoginStageConnect, 0, {});

    if (!agent->user_logged_in()) {
        emit(update_fn, BBL::LoginStageFinished, BAMBU_NETWORK_ERR_BIND_FAILED,
             "not logged in");
        return BAMBU_NETWORK_ERR_BIND_FAILED;
    }

    std::string access = agent->lan_access_code_for(dev_id);
    if (access.empty()) {
        emit(update_fn,
             BBL::LoginStageFinished,
             BAMBU_NETWORK_ERR_BIND_FAILED,
             "no LAN access code — connect to this printer once (Device tab) "
             "so the plugin can cache the access code, then retry Bind.");
        return BAMBU_NETWORK_ERR_BIND_FAILED;
    }

    emit(update_fn, BBL::LoginStageLogin, 0, {});

    std::string dev_name = agent->device_display_name_for_ip(dev_ip);
    if (dev_name.empty()) dev_name = "Printer";

    auto hdrs = agent->cloud_api_http_headers();
    if (hdrs.find("Authorization") == hdrs.end()) {
        emit(update_fn, BBL::LoginStageFinished, BAMBU_NETWORK_ERR_BIND_FAILED,
             "missing bearer token");
        return BAMBU_NETWORK_ERR_BIND_FAILED;
    }

    emit(update_fn, BBL::LoginStageWaitForLogin, 0, {});
    emit(update_fn, BBL::LoginStageGetIdentify, 0, {});
    emit(update_fn, BBL::LoginStageWaitAuth, 0, {});

    std::ostringstream os;
    os << '{'
       << "\"device_id\":" << obn::json::escape(dev_id) << ','
       << "\"device_name\":" << obn::json::escape(dev_name) << ','
       << "\"bind_code\":" << obn::json::escape(access) << ','
       << "\"timezone\":" << obn::json::escape(timezone) << ','
       << "\"notice\":" << (improved ? "true" : "false") << '}';

    const std::string url = api_base(agent) + "/v1/iot-service/api/user/bind";
    auto resp             = obn::http::post_json(url, os.str(), hdrs);

    OBN_INFO("bind_lan_to_account POST /user/bind http=%ld err=%s body=%s",
             resp.status_code,
             resp.error.c_str(),
             obn::log::redact(resp.body, 400).c_str());

    if (!resp.error.empty()) {
        emit(update_fn,
             BBL::LoginStageFinished,
             BAMBU_NETWORK_ERR_BIND_SOCKET_CONNECT_FAILED,
             resp.error);
        return BAMBU_NETWORK_ERR_BIND_SOCKET_CONNECT_FAILED;
    }

    if (!http_json_success(resp.body, resp.status_code)) {
        emit(update_fn,
             BBL::LoginStageFinished,
             BAMBU_NETWORK_ERR_BIND_POST_TICKET_TO_CLOUD_FAILED,
             resp.body);
        return BAMBU_NETWORK_ERR_BIND_POST_TICKET_TO_CLOUD_FAILED;
    }

    emit(update_fn, BBL::LoginStageFinished, 0, {});
    return BAMBU_NETWORK_SUCCESS;
}

int query_bind_status(Agent* agent,
                      const std::vector<std::string>& query_list,
                      unsigned int* http_code,
                      std::string* http_body)
{
    if (!agent) return BAMBU_NETWORK_ERR_QUERY_BIND_INFO_FAILED;
    if (!agent->user_logged_in()) return BAMBU_NETWORK_ERR_QUERY_BIND_INFO_FAILED;

    auto hdrs = agent->cloud_api_http_headers();
    const std::string url = api_base(agent) + "/v1/iot-service/api/user/bind";
    auto resp             = obn::http::get_json(url, hdrs);

    if (http_code) *http_code = static_cast<unsigned int>(resp.status_code);
    if (resp.error.empty() && resp.status_code >= 200 && resp.status_code < 300) {
        // Studio expects { "bind_list": [ { "dev_id","user_id","user_name" } ] }
        std::string perr;
        auto root = obn::json::parse(resp.body, &perr);
        obn::auth::Session s = agent->user_session_snapshot();
        std::ostringstream out;
        out << "{\"bind_list\":[";
        bool first = true;
        if (root) {
            auto devices_v = root->find("devices");
            const auto& devices = devices_v.as_array();
            for (const std::string& qdev : query_list) {
                for (const auto& dv : devices) {
                    obn::json::Value idv = dv.find("dev_id");
                    if (idv.as_string() != qdev) continue;
                    if (!first) out << ',';
                    first = false;
                    out << '{'
                        << "\"dev_id\":" << obn::json::escape(qdev) << ','
                        << "\"user_id\":" << obn::json::escape(s.user_id)
                        << ','
                        << "\"user_name\":"
                        << obn::json::escape(
                               !s.nick_name.empty() ? s.nick_name : s.user_name)
                        << '}';
                    break;
                }
            }
        }
        out << "]}";
        if (http_body) *http_body = out.str();
        return BAMBU_NETWORK_SUCCESS;
    }

    if (http_body) *http_body = resp.body;
    return BAMBU_NETWORK_ERR_QUERY_BIND_INFO_FAILED;
}

int modify_printer_name(Agent* agent, const std::string& dev_id, const std::string& dev_name)
{
    if (!agent || !agent->user_logged_in())
        return BAMBU_NETWORK_ERR_MODIFY_PRINTER_NAME_FAILED;
    auto hdrs = agent->cloud_api_http_headers();
    std::ostringstream body;
    body << '{'
         << "\"dev_id\":" << obn::json::escape(dev_id) << ','
         << "\"dev_name\":" << obn::json::escape(dev_name) << '}';

    const std::string url =
        api_base(agent) + "/v1/iot-service/api/user/device/info";
    auto resp = http_patch(url, body.str(), hdrs);
    OBN_INFO("modify_printer_name PATCH device/info http=%ld", resp.status_code);
    if (!resp.error.empty()) return BAMBU_NETWORK_ERR_MODIFY_PRINTER_NAME_FAILED;
    if (http_json_success(resp.body, resp.status_code)) return BAMBU_NETWORK_SUCCESS;
    return BAMBU_NETWORK_ERR_MODIFY_PRINTER_NAME_FAILED;
}

int unbind_device(Agent* agent, const std::string& dev_id)
{
    if (!agent || !agent->user_logged_in()) return BAMBU_NETWORK_ERR_UNBIND_FAILED;
    auto              hdrs = agent->cloud_api_http_headers();
    const std::string url  = api_base(agent) +
                            "/v1/iot-service/api/user/bind?dev_id=" +
                            obn::http::url_encode(dev_id);
    auto resp = http_delete(url, hdrs);
    OBN_INFO("unbind DELETE /user/bind http=%ld", resp.status_code);
    if (!resp.error.empty()) return BAMBU_NETWORK_ERR_UNBIND_FAILED;
    if (http_json_success(resp.body, resp.status_code)) return BAMBU_NETWORK_SUCCESS;
    return BAMBU_NETWORK_ERR_UNBIND_FAILED;
}

int request_web_sso_ticket(Agent* agent, std::string* ticket)
{
    if (ticket) ticket->clear();
    if (!agent || !agent->user_logged_in())
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    auto hdrs = agent->cloud_api_http_headers();

    const char* attempts[] = {
        "/v1/user-service/user/ticket/web",
        "/v1/user-service/user/web-ticket",
        "/v1/user-service/user/slicer/ticket",
    };
    for (const char* path : attempts) {
        std::string url = api_base(agent) + path;
        auto        resp = obn::http::post_json(url, "{}", hdrs);
        OBN_DEBUG("request_web_sso_ticket POST %s -> %ld", path, resp.status_code);
        if (resp.error.empty() && resp.status_code >= 200 && resp.status_code < 300) {
            std::string t = extract_ticket_from_json(resp.body);
            if (!t.empty()) {
                if (ticket) *ticket = std::move(t);
                return BAMBU_NETWORK_SUCCESS;
            }
        }
    }
    // Some builds expose a GET with no body.
    {
        std::string url = api_base(agent) + "/v1/user-service/user/ticket";
        auto        resp = obn::http::get_json(url, hdrs);
        if (resp.error.empty() && resp.status_code == 200) {
            std::string t = extract_ticket_from_json(resp.body);
            if (!t.empty()) {
                if (ticket) *ticket = std::move(t);
                return BAMBU_NETWORK_SUCCESS;
            }
        }
    }
    return BAMBU_NETWORK_ERR_INVALID_RESULT;
}

} // namespace cloud_bind
