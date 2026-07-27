#include "obn/bind_cloud.hpp"

#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/cloud_auth.hpp"
#include "obn/config.hpp"
#include "obn/http_client.hpp"
#include "obn/json_lite.hpp"
#include "obn/lan_bind_tcp.hpp"
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
    r.method  = obn::http::Method::PATCH;
    r.url     = url;
    r.body    = body;
    r.headers = hdrs;
    return obn::http::perform(r);
}

obn::http::Response http_delete_json(
    const std::string& url,
    const std::string& body,
    const std::map<std::string, std::string>& hdrs)
{
    obn::http::Request r;
    r.method  = obn::http::Method::DEL;
    r.url     = url;
    r.body    = body;
    r.headers = hdrs;
    return obn::http::perform(r);
}

void emit(BBL::OnUpdateStatusFn& fn, BBL::BindJobStage st, int code,
          const std::string& msg)
{
    if (fn) fn(static_cast<int>(st), code, msg);
}

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
    if (!root->find("devices").is_null()) return true;
    if (!root->find("deviceId").as_string().empty()) return true;
    return false;
}

std::string extract_ticket_from_json(const std::string& body)
{
    std::string perr;
    auto root = obn::json::parse(body, &perr);
    if (!root) return {};
    std::string t = root->find("ticket").as_string();
    if (!t.empty()) return t;
    t = root->find("data.ticket").as_string();
    if (!t.empty()) return t;
    return root->find("data.bind_ticket").as_string();
}

void fire_http_error(Agent* agent, long status, const std::string& body)
{
    if (!agent) return;
    if (status >= 200 && status < 300) return;
    if (status <= 0) return;
    agent->notify_http_error(static_cast<unsigned int>(status), body);
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

    // Stock: POST /v1/user-service/my/pincode/<PIN> body {"pincode":"<PIN>"}
    const std::string url = api_base(agent) + "/v1/user-service/my/pincode/" +
                            obn::http::url_encode(ping_code);
    const std::string body =
        std::string("{\"pincode\":") + obn::json::escape(ping_code) + "}";
    auto resp = obn::http::post_json(url, body, hdrs);
    OBN_INFO("ping_bind POST my/pincode/%s http=%ld body.len=%zu",
             ping_code.c_str(),
             resp.status_code,
             resp.body.size());
    fire_http_error(agent, resp.status_code, resp.body);
    if (!resp.error.empty()) return BAMBU_NETWORK_ERR_BIND_FAILED;
    if (http_json_success(resp.body, resp.status_code))
        return BAMBU_NETWORK_SUCCESS;
    return BAMBU_NETWORK_ERR_BIND_FAILED;
}

int bind_lan_to_account(Agent* agent,
                        const std::string& dev_ip,
                        const std::string& /*dev_id*/,
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

    auto hdrs = agent->cloud_api_http_headers();
    if (hdrs.find("Authorization") == hdrs.end()) {
        emit(update_fn, BBL::LoginStageFinished, BAMBU_NETWORK_ERR_BIND_FAILED,
             "missing bearer token");
        return BAMBU_NETWORK_ERR_BIND_FAILED;
    }

    emit(update_fn, BBL::LoginStageLogin, 0, {});
    emit(update_fn, BBL::LoginStageWaitForLogin, 0, {});
    emit(update_fn, BBL::LoginStageGetIdentify, 0, {});
    emit(update_fn, BBL::LoginStageWaitAuth, 0, {});

    const std::string region = agent->cloud_region();
    const std::string country = agent->country_code();
    std::string fail_info;
    int fail_err = 0;

    auto cloud_fn = [&](const std::string& ticket) -> int {
        // Stock device-ticket path: GET then POST my/ticket/<T>
        const std::string ticket_url = api_base(agent) +
                                       "/v1/user-service/my/ticket/" +
                                       obn::http::url_encode(ticket);
        auto getr = obn::http::get_json(ticket_url, hdrs);
        OBN_INFO("bind GET my/ticket/%s http=%ld", ticket.c_str(),
                 getr.status_code);
        fire_http_error(agent, getr.status_code, getr.body);
        if (!getr.error.empty() || getr.status_code < 200 ||
            getr.status_code >= 300) {
            return BAMBU_NETWORK_ERR_BIND_GET_CLOUD_TICKET_TIMEOUT;
        }

        const std::string post_body =
            std::string("{\"ticket\":") + obn::json::escape(ticket) + "}";
        auto postr = obn::http::post_json(ticket_url, post_body, hdrs);
        OBN_INFO("bind POST my/ticket/%s http=%ld", ticket.c_str(),
                 postr.status_code);
        fire_http_error(agent, postr.status_code, postr.body);
        if (!postr.error.empty() || postr.status_code < 200 ||
            postr.status_code >= 300) {
            return BAMBU_NETWORK_ERR_BIND_POST_TICKET_TO_CLOUD_FAILED;
        }
        return BAMBU_NETWORK_SUCCESS;
    };

    int rc = obn::lan_bind_tcp::login_bind_session(
        dev_ip, timezone, improved, region, country, cloud_fn, fail_info,
        &fail_err);

    if (rc != BAMBU_NETWORK_SUCCESS) {
        std::string info = fail_info;
        if (rc == BAMBU_NETWORK_ERR_BIND_ECODE_LOGIN_REPORT_FAILED &&
            fail_err != 0) {
            info = std::to_string(fail_err);
        }
        emit(update_fn, BBL::LoginStageFinished, rc, info);
        return rc;
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
    std::string url =
        api_base(agent) + "/v1/iot-service/api/user/bind_list?dev_ids=";
    for (size_t i = 0; i < query_list.size(); ++i) {
        if (i) url += ',';
        url += obn::http::url_encode(query_list[i]);
    }

    auto resp = obn::http::get_json(url, hdrs);
    OBN_INFO("query_bind_status GET bind_list http=%ld body.len=%zu",
             resp.status_code, resp.body.size());

    if (http_code) *http_code = static_cast<unsigned int>(resp.status_code);
    if (http_body) *http_body = resp.body;

    // Stock probe returns 0 even on HTTP 502 when the transport completed.
    if (!resp.error.empty()) {
        return BAMBU_NETWORK_ERR_QUERY_BIND_INFO_FAILED;
    }
    fire_http_error(agent, resp.status_code, resp.body);
    return BAMBU_NETWORK_SUCCESS;
}

int modify_printer_name(Agent* agent, const std::string& dev_id,
                        const std::string& dev_name)
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
    fire_http_error(agent, resp.status_code, resp.body);
    if (!resp.error.empty()) return BAMBU_NETWORK_ERR_MODIFY_PRINTER_NAME_FAILED;
    if (http_json_success(resp.body, resp.status_code)) return BAMBU_NETWORK_SUCCESS;
    return BAMBU_NETWORK_ERR_MODIFY_PRINTER_NAME_FAILED;
}

int unbind_device(Agent* agent, const std::string& dev_id)
{
    if (!agent || !agent->user_logged_in()) return BAMBU_NETWORK_ERR_UNBIND_FAILED;
    auto hdrs = agent->cloud_api_http_headers();
    // Stock: DELETE /v1/iot-service/api/user/bind body {"dev_id","force":false}
    const std::string url = api_base(agent) + "/v1/iot-service/api/user/bind";
    std::ostringstream body;
    body << '{'
         << "\"dev_id\":" << obn::json::escape(dev_id) << ','
         << "\"force\":false}";
    auto resp = http_delete_json(url, body.str(), hdrs);
    OBN_INFO("unbind DELETE /user/bind http=%ld", resp.status_code);
    fire_http_error(agent, resp.status_code, resp.body);
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

    const std::string mint_url =
        api_base(agent) + "/v1/user-service/user/ticket";
    auto mint = obn::http::get_json(mint_url, hdrs);
    OBN_DEBUG("request_web_sso_ticket GET user/ticket -> %ld", mint.status_code);
    fire_http_error(agent, mint.status_code, mint.body);
    if (!mint.error.empty() || mint.status_code < 200 || mint.status_code >= 300)
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    std::string t = extract_ticket_from_json(mint.body);
    if (t.empty()) return BAMBU_NETWORK_ERR_INVALID_RESULT;

    std::ostringstream bind_body;
    bind_body << "{\"ticket\":" << obn::json::escape(t) << "}";
    const std::string bind_url =
        api_base(agent) + "/v1/user-service/my/ticket/" + obn::http::url_encode(t);
    auto bind = obn::http::post_json(bind_url, bind_body.str(), hdrs);
    OBN_DEBUG("request_web_sso_ticket POST my/ticket/%s -> %ld",
              t.c_str(), bind.status_code);
    fire_http_error(agent, bind.status_code, bind.body);
    if (!bind.error.empty() || bind.status_code < 200 || bind.status_code >= 300)
        return BAMBU_NETWORK_ERR_INVALID_RESULT;

    if (ticket) *ticket = std::move(t);
    return BAMBU_NETWORK_SUCCESS;
}

} // namespace cloud_bind
