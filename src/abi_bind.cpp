#include <string>
#include <vector>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/bind_cloud.hpp"
#include "obn/log.hpp"

using obn::as_agent;

OBN_ABI int bambu_network_ping_bind(void* agent, std::string ping_code)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_BIND_FAILED;
    OBN_INFO("ping_bind code.len=%zu", ping_code.size());
    return obn::cloud_bind::ping_bind(a, ping_code);
}

OBN_ABI int bambu_network_bind_detect(void*       agent,
                                      std::string dev_ip,
                                      std::string sec_link,
                                      BBL::detectResult& detect)
{
    auto* a = as_agent(agent);
    if (!a) return -1;
    OBN_INFO("bind_detect dev_ip=%s sec_link=%s", dev_ip.c_str(), sec_link.c_str());
    // Wait ~4.5s for an SSDP NOTIFY from the printer on UDP :2021. No access
    // code is available in this ABI — same as the stock plugin, which also
    // discovers identity from LAN broadcast rather than MQTT here.
    return a->lookup_bind_detect(dev_ip, detect, 4500);
}

OBN_ABI int bambu_network_bind(void*       agent,
                               std::string dev_ip,
                               std::string dev_id,
#if ABI_VERSION >= 0x020800
                               std::string dev_model,
#endif
                               std::string sec_link,
                               std::string timezone,
                               bool        improved,
                               BBL::OnUpdateStatusFn update_fn)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_BIND_FAILED;
#if ABI_VERSION >= 0x020800
    OBN_INFO("bind dev_ip=%s dev_id=%s dev_model=%s sec_link=%s tz=%s improved=%d",
             dev_ip.c_str(),
             dev_id.c_str(),
             dev_model.c_str(),
             sec_link.c_str(),
             timezone.c_str(),
             improved);
#else
    OBN_INFO("bind dev_ip=%s dev_id=%s sec_link=%s tz=%s improved=%d",
             dev_ip.c_str(),
             dev_id.c_str(),
             sec_link.c_str(),
             timezone.c_str(),
             improved);
#endif
    // TODO: dev_model (get_show_printer_type()) is required by the 02.08.00.xx ABI signature but usage is unknown for now.

    return obn::cloud_bind::bind_lan_to_account(
        a, dev_ip, dev_id, sec_link, timezone, improved, std::move(update_fn));
}

OBN_ABI int bambu_network_unbind(void* agent, std::string dev_id)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_UNBIND_FAILED;
    OBN_INFO("unbind dev_id=%s", dev_id.c_str());
    return obn::cloud_bind::unbind_device(a, dev_id);
}

OBN_ABI int bambu_network_request_bind_ticket(void* agent, std::string* ticket)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_RESULT;
    OBN_DEBUG("request_bind_ticket");
    return obn::cloud_bind::request_web_sso_ticket(a, ticket);
}

OBN_ABI int bambu_network_query_bind_status(void* agent,
                                            std::vector<std::string> query_list,
                                            unsigned int* http_code,
                                            std::string* http_body)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_QUERY_BIND_INFO_FAILED;
    OBN_DEBUG("query_bind_status count=%zu", query_list.size());
    return obn::cloud_bind::query_bind_status(a, query_list, http_code, http_body);
}

OBN_ABI int bambu_network_modify_printer_name(void*       agent,
                                               std::string dev_id,
                                               std::string dev_name)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_MODIFY_PRINTER_NAME_FAILED;
    OBN_INFO("modify_printer_name dev=%s name=%s", dev_id.c_str(), dev_name.c_str());
    return obn::cloud_bind::modify_printer_name(a, dev_id, dev_name);
}

OBN_ABI int bambu_network_report_consent(void* /*agent*/, std::string expand)
{
    OBN_DEBUG("report_consent %s", expand.c_str());
    return BAMBU_NETWORK_SUCCESS;
}
