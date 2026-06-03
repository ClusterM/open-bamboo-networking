#include <string>
#include <vector>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/config.hpp"
#include "obn/log.hpp"

using obn::as_agent;

// Server connectivity -------------------------------------------------------

OBN_ABI int bambu_network_connect_server(void* agent)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    if (obn::config::current().block_cloud) {
        OBN_DEBUG("bambu_network_connect_server: blocked by block_cloud");
        return BAMBU_NETWORK_SUCCESS;
    }
    int rc = a->connect_cloud();
    OBN_INFO("bambu_network_connect_server -> %d", rc);
    return rc;
}

OBN_ABI bool bambu_network_is_server_connected(void* agent)
{
    auto* a = as_agent(agent);
    if (!a) return false;
    return a->cloud_connected();
}

OBN_ABI int bambu_network_refresh_connection(void* agent)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    if (obn::config::current().block_cloud) return BAMBU_NETWORK_SUCCESS;
    OBN_DEBUG("bambu_network_refresh_connection");
    return a->cloud_refresh();
}

// Topic subscriptions -------------------------------------------------------

// Studio calls start_subscribe("app") / stop_subscribe("app") from its
// IDLE hook to tell the cloud "the Studio window is focused / blurred".
// On Bambu's side this is a keepalive-ish hint that influences how
// aggressively the broker streams pushes; it's not tied to any
// specific MQTT topic. We just log it and move on.
OBN_ABI int bambu_network_start_subscribe(void* /*agent*/, std::string module)
{
    OBN_DEBUG("bambu_network_start_subscribe(%s) [no-op]", module.c_str());
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_stop_subscribe(void* /*agent*/, std::string module)
{
    OBN_DEBUG("bambu_network_stop_subscribe(%s) [no-op]", module.c_str());
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_add_subscribe(void* agent, std::vector<std::string> dev_list)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    if (obn::config::current().block_cloud) {
        OBN_DEBUG("bambu_network_add_subscribe: blocked by block_cloud");
        return BAMBU_NETWORK_SUCCESS;
    }
    OBN_INFO("bambu_network_add_subscribe(%zu devs)", dev_list.size());
    return a->cloud_add_subscribe(dev_list);
}

OBN_ABI int bambu_network_del_subscribe(void* agent, std::vector<std::string> dev_list)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    if (obn::config::current().block_cloud) {
        OBN_DEBUG("bambu_network_del_subscribe: blocked by block_cloud");
        return BAMBU_NETWORK_SUCCESS;
    }
    OBN_INFO("bambu_network_del_subscribe(%zu devs)", dev_list.size());
    return a->cloud_del_subscribe(dev_list);
}

OBN_ABI void bambu_network_enable_multi_machine(void* /*agent*/, bool /*enable*/)
{
    // Multi-machine mode only controls whether Studio shows the multi-
    // device UI. No extra state on the plugin side.
}

// Send a command to a specific device. Studio invokes this from the
// device control path without knowing which transport is live (LAN
// direct vs cloud tunnel). Prefer the LAN session when it matches the
// target dev_id; otherwise route through cloud MQTT.
OBN_ABI int bambu_network_send_message(void* agent,
                                       std::string dev_id,
                                       std::string json_str,
                                       int         qos,
                                       int         /*flag*/)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    // Try LAN first: send_message_to_printer returns INVALID_HANDLE
    // when no LAN session matches the dev_id, in which case we fall
    // through to cloud (unless blocked).
    int rc = a->send_message_to_printer(dev_id, json_str, qos);
    if (rc != BAMBU_NETWORK_ERR_INVALID_HANDLE) return rc;
    if (obn::config::current().block_cloud) {
        OBN_DEBUG("bambu_network_send_message: cloud fallback blocked");
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }
    return a->cloud_send_message(dev_id, json_str, qos);
}
