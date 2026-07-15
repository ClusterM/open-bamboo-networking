#include <string>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/cloud_filament.hpp"

using obn::as_agent;

// ABI shims for the Filament Manager cloud endpoints. The work happens
// inside `obn::cloud_filament::*`; this file just resolves the agent
// pointer and forwards.

OBN_ABI int bambu_network_get_filament_spools(void* agent,
                                              BBL::FilamentQueryParams params,
                                              std::string* http_body)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    return obn::cloud_filament::list(a, params, http_body);
}

OBN_ABI int bambu_network_create_filament_spool(void* agent,
                                                std::string request_body,
                                                std::string* http_body)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    return obn::cloud_filament::create(a, request_body, http_body);
}

OBN_ABI int bambu_network_update_filament_spool(void* agent,
                                                std::string spool_id,
                                                std::string request_body,
                                                std::string* http_body)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    return obn::cloud_filament::update(a, spool_id, request_body, http_body);
}

OBN_ABI int bambu_network_delete_filament_spools(void* agent,
                                                 BBL::FilamentDeleteParams params,
                                                 std::string* http_body)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    return obn::cloud_filament::batch_delete(a, params, http_body);
}

OBN_ABI int bambu_network_get_filament_config(void* agent,
                                              std::string* http_body)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    return obn::cloud_filament::config(a, http_body);
}

#if ABI_VERSION >= 0x020801

OBN_ABI int bambu_network_sync_ams_filaments(void* agent,
                                              BBL::AmsSyncParams params,
                                              std::string* http_body)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    return obn::cloud_filament::sync_ams(a, params, http_body);
}

#endif
