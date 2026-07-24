#include <string>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/config.hpp"
#include "obn/log.hpp"

using obn::as_agent;

namespace {
void log_print_params(const char* which, const BBL::PrintParams& p)
{
    OBN_INFO("%s dev=%s ip=%s ssl_mqtt=%d ssl_ftp=%d task=%s plate=%d ams=%s 3mf=%s md5=%s",
             which, p.dev_id.c_str(), p.dev_ip.c_str(), p.use_ssl_for_mqtt, p.use_ssl_for_ftp,
             p.task_name.c_str(), p.plate_index,
             p.ams_mapping.c_str(),
             p.ftp_file.c_str(), p.ftp_file_md5.c_str());
}

const char* cloud_print_mode_name(obn::config::CloudPrintMode m)
{
    switch (m) {
    case obn::config::CloudPrintMode::CloudOnly:   return "cloud_only";
    case obn::config::CloudPrintMode::TryLanFirst: return "try_lan_first";
    case obn::config::CloudPrintMode::LanOnly:     return "lan_only";
    }
    return "cloud_only";
}
} // namespace

OBN_ABI int bambu_network_start_print(void* agent,
                                      BBL::PrintParams      params,
                                      BBL::OnUpdateStatusFn update_fn,
                                      BBL::WasCancelledFn   cancel_fn,
                                      BBL::OnWaitFn         /*wait_fn*/)
{
    log_print_params("start_print", params);
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;

    const auto mode = obn::config::current().cloud_print;
    if (mode == obn::config::CloudPrintMode::LanOnly) {
        OBN_WARN("start_print: refused by cloud_print=lan_only");
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_INVALID_HANDLE,
                                 "cloud_print=lan_only");
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }
    return a->run_cloud_print_job(params, update_fn, cancel_fn,
                                  /*use_lan_channel=*/false);
}

OBN_ABI int bambu_network_start_local_print_with_record(void* agent,
                                                        BBL::PrintParams      params,
                                                        BBL::OnUpdateStatusFn update_fn,
                                                        BBL::WasCancelledFn   cancel_fn,
                                                        BBL::OnWaitFn         /*wait_fn*/)
{
    log_print_params("start_local_print_with_record", params);
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;

    const auto mode = obn::config::current().cloud_print;
    if (mode == obn::config::CloudPrintMode::TryLanFirst ||
        mode == obn::config::CloudPrintMode::LanOnly) {
        OBN_INFO("start_local_print_with_record: cloud_print=%s → local print",
                 cloud_print_mode_name(mode));
        // Success → 0 (Studio does not fall back). Failure → <0 so Studio
        // may call start_print (allowed only when cloud_print=try_lan_first).
        return a->run_local_print_job(params, update_fn, cancel_fn);
    }
    return a->run_cloud_print_job(params, update_fn, cancel_fn,
                                  /*use_lan_channel=*/true);
}

OBN_ABI int bambu_network_start_send_gcode_to_sdcard(void* agent,
                                                     BBL::PrintParams      params,
                                                     BBL::OnUpdateStatusFn update_fn,
                                                     BBL::WasCancelledFn   cancel_fn,
                                                     BBL::OnWaitFn         /*wait_fn*/)
{
    log_print_params("start_send_gcode_to_sdcard", params);
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    return a->run_send_gcode_to_sdcard(params, update_fn, cancel_fn);
}

OBN_ABI int bambu_network_start_local_print(void* agent,
                                            BBL::PrintParams      params,
                                            BBL::OnUpdateStatusFn update_fn,
                                            BBL::WasCancelledFn   cancel_fn)
{
    log_print_params("start_local_print", params);
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    return a->run_local_print_job(params, update_fn, cancel_fn);
}

OBN_ABI int bambu_network_start_sdcard_print(void* agent,
                                             BBL::PrintParams      params,
                                             BBL::OnUpdateStatusFn update_fn,
                                             BBL::WasCancelledFn   cancel_fn)
{
    log_print_params("start_sdcard_print", params);
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    return a->run_sdcard_print_job(params, update_fn, cancel_fn);
}
