#include <string>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/config.hpp"
#include "obn/log.hpp"
#include "obn/model_metadata.hpp"
#include "obn/print_route.hpp"

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
    case obn::config::CloudPrintMode::CloudForMakerWorldOnly:
        return "cloud_for_makerworld_only";
    }
    return "cloud_only";
}

// cloud_for_makerworld_only decides per job: a project downloaded from
// MakerWorld carries DesignModelId in 3D/3dmodel.model and is printed with a
// cloud record (so MakerWorld counts it), anything else stays on the LAN.
// The file decides; Studio's copy of the same tag (origin_model_id) only
// stands in when the file cannot be read.
obn::config::CloudPrintMode effective_mode(const char* which,
                                           const BBL::PrintParams& p)
{
    using obn::config::CloudPrintMode;
    const auto mode = obn::config::current().cloud_print;
    if (mode != CloudPrintMode::CloudForMakerWorldOnly) return mode;

    std::string design_id, err;
    const char* source = "file";
    if (!obn::model_metadata::makerworld_design_id(p.filename, &design_id, &err)) {
        OBN_WARN("%s: cloud_print=cloud_for_makerworld_only: cannot read %s of %s: %s",
                 which, obn::model_metadata::kModelMember, p.filename.c_str(),
                 err.c_str());
        design_id = p.origin_model_id;
        source    = "origin_model_id";
    }
    const CloudPrintMode out =
        design_id.empty() ? CloudPrintMode::LanOnly : CloudPrintMode::CloudOnly;
    if (design_id.empty()) {
        OBN_INFO("%s: cloud_print=cloud_for_makerworld_only: %s has no "
                 "DesignModelId (%s) -> %s",
                 which, p.filename.c_str(), source, cloud_print_mode_name(out));
    } else {
        OBN_INFO("%s: cloud_print=cloud_for_makerworld_only: %s DesignModelId=%s "
                 "(%s) -> %s",
                 which, p.filename.c_str(), design_id.c_str(), source,
                 cloud_print_mode_name(out));
    }
    return out;
}

// Shared by both print entry points; see obn/print_route.hpp. An attempt
// that is followed by another one reports its errors to the log only, so
// Studio does not show the failure of a print that then succeeds.
int run_print_routes(obn::Agent*                  a,
                     obn::print_route::Entry      entry,
                     const char*                  which,
                     const BBL::PrintParams&      params,
                     const BBL::OnUpdateStatusFn& update_fn,
                     const BBL::WasCancelledFn&   cancel_fn)
{
    namespace pr = obn::print_route;
    const auto mode   = effective_mode(which, params);
    const bool lan_ok = pr::lan_step_allowed(params.comments);
    const auto routes = pr::routes(mode, entry, lan_ok);

    std::string plan;
    for (auto r : routes) plan += std::string(plan.empty() ? "" : ",") + pr::route_name(r);
    OBN_INFO("%s: cloud_print=%s comments='%s' -> routes [%s]", which,
             cloud_print_mode_name(mode), params.comments.c_str(), plan.c_str());

    if (routes.empty()) {
        const char* configured =
            cloud_print_mode_name(obn::config::current().cloud_print);
        OBN_WARN("%s: refused by cloud_print=%s", which, configured);
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_INVALID_HANDLE,
                                 std::string("cloud_print=") + configured);
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }

    struct HeldError {
        bool        set = false;
        int         stage = 0;
        int         code  = 0;
        std::string info;
    };

    int ret = BAMBU_NETWORK_ERR_INVALID_HANDLE;
    for (size_t i = 0; i < routes.size(); ++i) {
        const pr::Route route = routes[i];
        const bool      last  = i + 1 == routes.size();
        const char*     name  = pr::route_name(route);

        HeldError             held;
        BBL::OnUpdateStatusFn attempt_fn = update_fn;
        if (!last && update_fn) {
            attempt_fn = [&update_fn, &held, which, name](int stage, int code, std::string info) {
                if (pr::is_error_update(stage, code)) {
                    OBN_WARN("%s: %s attempt: stage=%d code=%d info=%s", which, name,
                             stage, code, info.c_str());
                    held = {true, stage, code, std::move(info)};
                    return;
                }
                update_fn(stage, code, std::move(info));
            };
        }

        switch (route) {
        case pr::Route::LanRecord:
            ret = a->run_cloud_print_job(params, attempt_fn, cancel_fn,
                                         /*use_lan_channel=*/true);
            break;
        case pr::Route::Local:
            ret = a->run_local_print_job(params, attempt_fn, cancel_fn);
            break;
        case pr::Route::Cloud:
            ret = a->run_cloud_print_job(params, attempt_fn, cancel_fn,
                                         /*use_lan_channel=*/false);
            break;
        }
        if (ret >= 0) return ret;
        if (last) break;
        if (pr::stops_fallback(ret) || (cancel_fn && cancel_fn())) {
            OBN_WARN("%s: %s failed (%d), not falling back", which, name, ret);
            if (update_fn && held.set) update_fn(held.stage, held.code, held.info);
            return ret;
        }
        OBN_WARN("%s: %s failed (%d), trying %s", which, name, ret,
                 pr::route_name(routes[i + 1]));
    }
    return ret;
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
    return run_print_routes(a, obn::print_route::Entry::StartPrint, "start_print",
                            params, update_fn, cancel_fn);
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
    return run_print_routes(a, obn::print_route::Entry::WithRecord,
                            "start_local_print_with_record", params, update_fn, cancel_fn);
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
