#pragma once

// Which delivery attempts start_print / start_local_print_with_record make,
// per cloud_print mode. Pure so tests can pin it (tests/print_route_test.cpp).
//
// Studio (every tag from v02.03.00.70 on) fills PrintParams::comments before
// the first send: "" when IP, access code and storage are present and the
// firmware supports LAN delivery, otherwise "no_ip" / "low_version" /
// "no_sdcard" / "no_password". Up to v02.09.01.70 it then tries
// start_local_print_with_record and, on failure, sets "upload_failed" /
// "failed(N)" before falling back to start_print. v02.09.02.62 dropped the
// _with_record step and calls start_print with the untouched comment, so an
// empty comment on start_print means no LAN attempt has happened yet.

#include "obn/bambu_networking.hpp"
#include "obn/config.hpp"

#include <string>
#include <vector>

namespace obn::print_route {

enum class Entry {
    StartPrint,
    WithRecord,
};

enum class Route {
    LanRecord, // run_cloud_print_job(use_lan_channel=true): FTPS + cloud record,
               // plus the S3 copy the printer downloads unless slim_cloud
    Local,     // run_local_print_job: FTPS + MQTT, no cloud record
    Cloud,     // run_cloud_print_job(use_lan_channel=false): full upload to S3
};

inline bool lan_step_allowed(const std::string& comments)
{
    return comments.empty();
}

// `mode` must already be resolved per job (cloud_for_makerworld_only maps to
// CloudOnly or LanOnly). An empty result means the entry point refuses.
// _with_record never adds the trailing Cloud step: the Studios that call it
// fall back to start_print themselves.
inline std::vector<Route> routes(obn::config::CloudPrintMode mode,
                                 Entry entry,
                                 bool lan_step_ok)
{
    using obn::config::CloudPrintMode;
    const bool lan_only = mode == CloudPrintMode::LanOnly ||
                          mode == CloudPrintMode::CloudForMakerWorldOnly;
    const Route lan     = mode == CloudPrintMode::CloudOnly ? Route::LanRecord : Route::Local;

    if (entry == Entry::WithRecord) return {lan};

    std::vector<Route> out;
    if (lan_step_ok) out.push_back(lan);
    if (!lan_only) out.push_back(Route::Cloud);
    return out;
}

inline const char* route_name(Route r)
{
    switch (r) {
    case Route::LanRecord: return "lan_record";
    case Route::Local:     return "local";
    case Route::Cloud:     return "cloud";
    }
    return "?";
}

// Failures no other route can fix; mirrors should_stop_without_fallback in
// Studio's PrintJob.cpp.
inline bool stops_fallback(int ret)
{
    return ret == BAMBU_NETWORK_ERR_CANCELED ||
           ret == BAMBU_NETWORK_SIGNED_ERROR ||
           ret == BAMBU_NETWORK_ERR_PRINT_WR_FILE_NOT_EXIST ||
           ret == BAMBU_NETWORK_ERR_PRINT_SP_FILE_NOT_EXIST ||
           ret == BAMBU_NETWORK_ERR_PRINT_WR_FILE_OVER_SIZE ||
           ret == BAMBU_NETWORK_ERR_PRINT_SP_FILE_OVER_SIZE ||
           ret == BAMBU_NETWORK_ERR_PRINT_LP_FILE_OVER_SIZE;
}

// Studio's update_fn treats these as errors and records them for the dialog.
inline bool is_error_update(int stage, int code)
{
    return code > 100 || code < 0 || stage == BBL::PrintingStageERROR;
}

} // namespace obn::print_route
