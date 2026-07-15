#pragma once

// Filament-spool / filament-config endpoints on Bambu's cloud.
//
// Bambu's "Filament Manager" tab in Studio is a WebView dashboard
// that lets the user track every spool they own (RFID, vendor, type,
// remaining weight, color, etc.). The list lives in the cloud under
// `design-user-service/my/filament/v2`, and `wgtFilaManagerCloudClient`
// in Studio drives all reads/writes through the network plugin's five
// `bambu_network_*_filament_*` exports.
//
// This module is the cloud half: all HTTP I/O against
// `https://api.bambulab.<region>/v1/design-user-service/...`. The ABI
// layer (`src/abi_filament.cpp`) is a thin shim that just forwards
// FilamentQueryParams / FilamentDeleteParams shaped requests in here
// and hands the raw response body back to Studio for parsing.
//
// MITM-observed shape (snapshot from a stock 02.06.01.50 plugin):
//   GET    /my/filament/v2?offset=0&limit=20      → {"hits":[...]}
//   POST   /my/filament/v2                        → {} (200) — Studio
//                                                   re-LISTs to learn id
//   PUT    /my/filament/v2  body:{id,filamentName,...patch}
//                                                 → {"filamentV2":{...}}
//   DELETE /my/filament/v2/batch  body:{"ids":[...]}
//                                                 → {} (200)
//   GET    /filament/config                       → {"categories":[...],
//                                                    "filamentSettings":[...]}
// Authentication: `Authorization: Bearer <access_token>` from the
// session, content-type application/json. UA / X-BBL-* headers are
// already set by the global extra_http_headers wired via
// `bambu_network_set_extra_http_header`.

#include "obn/bambu_networking.hpp"

#include <string>

namespace BBL {
struct FilamentQueryParams;
struct FilamentDeleteParams;
#if ABI_VERSION >= 0x020801
struct AmsSyncParams;
#endif
}

namespace obn {
class Agent;

namespace cloud_filament {

// GET /my/filament/v2?<params>. Writes the raw JSON body into out_body
// (whatever the server returned, including the `{"hits":[...]}` envelope).
// Returns BAMBU_NETWORK_SUCCESS on HTTP 2xx, else
// BAMBU_NETWORK_ERR_GET_FILAMENTS_FAILED.
int list(Agent* agent, const BBL::FilamentQueryParams& params,
         std::string* out_body);

// POST /my/filament/v2. `request_body` is the JSON Studio assembled
// (CreateFilamentV2Req), forwarded verbatim. The server replies with
// `{}` on success and Studio re-lists to learn the new spool id.
// Returns BAMBU_NETWORK_SUCCESS on HTTP 2xx else
// BAMBU_NETWORK_ERR_CREATE_FILAMENT_FAILED.
int create(Agent* agent, const std::string& request_body,
           std::string* out_body);

// PUT /my/filament/v2. `spool_id` is informational (the server reads
// the id out of the JSON body); we keep it for the log line.
// Returns BAMBU_NETWORK_SUCCESS / BAMBU_NETWORK_ERR_UPDATE_FILAMENT_FAILED.
int update(Agent* agent, const std::string& spool_id,
           const std::string& request_body, std::string* out_body);

// DELETE /my/filament/v2/batch. Body is built from `params.ids` and
// `params.rfids` ({"ids":[...]} / {"RFIDs":[...]}). Returns
// BAMBU_NETWORK_SUCCESS / BAMBU_NETWORK_ERR_DELETE_FILAMENT_FAILED.
int batch_delete(Agent* agent, const BBL::FilamentDeleteParams& params,
                 std::string* out_body);

// GET /filament/config. Returns the category list and the cloud's
// canonical filament catalogue (vendor/type/name/id quadruples).
// Returns BAMBU_NETWORK_SUCCESS / BAMBU_NETWORK_ERR_GET_FILAMENT_CONFIG_FAILED.
int config(Agent* agent, std::string* out_body);

#if ABI_VERSION >= 0x020801
// POST /my/filament/v2/ams/sync. Studio calls this when AMS mount fields
// change (insert / remove / move spool) so the cloud catalogue keeps the
// latest in-printer snapshot. MITM shape:
//   {"devId":"...","items":[{RFID, amsSn, slotId, ...}]}
// Response is forwarded verbatim (createdRFIDs/results/filamentV2/hits).
int sync_ams(Agent* agent, const BBL::AmsSyncParams& params,
             std::string* out_body);
#endif

} // namespace cloud_filament
} // namespace obn
