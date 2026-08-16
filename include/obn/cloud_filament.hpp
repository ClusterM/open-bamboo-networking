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
#if ABI_VERSION >= 0x020802
struct SlotMappingsSyncParams;
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

#if ABI_VERSION >= 0x020802
// POST /my/filament/v2/slot-mappings/sync. Studio's Filament Manager calls
// this to bind a manually-tracked spool to an AMS slot, or to unbind one
// after the tray is emptied. MITM shape (stock 02.08.02.54):
//   {"devId":"...","mappings":[{"amsId":0,"amsSn":"...","amsType":3,
//                               "rfid":null,"slotId":"1","spoolId":null}]}
// Studio does not parse the response; it only logs it.
int sync_slot_mappings(Agent* agent, const BBL::SlotMappingsSyncParams& params,
                       std::string* out_body);
#endif

// Request-body serializers, exposed for tests that pin the wire format
// against MITM captures of the stock plugin.
namespace detail {
#if ABI_VERSION >= 0x020801
std::string build_ams_sync_body(const BBL::AmsSyncParams& params);
#endif
#if ABI_VERSION >= 0x020802
// Emits item keys in ASCII order (amsId, amsSn, amsType, rfid, slotId,
// spoolId), matching stock. `rfid` and `spoolId` are the two nullable
// fields: an empty rfid and a zero spoolId serialize as JSON null, which
// is how an unbind is expressed. amsId / amsType keep a literal 0.
std::string build_slot_mappings_body(const BBL::SlotMappingsSyncParams& params);

// True when every mapping passes the checks stock applies before it will
// touch the network: non-empty amsSn and slotId, and non-negative amsId,
// amsType and spoolId. A failing item makes stock return
// BAMBU_NETWORK_ERR_SLOT_MAPPINGS_SYNC_FAILED without issuing a request.
// An empty devId or an empty mappings array both pass — stock posts those.
bool slot_mappings_valid(const BBL::SlotMappingsSyncParams& params);
#endif
} // namespace detail

} // namespace cloud_filament
} // namespace obn
