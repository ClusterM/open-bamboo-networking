#pragma once

// User-preset synchronisation against Bambu's cloud "slicer setting"
// endpoint. This is section 6.9 of NETWORK_PLUGIN.md.
//
// The stock plugin treats the cloud only as a metadata store: it lists
// { setting_id, name, update_time, ... } and relies on matching files
// on disk for the actual contents. That's fine when the presets were
// authored on this machine, but it breaks cross-device sync: if the
// local preset cache is wiped, Studio downloads the metadata but has
// no file to pair it with, and the preset silently vanishes from the
// UI.
//
// We fix that by also calling `GET /v1/iot-service/api/slicer/setting
// /<setting_id>`, which returns the full config (`setting` map) the
// server was holding all along. Studio's `PresetCollection::
// load_user_preset` happily consumes the flattened values_map we build
// from that response, so after this path runs once on a fresh machine
// the user's cloud-stored presets appear just as they did on the
// machine where they were created.
//
// All endpoints live on `api.bambulab.com` (or `api.bambulab.cn` for
// region=CN) under `/v1/iot-service/api/slicer/setting`. Authentication
// is a simple `Authorization: Bearer <access_token>` header; the
// `X-BBL-*` fingerprint headers the stock plugin sends are not
// required by the server (confirmed by direct curl probes) so we don't
// bother replicating them here.

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace obn {
class Agent;

namespace cloud_presets {

struct Meta {
    std::string type;          // "print" | "printer" | "filament"
    std::string setting_id;    // "PPUS..", "PFUS..", "PMUS.."
    std::string name;
    std::string version;       // bundle version reported when uploaded
    std::string base_id;       // empty when the preset is a custom root
    std::string filament_id;   // filament only; empty otherwise
    std::string inherits;      // may be empty
    std::string update_time;   // "YYYY-MM-DD HH:MM:SS" (UTC) as returned by server
    std::int64_t updated_time_unix = 0; // same moment, seconds since epoch
    bool        is_public = false;
};

// Fetch the metadata list of user presets (public=false). `bundle_version`
// is sent as ?version=... - the server uses it to filter out presets the
// client wouldn't be able to load. Returns BAMBU_NETWORK_* code.
int list(Agent* agent,
         const std::string&       bundle_version,
         std::vector<Meta>*       out);

// Fetch one preset fully, parse it, and write a `values_map` in the
// shape `PresetCollection::load_user_preset()` expects: every key/value
// from `setting` (stringified), plus `setting_id`, `name`, `type`,
// `version`, `base_id`, `filament_id`, `updated_time` (unix seconds
// as string), `user_id` (from the authenticated session). The sync
// loop may merge list metadata (`setting_id`, `inherits`, …) when GET
// returns nulls or omits keys Studio still requires. Returns
// BAMBU_NETWORK_* code.
int get_full(Agent*                              agent,
             const std::string&                  setting_id,
             std::map<std::string, std::string>* values_map);

// Create a new user preset. `values_map` is the "serialized preset
// options + metadata" bundle produced by Studio's
// PresetBundle::get_differed_values_to_update(): every preset option
// as a string, plus the metadata keys (`version`, `base_id` or
// `filament_id`, `updated_time`, `type`, and the extruder id/variant).
//
// On success (`*http_code == 200`) the new setting_id is returned and
// values_map["updated_time"] is refreshed to the server's timestamp
// (unix seconds as string). On failure the function parses the
// server-side error code (if any) into values_map["code"] so Studio's
// existing `values_map["code"] == "14"` preset-limit check continues
// to work.
//
// Returns the new setting_id on success, "" on failure.
std::string create(Agent*                              agent,
                   const std::string&                  name,
                   std::map<std::string, std::string>& values_map,
                   unsigned int*                       http_code);

// Update an existing preset. Same shape of values_map as create();
// returns BAMBU_NETWORK_* code and refreshes values_map["updated_time"]
// on 200. Sets values_map["code"] on an error payload (so the
// limit/cap handling in sync_preset still works).
int update(Agent*                              agent,
           const std::string&                  setting_id,
           const std::string&                  name,
           std::map<std::string, std::string>& values_map,
           unsigned int*                       http_code);

// Delete a preset. Idempotent on the server: returns 200 even when the
// id doesn't exist. Returns BAMBU_NETWORK_SUCCESS on HTTP 2xx.
int del(Agent* agent, const std::string& setting_id);

} // namespace cloud_presets
} // namespace obn
