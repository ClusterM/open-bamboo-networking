#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/cloud_presets.hpp"
#include "obn/log.hpp"

using obn::as_agent;

namespace {

// Studio inspects exactly four fields on the metadata map the CheckFn
// receives (type / name / setting_id / updated_time). The key names
// are the BBL_JSON_KEY_* macros in Studio's Preset.hpp.
std::map<std::string, std::string>
meta_to_check_map(const obn::cloud_presets::Meta& m)
{
    std::map<std::string, std::string> out;
    out[IOT_JSON_KEY_TYPE]         = m.type;
    out[IOT_JSON_KEY_NAME]         = m.name;
    out[IOT_JSON_KEY_SETTING_ID]   = m.setting_id;
    out[IOT_JSON_KEY_UPDATED_TIME] = std::to_string(m.updated_time_unix);
    return out;
}

// Drive the common sync core shared by get_setting_list and
// get_setting_list2. The only difference is whether a per-item
// "should we download this?" check exists; when it's absent we
// behave as if CheckFn always said "yes".
int sync_user_presets(obn::Agent*          a,
                      const std::string&   bundle_version,
                      BBL::CheckFn         chk_fn,
                      BBL::ProgressFn      pro_fn,
                      BBL::WasCancelledFn  cancel_fn)
{
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;

    std::vector<obn::cloud_presets::Meta> metas;
    int rc = obn::cloud_presets::list(a, bundle_version, &metas);
    if (rc != BAMBU_NETWORK_SUCCESS) {
        if (pro_fn) pro_fn(100);
        return rc;
    }

    a->preset_cache_reset();
    const int total = static_cast<int>(metas.size());
    if (total == 0) {
        if (pro_fn) pro_fn(100);
        return BAMBU_NETWORK_SUCCESS;
    }

    int done = 0;
    for (const auto& m : metas) {
        if (cancel_fn && cancel_fn()) return BAMBU_NETWORK_ERR_CANCELED;

        bool want = true;
        if (chk_fn) want = chk_fn(meta_to_check_map(m));

        if (want) {
            std::map<std::string, std::string> values;
            int gr = obn::cloud_presets::get_full(a, m.setting_id, &values);
            if (gr == BAMBU_NETWORK_SUCCESS && !values.empty()) {
                // Make sure the values_map has everything the Studio
                // loader is going to look at (type/setting_id are
                // always present in the envelope; inject defensively).
                if (values.find(IOT_JSON_KEY_TYPE) == values.end() ||
                    values[IOT_JSON_KEY_TYPE].empty())
                    values[IOT_JSON_KEY_TYPE] = m.type;
                if (values.find(IOT_JSON_KEY_SETTING_ID) == values.end() ||
                    values[IOT_JSON_KEY_SETTING_ID].empty())
                    values[IOT_JSON_KEY_SETTING_ID] = m.setting_id;
                if (values.find(IOT_JSON_KEY_NAME) == values.end() ||
                    values[IOT_JSON_KEY_NAME].empty())
                    values[IOT_JSON_KEY_NAME] = m.name;
                if (values.find(IOT_JSON_KEY_VERSION) == values.end() ||
                    values[IOT_JSON_KEY_VERSION].empty())
                    values[IOT_JSON_KEY_VERSION] = m.version;
                if (!m.inherits.empty() &&
                    (values.find(IOT_JSON_KEY_INHERITS) == values.end() ||
                     values[IOT_JSON_KEY_INHERITS].empty())) {
                    values[IOT_JSON_KEY_INHERITS] = m.inherits;
                }
                if (m.type == IOT_FILAMENT_STRING && !m.filament_id.empty() &&
                    (values.find(IOT_JSON_KEY_FILAMENT_ID) == values.end() ||
                     values[IOT_JSON_KEY_FILAMENT_ID].empty())) {
                    values[IOT_JSON_KEY_FILAMENT_ID] = m.filament_id;
                }
                a->preset_cache_put(m.name, std::move(values));
            } else {
                OBN_WARN("preset sync: skipped %s (get_full rc=%d)",
                         m.setting_id.c_str(), gr);
            }
        }

        ++done;
        if (pro_fn) {
            int pct = total > 0 ? (done * 100) / total : 100;
            pro_fn(std::min(99, pct));
        }
    }
    if (pro_fn) pro_fn(100);
    return BAMBU_NETWORK_SUCCESS;
}

} // namespace

// Studio calls this from reload_settings() right after
// get_setting_list2 finishes, so we just hand back everything our
// sync loop cached. Drain so a second call on the same sync cycle
// returns empty (matches stock behaviour where the stock plugin's
// cache is invalidated by the PresetBundle load).
OBN_ABI int bambu_network_get_user_presets(
    void* agent,
    std::map<std::string, std::map<std::string, std::string>>* user_presets)
{
    auto* a = as_agent(agent);
    if (!a) {
        if (user_presets) user_presets->clear();
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }
    auto drained = a->preset_cache_drain();
    OBN_INFO("bambu_network_get_user_presets: returning %zu presets",
             drained.size());
    if (user_presets) *user_presets = std::move(drained);
    return BAMBU_NETWORK_SUCCESS;
}

// Called from sync_preset() on the "create a new cloud preset" path.
// values_map already has every serialized option; on success we
// return the new setting_id and refresh values_map["updated_time"].
OBN_IGNORE_RETURN_CXX_IN_EXTERN_C_BEGIN
OBN_ABI std::string bambu_network_request_setting_id(
    void* agent,
    std::string  name,
    std::map<std::string, std::string>* values_map,
    unsigned int* http_code)
{
    if (http_code) *http_code = 0;
    auto* a = as_agent(agent);
    if (!a || !values_map) return {};
    return obn::cloud_presets::create(a, name, *values_map, http_code);
}
OBN_IGNORE_RETURN_CXX_IN_EXTERN_C_END

// Called from sync_preset() on the "update existing cloud preset"
// path. Returns 0 on success; refreshes values_map["updated_time"].
OBN_ABI int bambu_network_put_setting(void*         agent,
                                      std::string   setting_id,
                                      std::string   name,
                                      std::map<std::string, std::string>* values_map,
                                      unsigned int* http_code)
{
    if (http_code) *http_code = 0;
    auto* a = as_agent(agent);
    if (!a || !values_map) return BAMBU_NETWORK_ERR_PUT_SETTING_FAILED;
    return obn::cloud_presets::update(a, setting_id, name, *values_map, http_code);
}

// Older ABI: list and download every user preset unconditionally.
// get_setting_list2 is the one Studio actually uses now, but we still
// honour this for completeness.
OBN_ABI int bambu_network_get_setting_list(void* agent,
                                           std::string         bundle_version,
                                           BBL::ProgressFn     pro_fn,
                                           BBL::WasCancelledFn cancel_fn)
{
    OBN_INFO("bambu_network_get_setting_list(version=%s)", bundle_version.c_str());
    return sync_user_presets(as_agent(agent), bundle_version,
                             /*chk_fn=*/{}, pro_fn, cancel_fn);
}

// Studio's preferred variant: lists user presets, asks us back via
// CheckFn whether each one needs downloading, and only then fetches
// the full body.
OBN_ABI int bambu_network_get_setting_list2(void*               agent,
                                            std::string         bundle_version,
                                            BBL::CheckFn        chk_fn,
                                            BBL::ProgressFn     pro_fn,
                                            BBL::WasCancelledFn cancel_fn)
{
    OBN_INFO("bambu_network_get_setting_list2(version=%s)", bundle_version.c_str());
    return sync_user_presets(as_agent(agent), bundle_version,
                             chk_fn, pro_fn, cancel_fn);
}

OBN_ABI int bambu_network_delete_setting(void* agent, std::string setting_id)
{
    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    return obn::cloud_presets::del(a, setting_id);
}
