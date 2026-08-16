#include "print_params_io.hpp"

#include <fstream>
#include <stdexcept>
#include <unordered_set>

#include <nlohmann/json.hpp>

namespace obn::plugin_runner {

namespace {

using json = nlohmann::json;

// Per-type setters. Each returns true if it actually mutated `dst`; the
// caller decides what to log.
bool set_string(const json& src, const char* key, std::string& dst,
                std::vector<std::string>& warnings)
{
    auto it = src.find(key);
    if (it == src.end()) return false;
    if (!it->is_string()) {
        warnings.emplace_back(std::string("'") + key + "' must be a string, ignoring");
        return false;
    }
    dst = it->get<std::string>();
    return true;
}

bool set_int(const json& src, const char* key, int& dst,
             std::vector<std::string>& warnings)
{
    auto it = src.find(key);
    if (it == src.end()) return false;
    if (!it->is_number_integer()) {
        warnings.emplace_back(std::string("'") + key + "' must be an integer, ignoring");
        return false;
    }
    dst = it->get<int>();
    return true;
}

bool set_bool(const json& src, const char* key, bool& dst,
              std::vector<std::string>& warnings)
{
    auto it = src.find(key);
    if (it == src.end()) return false;
    if (!it->is_boolean()) {
        warnings.emplace_back(std::string("'") + key + "' must be a boolean, ignoring");
        return false;
    }
    dst = it->get<bool>();
    return true;
}

// Allow-list of every PrintParams field this loader knows how to set.
// Anything else in the JSON triggers a `params_warning` event so users
// notice typos instead of silently sending defaults. Keep in sync with
// `BBL::PrintParams` in include/obn/bambu_networking.hpp (the snapshots
// under tools/abi_snapshot/v<MM.mm.pp>/ are the canonical record per
// ABI version) and with the per-field setter calls in
// load_print_params_overrides() below.
const std::unordered_set<std::string> kKnownKeys = {
    "dev_id", "task_name", "project_name", "preset_name", "filename",
    "config_filename", "plate_index", "ftp_folder", "ftp_file",
    "ftp_file_md5", "nozzle_mapping", "ams_mapping", "ams_mapping2",
    "ams_mapping_info", "nozzles_info", "connection_type", "comments",
    "origin_profile_id", "stl_design_id", "origin_model_id",
    "print_type", "dst_file", "dev_name", "dev_ip", "use_ssl_for_ftp",
    "use_ssl_for_mqtt", "username", "password", "task_bed_leveling",
    "task_flow_cali", "task_vibration_cali", "task_layer_inspect",
    "task_record_timelapse",
#if ABI_VERSION >= 0x020503
    "task_timelapse_use_internal",
#endif
    "task_use_ams", "task_bed_type", "extra_options", "auto_bed_leveling",
    "auto_flow_cali", "auto_offset_cali",
#if ABI_VERSION >= 0x020400
    "extruder_cali_manual_mode",
#endif
    "task_ext_change_assist", "try_emmc_print",
#if ABI_VERSION >= 0x020701
    "svc_context",
#endif
#if ABI_VERSION >= 0x020801
    "slicer_uid",
#endif
#if ABI_VERSION >= 0x020802
    "queue_plate_id",
#endif
};

void warn_unknown(const json& src, std::vector<std::string>& warnings)
{
    for (auto it = src.begin(); it != src.end(); ++it) {
        const std::string& key = it.key();
        if (kKnownKeys.find(key) == kKnownKeys.end()) {
            warnings.emplace_back("unknown key '" + key + "' in params JSON — ignoring");
        }
    }
}

void apply_overlay(const json& j, BBL::PrintParams& p,
                   std::vector<std::string>& w)
{
    set_string(j, "dev_id",            p.dev_id,            w);
    set_string(j, "task_name",         p.task_name,         w);
    set_string(j, "project_name",      p.project_name,      w);
    set_string(j, "preset_name",       p.preset_name,       w);
    set_string(j, "filename",          p.filename,          w);
    set_string(j, "config_filename",   p.config_filename,   w);
    set_int   (j, "plate_index",       p.plate_index,       w);
    set_string(j, "ftp_folder",        p.ftp_folder,        w);
    set_string(j, "ftp_file",          p.ftp_file,          w);
    set_string(j, "ftp_file_md5",      p.ftp_file_md5,      w);
    set_string(j, "nozzle_mapping",    p.nozzle_mapping,    w);
    set_string(j, "ams_mapping",       p.ams_mapping,       w);
    set_string(j, "ams_mapping2",      p.ams_mapping2,      w);
    set_string(j, "ams_mapping_info",  p.ams_mapping_info,  w);
    set_string(j, "nozzles_info",      p.nozzles_info,      w);
    set_string(j, "connection_type",   p.connection_type,   w);
    set_string(j, "comments",          p.comments,          w);
    set_int   (j, "origin_profile_id", p.origin_profile_id, w);
    set_int   (j, "stl_design_id",     p.stl_design_id,     w);
    set_string(j, "origin_model_id",   p.origin_model_id,   w);
    set_string(j, "print_type",        p.print_type,        w);
    set_string(j, "dst_file",          p.dst_file,          w);
    set_string(j, "dev_name",          p.dev_name,          w);

    set_string(j, "dev_ip",            p.dev_ip,            w);
    set_bool  (j, "use_ssl_for_ftp",   p.use_ssl_for_ftp,   w);
    set_bool  (j, "use_ssl_for_mqtt",  p.use_ssl_for_mqtt,  w);
    set_string(j, "username",          p.username,          w);
    set_string(j, "password",          p.password,          w);

    set_bool  (j, "task_bed_leveling",     p.task_bed_leveling,     w);
    set_bool  (j, "task_flow_cali",        p.task_flow_cali,        w);
    set_bool  (j, "task_vibration_cali",   p.task_vibration_cali,   w);
    set_bool  (j, "task_layer_inspect",    p.task_layer_inspect,    w);
    set_bool  (j, "task_record_timelapse", p.task_record_timelapse, w);
#if ABI_VERSION >= 0x020503
    set_bool  (j, "task_timelapse_use_internal", p.task_timelapse_use_internal, w);
#else
    if (j.contains("task_timelapse_use_internal")) {
        w.emplace_back("'task_timelapse_use_internal' present but ABI < 0x020503; "
                       "skipping (rebuild plugin_runner with newer --abi)");
    }
#endif
    set_bool  (j, "task_use_ams",                p.task_use_ams,                w);
    set_string(j, "task_bed_type",               p.task_bed_type,               w);
    set_string(j, "extra_options",               p.extra_options,               w);
    set_int   (j, "auto_bed_leveling",           p.auto_bed_leveling,           w);
    set_int   (j, "auto_flow_cali",              p.auto_flow_cali,              w);
    set_int   (j, "auto_offset_cali",            p.auto_offset_cali,            w);
#if ABI_VERSION >= 0x020400
    set_int   (j, "extruder_cali_manual_mode",   p.extruder_cali_manual_mode,   w);
#else
    if (j.contains("extruder_cali_manual_mode")) {
        w.emplace_back("'extruder_cali_manual_mode' present but ABI < 0x020400; "
                       "skipping (rebuild plugin_runner with newer --abi)");
    }
#endif
    set_bool  (j, "task_ext_change_assist",      p.task_ext_change_assist,      w);
    set_bool  (j, "try_emmc_print",              p.try_emmc_print,              w);
#if ABI_VERSION >= 0x020701
    set_string(j, "svc_context",                 p.svc_context,                 w);
#else
    if (j.contains("svc_context")) {
        w.emplace_back("'svc_context' present but ABI < 0x020701; "
                       "skipping (rebuild plugin_runner with newer --abi)");
    }
#endif
#if ABI_VERSION >= 0x020801
    set_string(j, "slicer_uid",                  p.slicer_uid,                  w);
#else
    if (j.contains("slicer_uid")) {
        w.emplace_back("'slicer_uid' present but ABI < 0x020801; "
                       "skipping (rebuild plugin_runner with newer --abi)");
    }
#endif
#if ABI_VERSION >= 0x020802
    set_string(j, "queue_plate_id",              p.queue_plate_id,              w);
#else
    if (j.contains("queue_plate_id")) {
        w.emplace_back("'queue_plate_id' present but ABI < 0x020802; "
                       "skipping (rebuild plugin_runner with newer --abi)");
    }
#endif
}

} // namespace

void load_print_params_from_json(const std::string&    json_path,
                                 BBL::PrintParams&     out,
                                 std::vector<std::string>& warnings)
{
    std::ifstream ifs(json_path);
    if (!ifs) {
        throw std::runtime_error("cannot open " + json_path + " for reading");
    }
    json j;
    try {
        ifs >> j;
    } catch (const std::exception& e) {
        throw std::runtime_error("failed to parse " + json_path + ": " + e.what());
    }
    if (!j.is_object()) {
        throw std::runtime_error(json_path + " must contain a JSON object at the top level");
    }
    warn_unknown(j, warnings);
    apply_overlay(j, out, warnings);
}

} // namespace obn::plugin_runner
