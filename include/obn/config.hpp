#pragma once

// User-editable settings in <config_dir>/obn.conf (INI-like key = value).
// Loaded once from bambu_network_create_agent(log_dir). Environment
// variables override individual keys where documented (see log.hpp).

#include <string>

namespace obn::config {

inline constexpr const char* kConfigFileName = "obn.conf";

struct Settings {
    // Logging (empty string = use built-in default for that key)
    std::string log_level;
    std::string log_stderr;
    std::string log_to_file;
    std::string log_file;

    // Cloud endpoints (per region; empty value falls back to production default)
    std::string cloud_global_api_host;
    std::string cloud_global_web_host;
    std::string cloud_global_mqtt_host;
    std::string cloud_cn_api_host;
    std::string cloud_cn_web_host;
    std::string cloud_cn_mqtt_host;

    // LAN / cloud networking
    bool lan_tls_skip_verify      = false;
    int  cloud_mqtt_port          = 8883;
    bool block_cloud              = true;

    // Print behavior overrides
    bool force_timelapse_external = false;

    // File transfer
    bool force_ftps               = false;

    // Device panel: static "Printer Preview" JPEG (mem:/N over TLS :6000)
    bool disable_camera_preview      = false;

    // MQTT connection persistence: Orca Slicer unconditionally tears down
    // and re-establishes the MQTT session after every print job, causing a
    // 5-30s reconnection delay.  Enabled by default to work around this.
    bool mqtt_keep_connection        = true;

    // MQTT push_status patches (all off by default)
    bool patch_mqtt_home_flag        = false;
    bool patch_mqtt_ipcam_file       = false;
    bool patch_mqtt_internal_storage = false;

    // BambuSource logging (read-only via load_if_exists)
    std::string bambusource_log_level;
    std::string bambusource_log_file;
};

// Parse "0"/"1"/"true"/"false"/"yes"/"no" (case-insensitive) into a bool.
// Returns `fallback` for unrecognised values.
bool truthy(const std::string& val, bool fallback = false);

// Load from <config_dir>/obn.conf; create a commented template if missing.
// Thread-safe; subsequent calls return the same cached Settings until
// load_or_create is called with a different non-empty directory.
Settings load_or_create(const std::string& config_dir);

// Parse an existing obn.conf without creating a template if absent.
// Returns default Settings when the file does not exist.
Settings load_if_exists(const std::string& config_dir);

// Valid only after load_or_create(); otherwise returns default Settings.
const Settings& current();

// Resolve cloud endpoints for `region` ("CN"/"cn" = China, else global).
// Empty configured values fall back to production defaults.
std::string cloud_api_host_for(const Settings& s, const std::string& region);
std::string cloud_web_host_for(const Settings& s, const std::string& region);
std::string cloud_mqtt_host_for(const Settings& s, const std::string& region);

} // namespace obn::config
