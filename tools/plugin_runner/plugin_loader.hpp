#ifndef OBN_PLUGIN_RUNNER_PLUGIN_LOADER_HPP
#define OBN_PLUGIN_RUNNER_PLUGIN_LOADER_HPP

#include <functional>
#include <string>
#include <vector>

#include "obn/bambu_networking.hpp"

namespace obn::plugin_runner {

// Function-pointer aliases mirror Studio's NetworkAgent.hpp typedefs
// 1:1 — the per-ABI snapshots under tools/abi_snapshot/v<MM.mm.pp>/
// NetworkAgent.hpp are the canonical record. Only the subset we
// actually call is declared.
using func_check_debug_consistent     = int (*)(void* agent);
using func_get_version                = std::string (*)();
using func_create_agent               = void* (*)(std::string log_dir);
using func_destroy_agent              = int (*)(void* agent);
using func_init_log                   = int (*)(void* agent);
using func_set_config_dir             = int (*)(void* agent, std::string config_dir);
using func_set_cert_file              = int (*)(void* agent, std::string folder, std::string filename);
using func_set_country_code           = int (*)(void* agent, std::string country_code);
using func_start                      = int (*)(void* agent);

using func_set_on_printer_connected_fn = int (*)(void* agent, BBL::OnPrinterConnectedFn fn);
using func_set_on_server_connected_fn  = int (*)(void* agent, BBL::OnServerConnectedFn  fn);
using func_set_on_http_error_fn        = int (*)(void* agent, BBL::OnHttpErrorFn        fn);
using func_set_get_country_code_fn     = int (*)(void* agent, BBL::GetCountryCodeFn     fn);
using func_set_on_subscribe_failure_fn = int (*)(void* agent, BBL::GetSubscribeFailureFn fn);
using func_set_on_message_fn           = int (*)(void* agent, BBL::OnMessageFn          fn);
using func_set_on_user_message_fn      = int (*)(void* agent, BBL::OnMessageFn          fn);
using func_set_on_local_connect_fn     = int (*)(void* agent, BBL::OnLocalConnectedFn   fn);
using func_set_on_local_message_fn     = int (*)(void* agent, BBL::OnMessageFn          fn);
using func_set_queue_on_main_fn        = int (*)(void* agent, BBL::QueueOnMainFn        fn);
using func_start_subscribe             = int (*)(void* agent, std::string module);
using func_stop_subscribe              = int (*)(void* agent, std::string module);
using func_send_message_to_printer     = int (*)(void* agent, std::string dev_id, std::string json_str, int qos, int flag);
using func_set_on_ssdp_msg_fn          = int (*)(void* agent, BBL::OnMsgArrivedFn       fn);
using func_set_server_callback         = int (*)(void* agent, BBL::OnServerErrFn        fn);
using func_set_extra_http_header       = int (*)(void* agent, std::map<std::string,std::string> extra_headers);
using func_enable_multi_machine        = void (*)(void* agent, bool enable);
using func_start_discovery             = bool (*)(void* agent, bool start, bool sending);

using func_connect_printer    = int (*)(void* agent, std::string dev_id, std::string dev_ip, std::string username, std::string password, bool use_ssl);
using func_disconnect_printer = int (*)(void* agent);
using func_change_user        = int (*)(void* agent, std::string user_info);
using func_is_user_login      = bool (*)(void* agent);
using func_user_logout        = int (*)(void* agent, bool request);
using func_build_login_cmd    = std::string (*)(void* agent);
using func_build_logout_cmd   = std::string (*)(void* agent);
using func_build_login_info   = std::string (*)(void* agent);
using func_get_user_id        = std::string (*)(void* agent);
using func_connect_server      = int (*)(void* agent);
using func_is_server_connected = bool (*)(void* agent);
using func_refresh_connection  = int (*)(void* agent);
using func_bind_detect         = int (*)(void* agent, std::string dev_ip, std::string sec_link, BBL::detectResult& detect);
using func_query_bind_status  = int (*)(void* agent, std::vector<std::string> query_list,
                                        unsigned int* http_code, std::string* http_body);
using func_request_bind_ticket = int (*)(void* agent, std::string* ticket);
using func_bind = int (*)(void* agent, std::string dev_ip, std::string dev_id, std::string dev_model,
                          std::string sec_link, std::string timezone, bool improved,
                          BBL::OnUpdateStatusFn update_fn);
// Provisions the per-printer device certificate the plugin uses to RSA-sign
// privileged MQTT commands (project_file, etc.). Studio calls this from
// set_on_printer_connected_fn right after command_request_push_all; without
// it bambu_network_send_message_to_printer rejects any payload whose
// top-level key is `print` / `upgrade` / `liveview` with rc=-4 — the same
// error start_local_print surfaces as -4030 ("send msg failed") on the
// Sending stage.
using func_install_device_cert = void (*)(void* agent, std::string dev_id, bool lan_only);
// Studio name: check_cert(); export symbol is bambu_network_update_cert.
// Fetches shared app cert / CRL / encrypted key from
// GET /v1/iot-service/api/user/applications/{enc_secret}/cert?...
using func_update_cert = int (*)(void* agent);

using func_start_send_gcode_to_sdcard    = int (*)(void* agent, BBL::PrintParams params, BBL::OnUpdateStatusFn update_fn, BBL::WasCancelledFn cancel_fn, BBL::OnWaitFn wait_fn);
using func_start_local_print             = int (*)(void* agent, BBL::PrintParams params, BBL::OnUpdateStatusFn update_fn, BBL::WasCancelledFn cancel_fn);
using func_start_sdcard_print            = int (*)(void* agent, BBL::PrintParams params, BBL::OnUpdateStatusFn update_fn, BBL::WasCancelledFn cancel_fn);
using func_start_local_print_with_record = int (*)(void* agent, BBL::PrintParams params, BBL::OnUpdateStatusFn update_fn, BBL::WasCancelledFn cancel_fn, BBL::OnWaitFn wait_fn);

// Cloud HTTP probes (optional — present on modern stock plugins; used by
// --action http_probe). BambuStudio ba049f6a2 still dlsym's these even
// when the GUI no longer calls them.
using func_get_studio_info_url     = std::string (*)(void* agent);
using func_get_my_message          = int (*)(void* agent, int type, int after, int limit,
                                             unsigned int* http_code, std::string* http_body);
using func_check_user_task_report  = int (*)(void* agent, int* task_id, bool* printable);
using func_get_task_plate_index    = int (*)(void* agent, std::string task_id, int* plate_index);
using func_get_slice_info          = int (*)(void* agent, std::string project_id,
                                             std::string profile_id, int plate_index,
                                             std::string* slice_json);

// MakerWorld probes (--action mw_probe). BBLModelTask layout must match
// Studio ProjectTask.hpp (non-virtual: 4 ints + 4 strings).
struct ProbeBBLModelTask {
    int         job_id      = 0;
    int         design_id   = 0;
    int         profile_id  = 0;
    int         instance_id = 0;
    std::string task_id;
    std::string model_id;
    std::string model_name;
    std::string profile_name;
};
using func_get_subtask = int (*)(void* agent, ProbeBBLModelTask* task,
                                 std::function<void(ProbeBBLModelTask*)> cb);
using func_get_model_mall_detail_url = int (*)(void* agent, std::string* url, std::string id);
using func_get_model_mall_rating = int (*)(void* agent, int job_id,
                                           std::string& rating_result,
                                           unsigned int& http_code,
                                           std::string& http_error);
using func_put_model_mall_rating = int (*)(void* agent, int rating_id, int score,
                                           std::string content,
                                           std::vector<std::string> images,
                                           unsigned int& http_code,
                                           std::string& http_error);
using func_get_mw_user_preference = int (*)(void* agent,
                                            std::function<void(std::string)> cb);
using func_get_mw_user_4ulist = int (*)(void* agent, int seed, int limit,
                                        std::function<void(std::string)> cb);

// Resolved entry points. Required pointers are validated by load(); optional
// pointers stay null if absent so the caller can branch on availability
// without crashing on older plugins.
struct PluginExports {
    void* dl_handle = nullptr;
    std::string so_path;
    std::string version;

    // Required for any meaningful use:
    func_create_agent               create_agent               = nullptr;
    func_destroy_agent              destroy_agent              = nullptr;
    func_init_log                   init_log                   = nullptr;
    func_set_config_dir             set_config_dir             = nullptr;
    func_set_cert_file              set_cert_file              = nullptr;
    func_set_country_code           set_country_code           = nullptr;
    func_start                      start                      = nullptr;
    func_get_version                get_version                = nullptr;
    func_connect_printer            connect_printer            = nullptr;
    func_disconnect_printer         disconnect_printer         = nullptr;

    // Callback installers (all required by stock plugins, even if we hand
    // them no-op lambdas — calling start() before they're set tends to
    // crash on null std::function invocation):
    func_set_on_printer_connected_fn set_on_printer_connected_fn = nullptr;
    func_set_on_server_connected_fn  set_on_server_connected_fn  = nullptr;
    func_set_on_http_error_fn        set_on_http_error_fn        = nullptr;
    func_set_get_country_code_fn     set_get_country_code_fn     = nullptr;
    func_set_on_subscribe_failure_fn set_on_subscribe_failure_fn = nullptr;
    func_set_on_message_fn           set_on_message_fn           = nullptr;
    func_set_on_user_message_fn      set_on_user_message_fn      = nullptr;
    func_set_on_local_connect_fn     set_on_local_connect_fn     = nullptr;
    func_set_on_local_message_fn     set_on_local_message_fn     = nullptr;
    func_set_queue_on_main_fn        set_queue_on_main_fn        = nullptr;
    func_start_subscribe             start_subscribe             = nullptr;
    func_stop_subscribe              stop_subscribe              = nullptr;

    // Direct MQTT publish onto device/<dev_id>/request. The killer
    // primitive for reverse-engineering the print command JSON shape:
    // hand-craft a payload, observe what the printer reports back via
    // local_message, iterate. qos=1 / flag=0 mirror the values Studio
    // uses for printer commands (MessageFlag::MSG_FLAG_NONE).
    func_send_message_to_printer     send_message_to_printer     = nullptr;
    func_set_on_ssdp_msg_fn          set_on_ssdp_msg_fn          = nullptr;
    func_set_server_callback         set_server_callback         = nullptr;

    // X-BBL-* HTTP headers Studio installs before start(); the plugin
    // attaches them to every outgoing HTTP request, including the LAN
    // /info ping inside bind_detect and the cloud auth flow. Some
    // builds gate critical paths on at least X-BBL-Client-Type being
    // present.
    func_set_extra_http_header       set_extra_http_header       = nullptr;

    // Multi-machine + SSDP discovery — Studio always wires both up
    // before start(). Most LAN-only print actions don't strictly need
    // them, but stock plugins still query their state during the MQTT
    // handshake; missing wires can leave the plugin in a half-init
    // state where local_connect fires status=Failed without an
    // underlying network error.
    func_enable_multi_machine        enable_multi_machine        = nullptr;
    func_start_discovery             start_discovery             = nullptr;

    // User session — all stock plugins refuse LAN print until change_user()
    // has been called once (even with an empty payload to mark "logged out"):
    func_change_user                 change_user                 = nullptr;
    func_is_user_login               is_user_login               = nullptr;
    func_user_logout                 user_logout                 = nullptr;
    func_build_login_cmd             build_login_cmd             = nullptr;
    func_build_logout_cmd            build_logout_cmd            = nullptr;
    func_build_login_info            build_login_info            = nullptr;
    func_get_user_id                 get_user_id                 = nullptr;
    func_connect_server              connect_server              = nullptr;
    func_is_server_connected         is_server_connected         = nullptr;
    func_refresh_connection          refresh_connection          = nullptr;
    func_check_debug_consistent      check_debug_consistent      = nullptr;
    func_install_device_cert         install_device_cert         = nullptr;
    func_update_cert                 update_cert                 = nullptr;
    // bind_detect: stock TCP :3000 login/detect (framed JSON), not HTTP
    // /info. Studio runs it before connect_printer. The plugin uses
    // connect_type / bind_state to choose the MQTT path. Skip it and
    // connect_printer can return success but local_connect ends up
    // ConnectStatusFailed (msg="-1"). Required for any LAN flow.
    func_bind_detect                 bind_detect                 = nullptr;
    // Optional bind/cloud helpers (--action query_bind / account_bind).
    func_query_bind_status           query_bind_status           = nullptr;
    func_request_bind_ticket         request_bind_ticket         = nullptr;
    func_bind                        bind                        = nullptr;

    // Print actions. At least one of the four must be present for the
    // wanted --action; main.cpp validates per-action.
    func_start_send_gcode_to_sdcard    start_send_gcode_to_sdcard    = nullptr;
    func_start_local_print             start_local_print             = nullptr;
    func_start_sdcard_print            start_sdcard_print            = nullptr;
    func_start_local_print_with_record start_local_print_with_record = nullptr;

    // Optional HTTP / task metadata probes (--action http_probe).
    func_get_studio_info_url     get_studio_info_url     = nullptr;
    func_get_my_message          get_my_message          = nullptr;
    func_check_user_task_report  check_user_task_report  = nullptr;
    func_get_task_plate_index    get_task_plate_index    = nullptr;
    func_get_slice_info          get_slice_info          = nullptr;

    // Optional MakerWorld probes (--action mw_probe).
    func_get_subtask                 get_subtask                 = nullptr;
    func_get_model_mall_detail_url   get_model_mall_detail_url   = nullptr;
    func_get_model_mall_rating       get_model_mall_rating       = nullptr;
    func_put_model_mall_rating       put_model_mall_rating       = nullptr;
    func_get_mw_user_preference      get_mw_user_preference      = nullptr;
    func_get_mw_user_4ulist          get_mw_user_4ulist          = nullptr;
};

// Loads `so_path`, resolves all entry points listed above. Throws
// std::runtime_error with a descriptive message if dlopen fails or any
// *required* entry point is missing. Optional entry points (the four
// start_*_print* family) only fail at action-dispatch time.
PluginExports load(const std::string& so_path);

// Releases the dl handle and zeroes pointers. Safe on a default-constructed
// PluginExports.
void unload(PluginExports& exports);

} // namespace obn::plugin_runner

#endif // OBN_PLUGIN_RUNNER_PLUGIN_LOADER_HPP
