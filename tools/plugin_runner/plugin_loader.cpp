#include "plugin_loader.hpp"

#include <dlfcn.h>

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace obn::plugin_runner {

namespace {

template <typename T>
T resolve(void* handle, const char* name)
{
    dlerror();
    void* sym = dlsym(handle, name);
    const char* err = dlerror();
    if (err) return nullptr;
    return reinterpret_cast<T>(sym);
}

template <typename T>
T resolve_required(void* handle, const char* name, const std::string& so_path)
{
    T fn = resolve<T>(handle, name);
    if (!fn) {
        throw std::runtime_error("plugin '" + so_path + "' is missing required symbol '" +
                                 name + "'");
    }
    return fn;
}

} // namespace

PluginExports load(const std::string& so_path)
{
    PluginExports out;
    out.so_path = so_path;

    // RTLD_NOW: surface unresolved-symbol errors right at dlopen rather
    // than at the first call to a stock function pointer (where the
    // resulting SIGSEGV would be much less informative).
    out.dl_handle = dlopen(so_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!out.dl_handle) {
        const char* err = dlerror();
        throw std::runtime_error("dlopen(" + so_path + ") failed: " +
                                 (err ? err : "<no dlerror>"));
    }

    out.create_agent      = resolve_required<func_create_agent>(out.dl_handle,
                                "bambu_network_create_agent", so_path);
    out.destroy_agent     = resolve_required<func_destroy_agent>(out.dl_handle,
                                "bambu_network_destroy_agent", so_path);
    out.init_log          = resolve_required<func_init_log>(out.dl_handle,
                                "bambu_network_init_log", so_path);
    out.set_config_dir    = resolve_required<func_set_config_dir>(out.dl_handle,
                                "bambu_network_set_config_dir", so_path);
    out.set_cert_file     = resolve_required<func_set_cert_file>(out.dl_handle,
                                "bambu_network_set_cert_file", so_path);
    out.set_country_code  = resolve_required<func_set_country_code>(out.dl_handle,
                                "bambu_network_set_country_code", so_path);
    out.start             = resolve_required<func_start>(out.dl_handle,
                                "bambu_network_start", so_path);
    out.get_version       = resolve_required<func_get_version>(out.dl_handle,
                                "bambu_network_get_version", so_path);
    out.connect_printer   = resolve_required<func_connect_printer>(out.dl_handle,
                                "bambu_network_connect_printer", so_path);
    out.disconnect_printer = resolve_required<func_disconnect_printer>(out.dl_handle,
                                "bambu_network_disconnect_printer", so_path);

    out.set_on_printer_connected_fn = resolve_required<func_set_on_printer_connected_fn>(
        out.dl_handle, "bambu_network_set_on_printer_connected_fn", so_path);
    out.set_on_server_connected_fn = resolve_required<func_set_on_server_connected_fn>(
        out.dl_handle, "bambu_network_set_on_server_connected_fn", so_path);
    out.set_on_http_error_fn = resolve_required<func_set_on_http_error_fn>(
        out.dl_handle, "bambu_network_set_on_http_error_fn", so_path);
    out.set_get_country_code_fn = resolve_required<func_set_get_country_code_fn>(
        out.dl_handle, "bambu_network_set_get_country_code_fn", so_path);
    out.set_on_subscribe_failure_fn = resolve_required<func_set_on_subscribe_failure_fn>(
        out.dl_handle, "bambu_network_set_on_subscribe_failure_fn", so_path);
    out.set_on_message_fn = resolve_required<func_set_on_message_fn>(
        out.dl_handle, "bambu_network_set_on_message_fn", so_path);
    out.set_on_user_message_fn = resolve_required<func_set_on_user_message_fn>(
        out.dl_handle, "bambu_network_set_on_user_message_fn", so_path);
    out.set_on_local_connect_fn = resolve_required<func_set_on_local_connect_fn>(
        out.dl_handle, "bambu_network_set_on_local_connect_fn", so_path);
    out.set_on_local_message_fn = resolve_required<func_set_on_local_message_fn>(
        out.dl_handle, "bambu_network_set_on_local_message_fn", so_path);
    // queue_on_main is optional: some early plugins didn't have it. main.cpp
    // tolerates a null pointer by not installing the callback (default
    // upstream behaviour: dispatch on the network thread directly).
    out.set_queue_on_main_fn = resolve<func_set_queue_on_main_fn>(
        out.dl_handle, "bambu_network_set_queue_on_main_fn");

    out.start_subscribe = resolve_required<func_start_subscribe>(
        out.dl_handle, "bambu_network_start_subscribe", so_path);
    out.stop_subscribe = resolve<func_stop_subscribe>(
        out.dl_handle, "bambu_network_stop_subscribe");
    out.send_message_to_printer = resolve_required<func_send_message_to_printer>(
        out.dl_handle, "bambu_network_send_message_to_printer", so_path);
    out.set_on_ssdp_msg_fn = resolve_required<func_set_on_ssdp_msg_fn>(
        out.dl_handle, "bambu_network_set_on_ssdp_msg_fn", so_path);
    out.set_server_callback = resolve_required<func_set_server_callback>(
        out.dl_handle, "bambu_network_set_server_callback", so_path);
    out.set_extra_http_header = resolve_required<func_set_extra_http_header>(
        out.dl_handle, "bambu_network_set_extra_http_header", so_path);
    out.enable_multi_machine = resolve_required<func_enable_multi_machine>(
        out.dl_handle, "bambu_network_enable_multi_machine", so_path);
    out.start_discovery = resolve_required<func_start_discovery>(
        out.dl_handle, "bambu_network_start_discovery", so_path);

    out.change_user             = resolve_required<func_change_user>(out.dl_handle,
                                      "bambu_network_change_user", so_path);
    out.is_user_login           = resolve_required<func_is_user_login>(out.dl_handle,
                                      "bambu_network_is_user_login", so_path);
    out.user_logout             = resolve<func_user_logout>(out.dl_handle,
                                      "bambu_network_user_logout");
    out.build_login_cmd         = resolve<func_build_login_cmd>(out.dl_handle,
                                      "bambu_network_build_login_cmd");
    out.build_logout_cmd        = resolve<func_build_logout_cmd>(out.dl_handle,
                                      "bambu_network_build_logout_cmd");
    out.build_login_info        = resolve<func_build_login_info>(out.dl_handle,
                                      "bambu_network_build_login_info");
    out.get_user_id             = resolve<func_get_user_id>(out.dl_handle,
                                      "bambu_network_get_user_id");
    out.connect_server          = resolve<func_connect_server>(out.dl_handle,
                                      "bambu_network_connect_server");
    out.is_server_connected     = resolve<func_is_server_connected>(out.dl_handle,
                                      "bambu_network_is_server_connected");
    out.refresh_connection      = resolve<func_refresh_connection>(out.dl_handle,
                                      "bambu_network_refresh_connection");
    out.bind_detect             = resolve_required<func_bind_detect>(out.dl_handle,
                                      "bambu_network_bind_detect", so_path);
    out.query_bind_status       = resolve<func_query_bind_status>(out.dl_handle,
                                      "bambu_network_query_bind_status");
    out.request_bind_ticket     = resolve<func_request_bind_ticket>(out.dl_handle,
                                      "bambu_network_request_bind_ticket");
    out.bind                    = resolve<func_bind>(out.dl_handle,
                                      "bambu_network_bind");
    // Optional in older builds.
    out.check_debug_consistent  = resolve<func_check_debug_consistent>(out.dl_handle,
                                      "bambu_network_check_debug_consistent");
    // install_device_cert is optional only on plugins old enough to predate
    // the per-printer cert provisioning (pre-02.04 era). Modern builds gate
    // privileged MQTT publish on it having run at least once.
    out.install_device_cert     = resolve<func_install_device_cert>(out.dl_handle,
                                      "bambu_network_install_device_cert");
    out.update_cert             = resolve<func_update_cert>(out.dl_handle,
                                      "bambu_network_update_cert");

    // Print-action entry points are all optional at load time; per-action
    // dispatch in main.cpp re-validates that the user-requested one was
    // actually resolved.
    out.start_send_gcode_to_sdcard = resolve<func_start_send_gcode_to_sdcard>(
        out.dl_handle, "bambu_network_start_send_gcode_to_sdcard");
    out.start_local_print = resolve<func_start_local_print>(
        out.dl_handle, "bambu_network_start_local_print");
    out.start_sdcard_print = resolve<func_start_sdcard_print>(
        out.dl_handle, "bambu_network_start_sdcard_print");
    out.start_local_print_with_record = resolve<func_start_local_print_with_record>(
        out.dl_handle, "bambu_network_start_local_print_with_record");
    out.start_print = resolve<func_start_print>(
        out.dl_handle, "bambu_network_start_print");

    out.get_studio_info_url = resolve<func_get_studio_info_url>(
        out.dl_handle, "bambu_network_get_studio_info_url");
    out.get_my_message = resolve<func_get_my_message>(
        out.dl_handle, "bambu_network_get_my_message");
    out.check_user_task_report = resolve<func_check_user_task_report>(
        out.dl_handle, "bambu_network_check_user_task_report");
    out.get_task_plate_index = resolve<func_get_task_plate_index>(
        out.dl_handle, "bambu_network_get_task_plate_index");
    out.get_slice_info = resolve<func_get_slice_info>(
        out.dl_handle, "bambu_network_get_slice_info");

    out.get_subtask = resolve<func_get_subtask>(
        out.dl_handle, "bambu_network_get_subtask");
    out.get_model_mall_detail_url = resolve<func_get_model_mall_detail_url>(
        out.dl_handle, "bambu_network_get_model_mall_detail_url");
    out.get_model_mall_rating = resolve<func_get_model_mall_rating>(
        out.dl_handle, "bambu_network_get_model_mall_rating");
    out.put_model_mall_rating = resolve<func_put_model_mall_rating>(
        out.dl_handle, "bambu_network_put_model_mall_rating");
    out.get_mw_user_preference = resolve<func_get_mw_user_preference>(
        out.dl_handle, "bambu_network_get_mw_user_preference");
    out.get_mw_user_4ulist = resolve<func_get_mw_user_4ulist>(
        out.dl_handle, "bambu_network_get_mw_user_4ulist");

    out.get_filament_spools = resolve<func_get_filament_spools>(
        out.dl_handle, "bambu_network_get_filament_spools");
    out.get_filament_config = resolve<func_get_filament_config>(
        out.dl_handle, "bambu_network_get_filament_config");
#if ABI_VERSION >= 0x020801
    out.sync_ams_filaments = resolve<func_sync_ams_filaments>(
        out.dl_handle, "bambu_network_sync_ams_filaments");
#endif
#if ABI_VERSION >= 0x020802
    out.sync_slot_mappings = resolve<func_sync_slot_mappings>(
        out.dl_handle, "bambu_network_sync_slot_mappings");
#endif

    if (out.get_version) {
        try { out.version = out.get_version(); } catch (...) { out.version.clear(); }
    }
    return out;
}

void unload(PluginExports& exports)
{
    // Intentionally no `dlclose` here. Stock plugins keep singleton thread
    // pools alive past `destroy_agent` (boost::asio io_context, mqtt-cpp
    // worker, libcurl share, …) and rely on libc's atexit chain to drain
    // them at process exit. Forcing dlclose mid-process triggers their
    // global destructors against still-running threads and reliably
    // SIGABRTs. Process exit will reclaim the mapping anyway.
    exports = PluginExports{};
}

} // namespace obn::plugin_runner
