// Smoke test: ensures every symbol Bambu Studio resolves via GetProcAddress
// (Windows) or dlsym (POSIX) is present in the built plugin, that
// bambu_network_get_version() returns a non-empty, SLIC3R_VERSION-compatible
// string, and that bambu_network_create_agent / destroy_agent round-trip a
// std::string across the DLL boundary without crashing.
//
// Dual purpose: (a) cheap CI sanity check that mirrors what Studio does at
// load time; (b) lets us validate Windows builds without depending on
// Studio's GUI starting up successfully (it has its own pre-existing
// initialization issues unrelated to this plugin).

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#else
#  include <dlfcn.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

namespace {

#if defined(_WIN32)
using lib_handle_t = HMODULE;

lib_handle_t open_lib(const char* path)
{
    return ::LoadLibraryA(path);
}

void* lookup_sym(lib_handle_t h, const char* name)
{
    return reinterpret_cast<void*>(::GetProcAddress(h, name));
}

void close_lib(lib_handle_t h) { ::FreeLibrary(h); }

const char* last_error_str()
{
    static char buf[512];
    DWORD err = ::GetLastError();
    char* msg = nullptr;
    const DWORD n = ::FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
            | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&msg), 0, nullptr);
    if (n > 0 && msg) {
        std::snprintf(buf, sizeof(buf), "win32 error %lu (%.*s)",
                      static_cast<unsigned long>(err),
                      static_cast<int>(n), msg);
        ::LocalFree(msg);
    } else {
        std::snprintf(buf, sizeof(buf), "win32 error %lu",
                      static_cast<unsigned long>(err));
    }
    return buf;
}

void add_plugin_dir_to_dll_search(const char* plugin_path)
{
    const std::filesystem::path dir =
        std::filesystem::path(plugin_path).parent_path();
    if (dir.empty()) return;
    // Let LoadLibrary resolve deps colocated with the plugin (CI build dir).
    ::SetDllDirectoryA(dir.string().c_str());
}
#else
using lib_handle_t = void*;

lib_handle_t open_lib(const char* path)
{
    return ::dlopen(path, RTLD_LAZY);
}

void* lookup_sym(lib_handle_t h, const char* name)
{
    return ::dlsym(h, name);
}

void close_lib(lib_handle_t h) { ::dlclose(h); }

const char* last_error_str()
{
    const char* e = ::dlerror();
    return e ? e : "(null)";
}
#endif

} // namespace

namespace {

// Canonical list copied from BambuStudio's NetworkAgent.cpp resolver and the
// real plugin's ELF exports. Keep this list in sync when Studio changes.
const char* kBambuNetworkSymbols[] = {
    "bambu_network_check_debug_consistent",
    "bambu_network_get_version",
    "bambu_network_create_agent",
    "bambu_network_destroy_agent",
    "bambu_network_init_log",
    "bambu_network_set_config_dir",
    "bambu_network_set_cert_file",
    "bambu_network_set_country_code",
    "bambu_network_start",
    "bambu_network_set_on_ssdp_msg_fn",
    "bambu_network_set_on_user_login_fn",
    "bambu_network_set_on_printer_connected_fn",
    "bambu_network_set_on_server_connected_fn",
    "bambu_network_set_on_http_error_fn",
    "bambu_network_set_get_country_code_fn",
    "bambu_network_set_on_subscribe_failure_fn",
    "bambu_network_set_on_message_fn",
    "bambu_network_set_on_user_message_fn",
    "bambu_network_set_on_local_connect_fn",
    "bambu_network_set_on_local_message_fn",
    "bambu_network_set_queue_on_main_fn",
    "bambu_network_set_server_callback",
    "bambu_network_connect_server",
    "bambu_network_is_server_connected",
    "bambu_network_refresh_connection",
    "bambu_network_start_subscribe",
    "bambu_network_stop_subscribe",
    "bambu_network_add_subscribe",
    "bambu_network_del_subscribe",
    "bambu_network_enable_multi_machine",
    "bambu_network_send_message",
    "bambu_network_connect_printer",
    "bambu_network_disconnect_printer",
    "bambu_network_send_message_to_printer",
    "bambu_network_update_cert",
    "bambu_network_install_device_cert",
    "bambu_network_start_discovery",
    "bambu_network_change_user",
    "bambu_network_is_user_login",
    "bambu_network_user_logout",
    "bambu_network_get_user_id",
    "bambu_network_get_user_name",
    "bambu_network_get_user_avatar",
    "bambu_network_get_user_nickanme",
    "bambu_network_build_login_cmd",
    "bambu_network_build_logout_cmd",
    "bambu_network_build_login_info",
    "bambu_network_get_my_profile",
    "bambu_network_get_my_token",
    "bambu_network_get_user_info",
    "bambu_network_ping_bind",
    "bambu_network_bind_detect",
    "bambu_network_bind",
    "bambu_network_unbind",
    "bambu_network_request_bind_ticket",
    "bambu_network_query_bind_status",
    "bambu_network_modify_printer_name",
    "bambu_network_report_consent",
    "bambu_network_get_bambulab_host",
    "bambu_network_get_user_selected_machine",
    "bambu_network_set_user_selected_machine",
    "bambu_network_start_print",
    "bambu_network_start_local_print_with_record",
    "bambu_network_start_send_gcode_to_sdcard",
    "bambu_network_start_local_print",
    "bambu_network_start_sdcard_print",
    "bambu_network_get_user_presets",
    "bambu_network_request_setting_id",
    "bambu_network_put_setting",
    "bambu_network_get_setting_list",
    "bambu_network_get_setting_list2",
    "bambu_network_delete_setting",
    "bambu_network_get_studio_info_url",
    "bambu_network_set_extra_http_header",
    "bambu_network_get_my_message",
    "bambu_network_check_user_task_report",
    "bambu_network_get_user_print_info",
    "bambu_network_get_user_tasks",
    "bambu_network_get_filament_spools",
    "bambu_network_create_filament_spool",
    "bambu_network_update_filament_spool",
    "bambu_network_delete_filament_spools",
    "bambu_network_get_filament_config",
    "bambu_network_get_printer_firmware",
    "bambu_network_get_task_plate_index",
    "bambu_network_get_subtask_info",
    "bambu_network_get_slice_info",
    "bambu_network_get_camera_url",
    "bambu_network_get_camera_url_for_golive",
    "bambu_network_get_hms_snapshot",
    "bambu_network_get_design_staffpick",
    "bambu_network_start_publish",
    "bambu_network_get_model_publish_url",
    "bambu_network_get_subtask",
    "bambu_network_get_model_mall_home_url",
    "bambu_network_get_model_mall_detail_url",
    "bambu_network_put_model_mall_rating",
    "bambu_network_get_oss_config",
    "bambu_network_put_rating_picture_oss",
    "bambu_network_get_model_mall_rating",
    "bambu_network_get_mw_user_preference",
    "bambu_network_get_mw_user_4ulist",
    "bambu_network_track_enable",
    "bambu_network_track_remove_files",
    "bambu_network_track_event",
    "bambu_network_track_header",
    "bambu_network_track_update_property",
    "bambu_network_track_get_property",
};

const char* kFtSymbols[] = {
    "ft_abi_version",
    "ft_free",
    "ft_job_result_destroy",
    "ft_job_msg_destroy",
    "ft_tunnel_create",
    "ft_tunnel_retain",
    "ft_tunnel_release",
    "ft_tunnel_start_connect",
    "ft_tunnel_sync_connect",
    "ft_tunnel_set_status_cb",
    "ft_tunnel_shutdown",
    "ft_job_create",
    "ft_job_retain",
    "ft_job_release",
    "ft_job_set_result_cb",
    "ft_job_get_result",
    "ft_tunnel_start_job",
    "ft_job_cancel",
    "ft_job_set_msg_cb",
    "ft_job_try_get_msg",
    "ft_job_get_msg",
};

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::fprintf(stderr,
                     "usage: %s <path-to-bambu_networking.{so,dll}>\n",
                     argv[0]);
        return 2;
    }

#if defined(_WIN32)
    add_plugin_dir_to_dll_search(argv[1]);
#endif
    lib_handle_t h = open_lib(argv[1]);
    if (!h) {
        std::fprintf(stderr, "open_lib failed: %s\n", last_error_str());
        return 1;
    }

    int missing = 0;
    for (const char* name : kBambuNetworkSymbols) {
        if (!lookup_sym(h, name)) {
            std::fprintf(stderr, "MISSING: %s\n", name);
            ++missing;
        }
    }
    for (const char* name : kFtSymbols) {
        if (!lookup_sym(h, name)) {
            std::fprintf(stderr, "MISSING: %s\n", name);
            ++missing;
        }
    }

    using fn_ver       = std::string (*)();
    using fn_dbg       = bool (*)(bool);
    using fn_create    = void* (*)(std::string);
    using fn_destroy   = int (*)(void*);
    using fn_set_dir   = int (*)(void*, std::string);

    auto ver       = reinterpret_cast<fn_ver>(lookup_sym(h, "bambu_network_get_version"));
    auto dbg       = reinterpret_cast<fn_dbg>(lookup_sym(h, "bambu_network_check_debug_consistent"));
    auto create_a  = reinterpret_cast<fn_create>(lookup_sym(h, "bambu_network_create_agent"));
    auto destroy_a = reinterpret_cast<fn_destroy>(lookup_sym(h, "bambu_network_destroy_agent"));
    auto set_dir   = reinterpret_cast<fn_set_dir>(lookup_sym(h, "bambu_network_set_config_dir"));

    if (ver) {
        std::string v = ver();
        std::printf("version: %s\n", v.c_str());
        if (v.size() < 8) {
            std::fprintf(stderr, "VERSION TOO SHORT (need >=8 chars)\n");
            ++missing;
        }
    }
    if (dbg) {
        std::printf("debug_consistent(false)=%d true=%d\n", dbg(false), dbg(true));
    }

    // Round-trip std::string across the DLL boundary. Same flow Studio uses:
    // create_agent("<log_dir>") -> set_config_dir(agent, "<data_dir>") ->
    // destroy_agent(agent). On Windows this also exercises the heap shared
    // between the host (test exe) and the plugin DLL via MSVCRT/UCRT, which
    // is the most common ABI pitfall when mixing /MT and /MD or different
    // toolsets.
    if (create_a && destroy_a) {
        std::string log_dir = ".";
        void* agent = create_a(log_dir);
        std::printf("create_agent(\"%s\") -> %p\n", log_dir.c_str(), agent);
        if (!agent) {
            std::fprintf(stderr, "create_agent returned null\n");
            ++missing;
        } else {
            if (set_dir) {
                int rc = set_dir(agent, std::string("."));
                std::printf("set_config_dir(\".\") -> %d\n", rc);
            }
            int rc = destroy_a(agent);
            std::printf("destroy_agent -> %d\n", rc);
        }
    }

    // ft_abi_version must be 1 per FileTransferUtils.hpp.
    using fn_ft = int (*)();
    auto ft_ver = reinterpret_cast<fn_ft>(lookup_sym(h, "ft_abi_version"));
    if (ft_ver) {
        int v = ft_ver();
        std::printf("ft_abi_version: %d\n", v);
        if (v != 1) {
            std::fprintf(stderr, "ft_abi_version must be 1 (got %d)\n", v);
            ++missing;
        }
    }

    close_lib(h);
    if (missing) {
        std::fprintf(stderr, "%d problem(s) found\n", missing);
        return 1;
    }
    std::printf("OK (all %zu + %zu symbols present)\n",
                sizeof(kBambuNetworkSymbols) / sizeof(*kBambuNetworkSymbols),
                sizeof(kFtSymbols) / sizeof(*kFtSymbols));
    return 0;
}
