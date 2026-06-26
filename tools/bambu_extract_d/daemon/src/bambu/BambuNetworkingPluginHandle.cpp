

#include "BambuNetworkingPluginHandle.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#if defined(_WIN32)
#  include <windows.h>
#else
#  include <dlfcn.h>
#endif

namespace Slic3r {
namespace bambu {

namespace {

extern "C++" {
    using func_create_agent          = void* (*)(std::string log_dir);
    using func_destroy_agent         = int   (*)(void* agent);
    using func_get_version           = std::string (*)(void);
    using func_init_log              = int   (*)(void* agent);
    using func_set_config_dir        = int   (*)(void* agent, std::string config_dir);
    using func_set_country_code      = int   (*)(void* agent, std::string country_code);
    using func_start                 = int   (*)(void* agent);
    using func_is_user_login         = bool  (*)(void* agent);
    using func_is_server_connected   = bool  (*)(void* agent);
    using func_get_user_print_info   = int   (*)(void* agent,
                                                 unsigned int* http_code,
                                                 std::string*  http_body);
    using func_add_subscribe         = int   (*)(void* agent,
                                                 std::vector<std::string> dev_list);
    using func_del_subscribe         = int   (*)(void* agent,
                                                 std::vector<std::string> dev_list);
    using func_send_message_to_print = int   (*)(void* agent,
                                                 std::string dev_id,
                                                 std::string json_str,
                                                 int qos,
                                                 int flag);
    using func_set_on_message_fn     = int   (*)(void* agent,
                                                 std::function<void(std::string dev_id,
                                                                    std::string msg)> fn);
    using func_set_on_server_conn_fn = int   (*)(void* agent,
                                                 std::function<void(int return_code,
                                                                    int reason_code)> fn);








    using func_set_cert_file         = int (*)(void* agent,
                                               std::string folder,
                                               std::string filename);
    using func_set_extra_http_header = int (*)(void* agent,
                                               std::map<std::string,
                                                        std::string> extra_headers);
    using func_connect_server        = int (*)(void* agent);





    using func_connect_printer       = int   (*)(void* agent,
                                                 std::string dev_id,
                                                 std::string dev_ip,
                                                 std::string username,
                                                 std::string password,
                                                 bool        use_ssl);
    using func_disconnect_printer    = int   (*)(void* agent);
    using func_set_user_selected_machine = int  (*)(void* agent,
                                                    std::string dev_id);
    using func_install_device_cert       = void (*)(void* agent,
                                                    std::string dev_id,
                                                    bool        lan_only);
    using func_set_on_local_msg_fn   = int   (*)(void* agent,
                                                 std::function<void(std::string dev_id,
                                                                    std::string msg)> fn);
    using func_set_on_local_conn_fn  = int   (*)(void* agent,
                                                 std::function<void(int         status,
                                                                    std::string dev_id,
                                                                    std::string msg)> fn);

















    using func_set_queue_on_main_fn  = int (*)(void* agent,
                                               std::function<void(std::function<void()>)> fn);
    using func_set_on_printer_conn_fn= int (*)(void* agent,
                                               std::function<void(std::string topic_str)> fn);
    using func_set_get_country_code_fn = int (*)(void* agent,
                                                 std::function<std::string()> fn);
    using func_set_on_subscribe_fail_fn = int (*)(void* agent,
                                                  std::function<void(std::string topic)> fn);
    using func_set_server_callback   = int (*)(void* agent,
                                               std::function<void(std::string url,
                                                                  int status)> fn);





    using func_enable_multi_machine  = void (*)(void* agent, bool enable);













    struct PluginPrintParams {
        std::string dev_id;
        std::string task_name;
        std::string project_name;
        std::string preset_name;
        std::string filename;
        std::string config_filename;
        int         plate_index = 0;
        std::string ftp_folder;
        std::string ftp_file;
        std::string ftp_file_md5;
        std::string nozzle_mapping;
        std::string ams_mapping;
        std::string ams_mapping2;
        std::string ams_mapping_info;
        std::string nozzles_info;
        std::string connection_type;
        std::string comments;
        int         origin_profile_id = 0;
        int         stl_design_id = 0;
        std::string origin_model_id;
        std::string print_type;
        std::string dst_file;
        std::string dev_name;

        std::string dev_ip;
        bool        use_ssl_for_ftp  = true;
        bool        use_ssl_for_mqtt = true;
        std::string username;
        std::string password;

        bool        task_bed_leveling          = false;
        bool        task_flow_cali             = false;
        bool        task_vibration_cali        = false;
        bool        task_layer_inspect         = false;
        bool        task_record_timelapse      = false;
        bool        task_timelapse_use_internal= false;
        bool        task_use_ams               = false;
        std::string task_bed_type;
        std::string extra_options;
        int         auto_bed_leveling         = 0;
        int         auto_flow_cali             = 0;
        int         auto_offset_cali           = 0;
        int         extruder_cali_manual_mode  = -1;
        bool        task_ext_change_assist     = false;
        bool        try_emmc_print             = false;
    };

    using func_start_send_gcode_to_sdcard = int (*)(
        void* agent,
        PluginPrintParams params,
        std::function<void(int status, int code, std::string msg)> update_fn,
        std::function<bool()>                                       cancel_fn,
        std::function<bool(int status, std::string job_info)>       wait_fn);


    using func_start_local_print = int (*)(
        void* agent,
        PluginPrintParams params,
        std::function<void(int status, int code, std::string msg)> update_fn,
        std::function<bool()>                                       cancel_fn);

    using func_start_sdcard_print = int (*)(
        void* agent,
        PluginPrintParams params,
        std::function<void(int status, int code, std::string msg)> update_fn,
        std::function<bool()>                                       cancel_fn);

    using func_start_print = int (*)(
        void* agent,
        PluginPrintParams params,
        std::function<void(int status, int code, std::string msg)> update_fn,
        std::function<bool()>                                       cancel_fn,
        std::function<bool(int status, std::string job_info)>       wait_fn);

    using func_start_local_print_with_record = int (*)(
        void* agent,
        PluginPrintParams params,
        std::function<void(int status, int code, std::string msg)> update_fn,
        std::function<bool()>                                       cancel_fn,
        std::function<bool(int status, std::string job_info)>       wait_fn);




    using func_get_camera_url = int (*)(void* agent,
                                        std::string dev_id,
                                        std::function<void(std::string)> cb);
}

std::string env_or_empty(const char* name) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string();
}

std::string home_dir() { return env_or_empty("HOME"); }

std::vector<std::string> default_plugin_candidates() {
    std::vector<std::string> out;
    std::string from_env = env_or_empty("BAMBU_BRIDGE_PLUGIN_PATH");
    if (!from_env.empty()) out.push_back(from_env);
#if defined(_WIN32)
    out.emplace_back("bambu_networking.dll");
#elif defined(__APPLE__)
    out.emplace_back("/usr/local/lib/libbambu_networking.dylib");
    std::string h = home_dir();
    if (!h.empty())
        out.push_back(h + "/Library/Application Support/BambuStudio/plugins/libbambu_networking.dylib");
#else
    out.emplace_back("/usr/lib/x86_64-linux-gnu/libbambu_networking.so");
    std::string h = home_dir();
    if (!h.empty())
        out.push_back(h + "/.config/BambuStudio/plugins/libbambu_networking.so");
#endif
    return out;
}

struct DynLib {
#if defined(_WIN32)
    HMODULE handle = nullptr;
#else
    void*   handle = nullptr;
#endif
    std::string path;

    bool open(const std::string& p) {
        path = p;
#if defined(_WIN32)
        handle = LoadLibraryA(p.c_str());
#else
        handle = dlopen(p.c_str(), RTLD_LAZY | RTLD_LOCAL);
#endif
        return handle != nullptr;
    }
    template <typename FnT>
    FnT sym(const char* name) const {
        if (!handle) return nullptr;
#if defined(_WIN32)
        return reinterpret_cast<FnT>(GetProcAddress(handle, name));
#else
        return reinterpret_cast<FnT>(dlsym(handle, name));
#endif
    }
    void close() {
        if (!handle) return;
#if defined(_WIN32)
        FreeLibrary(handle);
#else
        dlclose(handle);
#endif
        handle = nullptr;
    }
    ~DynLib() { close(); }
};

}

struct BambuNetworkingPluginHandle::Impl {
    PluginHandleConfig cfg;

    DynLib  lib;
    void*   agent = nullptr;
    bool    started = false;


    func_create_agent          create_agent          = nullptr;
    func_destroy_agent         destroy_agent         = nullptr;
    func_get_version           get_version           = nullptr;
    func_init_log              init_log              = nullptr;
    func_set_config_dir        set_config_dir        = nullptr;
    func_set_country_code      set_country_code      = nullptr;
    func_start                 start                 = nullptr;
    func_is_user_login         is_user_login         = nullptr;
    func_is_server_connected   is_server_connected   = nullptr;
    func_get_user_print_info   get_user_print_info   = nullptr;
    func_add_subscribe         add_subscribe         = nullptr;
    func_del_subscribe         del_subscribe         = nullptr;
    func_send_message_to_print send_message_to_print = nullptr;
    func_set_on_message_fn     set_on_message_fn     = nullptr;
    func_set_on_server_conn_fn set_on_server_conn_fn = nullptr;
    func_set_cert_file         set_cert_file         = nullptr;
    func_set_extra_http_header set_extra_http_header = nullptr;
    func_connect_server        connect_server        = nullptr;
    func_start_send_gcode_to_sdcard      start_send_gcode_to_sdcard      = nullptr;
    func_start_local_print_with_record   start_local_print_with_record   = nullptr;
    func_start_local_print               start_local_print               = nullptr;
    func_start_sdcard_print              start_sdcard_print              = nullptr;
    func_start_print                     start_print                     = nullptr;
    func_connect_printer                 connect_printer                 = nullptr;
    func_disconnect_printer              disconnect_printer              = nullptr;
    func_set_user_selected_machine       set_user_selected_machine       = nullptr;
    func_install_device_cert             install_device_cert             = nullptr;
    func_set_on_local_msg_fn             set_on_local_msg_fn             = nullptr;
    func_set_on_local_conn_fn            set_on_local_conn_fn            = nullptr;
    func_get_camera_url                  get_camera_url                  = nullptr;
    func_set_queue_on_main_fn            set_queue_on_main_fn            = nullptr;
    func_set_on_printer_conn_fn          set_on_printer_conn_fn          = nullptr;
    func_set_get_country_code_fn         set_get_country_code_fn         = nullptr;
    func_set_on_subscribe_fail_fn        set_on_subscribe_fail_fn        = nullptr;
    func_set_server_callback             set_server_callback             = nullptr;
    func_enable_multi_machine            enable_multi_machine            = nullptr;





    std::function<void(std::string, std::string)> on_message_cb;
    std::function<void(int, int)>                 on_server_conn_cb;
    std::function<void(std::string, std::string)> on_local_msg_cb;
    std::function<void(int, std::string, std::string)> on_local_conn_cb;



    std::function<void(std::function<void()>)>    queue_on_main_cb;
    std::function<void(std::string)>              on_printer_conn_cb;
    std::function<std::string()>                  get_country_code_cb;
    std::function<void(std::string)>              on_subscribe_fail_cb;
    std::function<void(std::string, int)>         server_err_cb;




    std::mutex                                                                  mu;
    std::unordered_map<std::string, BambuNetworkingPluginHandle::MessageReceiver> receivers;
    std::unordered_map<std::string, BambuNetworkingPluginHandle::MessageReceiver> local_receivers;
    std::function<void(int, int)>                                                 local_connected_cb;


    std::atomic<bool> server_connected{false};

    std::atomic<bool> local_connected{false};


    std::atomic<bool> ready_override{false};

    explicit Impl(PluginHandleConfig c) : cfg(std::move(c)) {}

    ~Impl() {
        if (agent && destroy_agent) {
            destroy_agent(agent);
            agent = nullptr;
        }
    }

    bool load_plugin() {
        if (lib.handle) return true;
        std::vector<std::string> candidates;
        if (!cfg.plugin_path.empty()) candidates.push_back(cfg.plugin_path);
        else                          candidates = default_plugin_candidates();
        for (const auto& cand : candidates) {
            if (lib.open(cand)) break;
        }
        if (!lib.handle) return false;

        create_agent          = lib.sym<func_create_agent>         ("bambu_network_create_agent");
        destroy_agent         = lib.sym<func_destroy_agent>        ("bambu_network_destroy_agent");
        get_version           = lib.sym<func_get_version>          ("bambu_network_get_version");
        init_log              = lib.sym<func_init_log>             ("bambu_network_init_log");
        set_config_dir        = lib.sym<func_set_config_dir>       ("bambu_network_set_config_dir");
        set_country_code      = lib.sym<func_set_country_code>     ("bambu_network_set_country_code");
        start                 = lib.sym<func_start>                ("bambu_network_start");
        is_user_login         = lib.sym<func_is_user_login>        ("bambu_network_is_user_login");
        is_server_connected   = lib.sym<func_is_server_connected>  ("bambu_network_is_server_connected");
        get_user_print_info   = lib.sym<func_get_user_print_info>  ("bambu_network_get_user_print_info");
        add_subscribe         = lib.sym<func_add_subscribe>        ("bambu_network_add_subscribe");
        del_subscribe         = lib.sym<func_del_subscribe>        ("bambu_network_del_subscribe");





        send_message_to_print = lib.sym<func_send_message_to_print>("bambu_network_send_message");
        set_on_message_fn     = lib.sym<func_set_on_message_fn>    ("bambu_network_set_on_message_fn");
        set_on_server_conn_fn = lib.sym<func_set_on_server_conn_fn>("bambu_network_set_on_server_connected_fn");
        set_cert_file         = lib.sym<func_set_cert_file>        ("bambu_network_set_cert_file");
        set_extra_http_header = lib.sym<func_set_extra_http_header>("bambu_network_set_extra_http_header");
        connect_server        = lib.sym<func_connect_server>       ("bambu_network_connect_server");
        start_send_gcode_to_sdcard = lib.sym<func_start_send_gcode_to_sdcard>(
            "bambu_network_start_send_gcode_to_sdcard");
        start_local_print_with_record = lib.sym<func_start_local_print_with_record>(
            "bambu_network_start_local_print_with_record");
        start_local_print = lib.sym<func_start_local_print>(
            "bambu_network_start_local_print");
        start_sdcard_print = lib.sym<func_start_sdcard_print>(
            "bambu_network_start_sdcard_print");
        start_print = lib.sym<func_start_print>(
            "bambu_network_start_print");
        connect_printer     = lib.sym<func_connect_printer>   ("bambu_network_connect_printer");
        disconnect_printer  = lib.sym<func_disconnect_printer>("bambu_network_disconnect_printer");
        set_user_selected_machine = lib.sym<func_set_user_selected_machine>(
            "bambu_network_set_user_selected_machine");
        install_device_cert = lib.sym<func_install_device_cert>(
            "bambu_network_install_device_cert");
        set_on_local_msg_fn = lib.sym<func_set_on_local_msg_fn>("bambu_network_set_on_local_message_fn");
        set_on_local_conn_fn = lib.sym<func_set_on_local_conn_fn>("bambu_network_set_on_local_connect_fn");
        get_camera_url       = lib.sym<func_get_camera_url>     ("bambu_network_get_camera_url");





        set_queue_on_main_fn = lib.sym<func_set_queue_on_main_fn>(
            "bambu_network_set_queue_on_main_fn");
        set_on_printer_conn_fn = lib.sym<func_set_on_printer_conn_fn>(
            "bambu_network_set_on_printer_connected_fn");
        set_get_country_code_fn = lib.sym<func_set_get_country_code_fn>(
            "bambu_network_set_get_country_code_fn");
        set_on_subscribe_fail_fn = lib.sym<func_set_on_subscribe_fail_fn>(
            "bambu_network_set_on_subscribe_failure_fn");
        set_server_callback = lib.sym<func_set_server_callback>(
            "bambu_network_set_server_callback");
        enable_multi_machine = lib.sym<func_enable_multi_machine>(
            "bambu_network_enable_multi_machine");




        return create_agent != nullptr;
    }

    bool ensure_started(BambuNetworkingPluginHandle* self) {
        if (!load_plugin()) {
            std::fprintf(stderr, "[plugin] ensure_started: load_plugin FAILED "
                "(lib.handle=%p create_agent=%p path='%s')\n",
                (void*)lib.handle, (void*)create_agent, cfg.plugin_path.c_str());
            std::fflush(stderr);
            return false;
        }
        if (!agent) {
            agent = create_agent(cfg.log_dir);
            std::fprintf(stderr, "[plugin] ensure_started: create_agent('%s') "
                "-> agent=%p\n", cfg.log_dir.c_str(), (void*)agent);
            std::fflush(stderr);
            if (!agent) return false;
        }
        if (started) return true;





        if (set_config_dir && !cfg.config_dir.empty())
            set_config_dir(agent, cfg.config_dir);
        if (init_log) init_log(agent);

        if (set_cert_file && !cfg.cert_dir.empty() && !cfg.cert_file.empty()) {
            (void) set_cert_file(agent, cfg.cert_dir, cfg.cert_file);
        }

        if (set_extra_http_header && !cfg.extra_http_headers.empty()) {
            (void) set_extra_http_header(agent, cfg.extra_http_headers);
        }




        if (set_on_message_fn) {
            on_message_cb = [self](std::string dev_id, std::string msg) {
                self->dispatch_message(dev_id, msg);
            };
            set_on_message_fn(agent, on_message_cb);
        }
        if (set_on_server_conn_fn) {
            auto* impl_ptr = this;
            on_server_conn_cb = [impl_ptr](int rc, int ) {

                impl_ptr->server_connected.store(rc == 0);
            };
            set_on_server_conn_fn(agent, on_server_conn_cb);
        }







        if (set_on_local_msg_fn) {
            on_local_msg_cb = [self](std::string dev_id, std::string msg) {
                self->dispatch_local_message(dev_id, msg);
            };
            set_on_local_msg_fn(agent, on_local_msg_cb);
        }
        if (set_on_local_conn_fn) {
            on_local_conn_cb = [self](int rc, std::string ,
                                      std::string ) {
                self->dispatch_local_connected(rc == 0);
            };
            set_on_local_conn_fn(agent, on_local_conn_cb);
        }


















        if (set_queue_on_main_fn) {
            queue_on_main_cb = [](std::function<void()> work) {
                if (work) work();
            };
            set_queue_on_main_fn(agent, queue_on_main_cb);
        }





        if (set_on_printer_conn_fn) {











            on_printer_conn_cb = [this](std::string topic_str) {

                std::string dev = topic_str;
                const std::string pfx = "tunnel/";
                if (dev.compare(0, pfx.size(), pfx) == 0)
                    dev = dev.substr(pfx.size());
                std::fprintf(stderr,
                    "[plugin-cb] on_printer_connected topic=%s dev=%s -> "
                    "set_user_selected_machine + install_device_cert "
                    "(arm enc_msg signing gate)\n",
                    topic_str.c_str(), dev.c_str());
                std::fflush(stderr);
                if (set_user_selected_machine)
                    set_user_selected_machine(agent, dev);
                if (install_device_cert)
                    install_device_cert(agent, dev, false);
            };
            set_on_printer_conn_fn(agent, on_printer_conn_cb);
        }




        if (set_get_country_code_fn) {
            std::string cc = cfg.country_code;
            get_country_code_cb = [cc]() -> std::string { return cc; };
            set_get_country_code_fn(agent, get_country_code_cb);
        }




        if (set_on_subscribe_fail_fn) {
            on_subscribe_fail_cb = [](std::string topic) {
                std::fprintf(stderr,
                    "[plugin-cb] on_subscribe_failure topic=%s\n",
                    topic.c_str());
                std::fflush(stderr);
            };
            set_on_subscribe_fail_fn(agent, on_subscribe_fail_cb);
        }


        if (set_server_callback) {
            server_err_cb = [](std::string url, int status) {
                std::fprintf(stderr,
                    "[plugin-cb] server_callback url=%s status=%d\n",
                    url.c_str(), status);
                std::fflush(stderr);
            };
            set_server_callback(agent, server_err_cb);
        }

        if (set_country_code && !cfg.country_code.empty())
            set_country_code(agent, cfg.country_code);









        if (enable_multi_machine) {
            enable_multi_machine(agent, true);
            std::fprintf(stderr, "[plugin] enable_multi_machine(true)\n");
            std::fflush(stderr);
        }

        int start_rc = start ? start(agent) : -999;
        std::fprintf(stderr,
            "[plugin] start rc=%d login=%d server_connected=%d\n",
            start_rc,
            is_user_login ? int(is_user_login(agent)) : -1,
            is_server_connected ? int(is_server_connected(agent)) : -1);
        std::fflush(stderr);






        if (connect_server) {
            int rc = connect_server(agent);
            std::fprintf(stderr,
                "[plugin] connect_server rc=%d (post-call login=%d server_connected=%d)\n",
                rc,
                is_user_login ? int(is_user_login(agent)) : -1,
                is_server_connected ? int(is_server_connected(agent)) : -1);
            std::fflush(stderr);
        }











        started = true;
        return true;
    }
};

BambuNetworkingPluginHandle::BambuNetworkingPluginHandle(PluginHandleConfig cfg)
    : m_impl(std::make_unique<Impl>(std::move(cfg))) {}

BambuNetworkingPluginHandle::~BambuNetworkingPluginHandle() = default;

bool BambuNetworkingPluginHandle::init() {
    return m_impl->ensure_started(this);
}

bool BambuNetworkingPluginHandle::agent_ready() const {
    if (m_impl->ready_override.load()) return true;
    return m_impl->agent != nullptr && m_impl->started;
}

std::string BambuNetworkingPluginHandle::plugin_version() const {



    if (!m_impl->get_version) return "00.00.00.00";
    return m_impl->get_version();
}

bool BambuNetworkingPluginHandle::is_user_login() const {
    if (!m_impl->agent || !m_impl->is_user_login) return false;
    return m_impl->is_user_login(m_impl->agent);
}

bool BambuNetworkingPluginHandle::is_server_connected() const {
    if (m_impl->ready_override.load()) {

        return m_impl->server_connected.load();
    }
    if (!m_impl->agent) return false;

    if (m_impl->server_connected.load()) return true;
    if (m_impl->is_server_connected) return m_impl->is_server_connected(m_impl->agent);
    return false;
}

bool BambuNetworkingPluginHandle::get_user_print_info(unsigned int* http_code,
                                                     std::string*  http_body) const {
    if (!m_impl->agent || !m_impl->get_user_print_info) return false;
    return m_impl->get_user_print_info(m_impl->agent, http_code, http_body) == 0;
}

int BambuNetworkingPluginHandle::subscribe_device(const std::string& dev_id) {
    if (!m_impl->agent || !m_impl->add_subscribe) return -1;
    std::vector<std::string> v{dev_id};
    return m_impl->add_subscribe(m_impl->agent, v);
}

int BambuNetworkingPluginHandle::unsubscribe_device(const std::string& dev_id) {
    if (!m_impl->agent || !m_impl->del_subscribe) return -1;
    std::vector<std::string> v{dev_id};
    return m_impl->del_subscribe(m_impl->agent, v);
}

int BambuNetworkingPluginHandle::publish_to_device(const std::string& dev_id,
                                                  const std::string& json_payload,
                                                  int                qos) {
    if (!m_impl->agent || !m_impl->send_message_to_print) return -1;


    return m_impl->send_message_to_print(m_impl->agent, dev_id, json_payload, qos, 0);
}

int BambuNetworkingPluginHandle::upload_gcode_to_sdcard(
        const CloudUploadParams& params) {
    if (!m_impl->agent) {
        return -1000;
    }
    if (!m_impl->start_send_gcode_to_sdcard) {
        return -1001;
    }

    PluginPrintParams pp{};
    pp.dev_id           = params.dev_id;
    pp.dev_ip           = params.dev_ip;
    pp.username         = "bblp";
    pp.password         = params.access_code;
    pp.filename         = params.local_file_path;
    pp.project_name     = params.project_name.empty()
                          ? params.local_file_path
                          : params.project_name;
    pp.connection_type  = params.connection_type;
    pp.use_ssl_for_ftp  = params.use_ssl_for_ftp;
    pp.use_ssl_for_mqtt = params.use_ssl_for_mqtt;

    int rc = m_impl->start_send_gcode_to_sdcard(
        m_impl->agent, std::move(pp),
         {},  {},  {});

    return rc;
}

void BambuNetworkingPluginHandle::register_receiver(const std::string& dev_id,
                                                    MessageReceiver    cb) {
    std::lock_guard<std::mutex> lk(m_impl->mu);
    if (cb) m_impl->receivers[dev_id] = std::move(cb);
    else    m_impl->receivers.erase(dev_id);
}

void BambuNetworkingPluginHandle::unregister_receiver(const std::string& dev_id) {
    std::lock_guard<std::mutex> lk(m_impl->mu);
    m_impl->receivers.erase(dev_id);
}

void BambuNetworkingPluginHandle::deliver_message_for_test(const std::string& dev_id,
                                                          const std::string& payload) {
    dispatch_message(dev_id, payload);
}

void BambuNetworkingPluginHandle::deliver_server_connected_for_test(bool connected) {
    m_impl->server_connected.store(connected);
}

void BambuNetworkingPluginHandle::set_agent_ready_for_test(bool ready) {
    m_impl->ready_override.store(ready);
}

void BambuNetworkingPluginHandle::dispatch_message(const std::string& dev_id,
                                                  const std::string& payload) {
    MessageReceiver cb;
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        auto it = m_impl->receivers.find(dev_id);
        if (it == m_impl->receivers.end()) return;
        cb = it->second;
    }
    if (!cb) return;





    std::string topic = "device/" + dev_id + "/report";
    std::vector<uint8_t> bytes(payload.begin(), payload.end());
    cb(std::move(topic), std::move(bytes), 0);
}

int BambuNetworkingPluginHandle::connect_printer(const std::string& dev_id,
                                                 const std::string& dev_ip,
                                                 const std::string& username,
                                                 const std::string& password,
                                                 bool               use_ssl) {
    if (!m_impl->agent)            return -1;
    if (!m_impl->connect_printer)  return -2;
    return m_impl->connect_printer(m_impl->agent, dev_id, dev_ip,
                                   username, password, use_ssl);
}

int BambuNetworkingPluginHandle::set_user_selected_machine(const std::string& dev_id) {
    if (!m_impl->agent)                    return -1;
    if (!m_impl->set_user_selected_machine) return -2;
    return m_impl->set_user_selected_machine(m_impl->agent, dev_id);
}

void BambuNetworkingPluginHandle::install_device_cert(const std::string& dev_id,
                                                      bool lan_only) {
    if (!m_impl->agent)              return;
    if (!m_impl->install_device_cert) return;
    m_impl->install_device_cert(m_impl->agent, dev_id, lan_only);
}

int BambuNetworkingPluginHandle::disconnect_printer() {
    if (!m_impl->agent)               return -1;
    if (!m_impl->disconnect_printer)  return -2;
    int rc = m_impl->disconnect_printer(m_impl->agent);





    m_impl->local_connected.store(false);
    return rc;
}

int BambuNetworkingPluginHandle::send_message_to_printer(const std::string& dev_id,
                                                        const std::string& json_payload,
                                                        int                qos) {
    if (!m_impl->agent || !m_impl->send_message_to_print) return -1;
    return m_impl->send_message_to_print(m_impl->agent, dev_id,
                                         json_payload, qos, 0);
}

namespace {

template <typename SrcT, typename DstT>
void copy_gui_fields_into_plugin_params(
        const SrcT&                                         src,
        DstT&                                               dst,
        const std::string&                                  default_connection) {
    dst.dev_id           = src.dev_id;
    dst.dev_ip           = src.dev_ip;
    dst.username         = "bblp";
    dst.password         = src.access_code;
    dst.filename         = src.local_file_path;
    dst.project_name     = src.project_name.empty()
                           ? src.local_file_path : src.project_name;
    dst.connection_type  = src.connection_type.empty()
                           ? default_connection : src.connection_type;
    dst.use_ssl_for_ftp  = src.use_ssl_for_ftp;
    dst.use_ssl_for_mqtt = src.use_ssl_for_mqtt;


    dst.task_name                  = src.task_name;
    dst.preset_name                = src.preset_name;
    dst.config_filename            = src.config_filename;
    dst.plate_index                = src.plate_index;
    dst.nozzle_mapping             = src.nozzle_mapping;
    dst.ams_mapping                = src.ams_mapping;
    dst.ams_mapping2               = src.ams_mapping2;
    dst.ams_mapping_info           = src.ams_mapping_info;
    dst.nozzles_info               = src.nozzles_info;
    dst.comments                   = src.comments;
    dst.origin_profile_id          = src.origin_profile_id;
    dst.stl_design_id              = src.stl_design_id;
    dst.origin_model_id            = src.origin_model_id;
    dst.print_type                 = src.print_type;
    dst.dst_file                   = src.dst_file;
    dst.dev_name                   = src.dev_name;
    dst.task_bed_leveling          = src.task_bed_leveling;
    dst.task_flow_cali             = src.task_flow_cali;
    dst.task_vibration_cali        = src.task_vibration_cali;
    dst.task_layer_inspect         = src.task_layer_inspect;
    dst.task_record_timelapse      = src.task_record_timelapse;
    dst.task_timelapse_use_internal= src.task_timelapse_use_internal;
    dst.task_use_ams               = src.task_use_ams;
    dst.task_bed_type              = src.task_bed_type;
    dst.extra_options              = src.extra_options;
    dst.auto_bed_leveling          = src.auto_bed_leveling;
    dst.auto_flow_cali             = src.auto_flow_cali;
    dst.auto_offset_cali           = src.auto_offset_cali;
    dst.extruder_cali_manual_mode  = src.extruder_cali_manual_mode;
    dst.task_ext_change_assist     = src.task_ext_change_assist;
    dst.try_emmc_print             = src.try_emmc_print;
}
}

int BambuNetworkingPluginHandle::start_local_print_with_record(
        const LocalPrintParams& params) {
    if (!m_impl->agent)                            return -1;
    if (!m_impl->start_local_print_with_record)    return -2;
    PluginPrintParams pp{};
    copy_gui_fields_into_plugin_params(params, pp,  "lan");












    if (std::getenv("BAMBU_BRIDGE_PRINT_TRACE")) {
        auto* impl = m_impl.get();
        (void)impl;




        long cancel_after = 0;
        if (const char* ca = std::getenv("BAMBU_BRIDGE_PRINT_CANCEL_AFTER_STAGE"))
            cancel_after = std::atol(ca);
        auto stage_count = std::make_shared<std::atomic<long>>(0);
        auto t0 = std::chrono::steady_clock::now();
        long max_ms = 60000;
        if (const char* mm = std::getenv("BAMBU_BRIDGE_PRINT_MAX_MS"))
            max_ms = std::atol(mm);
        auto update_fn = [stage_count](int status, int code, std::string msg) {
            long n = ++(*stage_count);
            std::fprintf(stderr,
                "[plugin-print] stage#%ld status=%d code=%d msg=%s\n",
                n, status, code, msg.c_str());
            std::fflush(stderr);
        };
        auto cancel_fn = [stage_count, cancel_after, t0, max_ms]() -> bool {
            bool by_stage = (cancel_after > 0 &&
                             stage_count->load() >= cancel_after);
            bool by_time =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count() >= max_ms;
            if (by_stage || by_time) {
                std::fprintf(stderr,
                    "[plugin-print] cancel_fn -> true (by_stage=%d by_time=%d "
                    "stages=%ld)\n", int(by_stage), int(by_time),
                    stage_count->load());
                std::fflush(stderr);
                return true;
            }
            return false;
        };
        auto wait_fn = [](int , std::string ) -> bool {
            return true;
        };
        return m_impl->start_local_print_with_record(
            m_impl->agent, std::move(pp),
            update_fn, cancel_fn, wait_fn);
    }




    return m_impl->start_local_print_with_record(
        m_impl->agent, std::move(pp),
         {},  {},  {});
}

int BambuNetworkingPluginHandle::start_local_print(
        const LocalPrintParams& params) {
    if (!m_impl->agent)            return -1;
    if (!m_impl->start_local_print) return -2;
    PluginPrintParams pp{};
    copy_gui_fields_into_plugin_params(params, pp,  "lan");

    if (std::getenv("BAMBU_BRIDGE_PRINT_TRACE")) {
        auto stage_count = std::make_shared<std::atomic<long>>(0);
        auto t0 = std::chrono::steady_clock::now();
        long max_ms = 60000;
        if (const char* mm = std::getenv("BAMBU_BRIDGE_PRINT_MAX_MS"))
            max_ms = std::atol(mm);
        long cancel_after = 0;
        if (const char* ca = std::getenv("BAMBU_BRIDGE_PRINT_CANCEL_AFTER_STAGE"))
            cancel_after = std::atol(ca);
        auto update_fn = [stage_count](int status, int code, std::string msg) {
            long n = ++(*stage_count);
            std::fprintf(stderr,
                "[plugin-print] (no-record) stage#%ld status=%d code=%d "
                "msg=%s\n", n, status, code, msg.c_str());
            std::fflush(stderr);
        };
        auto cancel_fn = [stage_count, cancel_after, t0, max_ms]() -> bool {
            bool by_stage = (cancel_after > 0 &&
                             stage_count->load() >= cancel_after);
            bool by_time =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count() >= max_ms;
            if (by_stage || by_time) {
                std::fprintf(stderr,
                    "[plugin-print] (no-record) cancel_fn -> true "
                    "(by_stage=%d by_time=%d stages=%ld)\n",
                    int(by_stage), int(by_time), stage_count->load());
                std::fflush(stderr);
                return true;
            }
            return false;
        };
        return m_impl->start_local_print(
            m_impl->agent, std::move(pp), update_fn, cancel_fn);
    }
    return m_impl->start_local_print(
        m_impl->agent, std::move(pp),
         {},  {});
}

int BambuNetworkingPluginHandle::start_sdcard_print(
        const LocalPrintParams& params) {
    if (!m_impl->agent)             return -1;
    if (!m_impl->start_sdcard_print) return -2;
    PluginPrintParams pp{};
    copy_gui_fields_into_plugin_params(params, pp,  "lan");
    return m_impl->start_sdcard_print(
        m_impl->agent, std::move(pp),
         {},  {});
}

bool BambuNetworkingPluginHandle::is_local_connected() const {
    if (m_impl->ready_override.load()) return m_impl->local_connected.load();
    if (!m_impl->agent) return false;
    return m_impl->local_connected.load();
}

void BambuNetworkingPluginHandle::register_local_message_receiver(
        const std::string& dev_id, MessageReceiver cb) {
    std::lock_guard<std::mutex> lk(m_impl->mu);
    if (cb) m_impl->local_receivers[dev_id] = std::move(cb);
    else    m_impl->local_receivers.erase(dev_id);
}

void BambuNetworkingPluginHandle::unregister_local_message_receiver(
        const std::string& dev_id) {
    std::lock_guard<std::mutex> lk(m_impl->mu);
    m_impl->local_receivers.erase(dev_id);
}

void BambuNetworkingPluginHandle::register_local_connected_callback(
        std::function<void(int, int)> cb) {
    std::lock_guard<std::mutex> lk(m_impl->mu);
    m_impl->local_connected_cb = std::move(cb);
}

void BambuNetworkingPluginHandle::deliver_local_message_for_test(
        const std::string& dev_id, const std::string& payload) {
    dispatch_local_message(dev_id, payload);
}

void BambuNetworkingPluginHandle::deliver_local_connected_for_test(bool connected) {
    dispatch_local_connected(connected);
}

void BambuNetworkingPluginHandle::dispatch_local_message(const std::string& dev_id,
                                                        const std::string& payload) {
    MessageReceiver cb;
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        auto it = m_impl->local_receivers.find(dev_id);
        if (it == m_impl->local_receivers.end()) return;
        cb = it->second;
    }
    if (!cb) return;



    std::string topic = "device/" + dev_id + "/report";
    std::vector<uint8_t> bytes(payload.begin(), payload.end());
    cb(std::move(topic), std::move(bytes), 0);
}

void BambuNetworkingPluginHandle::dispatch_local_connected(bool connected) {
    m_impl->local_connected.store(connected);
    std::function<void(int, int)> cb;
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        cb = m_impl->local_connected_cb;
    }
    if (cb) cb(connected ? 0 : -1, 0);
}

int BambuNetworkingPluginHandle::get_camera_url(const std::string& dev_id,
                                                std::string*       url_out,
                                                int                timeout_ms) {
    if (!url_out)              return -3;
    url_out->clear();
    if (!m_impl->agent)        return -1;
    if (!m_impl->get_camera_url) return -2;







    struct Shared {
        std::mutex              mu;
        std::condition_variable cv;
        bool                    done = false;
        std::string             url;
    };
    auto shared = std::make_shared<Shared>();

    int rc = m_impl->get_camera_url(m_impl->agent, dev_id,
        [shared](std::string url) {
            std::lock_guard<std::mutex> lk(shared->mu);
            shared->url  = std::move(url);
            shared->done = true;
            shared->cv.notify_all();
        });
    if (rc != 0) return -3;

    std::unique_lock<std::mutex> lk(shared->mu);
    if (!shared->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                             [&] { return shared->done; })) {
        return -4;
    }
    *url_out = shared->url;
    return 0;
}

}
}
