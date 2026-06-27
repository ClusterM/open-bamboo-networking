#ifndef SLIC3R_BAMBU_BRIDGE_PLUGIN_HANDLE_HPP
#define SLIC3R_BAMBU_BRIDGE_PLUGIN_HANDLE_HPP

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace Slic3r {
namespace bambu {

struct PluginHandleConfig {
    std::string plugin_path;
    std::string log_dir;
    std::string config_dir;
    std::string country_code;

    std::map<std::string, std::string> extra_http_headers;

    std::string cert_dir;
    std::string cert_file;
};

class BambuNetworkingPluginHandle {
public:
    explicit BambuNetworkingPluginHandle(PluginHandleConfig cfg = {});
    virtual ~BambuNetworkingPluginHandle();

    BambuNetworkingPluginHandle(const BambuNetworkingPluginHandle&)            = delete;
    BambuNetworkingPluginHandle& operator=(const BambuNetworkingPluginHandle&) = delete;

    virtual bool init();

    virtual bool agent_ready() const;

    virtual std::string plugin_version() const;

    virtual bool is_user_login() const;

    virtual bool is_server_connected() const;

    virtual bool get_user_print_info(unsigned int* http_code,
                                     std::string*  http_body) const;

    virtual int subscribe_device  (const std::string& dev_id);
    virtual int unsubscribe_device(const std::string& dev_id);

    virtual int publish_to_device(const std::string& dev_id,
                                  const std::string& json_payload,
                                  int                qos);

    struct CloudUploadParams {
        std::string dev_id;
        std::string dev_ip;
        std::string access_code;
        std::string local_file_path;
        std::string project_name;
        std::string connection_type;
        bool        use_ssl_for_ftp  = true;
        bool        use_ssl_for_mqtt = true;

        std::string task_name;
        std::string preset_name;
        std::string config_filename;
        int         plate_index            = 0;
        std::string nozzle_mapping;
        std::string ams_mapping;
        std::string ams_mapping2;
        std::string ams_mapping_info;
        std::string nozzles_info;
        std::string comments;
        int         origin_profile_id      = 0;
        int         stl_design_id          = 0;
        std::string origin_model_id;
        std::string print_type;
        std::string dst_file;
        std::string dev_name;
        bool        task_bed_leveling          = false;
        bool        task_flow_cali             = false;
        bool        task_vibration_cali        = false;
        bool        task_layer_inspect         = false;
        bool        task_record_timelapse      = false;
        bool        task_timelapse_use_internal= false;
        bool        task_use_ams               = false;
        std::string task_bed_type;
        std::string extra_options;
        int         auto_bed_leveling          = 0;
        int         auto_flow_cali              = 0;
        int         auto_offset_cali            = 0;
        int         extruder_cali_manual_mode  = -1;
        bool        task_ext_change_assist     = false;
        bool        try_emmc_print             = false;
    };
    virtual int upload_gcode_to_sdcard(const CloudUploadParams& params);

    using MessageReceiver =
        std::function<void(std::string topic,
                           std::vector<uint8_t> payload,
                           uint8_t qos)>;

    virtual int connect_printer(const std::string& dev_id,
                                const std::string& dev_ip,
                                const std::string& username,
                                const std::string& password,
                                bool               use_ssl);

    virtual int set_user_selected_machine(const std::string& dev_id);

    virtual void install_device_cert(const std::string& dev_id, bool lan_only);

    virtual int disconnect_printer();

    virtual int send_message_to_printer(const std::string& dev_id,
                                        const std::string& json_payload,
                                        int                qos);

    struct LocalPrintParams {
        std::string dev_id;
        std::string dev_ip;
        std::string access_code;
        std::string local_file_path;
        std::string project_name;
        std::string connection_type;
        bool        use_ssl_for_ftp  = true;
        bool        use_ssl_for_mqtt = true;

        std::string task_name;
        std::string preset_name;
        std::string config_filename;
        int         plate_index            = 0;
        std::string nozzle_mapping;
        std::string ams_mapping;
        std::string ams_mapping2;
        std::string ams_mapping_info;
        std::string nozzles_info;
        std::string comments;
        int         origin_profile_id      = 0;
        int         stl_design_id          = 0;
        std::string origin_model_id;
        std::string print_type;
        std::string dst_file;
        std::string dev_name;
        bool        task_bed_leveling          = false;
        bool        task_flow_cali             = false;
        bool        task_vibration_cali        = false;
        bool        task_layer_inspect         = false;
        bool        task_record_timelapse      = false;
        bool        task_timelapse_use_internal= false;
        bool        task_use_ams               = false;
        std::string task_bed_type;
        std::string extra_options;
        int         auto_bed_leveling          = 0;
        int         auto_flow_cali              = 0;
        int         auto_offset_cali            = 0;
        int         extruder_cali_manual_mode  = -1;
        bool        task_ext_change_assist     = false;
        bool        try_emmc_print             = false;

    };
    virtual int start_local_print_with_record(const LocalPrintParams& params);

    virtual int start_local_print(const LocalPrintParams& params);

    virtual int start_sdcard_print(const LocalPrintParams& params);

    virtual bool is_local_connected() const;

    virtual void register_local_message_receiver  (const std::string& dev_id,
                                                   MessageReceiver    cb);
    virtual void unregister_local_message_receiver(const std::string& dev_id);

    virtual void register_local_connected_callback(
        std::function<void(int return_code, int reason_code)> cb);

    void deliver_local_message_for_test(const std::string& dev_id,
                                        const std::string& payload);
    void deliver_local_connected_for_test(bool connected);

    virtual void register_receiver  (const std::string& dev_id,
                                     MessageReceiver    cb);
    virtual void unregister_receiver(const std::string& dev_id);

    void deliver_message_for_test(const std::string& dev_id,
                                  const std::string& payload);

    virtual int get_camera_url(const std::string& dev_id,
                               std::string*       url_out,
                               int                timeout_ms = 10000);

    void deliver_server_connected_for_test(bool connected);

protected:

    void set_agent_ready_for_test(bool ready);

    void dispatch_message(const std::string& dev_id,
                          const std::string& payload);

    void dispatch_local_message(const std::string& dev_id,
                                const std::string& payload);

    void dispatch_local_connected(bool connected);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}
}

#endif
