#ifndef SLIC3R_BAMBU_BRIDGE_HEADLESS_BRIDGE_APP_HPP
#define SLIC3R_BAMBU_BRIDGE_HEADLESS_BRIDGE_APP_HPP

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace Slic3r {
namespace bambu {

class BambuNetworkingPluginHandle;
class BambuSourceHandle;
class CloudInventory;

namespace tls    { class CertFactory;   }
namespace server { class SsdpResponder; }
namespace server { class SsdpListener;  }
namespace server { class MqttBroker;    }
namespace server { class FtpsServer;    }
namespace server { class RtspServer;    }
namespace server { class VirtualTunnelServer; }
namespace router { class LanUplink;          }
namespace router { class CloudUplink;        }
namespace router { class LanUploadSink;      }
namespace router { class CloudUploadSink;    }
namespace router { class LanCameraSource;    }
namespace router { class CloudCameraSource;  }
namespace router { class JpegCameraSource;   }
namespace router { class NullCameraSource;   }
namespace router { class SessionRouter;      }
namespace router { class UploadSinkRouter;   }
namespace router { class CameraSourceRouter; }
namespace router { class UplinkHealthMonitor;}
namespace router { class NativeStorageDelegate; }

namespace headless {

struct VirtualPrinter {
    std::string dev_id;
    std::string dev_name;
    std::string lan_ip;
    std::string access_code;
    std::string model;
    std::string firmware;

    std::string camera_url;
};

struct AppConfig {

    std::string  plugin_path;

    std::string  bambu_source_path;

    std::string  config_dir;
    std::string  country_code;

    std::map<std::string, std::string> http_extra_headers;

    std::string cert_dir;
    std::string cert_file;

    std::chrono::seconds lan_ip_stale_after{120};

    std::vector<std::string> only_dev_ids;

    std::string  lan_iface_bind = "0.0.0.0";

    std::chrono::seconds inventory_poll{60};

    std::filesystem::path cert_cache_dir;

    bool         enable_ssdp  = true;
    bool         enable_mqtt  = true;
    bool         enable_ftps  = true;
    bool         enable_rtsp  = true;
    bool         enable_vtun  = true;

    uint16_t     mqtt_port_base = 8883;
    uint16_t     ftps_port_base = 39990;
    uint16_t     rtsp_port_base = 38322;

    uint16_t     vtun_port_base = 39998;

    std::string  ssdp_default_name     = "Bambu Bridge";
    std::string  ssdp_default_model    = "H2S";
    std::string  ssdp_default_firmware = "01.02.00.00";

    std::string  slicer_net_ver;
    std::string  slicer_cli_id;
    std::string  slicer_cli_ver;

    bool         host_drives_inventory = true;

    std::function<std::vector<VirtualPrinter>()> printer_source;
};

class App {
public:
    explicit App(AppConfig cfg);
    ~App();

    App(const App&)            = delete;
    App& operator=(const App&) = delete;

    int run();

    void shutdown();

    void set_virtual_printers(std::vector<VirtualPrinter> printers);

    void set_plugin_handle_for_test(
        std::shared_ptr<BambuNetworkingPluginHandle> handle);

    void attach_plugin_handle(
        std::shared_ptr<BambuNetworkingPluginHandle> handle) {
        set_plugin_handle_for_test(std::move(handle));
    }

    struct RealDeviceInfo {
        std::string real_dev_id;
        std::string lan_ip;
    };
    RealDeviceInfo lookup_real_device(const std::string& dev_id) const;

    uint16_t mqtt_port_for_dev_id(const std::string& dev_id) const;

    void set_bambu_source_handle_for_test(
        std::shared_ptr<BambuSourceHandle> handle);

    using StorageDelegate = std::function<void(
        const std::string& real_dev_id,
        const std::string& real_lan_ip,
        const std::string& access_code,
        const std::string& dev_ver,
        const std::string& net_ver,
        const std::string& cli_id,
        const std::string& cli_ver,
        int                cmdtype,
        std::string        request_body_json,
        std::function<void(int, std::string)> reply_cb)>;

    void attach_storage_delegate(
        StorageDelegate                         delegate,
        std::function<void(const std::string&)> release_cb = {});

    using CameraUrlResolver = std::function<
        int(const std::string& dev_id_or_ask,
            std::function<void(std::string url)> cb)>;
    void set_camera_url_resolver(CameraUrlResolver fn);

    bool poll_inventory_once();

    struct DeviceBinding {
        std::string dev_id;
        std::string lan_ip;
        uint16_t    mqtt_port = 0;
        uint16_t    ftps_port = 0;
        uint16_t    rtsp_port = 0;
        uint16_t    vtun_port = 0;
    };
    std::vector<DeviceBinding> device_bindings() const;

    struct MtlsInfo {
        std::string lan_ip;
        std::string access_code;
        std::string cert_path;
        std::string key_path;
    };
    bool mtls_info_for(const std::string& dev_id, MtlsInfo& out) const;

private:
    struct DeviceState;

    bool initialise();

    void teardown();

    void reconcile_once();

    void expire_stale_lan_ips();

    void poll_loop();

    void add_device_locked(const VirtualPrinter& vp);
    void update_lan_ip_locked(DeviceState&        state,
                              const std::string&  lan_ip);
    void remove_device_locked(const std::string& dev_id);

    AppConfig                                       m_cfg;

    std::shared_ptr<BambuNetworkingPluginHandle>          m_plugin;
    bool                                                  m_plugin_injected = false;
    std::shared_ptr<BambuSourceHandle>                    m_bambu_source;
    bool                                                  m_bambu_source_injected = false;

    StorageDelegate                                       m_storage_delegate;
    std::function<void(const std::string&)>               m_storage_release_cb;

    CameraUrlResolver                                     m_camera_url_resolver;

    std::shared_ptr<router::LanUplink>                    m_lan_uplink;

    struct DeviceState {
        std::string                                       dev_id;
        std::string                                       lan_ip;
        std::string                                       access_code;

        std::string                                       model;

        std::string                                       firmware_ver;

        std::string                                       camera_url;
        std::size_t                                       index = 0;
        uint16_t                                          mqtt_port = 0;
        uint16_t                                          ftps_port = 0;
        uint16_t                                          rtsp_port = 0;
        uint16_t                                          vtun_port = 0;

        std::chrono::steady_clock::time_point             lan_ip_last_seen{};
        std::shared_ptr<router::CameraSourceRouter>       cam_router;
        std::shared_ptr<router::LanCameraSource>          lan_cam;
        std::shared_ptr<router::CloudCameraSource>        cloud_cam;

        std::shared_ptr<router::JpegCameraSource>         jpeg_cam;
    };
    mutable std::mutex                                    m_devices_mu;
    std::map<std::string, DeviceState>                    m_devices;
    std::size_t                                           m_next_index = 0;

    std::map<std::string, std::size_t>                    m_pinned_offset;
    std::string                                           m_port_map_path;
    bool                                                  m_port_map_loaded = false;

    std::string                                           m_ssdp_advertise_ip;

    std::atomic<bool>                                     m_initialised{false};
    std::atomic<bool>                                     m_stop{false};
    std::condition_variable                               m_stop_cv;
    std::mutex                                            m_stop_mu;
    std::thread                                           m_poll_thread;

    std::thread                                           m_gcode_pulse_thread;
    std::atomic<bool>                                     m_gcode_pulse_started{false};

    std::thread                                           m_print3mf_thread;
    std::atomic<bool>                                     m_print3mf_started{false};
};

}
}
}

#endif
