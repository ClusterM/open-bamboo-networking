

#ifndef SLIC3R_BAMBU_BRIDGE_ROUTER_LAN_UPLINK_HPP
#define SLIC3R_BAMBU_BRIDGE_ROUTER_LAN_UPLINK_HPP

#include "../server/IUplink.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace Slic3r {
namespace bambu {

class BambuNetworkingPluginHandle;
class EncMsgEnvelope;

namespace router {

struct LanUplinkConfig {
    std::string  dev_id;
    std::string  printer_ip;
    std::string  access_code;
    bool         use_ssl = true;


    uint16_t                printer_port = 8883;
    std::chrono::seconds    connect_timeout{10};
    std::chrono::seconds    keepalive{30};










    std::string  mtls_cert_path;
    std::string  mtls_key_path;
};

class LanUplink : public server::IUplink {
public:
    LanUplink();
    ~LanUplink() override;

    LanUplink(const LanUplink&)            = delete;
    LanUplink& operator=(const LanUplink&) = delete;






    void attach_plugin(std::shared_ptr<BambuNetworkingPluginHandle> handle);



    std::shared_ptr<BambuNetworkingPluginHandle> plugin_handle() const;









    void attach_enc_msg_envelope(std::shared_ptr<EncMsgEnvelope> envelope);
    std::shared_ptr<EncMsgEnvelope> enc_msg_envelope() const;







    void add_device   (LanUplinkConfig cfg);
    void remove_device(const std::string& dev_id);



    bool is_connected(const std::string& dev_id) const;


    void on_subscribe  (const std::string& dev_id, std::string topic) override;
    void on_publish    (const std::string& dev_id, std::string topic,
                        std::vector<uint8_t> payload, uint8_t qos) override;
    void on_unsubscribe(const std::string& dev_id, std::string topic) override;
    void on_disconnect (const std::string& dev_id) override;
    void attach_downstream(const std::string& dev_id,
                           uint64_t            session_id,
                           DownstreamPublisher publisher) override;
    void detach_downstream(const std::string& dev_id,
                           uint64_t            session_id) override;



    void attach_downstream(const std::string& dev_id,
                           DownstreamPublisher publisher) override;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}
}
}

#endif
