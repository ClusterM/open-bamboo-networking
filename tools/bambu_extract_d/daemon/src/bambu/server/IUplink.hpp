#ifndef SLIC3R_BAMBU_BRIDGE_SERVER_IUPLINK_HPP
#define SLIC3R_BAMBU_BRIDGE_SERVER_IUPLINK_HPP

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace Slic3r {
namespace bambu {
namespace server {

class IUplink {
public:
    virtual ~IUplink() = default;

    virtual void on_subscribe  (const std::string& dev_id, std::string topic) = 0;
    virtual void on_publish    (const std::string& dev_id, std::string topic,
                                std::vector<uint8_t> payload, uint8_t qos) = 0;
    virtual void on_unsubscribe(const std::string& dev_id, std::string topic) = 0;
    virtual void on_disconnect (const std::string& dev_id) = 0;

    using DownstreamPublisher = std::function<void(std::string topic,
                                                   std::vector<uint8_t> payload,
                                                   uint8_t qos)>;

    virtual void attach_downstream(const std::string& dev_id,
                                   uint64_t            session_id,
                                   DownstreamPublisher publisher) = 0;

    virtual void detach_downstream(const std::string& dev_id,
                                   uint64_t            session_id) = 0;

    virtual void attach_downstream(const std::string& dev_id,
                                   DownstreamPublisher publisher) = 0;
};

}
}
}

#endif
