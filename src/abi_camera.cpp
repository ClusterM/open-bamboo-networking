#include <functional>
#include <string>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/camera.hpp"

using obn::as_agent;

// Returns a local MJPEG URL for JPEG-capable printer models (A1, P1, N2S, …).
// For H.264 LAN models (X1, H2, …) and cloud paths (Agora/TUTK) we return an
// empty string: Studio takes its native LAN / cloud branch in those cases and
// never needs us to provide a URL.
OBN_ABI int bambu_network_get_camera_url(void* agent,
                                         std::string dev_id,
                                         std::function<void(std::string)> callback)
{
    if (agent) as_agent(agent)->maybe_setup_camera(dev_id);
    std::string url = obn::camera::get_url(dev_id);
    if (callback) callback(url);
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_camera_url_for_golive(void* agent,
                                                    std::string dev_id,
                                                    std::string /*sdev_id*/,
                                                    std::function<void(std::string)> callback)
{
    if (agent) as_agent(agent)->maybe_setup_camera(dev_id);
    std::string url = obn::camera::get_url(dev_id);
    if (callback) callback(url);
    return BAMBU_NETWORK_SUCCESS;
}

// Snapshot requires the cloud path (HMS service); not implemented.
OBN_ABI int bambu_network_get_hms_snapshot(void* /*agent*/,
                                           std::string& /*dev_id*/,
                                           std::string& /*file_name*/,
                                           std::function<void(std::string, int)> callback)
{
    if (callback) callback(std::string{}, -1);
    return BAMBU_NETWORK_SUCCESS;
}
