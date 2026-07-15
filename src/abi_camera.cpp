#include <functional>
#include <string>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/camera.hpp"
#include "obn/log.hpp"

using obn::as_agent;

// Prefer a real stream: LAN MJPEG for JPEG-capable models (A1, P1, N2S, …)
// or the Agora/TUTK cloud relay (see obn::camera), started lazily by
// maybe_setup_camera(). When neither source claims the printer (H.264 LAN
// models Studio drives natively, or a source we don't yet implement) fall
// back to handing Studio the printer's own LAN URL if we know its IP +
// access code:
//
//   bambu:///local/<ip>?port=6000&user=bblp&passwd=<code>[&lv=rtsps]
//
// Studio only checks that the reply starts with "bambu:///", so the file
// browser (PrinterFileSystem CTRL over :6000), the device-panel snapshot
// (mem:/N via FileTransferObject) and liveview all take the local route.
// The lv= hint tells libBambuSource to fetch video over RTSP(S) :322
// instead of MJPEG :6000 on X1/P1S/P2S-class printers (see
// stubs/BambuSource.cpp). When neither route is available we return an
// empty URL and Studio drives itself into its normal "connection failed"
// path.
OBN_ABI int bambu_network_get_camera_url(void* agent,
                                         std::string dev_id,
                                         std::function<void(std::string)> callback)
{
    // Studio packs "dev_id|dev_ver|protocols[|channel]" into the first
    // argument (MediaPlayCtrl.cpp / MediaFilePanel.cpp); only the leading
    // serial matters to us.
    const std::string serial = dev_id.substr(0, dev_id.find('|'));

    std::string url;
    const char* source = "(none)";
    if (auto* a = as_agent(agent); a && !serial.empty()) {
        a->maybe_setup_camera(serial);
        url = obn::camera::get_url(serial);
        if (!url.empty()) {
            source = "stream";
        } else {
            url = a->camera_url_for(serial);
            if (!url.empty()) source = "LAN fallback URL";
        }
    }
    OBN_INFO("get_camera_url dev=%s -> %s", serial.c_str(), source);
    if (callback) callback(std::move(url));
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_camera_url_for_golive(void* agent,
                                                    std::string dev_id,
                                                    std::string /*sdev_id*/,
                                                    std::function<void(std::string)> callback)
{
    // Go-Live streams to third-party platforms via Agora only; there is no
    // LAN equivalent to fall back to.
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
