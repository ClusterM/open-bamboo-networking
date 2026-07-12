#include <functional>
#include <string>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/log.hpp"

using obn::as_agent;

// Cloud-signed TUTK/Agora liveview is intentionally not implemented -
// this plugin is a LAN-first replacement and the tunnels require the
// proprietary TUTK/Agora SDKs. Instead, when Studio asks for a remote
// URL (cloud-paired printer, not in LAN Only Mode: MediaFilePanel::
// fetchUrl, MediaPlayCtrl::Play/RequestFileSystemUrl) we hand back the
// printer's LAN URL if we know its IP + access code:
//
//   bambu:///local/<ip>?port=6000&user=bblp&passwd=<code>[&lv=rtsps]
//
// Studio only checks that the reply starts with "bambu:///", so the
// file browser (PrinterFileSystem CTRL over :6000), the device-panel
// snapshot (mem:/N via FileTransferObject) and liveview all take the
// local route even while the printer is cloud-paired. The lv= hint
// tells libBambuSource to fetch video over RTSP(S) :322 instead of
// MJPEG :6000 on X1/P1S/P2S-class printers (see stubs/BambuSource.cpp).
//
// When the LAN route is unknown (printer on another network) we return
// an empty URL and Studio drives itself into its normal "connection
// failed" path.
OBN_ABI int bambu_network_get_camera_url(void* agent,
                                         std::string dev_id,
                                         std::function<void(std::string)> callback)
{
    // Studio packs "dev_id|dev_ver|protocols[|channel]" into the first
    // argument (MediaPlayCtrl.cpp / MediaFilePanel.cpp); only the leading
    // serial matters to us.
    const std::string serial = dev_id.substr(0, dev_id.find('|'));

    std::string url;
    if (auto* a = as_agent(agent); a && !serial.empty()) {
        url = a->camera_url_for(serial);
    }
    OBN_INFO("get_camera_url dev=%s -> %s", serial.c_str(),
             url.empty() ? "(none)" : "LAN fallback URL");
    if (callback) callback(std::move(url));
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_camera_url_for_golive(void* /*agent*/,
                                                    std::string /*dev_id*/,
                                                    std::string /*sdev_id*/,
                                                    std::function<void(std::string)> callback)
{
    // Go-Live streams to third-party platforms via Agora only; there is
    // no LAN equivalent to fall back to.
    if (callback) callback(std::string{});
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_hms_snapshot(void* /*agent*/,
                                           std::string& /*dev_id*/,
                                           std::string& /*file_name*/,
                                           std::function<void(std::string, int)> callback)
{
    if (callback) callback(std::string{}, -1);
    return BAMBU_NETWORK_SUCCESS;
}
