#include <functional>
#include <string>
#include <thread>
#include <utility>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/log.hpp"

using obn::as_agent;

// When Studio asks for a remote URL (MediaFilePanel::fetchUrl,
// MediaPlayCtrl::Play/RequestFileSystemUrl), we first prefer the printer's
// LAN URL if its IP + access code are known:
//
//   bambu:///local/<ip>?port=6000&user=bblp&passwd=<code>[&lv=rtsps]
//
// Studio only checks that the reply starts with "bambu:///", so the
// file browser (PrinterFileSystem CTRL over :6000), the device-panel
// snapshot (mem:/N via FileTransferObject) and liveview take the local route
// even while the printer is cloud-paired. The lv= hint tells libBambuSource to
// fetch video over RTSP(S) :322 instead of MJPEG :6000 on X1/P1S/P2S printers.
//
// When no LAN route is known (e.g. printer remote or off-LAN), we query the
// Bambu cloud iot-service ttcode endpoint to mint a bambu:///tutk?... URL,
// proactively dispatching the signed and encrypted liveview prepare command
// so the printer starts its tutk_server.
OBN_ABI int bambu_network_get_camera_url(void* agent,
                                         std::string dev_id,
                                         std::function<void(std::string)> callback)
{
    // Studio packs "dev_id|dev_ver|protocols[|channel]" into the first
    // argument (MediaPlayCtrl.cpp / MediaFilePanel.cpp); only the leading
    // serial matters to us for the synchronous LAN route lookup.
    const std::string serial = dev_id.substr(0, dev_id.find('|'));

    auto* a = as_agent(agent);
    if (!a || serial.empty()) {
        if (callback) callback(std::string{});
        return BAMBU_NETWORK_SUCCESS;
    }

    std::string url = a->camera_url_for(serial);
    if (!url.empty()) {
        OBN_INFO("get_camera_url dev=%s -> LAN URL", serial.c_str());
        if (callback) callback(std::move(url));
        return BAMBU_NETWORK_SUCCESS;
    }

    // When no LAN route is known, cloud URL minting and liveview.prepare
    // involves an HTTP POST and MQTT publish. Offload to a worker thread so
    // Studio's UI / MediaPlayCtrl thread returns immediately (research/08.11.1).
    std::thread([a, dev_id = std::move(dev_id), serial, callback = std::move(callback)]() {
        std::string cloud_url = a->remote_camera_url(dev_id);
        OBN_INFO("get_camera_url dev=%s -> %s", serial.c_str(),
                 cloud_url.empty() ? "(none)" : "TUTK cloud URL");
        if (callback) {
            callback(std::move(cloud_url));
        }
    }).detach();

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
