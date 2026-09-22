#include <functional>
#include <string>

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
    // serial matters to us.
    const std::string serial = dev_id.substr(0, dev_id.find('|'));

    std::string url;
    if (auto* a = as_agent(agent); a && !serial.empty()) {
        url = a->camera_url_for(serial);
        if (url.empty()) {
            url = a->remote_camera_url(dev_id);
        }
    }
    OBN_INFO("get_camera_url dev=%s -> %s", serial.c_str(),
             url.empty() ? "(none)" : (url.find("tutk") != std::string::npos ? "TUTK cloud URL" : "LAN URL"));
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

OBN_ABI const char* obn_get_tutk_camera_url(const char* dev_id)
{
    static thread_local std::string s_last_url;
    s_last_url.clear();
    if (!dev_id || !*dev_id) return nullptr;

    auto* a = obn::Agent::active_instance();
    if (!a) {
        OBN_WARN("obn_get_tutk_camera_url: no active agent for dev=%s", dev_id);
        return nullptr;
    }

    s_last_url = a->remote_camera_url(dev_id);
    if (s_last_url.empty()) {
        OBN_WARN("obn_get_tutk_camera_url: remote_camera_url returned empty for dev=%s", dev_id);
        return nullptr;
    }
    OBN_INFO("obn_get_tutk_camera_url: dev=%s -> %.80s", dev_id, s_last_url.c_str());
    return s_last_url.c_str();
}
