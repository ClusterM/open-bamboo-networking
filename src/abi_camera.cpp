#include <functional>
#include <string>
#include <system_error>
#include <thread>
#include <utility>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/config.hpp"
#include "obn/lan_tls.hpp"
#include "obn/log.hpp"
#include "obn/signing.hpp"

using obn::as_agent;

// Studio only calls this for a cloud-bound printer (MediaPlayCtrl::Play,
// RequestFileSystemUrl, MediaFilePanel::fetchUrl); in LAN-only mode it builds
// the local URL itself (research/08.11). Two answers are possible:
//
//   bambu:///tutk?uid=<ttcode>&authkey=..&passwd=..&region=..   (cloud mint)
//   bambu:///local/<ip>?port=6000&user=bblp&passwd=<code>[&lv=rtsps]
//
// Like the stock plugin we mint TUTK by default: POST /user/ttcode returns
// the printer's TUTK credentials and makes the cloud push liveview.prepare,
// which starts the printer's tutk_server. The LAN URL is used instead when
// prefer_rtsp is set, when the cloud is unusable (block_cloud, no session)
// or when the mint fails, provided the printer's IP + access code are known.
// Studio only checks that the reply starts with "bambu:///", so the file
// browser (CTRL over :6000), the device-panel snapshot and liveview all work
// over LAN that way; the lv= hint makes libBambuSource fetch video over
// RTSP(S) :322 instead of MJPEG :6000 on X1/P1S/P2S printers.
OBN_ABI int bambu_network_get_camera_url(void* agent,
                                         std::string dev_id,
                                         std::function<void(std::string)> callback)
{
    // Studio packs "dev_id|dev_ver|protocols[|channel]" into the first
    // argument (MediaPlayCtrl.cpp / MediaFilePanel.cpp).
    const std::string serial = dev_id.substr(0, dev_id.find('|'));

    auto* a = as_agent(agent);
    if (!a || serial.empty()) {
        if (callback) callback(std::string{});
        return BAMBU_NETWORK_SUCCESS;
    }

    std::string lan_url = a->camera_url_for(serial);
    // /user/ttcode answers 403 without both PoP headers, so without the slicer
    // key + cert TUTK is out of reach and there is no point trying the mint.
    const bool cloud_usable = !obn::config::current().block_cloud &&
                              !a->user_session_snapshot().access_token.empty() &&
                              obn::signing::slicer_signing_key_present() &&
                              !obn::signing::app_certification_id().empty();
    if (!lan_url.empty() && (obn::config::current().prefer_rtsp || !cloud_usable)) {
        OBN_INFO("get_camera_url dev=%s -> LAN URL (%s)", serial.c_str(),
                 cloud_usable ? "prefer_rtsp" : "cloud unavailable");
        if (callback) callback(std::move(lan_url));
        return BAMBU_NETWORK_SUCCESS;
    }

    // Cloud URL minting is an HTTP POST. Offload to a worker thread so
    // Studio's UI / MediaPlayCtrl thread returns immediately (research/08.11.1).
    // The full packed key goes to the mint: dev_ver and protocols are part of
    // the /user/ttcode request body.
    auto mint = [a, dev_id, serial, lan_url, callback]() {
        std::string url = a->remote_camera_url(dev_id);
        const char* kind = "TUTK cloud URL";
        if (url.empty() && !lan_url.empty()) {
            url  = lan_url;
            kind = "LAN URL (mint failed)";
        }
        OBN_INFO("get_camera_url dev=%s -> %s", serial.c_str(),
                 url.empty() ? "(none)" : kind);
        if (callback) callback(std::move(url));
    };
    try {
        std::thread(std::move(mint)).detach();
    } catch (const std::system_error& e) {
        OBN_WARN("get_camera_url: thread spawn failed (%s)", e.what());
        if (callback) callback(std::string{});
    }
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

// Private exports for this project's BambuSource (stubs/BambuSource.cpp),
// which resolves them from the already-loaded plugin (dlsym(RTLD_DEFAULT) /
// GetProcAddress) to switch transports mid-session: a LAN tunnel whose TLS
// or RTSP dial fails asks for a TUTK URL, and a TUTK tunnel opened for the
// file browser (CTRL, which our TUTK client does not carry) asks for the LAN
// URL; obn_get_lan_serial fills in the serial for URLs without device=.
// Not part of Studio's ABI. `dev_id` is the bare serial. All are synchronous
// (the TUTK one blocks on the /user/ttcode POST), must not be called from
// Studio's UI thread, and return a pointer to a thread_local buffer that
// stays valid until the next call on the same thread, or nullptr when there
// is no answer.

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
        OBN_WARN("obn_get_tutk_camera_url: no TUTK URL for dev=%s", dev_id);
        return nullptr;
    }
    OBN_INFO("obn_get_tutk_camera_url: dev=%s -> TUTK URL", dev_id);
    return s_last_url.c_str();
}

OBN_ABI const char* obn_get_lan_camera_url(const char* dev_id)
{
    static thread_local std::string s_last_url;
    s_last_url.clear();
    if (!dev_id || !*dev_id) return nullptr;

    auto* a = obn::Agent::active_instance();
    if (!a) return nullptr;

    s_last_url = a->camera_url_for(dev_id);
    if (s_last_url.empty()) {
        OBN_WARN("obn_get_lan_camera_url: no LAN route for dev=%s", dev_id);
        return nullptr;
    }
    return s_last_url.c_str();
}

// Serial of the printer last seen at `ip` (SSDP / connect_printer), for
// tunnel URLs Studio builds without device= (print upload, part skip).
OBN_ABI const char* obn_get_lan_serial(const char* ip)
{
    static thread_local std::string s_serial;
    s_serial.clear();
    if (!ip || !*ip) return nullptr;
    if (auto serial = obn::lan_tls::registry_lookup_serial(ip)) s_serial = *serial;
    return s_serial.empty() ? nullptr : s_serial.c_str();
}
