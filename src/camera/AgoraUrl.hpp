//
// AgoraUrl — parser for the bambu:///agora?... camera URL.
//
// URL format consumed:
//   bambu:///agora?app=<APP_ID>
//                 &channel=<CHANNEL_NAME>
//                 &token=<AGORA_TOKEN>
//                 &user=<UID_uint32>
//                 &region=<cn|eu|na|us>
//                 &device=<SN>
//                 &dev_ver=<DEVICE_VER>
//                 &net_ver=<NET_VER>
//                 &cli_id=<CLIENT_ID>
//                 &cli_ver=<CLIENT_VER>
//                 [&refresh_url=<HEX_FNPTR>]   // token-refresh callback
//                 [&auxiliary_enable=1]          // use auxiliary refresh path

#pragma once

#include <cstdint>
#include <string>

namespace bambu_net {
namespace camera {

// Region codes that libBambuSource maps from the "region" URL param.
enum class AgoraRegion : uint32_t {
    Default = 0xFFFFFFFF,  // let SDK decide
    CN      = 1,
    NA      = 2,
    EU      = 4,
    US      = 0x800,
};

AgoraRegion agora_region_from_string(const std::string& s);

// Parsed representation of a bambu:///agora?... URL.
struct AgoraUrl {
    std::string   app_id;       // Agora App ID
    std::string   channel;      // Agora channel name / TUTK relay ID
    std::string   token;        // Agora auth token
    std::string   passwd;       // printer passwd; PSK = SHA256(passwd) for TUTK relay DTLS
    uint32_t      uid     = 0;  // local user ID (numeric, Agora-SDK field)
    std::string   tutk_uid;     // TUTK device UID (20-char string from cloud API)
    AgoraRegion   region  = AgoraRegion::Default;
    std::string   device;       // printer serial number
    std::string   dev_ver;
    std::string   net_ver;
    std::string   cli_id;
    std::string   cli_ver;
    // Token-refresh: either a function pointer encoded as hex, or auxiliary path.
    uintptr_t     refresh_fn  = 0;
    bool          auxiliary   = false;

    static bool parse(const std::string& url, AgoraUrl& out, std::string& err);
};

}  // namespace camera
}  // namespace bambu_net
