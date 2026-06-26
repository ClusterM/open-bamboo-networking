

#include "App.hpp"
#include "SignalHandler.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#if defined(__linux__)
#  include <sys/prctl.h>
#endif

using Slic3r::bambu::headless::App;
using Slic3r::bambu::headless::AppConfig;
using Slic3r::bambu::headless::VirtualPrinter;
using Slic3r::bambu::headless::SignalHandler;

namespace {

void print_usage(std::FILE* out) {
    std::fprintf(out,
"usage: bambu-daemon [options]\n"
"\n"
"Walks the cloud inventory of the logged-in Bambu user and stands\n"
"up SSDP + MQTT + FTPS + RTSP servers for every cloud-bound printer,\n"
"sharing a single bambu_networking plugin handle. Each device gets\n"
"an ascending high-port set per role so multiple printers can run\n"
"on the same host without colliding.\n"
"\n"
"Plugin options:\n"
"  --plugin <path>        Path to libbambu_networking.so. If unset,\n"
"                         falls back to $BAMBU_BRIDGE_PLUGIN_PATH,\n"
"                         then the plugin handle's default probe.\n"
"  --config-dir <path>    Plugin set_config_dir() pass-through.\n"
"  --country-code <cc>    Plugin set_country_code() pass-through.\n"
"\n"
"Device injection (bypasses cloud inventory; preferred for a single\n"
"known printer / the extract-d gate):\n"
"  --dev-id <serial>      Inject this printer directly via\n"
"                         App::printer_source, skipping\n"
"                         CloudInventory::refresh(). Repeatable.\n"
"  --access-code <code>   LAN access code for the injected printer.\n"
"  --lan-ip <ip>          LAN IP for the injected printer (optional;\n"
"                         SSDP fills it in if omitted).\n"
"  --model <m>            Printer model (default: SSDP fallback).\n"
"  --firmware <v>         Printer firmware (default: SSDP fallback).\n"
"\n"
"Server options:\n"
"  --bind <ip>            Bind IP for all per-device listeners\n"
"                         (default: 0.0.0.0).\n"
"  --no-ssdp              Disable the SSDP responder.\n"
"  --no-mqtt              Disable the per-device MQTT broker.\n"
"  --no-ftps              Disable the per-device FTPS server.\n"
"  --no-rtsp              Disable the per-device RTSP server.\n"
"  --mqtt-port-base N     Per-device MQTT port base (default 38883).\n"
"  --ftps-port-base N     Per-device FTPS port base (default 39990).\n"
"  --rtsp-port-base N     Per-device RTSP port base (default 38322).\n"
"  --cert-cache-dir <p>   Directory for per-device certs (default:\n"
"                         $XDG_CONFIG_HOME/BambuStudio/bridge/certs).\n"
"\n"
"Cadence:\n"
"  --inventory-poll-seconds N\n"
"                         How often to refresh the cloud inventory\n"
"                         and add / remove / re-IP devices.\n"
"                         Default: 60s.\n"
"\n"
"Misc:\n"
"  -v, --verbose          Verbose logging (currently a no-op; reserved\n"
"                         for phase 11 wire-diff capture).\n"
"  -h, --help             Show this help and exit.\n");
}

struct InjectedPrinter {
    std::string dev_id;
    std::string access_code;
    std::string lan_ip;
    std::string model;
    std::string firmware;
};

bool needs_value(int argc, char** argv, int i, const char* flag) {
    if (i + 1 >= argc) {
        std::fprintf(stderr, "bambu-daemon: %s requires a value\n", flag);
        return false;
    }
    return true;
}

}

int main(int argc, char** argv) {
#if defined(__linux__)






    prctl(PR_SET_NAME, "bambustu_main", 0, 0, 0);
#endif

    AppConfig cfg;



    cfg.host_drives_inventory = false;


    cfg.mqtt_port_base = 38883;
    cfg.ftps_port_base = 39990;
    cfg.rtsp_port_base = 38322;

    std::vector<InjectedPrinter> injected;
    bool verbose = false;

    auto cur = [&]() -> InjectedPrinter& {
        if (injected.empty()) injected.emplace_back();
        return injected.back();
    };

    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (!std::strcmp(a, "--plugin")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cfg.plugin_path = argv[++i];
        } else if (!std::strcmp(a, "--config-dir")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cfg.config_dir = argv[++i];
        } else if (!std::strcmp(a, "--country-code")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cfg.country_code = argv[++i];
        } else if (!std::strcmp(a, "--cloud-cert-dir")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cfg.cert_dir = argv[++i];
        } else if (!std::strcmp(a, "--cloud-cert-file")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cfg.cert_file = argv[++i];
        } else if (!std::strcmp(a, "--dev-id")) {
            if (!needs_value(argc, argv, i, a)) return 2;

            injected.emplace_back();
            injected.back().dev_id = argv[++i];
        } else if (!std::strcmp(a, "--access-code")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cur().access_code = argv[++i];
        } else if (!std::strcmp(a, "--lan-ip")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cur().lan_ip = argv[++i];
        } else if (!std::strcmp(a, "--model")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cur().model = argv[++i];
        } else if (!std::strcmp(a, "--firmware")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cur().firmware = argv[++i];
        } else if (!std::strcmp(a, "--bind")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cfg.lan_iface_bind = argv[++i];
        } else if (!std::strcmp(a, "--no-ssdp")) {
            cfg.enable_ssdp = false;
        } else if (!std::strcmp(a, "--no-mqtt")) {
            cfg.enable_mqtt = false;
        } else if (!std::strcmp(a, "--no-ftps")) {
            cfg.enable_ftps = false;
        } else if (!std::strcmp(a, "--no-rtsp")) {
            cfg.enable_rtsp = false;
        } else if (!std::strcmp(a, "--mqtt-port-base")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cfg.mqtt_port_base = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (!std::strcmp(a, "--ftps-port-base")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cfg.ftps_port_base = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (!std::strcmp(a, "--rtsp-port-base")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cfg.rtsp_port_base = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (!std::strcmp(a, "--cert-cache-dir")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cfg.cert_cache_dir = argv[++i];
        } else if (!std::strcmp(a, "--inventory-poll-seconds")) {
            if (!needs_value(argc, argv, i, a)) return 2;
            cfg.inventory_poll = std::chrono::seconds(std::atoi(argv[++i]));
        } else if (!std::strcmp(a, "-v") || !std::strcmp(a, "--verbose")) {
            verbose = true;
        } else if (!std::strcmp(a, "-h") || !std::strcmp(a, "--help")) {
            print_usage(stdout);
            return 0;
        } else {
            std::fprintf(stderr,
                "bambu-daemon: unknown option '%s'\n", a);
            print_usage(stderr);
            return 2;
        }
    }
    (void)verbose;


    if (cfg.plugin_path.empty()) {
        if (const char* env = std::getenv("BAMBU_BRIDGE_PLUGIN_PATH"))
            cfg.plugin_path = env;
    }








    if (cfg.cert_dir.empty()) {
        if (const char* env = std::getenv("BAMBU_BRIDGE_CLOUD_CERT_DIR"))
            cfg.cert_dir = env;
    }
    if (cfg.cert_file.empty()) {
        if (const char* env = std::getenv("BAMBU_BRIDGE_CLOUD_CERT_FILE"))
            cfg.cert_file = env;
        else if (!cfg.cert_dir.empty())
            cfg.cert_file = "slicer_base64.cer";
    }



    std::vector<VirtualPrinter> seeded;
    for (auto& ip : injected) {
        if (ip.dev_id.empty()) continue;
        VirtualPrinter vp;
        vp.dev_id      = ip.dev_id;
        vp.dev_name    = ip.dev_id;
        vp.lan_ip      = ip.lan_ip;
        vp.access_code = ip.access_code;
        vp.model       = ip.model;
        vp.firmware    = ip.firmware;
        seeded.push_back(std::move(vp));
    }





    if (!seeded.empty()) {
        cfg.printer_source = [seeded]() { return seeded; };
        std::fprintf(stderr,
            "[bambu-daemon] printer_source seeded with %zu printer(s); "
            "CloudInventory bypassed\n", seeded.size());
        for (const auto& vp : seeded)
            std::fprintf(stderr,
                "[bambu-daemon]   dev_id=%s lan_ip=%s model=%s ac_len=%zu\n",
                vp.dev_id.c_str(), vp.lan_ip.c_str(), vp.model.c_str(),
                vp.access_code.size());
    }

    std::fprintf(stderr,
        "[bambu-daemon] starting; plugin='%s' bind=%s mqtt_base=%u\n",
        cfg.plugin_path.c_str(), cfg.lan_iface_bind.c_str(),
        unsigned(cfg.mqtt_port_base));
    std::fflush(stderr);








    if (!std::getenv("BAMBU_BRIDGE_GCODE_CMD_MS"))
        ::setenv("BAMBU_BRIDGE_GCODE_CMD_MS", "2000", 0);

    App app(std::move(cfg));


    SignalHandler signals([&app] { app.shutdown(); });

    int rc = 0;
    try {
        rc = app.run();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bambu-daemon: fatal: %s\n", e.what());
        return 1;
    }

    std::fprintf(stderr, "[bambu-daemon] exited cleanly rc=%d\n", rc);
    return rc;
}
