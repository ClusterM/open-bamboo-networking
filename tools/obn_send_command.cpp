// obn_send_command — send a device command to a Bambu printer THROUGH the OSS
// plugin, exercising its real signing path. A "print"-envelope command is
// RSA-SHA256 signed with the configured slicer key (config_dir/slicer_key.pem +
// slicer_cert_id.txt) by obn::signing::maybe_sign before it is published to
// device/<dev_id>/request; the printer only accepts it if that signature is
// valid, so a successful colour/filament change is proof the OSS signing works.
//
//   obn_send_command <config_dir> <dev_id> <ip> <access_code> <command.json>
//
// config_dir must contain slicer_key.pem and slicer_cert_id.txt. TLS to the
// printer is left unverified (self-signed printer cert) via OBN_SKIP_TLS_VERIFY.

#include "obn/agent.hpp"
#include "obn/config.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <thread>

static std::string slurp(const std::string& path) {
    std::ifstream in(path);
    return std::string((std::istreambuf_iterator<char>(in)), {});
}

int main(int argc, char** argv) {
    bool cloud = false;
    int  a0 = 1;
    if (argc > 1 && std::string(argv[1]) == "--cloud") { cloud = true; ++a0; }

    if (cloud ? (argc - a0 != 4) : (argc - a0 != 5)) {
        std::fprintf(stderr,
            "usage (LAN):   %s <config_dir> <dev_id> <ip> <access_code> <command.json>\n"
            "usage (cloud): %s --cloud <config_dir> <dev_id> <login.json> <command.json>\n",
            argv[0], argv[0]);
        return 2;
    }

    // Accept the printer's / broker's self-signed-or-unverified TLS.
    setenv("OBN_SKIP_TLS_VERIFY", "1", 1);

    std::string cfg_dir = argv[a0];
    obn::config::load_or_create(cfg_dir);   // picks up slicer_key.pem / slicer_cert_id.txt

    obn::Agent a("/tmp");
    a.set_config_dir(cfg_dir);

    std::string dev = argv[a0 + 1];

    if (cloud) {
        std::string login = slurp(argv[a0 + 2]);
        std::string json  = slurp(argv[a0 + 3]);
        if (login.empty() || json.empty()) { std::fprintf(stderr, "empty login/command\n"); return 2; }

        a.apply_login_info(login);
        int rc = a.connect_cloud();
        std::fprintf(stderr, "connect_cloud rc=%d\n", rc);
        if (rc != 0) return rc;
        std::this_thread::sleep_for(std::chrono::seconds(3));   // cloud CONNACK + subscribe

        std::fprintf(stderr, "cloud-publishing (%zu bytes, signed if \"print\"):\n%s\n", json.size(), json.c_str());
        int src = a.cloud_send_message(dev, json, /*qos=*/1);
        std::fprintf(stderr, "cloud_send_message rc=%d\n", src);
        std::this_thread::sleep_for(std::chrono::seconds(3));
        a.disconnect_cloud();
        if (src == 0) std::fprintf(stderr, "OK: command published to the cloud for device %s\n", dev.c_str());
        return src;
    }

    std::string ip = argv[a0 + 2], code = argv[a0 + 3];
    std::string json = slurp(argv[a0 + 4]);
    if (json.empty()) { std::fprintf(stderr, "empty command\n"); return 2; }

    int rc = a.connect_printer(dev, ip, "bblp", code, /*use_ssl=*/true);
    std::fprintf(stderr, "connect_printer(%s @ %s) rc=%d\n", dev.c_str(), ip.c_str(), rc);
    if (rc != 0) return rc;
    std::this_thread::sleep_for(std::chrono::seconds(2));   // CONNACK + subscribe

    std::fprintf(stderr, "publishing (%zu bytes, signed if \"print\"):\n%s\n", json.size(), json.c_str());
    int src = a.send_message_to_printer(dev, json, /*qos=*/1);
    std::fprintf(stderr, "send_message_to_printer rc=%d\n", src);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    a.disconnect_printer();

    if (src == 0) std::fprintf(stderr, "OK: command published to device/%s/request\n", dev.c_str());
    return src;
}
