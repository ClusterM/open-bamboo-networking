// Live LAN MQTT integration test: connects to a real Bambu printer, asks
// it to dump its full state via `pushall`, and prints the first report
// message received.
//
// Environment variables (all optional; test is skipped if the IP is empty):
//   OBN_PRINTER_IP     e.g. 10.13.1.30
//   OBN_PRINTER_SERIAL e.g. 22E8BJ610801473
//   OBN_ACCESS_CODE    e.g. 03f06755
//   OBN_CERT_FOLDER    e.g. /home/cluster/.local/BambuStudio/resources/cert
//                        (when set, enables chain verification against
//                         <folder>/printer.cer and tests install_device_cert)
//   OBN_TEST_CONFIG_DIR e.g. /tmp/obn-test
//                        (where install_device_cert will drop the captured
//                         per-printer PEM; defaults to /tmp/obn-test)
//
// Usage (manual):
//   ctest --test-dir build -R lan_live --output-on-failure -V

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>

#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"

namespace {

struct State {
    std::mutex              mu;
    std::condition_variable cv;
    std::atomic<int>        connect_status{-1};
    std::string             last_dev_id;
    std::string             last_json;
    std::atomic<bool>       got_message{false};
};

const char* env_or(const char* k, const char* dflt)
{
    const char* v = std::getenv(k);
    return (v && *v) ? v : dflt;
}

} // namespace

int main()
{
    const std::string ip          = env_or("OBN_PRINTER_IP",     "");
    const std::string serial      = env_or("OBN_PRINTER_SERIAL", "");
    const std::string code        = env_or("OBN_ACCESS_CODE",    "");
    const std::string cert_folder = env_or("OBN_CERT_FOLDER",    "");
    const std::string config_dir  = env_or("OBN_TEST_CONFIG_DIR", "/tmp/obn-test");

    if (ip.empty() || serial.empty() || code.empty()) {
        std::printf("SKIP: set OBN_PRINTER_IP / OBN_PRINTER_SERIAL / OBN_ACCESS_CODE to run\n");
        return 0;
    }
    std::printf("connecting to %s  dev=%s\n", ip.c_str(), serial.c_str());

    obn::Agent agent("/tmp/obn-test-log");
    agent.set_config_dir(config_dir);
    if (!cert_folder.empty())
        agent.set_cert_file(cert_folder, "slicer_base64.cer");

    State st;

    agent.set_on_local_connect_fn(
        [&st](int status, std::string dev_id, std::string msg) {
            std::printf("[on_local_connect] status=%d dev=%s msg=%s\n",
                        status, dev_id.c_str(), msg.c_str());
            st.connect_status.store(status, std::memory_order_release);
            std::lock_guard<std::mutex> lk(st.mu);
            st.cv.notify_all();
        });

    agent.set_on_local_message_fn(
        [&st](std::string dev_id, std::string json) {
            if (st.got_message.exchange(true)) return;
            std::printf("[on_local_message] dev=%s  bytes=%zu\n",
                        dev_id.c_str(), json.size());
            std::lock_guard<std::mutex> lk(st.mu);
            st.last_dev_id = dev_id;
            st.last_json   = json;
            st.cv.notify_all();
        });

    int rc = agent.connect_printer(serial, ip, "bblp", code, /*use_ssl=*/true);
    if (rc != BAMBU_NETWORK_SUCCESS) {
        std::fprintf(stderr, "connect_printer failed rc=%d\n", rc);
        return 1;
    }

    // Wait for the TLS + MQTT handshake to complete (up to 10s).
    {
        std::unique_lock<std::mutex> lk(st.mu);
        st.cv.wait_for(lk, std::chrono::seconds(10),
                       [&] { return st.connect_status.load() >= 0; });
    }
    if (st.connect_status.load() != BBL::ConnectStatusOk) {
        std::fprintf(stderr, "connect did not reach OK (status=%d)\n",
                     st.connect_status.load());
        agent.disconnect_printer();
        return 2;
    }

    // Ask the printer to send its full state snapshot. This is the same
    // payload Studio uses (see ../research/INDEX.md / OpenBambuAPI/mqtt.md).
    const std::string pushall =
        R"({"pushing":{"sequence_id":"0","command":"pushall"}})";
    rc = agent.send_message_to_printer(serial, pushall, /*qos=*/0);
    if (rc != BAMBU_NETWORK_SUCCESS) {
        std::fprintf(stderr, "send_message_to_printer failed rc=%d\n", rc);
        agent.disconnect_printer();
        return 3;
    }
    std::printf("pushall sent, waiting for report...\n");

    {
        std::unique_lock<std::mutex> lk(st.mu);
        st.cv.wait_for(lk, std::chrono::seconds(10),
                       [&] { return st.got_message.load(); });
    }

    // Exercise install_device_cert the same way Studio does: once right
    // after on_printer_connected_fn, then a couple of "timer ticks". The
    // second/third calls must be cheap no-ops thanks to the cache.
    std::printf("install_device_cert x3 (dedup expected on 2/3)\n");
    agent.install_device_cert(serial, /*lan_only=*/true);
    agent.install_device_cert(serial, /*lan_only=*/true);
    agent.install_device_cert(serial, /*lan_only=*/true);

    agent.disconnect_printer();

    if (!st.got_message.load()) {
        std::fprintf(stderr, "no report message received within timeout\n");
        return 4;
    }

    std::printf("ok: first report json (truncated 400):\n%.*s%s\n",
                static_cast<int>(std::min<size_t>(st.last_json.size(), 400)),
                st.last_json.c_str(),
                st.last_json.size() > 400 ? "..." : "");
    return 0;
}
