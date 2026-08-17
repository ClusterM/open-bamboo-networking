#pragma once

// MQTT sequence_id for frames the plugin builds itself (project_file,
// app_cert_install, …). Stock 02.05.00–02.08.02 stays inside Studio's
// 20000–29999 window (DevUtil::is_studio_cmd) rather than using epoch-ms;
// project_file is always "20001" on a fresh process, app_cert_install is
// a random value in the same range. Reusing a constant across process
// restarts makes firmware reject the frame with
// `mqtt message verify failed` / err_code 84033544, and epoch-ms trips
// the AMS signed-32-bit hang, so we seed randomly once and increment.
// See research/06.02-mqtt.md and research/08.08-print-abi.md §8.8.1.

#include <atomic>
#include <cstdint>
#include <random>
#include <string>

namespace obn {

inline std::string next_mqtt_seq_id()
{
    static std::atomic<std::uint32_t> n{[] {
        std::random_device rd;
        return static_cast<std::uint32_t>(rd());
    }()};
    const std::uint32_t v = n.fetch_add(1, std::memory_order_relaxed);
    return std::to_string(20000 + (v % 10000));
}

} // namespace obn
