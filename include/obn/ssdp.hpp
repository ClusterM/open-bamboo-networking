#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace obn::ssdp {

// Bambu printers broadcast SSDP NOTIFY on UDP :2021 every 5 s (observed).
inline constexpr int kNotifyPeriodMs   = 5000;
// bind_detect wait: one full period plus margin for listener startup/jitter.
inline constexpr int kBindDetectWaitMs = 5500;

// HTTP-style header bag parsed out of a NOTIFY / M-SEARCH packet. Keys are
// lowercased so `get("usn")` matches whether the printer sent `USN` or
// `Usn`. Values preserve the original bytes verbatim (header values from
// printers can carry UTF-8 device names).
class Headers {
public:
    void set(std::string key, std::string value);
    const std::string* get(const std::string& lc_key) const;

    // Convenience for logging: returns value or "" if missing.
    std::string value(const std::string& lc_key) const;

private:
    std::map<std::string, std::string> kv_;
};

// Parses a raw UDP payload produced by a Bambu printer (or any
// SSDP-compatible device). Returns nullopt if the buffer isn't a parseable
// HTTP-style message (malformed, empty, unexpected request line).
bool parse(const char* data, std::size_t size, Headers& out);

// Maps parsed headers to the JSON string Studio's DeviceManager expects.
// Always produces required keys even if the packet missed them (Studio
// throws on ::json::parse if "dev_name"/"dev_id"/... are absent).
std::string to_device_info_json(const Headers& h);

// Background UDP listener on 0.0.0.0:<port>. Bambu printers send SSDP NOTIFY
// to 255.255.255.255:2021 every 5 s; we only listen passively.
class Discovery {
public:
    using OnMessage = std::function<void(std::string json)>;

    Discovery();
    ~Discovery();
    Discovery(const Discovery&)            = delete;
    Discovery& operator=(const Discovery&) = delete;

    // Starts the listener. Returns true on success (socket bound, thread
    // spawned). Safe to call repeatedly: calls after the first while still
    // running are no-ops and return true.
    bool start(int port, OnMessage cb);

    // Stops the listener and joins the worker thread. Safe to call when
    // not started. After stop() the Discovery can be started again.
    void stop();

    bool running() const { return running_.load(std::memory_order_acquire); }

private:
    void run_();

    // Stored as uintptr_t so we don't have to drag obn::os::socket_t (and the
    // <winsock2.h> include behind it) into a public header. ssdp.cpp casts
    // through obn::os::socket_t at use sites.
    std::uintptr_t       fd_{static_cast<std::uintptr_t>(-1)};
    std::thread          worker_;
    std::atomic<bool>    running_{false};
    std::mutex           start_mu_;
    std::mutex           cb_mu_;
    OnMessage            cb_;
    int                  port_{2021};
};

} // namespace obn::ssdp
