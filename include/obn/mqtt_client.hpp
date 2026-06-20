#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>

struct mosquitto;
struct mosquitto_message;

namespace obn::mqtt {

struct ConnectConfig {
    std::string host;
    int         port         = 8883;
    std::string username;
    std::string password;
    bool        use_tls      = true;
    // Optional path to a PEM file used as the trust anchor for chain
    // verification. For LAN mode this should point at Studio's
    // resources/cert/printer.cer (the BBL Root/Intermediate CA bundle). If
    // empty, peer verification is disabled entirely (fallback for non-
    // standard installs where the bundle is missing).
    std::string ca_file;
    // When non-empty and verify is enabled, passed to mosquitto_tls_verify_hostname_set
    // (TCP still uses cfg.host). For LAN this is the printer serial (dev_id).
    std::string tls_verify_hostname;
    // Skip hostname verification (legacy / OBN_SKIP_TLS_VERIFY path).
    bool        tls_insecure = false;
    // Force cert_reqs=SSL_VERIFY_NONE: SSL handshake proceeds without
    // checking that the server's certificate is signed by anything we
    // trust. Used for the cloud broker on Windows where we lack a
    // public CA bundle (vcpkg's openssl-static-md ships no default
    // trust store): we still hand mosquitto a real PEM file for
    // tls_set's parameter validation, but the chain is intentionally
    // not verified. Defaults to false so LAN keeps validating against
    // Studio's printer.cer bundle.
    bool        tls_skip_chain_verify = false;
    int         keepalive_s  = 60;
    std::string client_id;
};

struct Message {
    std::string topic;
    std::string payload;
    int         qos    = 0;
    bool        retain = false;
};

// Thin wrapper around libmosquitto. Owns one background network thread per
// instance (via mosquitto_loop_start). All three callbacks may be invoked
// from that network thread, never concurrently for the same Client.
class Client {
public:
    using OnConnectCb    = std::function<void(int rc)>;
    using OnDisconnectCb = std::function<void(int rc)>;
    using OnMessageCb    = std::function<void(const Message&)>;

    explicit Client(std::string client_id);
    ~Client();

    Client(const Client&)            = delete;
    Client& operator=(const Client&) = delete;

    void set_on_connect(OnConnectCb cb);
    void set_on_disconnect(OnDisconnectCb cb);
    void set_on_message(OnMessageCb cb);

    // Configures TLS (if enabled) and calls mosquitto_connect_async followed
    // by mosquitto_loop_start. Returns 0 on success, a libmosquitto MOSQ_ERR_*
    // code otherwise.
    int connect(const ConnectConfig& cfg);

    int subscribe(const std::string& topic, int qos = 0);
    int unsubscribe(const std::string& topic);
    int publish(const std::string& topic, const std::string& payload, int qos = 0, bool retain = false);

    void disconnect();

    bool is_connected() const { return connected_.load(std::memory_order_acquire); }

    // Maps a libmosquitto return code to a human-readable string.
    static const char* err_str(int rc);
    // MQTT CONNACK return code (on_connect callback), not MOSQ_ERR_*.
    static const char* connack_str(int rc);

    // Like err_str(), but on Windows also folds in the most-recent
    // WSAGetLastError() value when rc is MOSQ_ERR_ERRNO. mosquitto_strerror
    // for ERRNO falls back to strerror(errno), which on Windows yields
    // "No error" because Winsock failures land in WSAGetLastError, not
    // CRT errno. Capture the WSA code explicitly via this helper at the
    // failure site so the log actually points to the underlying problem.
    static std::string detailed_err(int rc, int wsa_err = 0);

private:
    static void s_on_connect(::mosquitto* m, void* obj, int rc);
    static void s_on_disconnect(::mosquitto* m, void* obj, int rc);
    static void s_on_message(::mosquitto* m, void* obj, const ::mosquitto_message* msg);

    ::mosquitto*      mosq_{};
    std::string       client_id_;
    std::atomic<bool> connected_{false};
    std::atomic<bool> loop_started_{false};

    mutable std::mutex mu_;
    OnConnectCb        on_connect_;
    OnDisconnectCb     on_disconnect_;
    OnMessageCb        on_message_;
    std::string        merged_trust_path_;
};

// One-time mosquitto_lib_init for the lifetime of the loaded plugin. global_init
// is idempotent (std::call_once) and registers the single mosquitto_lib_cleanup
// for process/DLL teardown via atexit. global_cleanup is a no-op kept for call
// symmetry: tearing the library down per-Client used to call WSACleanup()
// mid-process and corrupt Winsock on reconnect
void global_init();
void global_cleanup();

} // namespace obn::mqtt
