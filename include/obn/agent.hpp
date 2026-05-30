#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "obn/auth.hpp"
#include "obn/bambu_networking.hpp"

namespace obn {
namespace mqtt { class Client; }
namespace ssdp { class Discovery; }
namespace cover_server { class Server; }
class CloudSession;

// Per-printer LAN MQTT session. Studio only holds one such connection at a
// time (multi-printer LAN view is a future extension), so Agent owns a single
// LanSession and tears it down before opening a new one.
class LanSession {
public:
    LanSession(std::string dev_id,
               std::string dev_ip,
               std::string username,
               std::string password,
               bool        use_ssl,
               std::string ca_file);
    ~LanSession();

    LanSession(const LanSession&)            = delete;
    LanSession& operator=(const LanSession&) = delete;

    // Dispatches its two callbacks on the MQTT network thread; the receiver
    // is responsible for queueing UI updates through Agent::queue_on_main.
    using ConnectedCb = std::function<void(int status /*ConnectStatus*/, std::string msg)>;
    using MessageCb   = std::function<void(std::string dev_id, std::string json)>;

    // Starts the MQTT connection asynchronously and returns once loop_start
    // succeeds. Returns a BAMBU_NETWORK_ERR_* code.
    int start(ConnectedCb on_connected, MessageCb on_message);

    int publish_json(const std::string& json_str, int qos);
    int disconnect();

    const std::string& dev_id() const { return dev_id_; }
    const std::string& dev_ip() const { return dev_ip_; }
    // Expose the LAN access-code so the cover-cache worker can mount
    // the printer's FTPS storage without asking Studio again.
    const std::string& username() const { return username_; }
    const std::string& password() const { return password_; }
    const std::string& ca_file()  const { return ca_file_; }

private:
    std::string report_topic_() const;
    std::string request_topic_() const;

    std::string dev_id_;
    std::string dev_ip_;
    std::string username_;
    std::string password_;
    bool        use_ssl_;
    std::string ca_file_;

    std::unique_ptr<mqtt::Client> client_;
    ConnectedCb                   on_connected_;
    MessageCb                     on_message_;
};

// The Agent object is created per Studio call to bambu_network_create_agent().
// For now it is an inert carrier for registered callbacks and configuration:
// later phases flesh out an internal event loop, MQTT clients and HTTP/FTPS
// session managers. Keeping this scaffold minimal is deliberate: phase 1 goal
// is just to get Studio to load the plugin without crashing or disabling
// itself.
class Agent {
public:
    explicit Agent(std::string log_dir);
    ~Agent();

    Agent(const Agent&)            = delete;
    Agent& operator=(const Agent&) = delete;

    // -----------------------------
    // Basic setters (noexcept).
    // -----------------------------
    void set_config_dir(std::string dir);
    void set_cert_file(std::string folder, std::string filename);
    void set_country_code(std::string code);
    void set_extra_http_headers(std::map<std::string, std::string> headers);
    void set_user_selected_machine(std::string dev_id);

    // -----------------------------
    // Callback registration.
    // Every callback is stored under a mutex so that later background threads
    // can read/invoke it safely.
    // -----------------------------
    void set_on_ssdp_msg_fn(BBL::OnMsgArrivedFn fn);
    void set_on_user_login_fn(BBL::OnUserLoginFn fn);
    void set_on_printer_connected_fn(BBL::OnPrinterConnectedFn fn);
    void set_on_server_connected_fn(BBL::OnServerConnectedFn fn);
    void set_on_http_error_fn(BBL::OnHttpErrorFn fn);
    void set_get_country_code_fn(BBL::GetCountryCodeFn fn);
    void set_on_subscribe_failure_fn(BBL::GetSubscribeFailureFn fn);
    void set_on_message_fn(BBL::OnMessageFn fn);
    void set_on_user_message_fn(BBL::OnMessageFn fn);
    void set_on_local_connect_fn(BBL::OnLocalConnectedFn fn);
    void set_on_local_message_fn(BBL::OnMessageFn fn);
    void set_queue_on_main_fn(BBL::QueueOnMainFn fn);
    void set_server_callback(BBL::OnServerErrFn fn);

    // -----------------------------
    // LAN printer session (one at a time).
    // -----------------------------
    int  connect_printer(std::string dev_id,
                         std::string dev_ip,
                         std::string username,
                         std::string password,
                         bool        use_ssl);
    int  disconnect_printer();
    int  send_message_to_printer(const std::string& dev_id,
                                 const std::string& json_str,
                                 int                qos);

    // Studio calls this every ~1 s from its refresh timer, plus once right
    // after on_printer_connected_fn. We only do real work the first time a
    // given `dev_id` is seen (and only in lan_only mode for now): capture the
    // printer's self-signed server certificate into <config_dir>/certs/.
    void install_device_cert(const std::string& dev_id, bool lan_only);

    // Starts/stops the LAN SSDP listener that feeds on_ssdp_msg_fn. Bambu
    // printers advertise themselves once every ~5 s via a UDP broadcast on
    // port 2021. Returns true if the listener is running after the call.
    bool start_discovery(bool enable, bool sending);

    // Implements bambu_network_start_local_print: upload the .3mf over
    // FTPS to the printer's storage, then publish a `project_file`
    // command over the active LAN MQTT session. Runs synchronously on the
    // caller's thread - Studio invokes this from its PrintJob worker.
    // Returns BAMBU_NETWORK_* code; on failure stage == PrintingStageERROR.
    int run_local_print_job(const BBL::PrintParams&   params,
                            BBL::OnUpdateStatusFn     update_fn,
                            BBL::WasCancelledFn       cancel_fn);

    // Implements bambu_network_start_send_gcode_to_sdcard: FTPS upload
    // only, no MQTT. Remote filename = PrintParams::project_name.
    int run_send_gcode_to_sdcard(const BBL::PrintParams& params,
                                 BBL::OnUpdateStatusFn   update_fn,
                                 BBL::WasCancelledFn     cancel_fn);

    // Implements bambu_network_start_sdcard_print: the "Print" button
    // from Device -> Files. The file is already on the printer's
    // storage (we list/browse it via the PrinterFileSystem bridge), so
    // there's no FTPS upload - we just publish a `project_file` MQTT
    // command with url=ftp://<path> on the LAN channel. Studio
    // hard-codes this path to `start_sdcard_print` and calls it
    // "cloud service" in the UI, but on Developer Mode printers there
    // is no cloud route; going over LAN MQTT is the only thing the
    // printer will actually accept.
    int run_sdcard_print_job(const BBL::PrintParams& params,
                             BBL::OnUpdateStatusFn   update_fn,
                             BBL::WasCancelledFn     cancel_fn);

    // Implements bambu_network_start_print (use_lan_channel=false) and
    // bambu_network_start_local_print_with_record (use_lan_channel=true).
    //
    // Orchestrates Bambu's cloud-print sequence reverse-engineered from
    // MITM of the original plugin:
    //   1.  POST /iot-service/api/user/project          - create project
    //   2.  PUT  <presigned S3 url>                     - upload config 3mf
    //   3.  PUT  /iot-service/api/user/notification     - notify upload
    //   4.  GET  /iot-service/api/user/notification?... - poll
    //   5.  PATCH /iot-service/api/user/project/<pid>   - register (ftp:// url)
    //   6.  GET  /iot-service/api/user/upload?models=.. - request second url
    //   7.  PUT  <presigned S3 url>                     - upload full 3mf
    //   8.  PATCH /iot-service/api/user/project/<pid>   - register (https:// url)
    //   9.  (LAN only) FTPS STOR to /cache/<name>.gcode.3mf
    //  10.  POST /user-service/my/task                  - create task
    //  11.  MQTT publish project_file:
    //         - LAN channel: via LanSession, url=ftp://<name>
    //         - cloud channel: via CloudSession, url=<S3 presigned>
    int run_cloud_print_job(const BBL::PrintParams& params,
                            BBL::OnUpdateStatusFn   update_fn,
                            BBL::WasCancelledFn     cancel_fn,
                            bool                    use_lan_channel);

    // -----------------------------
    // Accessors used by stub returns.
    // -----------------------------
    std::string country_code() const;
    std::string log_dir() const { return log_dir_; }
    std::string config_dir() const;
    std::string cert_folder() const;
    std::string cert_filename() const;
    // Returns "<cert_folder>/printer.cer" if the file exists, otherwise "".
    // Used as the CA trust store for LAN MQTT so we can validate the chain
    // the same way Bambu's own plugin does.
    std::string bambu_ca_bundle_path() const;
    std::string user_selected_machine() const;

    // Invoked by LanSession from the MQTT network thread. Marshals the call
    // through queue_on_main_ when Studio registered one, so status callbacks
    // reach the Studio UI thread safely.
    void notify_local_connected(int status, const std::string& dev_id, const std::string& msg);
    void notify_local_message(const std::string& dev_id, const std::string& json);

    // Lookup: given a synthetic subtask id we minted in notify_local_message,
    // returns the (subtask_name, plate_idx) combo and a ready-to-fetch
    // URL for its cover PNG. Used by bambu_network_get_subtask_info to
    // turn the opaque id back into a fake "cloud subtask" JSON reply
    // Studio can parse.
    struct SubtaskCoverInfo {
        std::string subtask_name;
        int         plate_idx = 1;
        std::string url; // http://127.0.0.1:PORT/cover/...
    };
    bool lookup_synthetic_subtask(const std::string& subtask_id,
                                  SubtaskCoverInfo*  out) const;

    // -----------------------------
    // Firmware catalogue (synthesised from MQTT).
    // -----------------------------
    // Rendered on demand from device_fw_ by bambu_network_get_printer_
    // firmware. The stock plugin would fetch this from Bambu Lab's
    // cloud firmware catalogue (auth-gated); we instead rebuild the
    // subset Studio actually reads (versions + release-note text) out
    // of the push_status.upgrade_state and info.get_version MQTT
    // frames we already forward. That gives us:
    //   * Populated "Update" tab with current/new versions.
    //   * Non-empty Release Notes dialog.
    //   * A functional Upgrade button (Studio's upgrade_confirm MQTT
    //     command doesn't carry a URL; the printer already knows
    //     which firmware it advertised in new_ver_list).
    // What we can NOT do without cloud auth: flash an arbitrary
    // OTA URL (CtrlUpgradeFirmware path). Studio only takes that
    // path when the user explicitly picks a non-advertised version.
    std::string render_firmware_json(const std::string& dev_id) const;

    // Returns true if at least one MQTT firmware frame has been received
    // for this device (info.get_version or upgrade_state.new_ver_list).
    // Used by bambu_network_get_printer_firmware to decide whether to fall
    // back to the cloud firmware catalogue endpoint.
    bool has_firmware_data(const std::string& dev_id) const;

    // Public so parse helpers inside agent.cpp can reach them; nobody
    // outside the library has reason to touch these directly.
    struct ModuleFw {
        std::string name;          // "ota", "ams", "ahb", "cutting_module", ...
        std::string cur_ver;       // installed version string (e.g. 01.08.01.00)
        std::string new_ver;       // advertised-by-printer newer version, if any
        std::string product_name;  // "P2S", "X1-Carbon", "AMS 2 Pro", ...
        std::string sn;
    };
    struct DeviceFw {
        std::map<std::string, ModuleFw> modules; // keyed by ModuleFw::name
    };
    // Accessor for the update-fw worker; returns a pointer into the
    // map under mu_. Caller MUST hold mu_ for the entire access.
    DeviceFw& fw_state_for(const std::string& dev_id) { return device_fw_[dev_id]; }

    // -----------------------------
    // Cloud MQTT (Studio's "server" connection).
    // -----------------------------
    // Opens the long-lived TLS MQTT connection to us.mqtt.bambulab.com
    // using the currently-stored access token. Idempotent: safe to
    // call repeatedly, subsequent calls are no-ops while already
    // connected. Returns BAMBU_NETWORK_* code.
    int  connect_cloud();
    int  disconnect_cloud();
    bool cloud_connected() const;
    int  cloud_refresh();
    int  cloud_add_subscribe(const std::vector<std::string>& dev_ids);
    int  cloud_del_subscribe(const std::vector<std::string>& dev_ids);
    int  cloud_send_message(const std::string& dev_id,
                            const std::string& json_str,
                            int qos);

    // -----------------------------
    // Cloud user session.
    // -----------------------------
    // Accept a login_info JSON (the same body the Bambu cloud returns
    // from /user/login). Extracts tokens + profile fields, stores them
    // under <config_dir>/obn.auth.json. Returns 0 on success.
    int apply_login_info(const std::string& login_info_json);

    // Forget the current session and delete the persisted file.
    void clear_session();

    // Consult the disk-backed store and, if the refresh token is fresh
    // enough, perform a silent refresh so the next HTTP call has a
    // valid Bearer. Called on Agent construction.
    void hydrate_session();

    bool        user_logged_in() const;
    obn::auth::Session user_session_snapshot() const
    {
        return auth_store_ ? auth_store_->snapshot() : obn::auth::Session{};
    }

    // Human-readable region identifier used by cloud endpoints.
    std::string cloud_region() const;

    // ------------------------------------------------------------------
    // Cloud bind (bambu_network_bind / ping_bind / …)
    // ------------------------------------------------------------------
    // Every SSDP JSON line Studio receives is also fed here so bind_detect
    // can resolve dev_id/bind_state from IP without an MQTT password.
    void cache_ssdp_json_for_bind(const std::string& device_info_json);
    // Polls up to `wait_ms` for a cached SSDP snapshot whose dev_ip
    // matches. Returns 0 and fills `out` on success, -1 on parse/conn
    // failure, -3 if nothing arrived in time (Studio then switches to
    // manual serial entry — same as stock returning -3).
    int lookup_bind_detect(const std::string& dev_ip,
                           BBL::detectResult& out,
                           int                wait_ms);
    // Last LAN access code seen in connect_printer for this dev_id (needed
    // because bambu_network_bind does not pass the code in the ABI).
    std::string lan_access_code_for(const std::string& dev_id) const;
    // Friendly name from the last SSDP packet for this printer IP, or "".
    std::string device_display_name_for_ip(const std::string& dev_ip) const;
    // Bearer + optional Studio certification headers for api.bambulab.com.
    std::map<std::string, std::string> cloud_api_http_headers() const;

    // ------------------------------------------------------------------
    // User preset cache (bambu_network_get_setting_list2 -> get_user_presets).
    // ------------------------------------------------------------------
    // Studio splits cloud-preset sync across two ABI calls: first
    // get_setting_list2() walks the cloud catalogue and decides what
    // needs downloading, then get_user_presets() hands the downloaded
    // blobs back to the GUI so it can persist them as local files.
    // Between those two calls we buffer the downloaded values_maps
    // here, keyed by preset name. Concurrency-safe.
    void preset_cache_reset();
    void preset_cache_put(std::string name,
                         std::map<std::string, std::string> values);
    // Moves the cache out; subsequent calls return an empty map.
    std::map<std::string, std::map<std::string, std::string>>
        preset_cache_drain();

    // Cloud user_id of the authenticated session (stringified), or "".
    // Preset-sync includes this in every values_map it builds for
    // Studio's load_user_preset().
    std::string cloud_user_id() const;

private:
    mutable std::mutex mu_;
    std::string        log_dir_;
    std::string        config_dir_;
    std::string        cert_folder_;
    std::string        cert_filename_;
    std::string        country_code_{"US"};
    std::string        user_selected_machine_;
    std::map<std::string, std::string> extra_http_headers_;

    std::unique_ptr<LanSession> lan_session_;
    std::unique_ptr<ssdp::Discovery> discovery_;
    std::unique_ptr<CloudSession>   cloud_session_;
    // Lazy localhost HTTP server that hands cover PNGs to Studio's
    // wxWebRequest. Only spun up when we first mint a synthetic
    // subtask id; destructor joins its accept loop.
    std::unique_ptr<cover_server::Server> cover_server_;
    // subtask_id ("lan-<fnv>") -> (subtask_name, plate_idx, version)
    // mapping we emit in notify_local_message. `version` is the
    // gcode_start_time we sniffed off the same push_status frame; it's
    // forwarded back to cover_server::url_for / cover_cache::path_for so
    // every fresh print of a same-named .3mf gets a distinct cache
    // file and a distinct URL (otherwise Studio's wxImage cache would
    // pin the first thumbnail forever - see cover_cache.hpp).
    // Trimmed when the user swaps the active print, bounded to a
    // handful of entries.
    struct SyntheticSubtask {
        std::string subtask_name;
        int         plate_idx = 1;
        std::string version;
    };
    std::map<std::string, SyntheticSubtask> synthetic_subtasks_;

    // Per-device firmware snapshot, populated from MQTT forwarded
    // through notify_local_message. Keyed by dev_id; value is the
    // most recent picture we have of that printer's modules. See
    // render_firmware_json() for how it's turned into the body Studio
    // expects from bambu_network_get_printer_firmware. Structs are
    // declared above (ModuleFw / DeviceFw) so agent.cpp helpers can
    // reach them.
    std::map<std::string, DeviceFw> device_fw_;

    // First cloud report per dev_id flips this set, which is what
    // triggers the one-shot on_printer_connected("tunnel/<id>")
    // notification. Cleared on disconnect/resubscribe so reconnects
    // re-fire the notification.
    std::set<std::string> cloud_connected_devs_;

    // Holds the cloud session (tokens + profile). Lazily populated from
    // <config_dir>/obn.auth.json as soon as config_dir_ is set.
    std::unique_ptr<obn::auth::Store> auth_store_;

    // Tracks which printers we've already snapshotted a server cert for in
    // the current process. Keyed by dev_id. Studio's refresh timer calls
    // install_device_cert() ~1 Hz, and we don't want to pound the printer
    // with a fresh TLS handshake every tick.
    std::set<std::string> certified_devs_;
    // dev_ids for which a cert-snapshot worker is currently running. Prevents
    // stacking multiple blocking SSL_connect attempts on a printer that
    // refuses the extra handshake.
    std::set<std::string> cert_snapshot_inflight_;
    // Negative cache for cert snapshotting: dev_id -> time when we may retry.
    // If a snapshot attempt fails (e.g. printer rejects the second TLS
    // session while our LAN MQTT is already connected) we back off for a
    // while instead of hammering the printer on every 1 Hz refresh tick.
    std::unordered_map<std::string, std::chrono::steady_clock::time_point>
        cert_snapshot_cooldown_;

    // Last SSDP "device alive" JSON keyed by normalised LAN IP (see
    // ssdp::to_device_info_json). Used by lookup_bind_detect().
    std::unordered_map<std::string, std::string> ssdp_json_by_ip_;
    // connect_printer() stores the MQTT/FTPS password (access code) here so
    // bambu_network_bind can POST it to the cloud as bind_code.
    std::unordered_map<std::string, std::string> lan_access_code_by_dev_;

    // Buffer populated by bambu_network_get_setting_list2 and drained
    // by bambu_network_get_user_presets. See preset_cache_* above.
    std::map<std::string, std::map<std::string, std::string>> preset_cache_;

    // Callbacks - stored, not (yet) invoked.
    BBL::OnMsgArrivedFn       on_ssdp_msg_{};
    BBL::OnUserLoginFn        on_user_login_{};
    BBL::OnPrinterConnectedFn on_printer_connected_{};
    BBL::OnServerConnectedFn  on_server_connected_{};
    BBL::OnHttpErrorFn        on_http_error_{};
    BBL::GetCountryCodeFn     get_country_code_{};
    BBL::GetSubscribeFailureFn on_subscribe_failure_{};
    BBL::OnMessageFn          on_message_{};
    BBL::OnMessageFn          on_user_message_{};
    BBL::OnLocalConnectedFn   on_local_connect_{};
    BBL::OnMessageFn          on_local_message_{};
    BBL::QueueOnMainFn        queue_on_main_{};
    BBL::OnServerErrFn        server_err_{};
};

// Safe cast with null guard used by every exported function. Keeps the exports
// short and consistent. Returns nullptr for the one-arg handle variant.
inline Agent* as_agent(void* h) { return static_cast<Agent*>(h); }

} // namespace obn
