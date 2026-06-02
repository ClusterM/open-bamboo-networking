#include "obn/agent.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <map>
#include <thread>
#include <utility>

#include "obn/bambu_networking.hpp"
#include "obn/cert_store.hpp"
#include "obn/cloud_auth.hpp"
#include "obn/cloud_session.hpp"
#include "obn/config.hpp"
#include "obn/cover_cache.hpp"
#include "obn/cover_server.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"
#include "obn/print_params_ftp_prefs.hpp"
#include "obn/ssdp.hpp"
#include "obn/lan_tls.hpp"

namespace obn {

namespace {

std::string trim_ip_string(std::string s)
{
    while (!s.empty() &&
           (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
        s.pop_back();
    std::size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
        ++i;
    if (i > 0) s.erase(0, i);
    return s;
}

} // namespace

Agent::Agent(std::string log_dir) : log_dir_(std::move(log_dir)) {}
Agent::~Agent()
{
    if (discovery_) discovery_->stop();
    if (cloud_session_) cloud_session_->stop();
}

int Agent::connect_printer(std::string dev_id,
                           std::string dev_ip,
                           std::string username,
                           std::string password,
                           bool        use_ssl)
{
    // Studio calls connect_printer() again when the user switches to a
    // different printer or re-enters the access code. Tear down any prior
    // session cleanly so we don't leak MQTT threads.
    bool switching_printer = false;
    {
        std::unique_ptr<LanSession> prev;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (lan_session_ && lan_session_->dev_id() != dev_id) {
                switching_printer = true;
            }
            prev = std::move(lan_session_);
        }
        // prev.reset() happens outside the lock; destructor joins the MQTT
        // loop thread which may call back into notify_local_connected under
        // mu_.
    }

    if (switching_printer) {
        std::lock_guard<std::mutex> lk(mu_);
        certified_devs_.clear();
    }

    std::string ca_file = bambu_ca_bundle_path();
    obn::lan_tls::registry_set_ca_file(ca_file);
    obn::lan_tls::registry_put_ip_serial(dev_ip, dev_id);
    {
        std::string cfg_dir = config_dir();
        if (!cfg_dir.empty()) {
            std::string peer = cert_store::device_cert_path(cfg_dir, dev_id);
            std::error_code ec;
            bool have_peer = std::filesystem::is_regular_file(peer, ec);
            if (use_ssl && obn::lan_tls::verify_enabled() && !have_peer) {
                OBN_INFO("connect_printer: snapshot device cert before LAN MQTT");
                if (cert_store::capture_peer_cert_pem(
                        dev_ip, 8883, /*timeout_ms=*/3000, peer, dev_id)) {
                    have_peer = std::filesystem::is_regular_file(peer, ec);
                    if (have_peer) {
                        std::lock_guard<std::mutex> lk(mu_);
                        certified_devs_.insert(dev_id);
                    }
                } else {
                    OBN_WARN("connect_printer: device cert snapshot failed");
                }
            }
            if (std::filesystem::is_regular_file(peer, ec)) {
                obn::lan_tls::registry_set_peer_cert(dev_ip, peer);
            }
        }
    }

    auto session = std::make_unique<LanSession>(std::move(dev_id),
                                                std::move(dev_ip),
                                                std::move(username),
                                                std::move(password),
                                                use_ssl,
                                                std::move(ca_file));

    std::string sess_dev_id = session->dev_id();

    int rc = session->start(
        [this, sess_dev_id](int status, std::string msg) {
            notify_local_connected(status, sess_dev_id, msg);
        },
        [this](std::string d, std::string json) {
            notify_local_message(d, json);
        });

    if (rc == BAMBU_NETWORK_SUCCESS) {
        std::lock_guard<std::mutex> lk(mu_);
        lan_access_code_by_dev_[sess_dev_id] = session->password();
        lan_session_                         = std::move(session);
    }
    return rc;
}

int Agent::disconnect_printer()
{
    print_params_set_use_ssl_for_ftp(true);

    std::unique_ptr<LanSession> session;
    {
        std::lock_guard<std::mutex> lk(mu_);
        session = std::move(lan_session_);
    }
    if (session) session->disconnect();
    return BAMBU_NETWORK_SUCCESS;
}

int Agent::send_message_to_printer(const std::string& dev_id,
                                   const std::string& json_str,
                                   int                qos)
{
    LanSession* session = nullptr;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (lan_session_ && lan_session_->dev_id() == dev_id)
            session = lan_session_.get();
    }
    if (!session) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    return session->publish_json(json_str, qos);
}

void Agent::notify_local_connected(int status, const std::string& dev_id, const std::string& msg)
{
    BBL::OnLocalConnectedFn cb;
    BBL::QueueOnMainFn      queue;
    {
        std::lock_guard<std::mutex> lk(mu_);
        cb    = on_local_connect_;
        queue = queue_on_main_;
    }
    OBN_DEBUG("notify_local_connected status=%d dev=%s msg=%s cb=%d queued=%d",
              status, dev_id.c_str(), msg.c_str(), cb ? 1 : 0, queue ? 1 : 0);
    if (!cb) return;
    auto invoke = [cb, status, dev_id, msg]() { cb(status, dev_id, msg); };
    if (queue) queue(invoke);
    else       invoke();
}

namespace {

// --- Optional MQTT push_status patches (gated by obn.conf) ----------
//
// These rewrite incoming LAN push_status frames in place. They are all
// off by default and only enabled when the user opts in via obn.conf,
// because they lie to Studio about printer capabilities. They target
// printers (P2S, some A-series) whose firmware under-reports storage /
// file-browser support, leaving the corresponding Studio UI greyed out
// even though the underlying transport works.

// Printers with no SD-card slot (P2S uses a USB-A stick instead, newer
// A-series likewise) report `home_flag` with bits [8:9] == 0 (NO_SDCARD).
// Studio's DeviceManager parses those two bits straight into
// DevStorage::SdcardState, which gates the "Send to Printer" / "Print via
// LAN" UIs: the storage radio button goes grey and the Device/Storage
// pane shows a red error tile.
//
// Rewrite bits [8:9] from 00 (NO_SDCARD) -> 01 (HAS_SDCARD_NORMAL) in place
// on the JSON text. Only bits [8:9] are touched; real SD error states
// (ABNORMAL=2, READONLY=3) and printers already reporting HAS_SDCARD=1 are
// passed through unchanged so genuine "SD card missing" errors keep working.
//
// Returns true if the payload was patched.
bool try_rewrite_home_flag(std::string& payload)
{
    static const std::string kKey = "\"home_flag\":";
    std::size_t pos = payload.find(kKey);
    if (pos == std::string::npos) return false;
    std::size_t i = pos + kKey.size();
    while (i < payload.size() && payload[i] == ' ') ++i;
    std::size_t start = i;
    bool        negative = false;
    if (i < payload.size() && payload[i] == '-') { negative = true; ++i; }
    std::size_t digits_start = i;
    while (i < payload.size() && payload[i] >= '0' && payload[i] <= '9') ++i;
    if (i == digits_start) return false;

    long long flag = 0;
    try { flag = std::stoll(payload.substr(digits_start, i - digits_start)); }
    catch (...) { return false; }
    if (negative) flag = -flag;

    int sd_bits = static_cast<int>((flag >> 8) & 0x3);
    if (sd_bits != 0) return false;  // HAS_SDCARD_NORMAL/ABNORMAL/READONLY: pass through

    long long patched = flag | (1LL << 8);
    std::string repl  = std::to_string(patched);
    payload.replace(start, i - start, repl);
    return true;
}

// P2S / newer A-series firmware does not expose `ipcam.file` in push_status.
// If Studio sees no `ipcam.file` (or `file.local == "none"`) it short-circuits
// the MediaFilePanel with "Browsing file in storage is not supported in
// current firmware" and never opens the file tunnel.
//
// Inject `"file":{"local":"local","remote":"none","model_download":"enabled"}`
// into the ipcam block of frames that lack one. If a payload already carries
// `ipcam.file` (X1/P1S-class printers that advertise it) we pass through
// untouched.
//
// Returns true if the payload was patched.
bool try_inject_ipcam_file_local(std::string& payload)
{
    static const std::string kIpcam = "\"ipcam\":";
    std::size_t pos = payload.find(kIpcam);
    if (pos == std::string::npos) return false;
    // Walk to the opening brace of the ipcam object.
    std::size_t brace = payload.find('{', pos + kIpcam.size());
    if (brace == std::string::npos) return false;
    // Find the matching closing brace by depth counting. Strings are
    // tracked minimally (enough for well-formed JSON; printers always
    // emit that).
    std::size_t i = brace + 1;
    int depth = 1;
    bool in_str = false;
    bool esc = false;
    std::size_t end = std::string::npos;
    std::size_t file_hit = std::string::npos;
    for (; i < payload.size(); ++i) {
        char c = payload[i];
        if (in_str) {
            if (esc)          esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"')  in_str = false;
            continue;
        }
        if (c == '"') {
            in_str = true;
            // Opportunistically spot an existing "file": at the current
            // depth - if present, leave the payload alone.
            if (depth == 1 && payload.compare(i, 7, "\"file\":") == 0)
                file_hit = i;
            continue;
        }
        if (c == '{')      ++depth;
        else if (c == '}') { if (--depth == 0) { end = i; break; } }
    }
    if (end == std::string::npos) return false;
    if (file_hit != std::string::npos) return false;
    static const std::string kInject =
        ",\"file\":{\"local\":\"local\",\"remote\":\"none\","
        "\"model_download\":\"enabled\"}";
    payload.insert(end, kInject);
    return true;
}

// `print.fun2` is a hex-string capability bitmask. Bit 17 =
// `is_support_model_internal_storage`, which makes Studio show the
// internal-storage (eMMC) tab in the file browser. P2S supports eMMC
// (REQUEST_MEDIA_ABILITY on :6000 returns ["emmc","udisk"]) but does not
// advertise the bit, so Studio only shows external (USB) storage.
//
// Set bit 17 in place. We never inject `fun2` when it is absent, and leave
// payloads that already have the bit untouched.
//
// Returns true if the payload was patched.
bool try_patch_fun2_internal_storage(std::string& payload)
{
    static const std::string kKey = "\"fun2\":";
    std::size_t pos = payload.find(kKey);
    if (pos == std::string::npos) return false;
    std::size_t i = pos + kKey.size();
    while (i < payload.size() && payload[i] == ' ') ++i;
    if (i >= payload.size() || payload[i] != '"') return false;  // hex string only
    std::size_t start = i + 1;
    std::size_t end = start;
    while (end < payload.size() && payload[end] != '"') ++end;
    if (end >= payload.size()) return false;

    const std::string hex = payload.substr(start, end - start);
    if (hex.empty()) return false;
    unsigned long long bits = 0;
    try { bits = std::stoull(hex, nullptr, 16); }
    catch (...) { return false; }

    constexpr unsigned long long kBit17 = 1ULL << 17;
    if (bits & kBit17) return false;  // already advertised

    bits |= kBit17;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llx", bits);
    payload.replace(start, end - start, buf);
    return true;
}

// Extracts a JSON string-valued field from an arbitrary payload. Only
// matches top-level flat string fields (no escaping, no nested objects)
// because we only ever use it to read simple values like subtask_name
// that Bambu's firmware always emits as plain ASCII.
//
// On hit: returns true and writes the string value (without surrounding
// quotes) into *out. On miss: false, *out is left unchanged.
bool json_peek_string_field(const std::string& payload,
                            const std::string& key,
                            std::string*       out)
{
    std::string needle = "\"" + key + "\":";
    std::size_t pos = payload.find(needle);
    if (pos == std::string::npos) return false;
    pos += needle.size();
    while (pos < payload.size() && payload[pos] == ' ') ++pos;
    if (pos >= payload.size() || payload[pos] != '"') return false;
    std::size_t start = pos + 1;
    std::size_t end = start;
    while (end < payload.size() && payload[end] != '"') {
        if (payload[end] == '\\' && end + 1 < payload.size()) ++end;
        ++end;
    }
    if (end >= payload.size()) return false;
    *out = payload.substr(start, end - start);
    return true;
}

// Rewrites `"key":"0"` or `"key":""` to `"key":"<value>"` in place.
// LAN prints may emit zeros or empty strings for cloud ids.
bool patch_string_zero_to(std::string&       payload,
                          const std::string& key,
                          const std::string& value)
{
    std::string needle = "\"" + key + "\":";
    std::size_t pos = payload.find(needle);
    if (pos == std::string::npos) return false;
    std::size_t i = pos + needle.size();
    while (i < payload.size() && payload[i] == ' ') ++i;
    if (i + 2 > payload.size() || payload[i] != '"') return false;
    if (payload[i + 1] == '"') {
        payload.replace(i, 2, "\"" + value + "\"");
        return true;
    }
    if (i + 3 <= payload.size() && payload[i + 1] == '0' && payload[i + 2] == '"') {
        payload.replace(i, 3, "\"" + value + "\"");
        return true;
    }
    return false;
}

// FNV-1a 32-bit - deterministic across platforms and C++ runtimes, so
// Studio always computes the same synthetic subtask id for a given
// subtask name even across plugin rebuilds.
std::uint32_t fnv1a_32(const std::string& s)
{
    std::uint32_t h = 2166136261u;
    for (unsigned char c : s) { h ^= c; h *= 16777619u; }
    return h;
}

// Builds the synthetic subtask id Studio sees in place of the LAN print's
// "0"s. `version` is the per-print token (gcode_start_time) folded into
// the hash so a re-print of a same-named .3mf yields a brand new id.
// Studio's update_model_task() compares last_subtask_id_ != subtask_id_
// before re-fetching the cover; without `version` participating in the
// hash that comparison would short-circuit and the thumbnail would never
// refresh.
std::string synthetic_subtask_id(const std::string& subtask_name,
                                 const std::string& version)
{
    std::string keyed = subtask_name;
    if (!version.empty()) {
        keyed.push_back('\x01');
        keyed.append(version);
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "lan-%08x", fnv1a_32(keyed));
    return buf;
}

// LAN / Developer-Mode prints set project_id / profile_id / task_id /
// subtask_id to "0" or "" in push_status.print, which makes Studio's
// MachineObject::is_sdcard_printing() return true and routes the
// Device-panel thumbnail to the static SD-card placeholder bitmap. We
// don't want that: we have the original .3mf sitting in the printer's
// FTPS /cache/ and can hand Studio a real cover image.
//
// Swap the zero ids for synthetic non-zero ones derived from the
// (subtask_name, version) pair where `version` is gcode_start_time
// from the same frame. Studio will then hit the "cloud subtask" branch,
// eventually calling our bambu_network_get_subtask_info which hands
// back a JSON pointing at the local cover_server.
//
// Returns true if the payload was patched.
bool try_rewrite_print_ids(std::string& payload,
                           const std::string& version,
                           std::string* synthetic_id)
{
    // Cheap prefilter: only bother if we're looking at a push_status
    // frame that carries a subtask_name (i.e. a real print, not a
    // system_printing / system_status frame).
    std::string name;
    if (!json_peek_string_field(payload, "subtask_name", &name)) return false;
    if (name.empty() || name == "-1") return false;

    std::string id = synthetic_subtask_id(name, version);
    bool touched = false;
    touched |= patch_string_zero_to(payload, "project_id", "lan");
    touched |= patch_string_zero_to(payload, "profile_id", "lan");
    touched |= patch_string_zero_to(payload, "task_id",    id);
    touched |= patch_string_zero_to(payload, "subtask_id", id);
    if (touched && synthetic_id) *synthetic_id = id;
    return touched;
}

} // namespace

// Forward declarations for helpers defined further down; keeps the file
// readable (firmware-cache logic lives with render_firmware_json). These
// live in obn:: (not the anonymous namespace above) so the definition
// and the notify_local_message caller bind to the same symbol.
static void update_fw_state(Agent::DeviceFw* dev, const std::string& payload);

void Agent::notify_local_message(const std::string& dev_id, const std::string& json)
{
    BBL::OnMessageFn cb;
    {
        // Per Studio's NetworkAgent wiring, local MQTT report messages go to
        // on_local_message_. We intentionally do not marshal through
        // queue_on_main_ here: DeviceManager.cpp does its own thread hop
        // based on the JSON content (some update paths are fast-path).
        std::lock_guard<std::mutex> lk(mu_);
        cb = on_local_message_;
    }

    std::string patched = json;

    // Optional capability patches (off by default; opt-in via obn.conf).
    // These target printers that under-report storage / file-browser
    // support, leaving the corresponding Studio UI greyed out.
    {
        const auto& cfg = obn::config::current();
        if (cfg.patch_mqtt_home_flag)        try_rewrite_home_flag(patched);
        if (cfg.patch_mqtt_ipcam_file)       try_inject_ipcam_file_local(patched);
        if (cfg.patch_mqtt_internal_storage) try_patch_fun2_internal_storage(patched);
    }

    // Per-print token used to invalidate the cover cache when the user
    // re-uploads a different .3mf under the same filename. We need a
    // value that is constant for the life of one print and changes the
    // moment the next one starts. Three candidates, tried in order of
    // reliability across observed firmware:
    //
    //  1. `task_id` — the printer's own monotonic print-job counter
    //     (e.g. "8442", incremented per job). Present on P-/X-/A-series
    //     LAN-only frames even when subtask_id/job_id/lan_task_id are
    //     all "0", which makes it the most universally available
    //     stable per-print identifier in the report block.
    //
    //  2. `gcode_start_time` — wall-clock epoch when the print started.
    //     Some engineering / older firmware does not emit task_id but
    //     does emit this; keep it as a fallback.
    //
    //  3. Empty string — no token available; the cache key collapses to
    //     the legacy name-only FNV hash, preserving prior behaviour
    //     (i.e. the bug, but only on firmware that carries neither
    //     identifier — none observed in practice).
    //
    // Must be extracted *before* try_rewrite_print_ids, because that
    // helper rewrites task_id="0" -> synth_id and we'd then key against
    // our own synthetic id (circular).
    std::string version;
    json_peek_string_field(patched, "task_id", &version);
    if (version.empty() || version == "0") {
        version.clear();
        json_peek_string_field(patched, "gcode_start_time", &version);
    }

    // Print-cover workaround: turn a LAN-only "all zeros" print into a
    // synthetic cloud subtask so Studio's update_cloud_subtask path
    // fires and requests our cover URL.
    std::string synth_id;
    bool rewrote_ids = try_rewrite_print_ids(patched, version, &synth_id);

    // Cover-cache trigger. Two cases feed this path:
    //  * LAN-only prints: ids were "0", rewrite_print_ids swapped them
    //    for a synthetic "lan-<fnv>" id that we have to publish.
    //  * Cloud-initiated prints (subtask from Bambu cloud, even when
    //    Studio is now unbound): ids already carry real values like
    //    "893120535", Studio sends those to get_subtask_info. We need
    //    to map them onto the same cover PNG.
    // In both cases we pull `/cache/<subtask_name>.gcode.3mf` over
    // FTPS, which is what start_local_print_with_record / start_sdcard_
    // print deposit (cloud prints land there via the printer's own
    // cloud-download path too).
    std::string subtask_name;
    json_peek_string_field(patched, "subtask_name", &subtask_name);
    std::string real_subtask_id;
    json_peek_string_field(patched, "subtask_id", &real_subtask_id);

    std::string cover_id;
    // The `version` participates in the cache key only for the LAN /
    // synthetic branch. Real cloud subtask ids are already unique per
    // print on the server side, so a same-named reprint there gets a
    // brand-new subtask_id and the old cache key naturally retires —
    // mixing gcode_start_time in would just orphan PNGs faster.
    std::string cover_version;
    if (!subtask_name.empty() && subtask_name != "-1") {
        if (rewrote_ids && !synth_id.empty()) {
            cover_id      = synth_id;
            cover_version = version;
        } else if (!real_subtask_id.empty() && real_subtask_id != "0") {
            cover_id = real_subtask_id;
        }
    }

    if (!cover_id.empty()) {
        // Bambu firmware doesn't ship plate_idx in push_status; the
        // original .3mf is the source of truth (Metadata/slice_info.
        // config) but we haven't downloaded it yet. Default to 1 -
        // this matches our start_sdcard_print param path and is right
        // for 99% of single-plate .3mfs.
        int plate_idx = 1;

        std::string host, user, pass;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (lan_session_) {
                host = lan_session_->dev_ip();
                user = lan_session_->username();
                pass = lan_session_->password();
            }
            synthetic_subtasks_[cover_id] =
                SyntheticSubtask{subtask_name, plate_idx, cover_version};
            // Cap the map; the user only ever cares about the current
            // print but we keep a short history for races between
            // subtask switches and Studio's thumbnail re-request.
            while (synthetic_subtasks_.size() > 16) {
                synthetic_subtasks_.erase(synthetic_subtasks_.begin());
            }
            if (!cover_server_) {
                cover_server_ = std::make_unique<cover_server::Server>();
                if (int rc = cover_server_->start(); rc != 0) {
                    OBN_WARN("cover_server: start failed rc=%d", rc);
                    cover_server_.reset();
                }
            }
        }
        if (!host.empty()) {
            cover_cache::ensure(host, dev_id, user, pass,
                                subtask_name, plate_idx, cover_version);
        }
    }

    OBN_DEBUG("notify_local_message dev=%s bytes=%zu cb=%d print_ids=%d "
              "cover_id=%s ver=%s",
              dev_id.c_str(), patched.size(), cb ? 1 : 0,
              rewrote_ids ? 1 : 0,
              cover_id.empty() ? "-" : cover_id.c_str(),
              cover_version.empty() ? "-" : cover_version.c_str());

    // Harvest firmware info from any frame that carries it. Purely
    // additive; only populates an in-memory cache used by
    // bambu_network_get_printer_firmware.
    {
        std::lock_guard<std::mutex> lk(mu_);
        update_fw_state(&fw_state_for(dev_id), patched);
    }

    if (cb) cb(dev_id, patched);
}

// Pulls firmware bookkeeping out of every MQTT frame we forward. Studio
// assembles the same info internally (module_vers + upgrade->m_new_ver_list),
// but it never shares that back with the plugin, so we mirror it here so
// render_firmware_json has something to serve.
//
// Two shapes feed this:
//
//  * Reply to info.command=get_version:
//      {"info":{"command":"get_version","module":[
//          {"name":"ota","sw_ver":"01.08.01.00","product_name":"P2S",
//           "sn":"...","sw_new_ver":"01.09.01.00"},
//          {"name":"ams/0","sw_ver":"00.00.06.49", ... }, ...
//      ]}}
//    Present the printer's current and (optionally) advertised new
//    versions for every module it knows about.
//
//  * push_status.upgrade_state.new_ver_list (P1/X1 firmware only pushes
//    this when new firmware is actually available):
//      {"print":{"upgrade_state":{"new_ver_list":[
//          {"name":"ota","cur_ver":"01.08.01.00","new_ver":"01.09.01.00"}
//      ]}}}
//    Used to fill in new_ver when get_version didn't include it.
//
// We keep whichever field was set most recently per module; both push
// frequently enough that the record converges. Running under mu_.
static void parse_module_into(Agent::DeviceFw*        dev,
                              const obn::json::Value& item)
{
    if (!item.is_object()) return;
    // Every json_lite find() returns by value, so we must copy the
    // string out of each temporary before it dies. Binding to
    // `const std::string&` produces -Wdangling-reference under GCC 13.
    std::string name = item.find("name").as_string();
    if (name.empty()) return;
    auto& m = dev->modules[name];
    m.name = std::move(name);

    std::string cur = item.find("sw_ver").as_string();
    if (!cur.empty()) m.cur_ver = std::move(cur);
    std::string nv = item.find("sw_new_ver").as_string();
    if (!nv.empty()) m.new_ver = std::move(nv);
    std::string alt_nv = item.find("new_ver").as_string();
    if (!alt_nv.empty() && m.new_ver.empty()) m.new_ver = std::move(alt_nv);
    std::string alt_cur = item.find("cur_ver").as_string();
    if (!alt_cur.empty() && m.cur_ver.empty()) m.cur_ver = std::move(alt_cur);
    std::string prod = item.find("product_name").as_string();
    if (!prod.empty()) m.product_name = std::move(prod);
    std::string sn = item.find("sn").as_string();
    if (!sn.empty()) m.sn = std::move(sn);
}

static void update_fw_state(Agent::DeviceFw* dev, const std::string& payload)
{
    if (!dev) return;
    // Cheap prefilter: only parse if the string even hints at firmware
    // data. Keeps per-message cost close to zero for the dense push_status
    // heartbeat frames that otherwise dominate this path.
    if (payload.find("sw_ver") == std::string::npos &&
        payload.find("new_ver_list") == std::string::npos) {
        return;
    }
    auto v = obn::json::parse(payload);
    if (!v) return;

    // info.command=get_version reply (modules array).
    if (v->find("info.command").as_string() == "get_version") {
        auto modules = v->find("info.module");
        for (const auto& m : modules.as_array()) {
            parse_module_into(dev, m);
        }
    }

    // push_status.print.upgrade_state.new_ver_list.
    {
        auto list = v->find("print.upgrade_state.new_ver_list");
        for (const auto& m : list.as_array()) {
            parse_module_into(dev, m);
        }
    }
}

// Version-compare just good enough for Bambu's "XX.YY.ZZ.WW" scheme.
// Returns -1 if a<b, 0 if equal or uncomparable, +1 if a>b.
static int version_compare(const std::string& a, const std::string& b)
{
    if (a == b || a.empty() || b.empty()) return 0;
    auto parts = [](const std::string& s) {
        std::vector<int> out;
        size_t i = 0;
        while (i <= s.size()) {
            if (i == s.size() || s[i] == '.') {
                // treat empty/bad segment as 0; we want to keep going.
                // nothing to append here.
                ++i;
            } else {
                size_t j = i;
                int n = 0;
                while (j < s.size() && s[j] >= '0' && s[j] <= '9') {
                    n = n * 10 + (s[j] - '0');
                    ++j;
                }
                out.push_back(n);
                i = j;
            }
        }
        return out;
    };
    auto pa = parts(a);
    auto pb = parts(b);
    size_t n = std::max(pa.size(), pb.size());
    for (size_t i = 0; i < n; ++i) {
        int va = i < pa.size() ? pa[i] : 0;
        int vb = i < pb.size() ? pb[i] : 0;
        if (va < vb) return -1;
        if (va > vb) return +1;
    }
    return 0;
}

// Helper: append a JSON string value (opening quote, escaped contents,
// closing quote). obn::json::escape already produces the quoted form,
// so we just concat.
static void emit_json_string(std::string* dst, const std::string& s)
{
    dst->append(obn::json::escape(s));
}

static void emit_fw_entry(std::string*       dst,
                          bool*              first,
                          const std::string& version,
                          const std::string& description)
{
    if (!*first) dst->push_back(',');
    *first = false;
    dst->append(R"({"version":)");
    emit_json_string(dst, version);
    dst->append(R"(,"url":"","description":)");
    emit_json_string(dst, description);
    dst->push_back('}');
}

std::string Agent::render_firmware_json(const std::string& dev_id) const
{
    // Pull a snapshot under the lock; build the JSON text outside it.
    DeviceFw snap;
    bool have_device = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = device_fw_.find(dev_id);
        if (it != device_fw_.end()) {
            snap = it->second;
            have_device = true;
        }
    }

    // Release-note link derived from the OTA module's product_name.
    // Bambu's support site has per-series pages; we map Pn to the P1
    // page because they all share a changelog.
    std::string product;
    if (have_device) {
        auto ota = snap.modules.find("ota");
        if (ota != snap.modules.end()) product = ota->second.product_name;
    }
    auto product_slug = [&]() -> std::string {
        if (product.find("X1") != std::string::npos) return "x1";
        if (product.find("P2") != std::string::npos) return "p1";
        if (product.find("P1") != std::string::npos) return "p1";
        if (product.find("A1") != std::string::npos) return "a1";
        if (product.find("H2") != std::string::npos) return "h2d";
        if (product.find("N7") != std::string::npos) return "n7";
        return "all";
    }();
    std::string notes_url =
        "https://bambulab.com/en/support/firmware-download/" + product_slug;

    std::string body;
    body.reserve(512);
    body.append(R"({"devices":[{"dev_id":)");
    emit_json_string(&body, dev_id);
    body.append(R"(,"firmware":[)");

    bool first_ota = true;
    if (have_device) {
        auto ota_it = snap.modules.find("ota");
        if (ota_it != snap.modules.end()) {
            const auto& m = ota_it->second;
            // Current version entry - release-note dialog falls back
            // to it when the printer hasn't advertised a new version.
            if (!m.cur_ver.empty()) {
                std::string desc =
                    "Currently installed firmware. Full changelog at " +
                    notes_url + ".";
                emit_fw_entry(&body, &first_ota, m.cur_ver, desc);
            }
            // New-version entry - drives the "current -> new" arrow
            // and the release-note text the user sees after clicking.
            if (!m.new_ver.empty() &&
                version_compare(m.new_ver, m.cur_ver) > 0) {
                std::string desc =
                    "New firmware version " + m.new_ver +
                    " is available.\n\nRelease notes: " + notes_url +
                    "\n\nClick 'Update' to install; the printer already "
                    "knows which package to download. Do not turn off "
                    "the printer during the update (~10 minutes).";
                emit_fw_entry(&body, &first_ota, m.new_ver, desc);
            }
        }
    }
    body.append(R"(],"ams":[)");

    // Gather AMS entries; Studio's parser walks `ams_list.front().
    // firmware` so wrap whatever we have in a single element.
    std::string ams_fw;
    bool first_ams = true;
    if (have_device) {
        for (const auto& kv : snap.modules) {
            const std::string& key = kv.first;
            // "ams/0", "ams/1", ... from get_version; "ams" from
            // upgrade_state.new_ver_list.
            if (key != "ams" && key.rfind("ams/", 0) != 0) continue;
            const auto& m = kv.second;
            const std::string& advertised =
                !m.new_ver.empty() ? m.new_ver : m.cur_ver;
            if (advertised.empty()) continue;
            std::string desc = "AMS firmware. Release notes: " + notes_url;
            emit_fw_entry(&ams_fw, &first_ams, advertised, desc);
        }
    }
    if (!ams_fw.empty()) {
        body.append(R"({"firmware":[)");
        body.append(ams_fw);
        body.append(R"(]})");
    }
    body.append(R"(]}]})");
    return body;
}

bool Agent::lookup_synthetic_subtask(const std::string& subtask_id,
                                     SubtaskCoverInfo*  out) const
{
    if (!out) return false;
    std::lock_guard<std::mutex> lk(mu_);
    auto it = synthetic_subtasks_.find(subtask_id);
    if (it == synthetic_subtasks_.end()) return false;
    out->subtask_name = it->second.subtask_name;
    out->plate_idx    = it->second.plate_idx;
    if (cover_server_) {
        out->url = cover_server_->url_for(out->subtask_name,
                                          out->plate_idx,
                                          it->second.version);
    }
    return true;
}

void Agent::set_config_dir(std::string dir)
{
    {
        std::lock_guard<std::mutex> lk(mu_);
        config_dir_ = std::move(dir);
    }
    // Swap the auth store to a real on-disk file as soon as Studio
    // tells us where to keep it. Studio calls set_config_dir() exactly
    // once during plugin init, before any user-facing ABI.
    std::string cfg = config_dir();
    if (!cfg.empty()) {
        obn::lan_tls::registry_set_config_dir(cfg);
        // Reload obn.conf from data_dir and rewrite obn.lan_tls.env (log_dir from
        // create_agent may differ; BambuSource hydrates from the state file).
        (void)obn::config::load_or_create(cfg);
        auth_store_ = std::make_unique<obn::auth::Store>(cfg + "/obn.auth.json");
        auth_store_->load();
        hydrate_session();
    }
}

void Agent::set_cert_file(std::string folder, std::string filename)
{
    {
        std::lock_guard<std::mutex> lk(mu_);
        cert_folder_   = std::move(folder);
        cert_filename_ = std::move(filename);
    }
    obn::lan_tls::registry_set_ca_file(bambu_ca_bundle_path());
}

void Agent::set_country_code(std::string code)
{
    std::lock_guard<std::mutex> lk(mu_);
    country_code_ = std::move(code);
}

void Agent::set_extra_http_headers(std::map<std::string, std::string> headers)
{
    std::lock_guard<std::mutex> lk(mu_);
    extra_http_headers_ = std::move(headers);
}

void Agent::set_user_selected_machine(std::string dev_id)
{
    std::lock_guard<std::mutex> lk(mu_);
    user_selected_machine_ = std::move(dev_id);
}

std::string Agent::country_code() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return country_code_;
}

std::string Agent::config_dir() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return config_dir_;
}

std::string Agent::cert_folder() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return cert_folder_;
}

std::string Agent::cert_filename() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return cert_filename_;
}

std::string Agent::bambu_ca_bundle_path() const
{
    std::string folder;
    {
        std::lock_guard<std::mutex> lk(mu_);
        folder = cert_folder_;
    }
    if (folder.empty()) return {};
    // Strip a trailing separator on either platform so we can re-add a
    // single forward slash. std::filesystem could do this but the rest of
    // the function predates the cross-platform refactor and uses string
    // joining throughout; keep it consistent.
    char last = folder.back();
    if (last == '/' || last == '\\') folder.pop_back();
    // Studio ships two cert files in resources/cert/:
    //   slicer_base64.cer  - cloud bundle (*.bambulab.com); stored for Windows
    //                        cloud MQTT MVP (see connect_cloud). Not used for LAN.
    //   printer.cer        - BBL CA bundle (root/intermediates). LAN trust file.
    //                        Device leaf issuers (e.g. BBL Device CA N7-V2) may be
    //                        absent; LAN verify also uses install_device_cert snapshot.
    std::string path = (std::filesystem::path(folder) / "printer.cer").string();
    std::error_code ec;
    if (std::filesystem::is_regular_file(path, ec)) return path;
    return {};
}

std::string Agent::user_selected_machine() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return user_selected_machine_;
}

bool Agent::start_discovery(bool enable, bool sending)
{
    OBN_INFO("start_discovery enable=%d sending=%d", enable, sending);

    // The existing Discovery is held under mu_; we capture the callback
    // outside the lock to avoid holding it across the socket syscall.
    if (!enable) {
        std::unique_ptr<ssdp::Discovery> d;
        {
            std::lock_guard<std::mutex> lk(mu_);
            d = std::move(discovery_);
        }
        if (d) d->stop();
        return false;
    }

    BBL::OnMsgArrivedFn cb;
    BBL::QueueOnMainFn  queue;
    ssdp::Discovery*    d_ptr = nullptr;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!discovery_) discovery_ = std::make_unique<ssdp::Discovery>();
        d_ptr = discovery_.get();
        cb    = on_ssdp_msg_;
        queue = queue_on_main_;
    }

    // All SSDP messages are trampolined through queue_on_main_ so that
    // Studio's DeviceManager::on_machine_alive() mutates the UI-owned
    // machine list only on the main thread. Without this we eventually
    // race on_machine_alive against wx's own rendering and crash under
    // high packet rates.
    auto on_msg = [this](std::string json) {
        cache_ssdp_json_for_bind(json);
        BBL::OnMsgArrivedFn local_cb;
        BBL::QueueOnMainFn  local_queue;
        {
            std::lock_guard<std::mutex> lk(mu_);
            local_cb    = on_ssdp_msg_;
            local_queue = queue_on_main_;
        }
        if (!local_cb) return;
        auto invoke = [local_cb, json = std::move(json)]() mutable {
            local_cb(std::move(json));
        };
        if (local_queue) local_queue(invoke);
        else             invoke();
    };

    return d_ptr->start(2021, std::move(on_msg));
}

void Agent::install_device_cert(const std::string& dev_id, bool lan_only)
{
    // Studio calls this ~1 Hz from DeviceManagerRefresher::on_timer in
    // addition to once right after on_printer_connected_fn on the UI thread.
    // The actual cert snapshot does a blocking SSL_connect to port 8883 that
    // can hang for ~timeout_ms when the printer refuses the extra handshake
    // (seen in the field: TCP SYN/ACK fine, ClientHello goes nowhere). To
    // keep the UI responsive we offload that to a detached worker and
    // back off on failure.
    if (!lan_only) {
        // Cloud / hybrid mode: Bambu's own plugin fetches the device-
        // specific MQTT tunnel cert from MakerWorld here. We don't have
        // cloud auth plumbed in yet (phases 4-5), so log and bail cleanly.
        OBN_DEBUG("install_device_cert dev=%s lan_only=0, cloud cert fetch deferred to phase 4", dev_id.c_str());
        return;
    }

    // Fast-path checks (success-cache, in-flight, cooldown, matching LAN
    // session). All of them are cheap and must never block.
    std::string ip;
    std::string cfg_dir;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (certified_devs_.count(dev_id)) {
            return; // already snapshotted this session.
        }
        if (cert_snapshot_inflight_.count(dev_id)) {
            return; // a worker is on it.
        }
        auto it = cert_snapshot_cooldown_.find(dev_id);
        if (it != cert_snapshot_cooldown_.end() &&
            std::chrono::steady_clock::now() < it->second) {
            return; // recent failure, don't retry yet.
        }
        if (lan_session_ && lan_session_->dev_id() == dev_id)
            ip = lan_session_->dev_ip();
        cfg_dir = config_dir_;
    }

    if (ip.empty()) {
        OBN_DEBUG("install_device_cert dev=%s: no active LAN session, skipping", dev_id.c_str());
        return;
    }
    if (cfg_dir.empty()) {
        OBN_WARN("install_device_cert dev=%s: config_dir not set", dev_id.c_str());
        return;
    }

    const std::string out_path = cert_store::device_cert_path(cfg_dir, dev_id);
    {
        std::error_code ec;
        if (std::filesystem::is_regular_file(out_path, ec)) {
            std::lock_guard<std::mutex> lk(mu_);
            certified_devs_.insert(dev_id);
            if (!ip.empty()) {
                obn::lan_tls::registry_set_peer_cert(ip, out_path);
            }
            return;
        }
    }

    // Do not open a second TLS session to :8883 while LAN MQTT is up — the
    // printer drops one of them (seen as mqtt rc=7 / rc=5 on Orca reconnect).
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (lan_session_ && lan_session_->dev_id() == dev_id) {
            return;
        }
    }

    // Claim the inflight slot and launch the worker. cert_snapshot_inflight_
    // is cleared by the worker on exit, certified_devs_ only on success,
    // cooldown only on failure.
    {
        std::lock_guard<std::mutex> lk(mu_);
        cert_snapshot_inflight_.insert(dev_id);
    }

    std::thread([this, dev_id, ip, cfg_dir]() {
        std::string out_path = cert_store::device_cert_path(cfg_dir, dev_id);
        OBN_INFO("install_device_cert dev=%s ip=%s: snapshotting to %s",
                 dev_id.c_str(), ip.c_str(), out_path.c_str());
        bool ok = cert_store::capture_peer_cert_pem(
            ip, 8883, /*timeout_ms=*/3000, out_path, dev_id);
        std::lock_guard<std::mutex> lk(mu_);
        cert_snapshot_inflight_.erase(dev_id);
        if (ok) {
            certified_devs_.insert(dev_id);
            cert_snapshot_cooldown_.erase(dev_id);
            obn::lan_tls::registry_set_peer_cert(ip, out_path);
        } else {
            OBN_WARN("install_device_cert dev=%s: snapshot failed, cooldown 60s",
                     dev_id.c_str());
            cert_snapshot_cooldown_[dev_id] =
                std::chrono::steady_clock::now() + std::chrono::seconds(60);
        }
    }).detach();
}

#define OBN_SETTER(method, field, type)                 \
    void Agent::method(type fn)                         \
    {                                                   \
        std::lock_guard<std::mutex> lk(mu_);            \
        field = std::move(fn);                          \
    }

OBN_SETTER(set_on_ssdp_msg_fn,          on_ssdp_msg_,          BBL::OnMsgArrivedFn)
OBN_SETTER(set_on_user_login_fn,        on_user_login_,        BBL::OnUserLoginFn)
OBN_SETTER(set_on_printer_connected_fn, on_printer_connected_, BBL::OnPrinterConnectedFn)
OBN_SETTER(set_on_server_connected_fn,  on_server_connected_,  BBL::OnServerConnectedFn)
OBN_SETTER(set_on_http_error_fn,        on_http_error_,        BBL::OnHttpErrorFn)
OBN_SETTER(set_get_country_code_fn,     get_country_code_,     BBL::GetCountryCodeFn)
OBN_SETTER(set_on_subscribe_failure_fn, on_subscribe_failure_, BBL::GetSubscribeFailureFn)
OBN_SETTER(set_on_message_fn,           on_message_,           BBL::OnMessageFn)
OBN_SETTER(set_on_user_message_fn,      on_user_message_,      BBL::OnMessageFn)
OBN_SETTER(set_on_local_connect_fn,     on_local_connect_,     BBL::OnLocalConnectedFn)
OBN_SETTER(set_on_local_message_fn,     on_local_message_,     BBL::OnMessageFn)
OBN_SETTER(set_queue_on_main_fn,        queue_on_main_,        BBL::QueueOnMainFn)
OBN_SETTER(set_server_callback,         server_err_,           BBL::OnServerErrFn)

#undef OBN_SETTER

// --------------------------------------------------------------------------
// Cloud user session.
// --------------------------------------------------------------------------

std::string Agent::cloud_region() const
{
    std::string cc = country_code();
    return cc == "CN" ? "CN" : "GLOBAL";
}

void Agent::cache_ssdp_json_for_bind(const std::string& json)
{
    std::string perr;
    auto        root = obn::json::parse(json, &perr);
    if (!root) return;
    std::string ip = trim_ip_string(root->find("dev_ip").as_string());
    if (ip.empty()) return;
    const std::string dev_id = root->find("dev_id").as_string();
    if (!dev_id.empty()) {
        obn::lan_tls::registry_put_ip_serial(ip, dev_id);
    }
    std::lock_guard<std::mutex> lk(mu_);
    ssdp_json_by_ip_[ip] = json;
}

int Agent::lookup_bind_detect(const std::string& dev_ip,
                                BBL::detectResult& out,
                                int                wait_ms)
{
    const std::string want = trim_ip_string(dev_ip);
    if (want.empty()) return -1;

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(wait_ms);
    std::string json;
    for (;;) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            auto it = ssdp_json_by_ip_.find(want);
            if (it != ssdp_json_by_ip_.end()) json = it->second;
        }
        if (!json.empty()) break;
        if (std::chrono::steady_clock::now() >= deadline) {
            OBN_INFO("lookup_bind_detect: no SSDP for %s within %d ms",
                     want.c_str(),
                     wait_ms);
            return -3;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    std::string perr;
    auto root = obn::json::parse(json, &perr);
    if (!root) {
        OBN_WARN("lookup_bind_detect: bad JSON: %s", perr.c_str());
        return -1;
    }

    out.command      = "bind_detect";
    out.dev_id       = root->find("dev_id").as_string();
    out.dev_name     = root->find("dev_name").as_string();
    out.model_id     = root->find("dev_type").as_string();
    out.version      = root->find("ssdp_version").as_string();
    out.bind_state   = root->find("bind_state").as_string();
    out.connect_type = root->find("connect_type").as_string();
    out.result_msg   = "ok";

    if (out.dev_id.empty()) {
        OBN_WARN("lookup_bind_detect: empty dev_id in SSDP json");
        return -1;
    }
    return 0;
}

std::string Agent::lan_access_code_for(const std::string& dev_id) const
{
    std::lock_guard<std::mutex> lk(mu_);
    auto                        it = lan_access_code_by_dev_.find(dev_id);
    if (it != lan_access_code_by_dev_.end()) return it->second;
    if (lan_session_ && lan_session_->dev_id() == dev_id) return lan_session_->password();
    return {};
}

std::string Agent::device_display_name_for_ip(const std::string& dev_ip) const
{
    const std::string ip = trim_ip_string(dev_ip);
    std::lock_guard<std::mutex> lk(mu_);
    auto it = ssdp_json_by_ip_.find(ip);
    if (it == ssdp_json_by_ip_.end()) return {};
    std::string perr;
    auto        root = obn::json::parse(it->second, &perr);
    if (!root) return {};
    return root->find("dev_name").as_string();
}

std::map<std::string, std::string> Agent::cloud_api_http_headers() const
{
    std::map<std::string, std::string> h;
    obn::auth::Session                 s;
    {
        std::lock_guard<std::mutex> lk(mu_);
        s = auth_store_ ? auth_store_->snapshot() : obn::auth::Session{};
        for (const auto& kv : extra_http_headers_) h[kv.first] = kv.second;
    }
    if (!s.access_token.empty()) h["Authorization"] = "Bearer " + s.access_token;
    h["Accept"]        = "application/json";
    h["Content-Type"]  = "application/json";
    return h;
}

std::string Agent::cloud_user_id() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return auth_store_ ? auth_store_->snapshot().user_id : std::string{};
}

void Agent::preset_cache_reset()
{
    std::lock_guard<std::mutex> lk(mu_);
    preset_cache_.clear();
}

void Agent::preset_cache_put(std::string name,
                             std::map<std::string, std::string> values)
{
    std::lock_guard<std::mutex> lk(mu_);
    preset_cache_[std::move(name)] = std::move(values);
}

std::map<std::string, std::map<std::string, std::string>>
Agent::preset_cache_drain()
{
    std::map<std::string, std::map<std::string, std::string>> out;
    std::lock_guard<std::mutex> lk(mu_);
    out.swap(preset_cache_);
    return out;
}

bool Agent::user_logged_in() const
{
    return auth_store_ && auth_store_->snapshot().logged_in();
}

int Agent::apply_login_info(const std::string& login_info_json)
{
    if (!auth_store_) {
        OBN_WARN("apply_login_info: config_dir not set yet; dropping");
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }
    std::string perr;
    auto root = obn::json::parse(login_info_json, &perr);
    if (!root) {
        OBN_WARN("apply_login_info: bad JSON: %s", perr.c_str());
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }

    // change_user() gets called with two very different shapes and we have
    // to tolerate both:
    //
    //  A. Raw API response to /v1/user-service/user/ticket/<T> (from our
    //     own login_with_ticket, via the login WebView's window.postMessage
    //     path). camelCase fields right at the root:
    //       {"accessToken":"...","refreshToken":"...","expiresIn":N,
    //        "refreshExpiresIn":N,"tfaKey":"","accessMethod":"ticket",...}
    //
    //  B. Studio-built envelope out of HttpServer.cpp:538-546 (the
    //     third-party-login flow that lands on localhost:<port>). Nested,
    //     snake_case, and expires_in is stringified:
    //       {"data":{"token":"...","refresh_token":"...",
    //                "expires_in":"31536000","refresh_expires_in":"...",
    //                "user":{"uid":"...","name":"...",
    //                        "account":"...","avatar":"..."}}}
    //
    // We probe B first (data.token takes precedence) because if both are
    // present the envelope is the canonical one: it also carries the
    // already-fetched profile, which saves us a second /my/profile HTTP.

    auto read_int_or_str = [](const obn::json::Value& v) -> std::int64_t {
        if (v.is_number()) return v.as_int(0);
        const auto& s = v.as_string();
        if (s.empty()) return 0;
        try { return std::stoll(s); } catch (...) { return 0; }
    };

    std::string access_token  = root->find("data.token").as_string();
    std::string refresh_token = root->find("data.refresh_token").as_string();
    std::int64_t expires_in   = read_int_or_str(root->find("data.expires_in"));
    std::string account       = root->find("data.user.account").as_string();
    std::string user_id       = root->find("data.user.uid").as_string();
    std::string user_name     = root->find("data.user.name").as_string();
    std::string nick_name     = root->find("data.user.nickname").as_string();
    std::string avatar        = root->find("data.user.avatar").as_string();

    bool have_profile_inline = !user_id.empty() || !user_name.empty() ||
                               !avatar.empty() || !account.empty();

    if (access_token.empty()) {
        // Shape A: raw API response. Profile is *not* included here.
        access_token  = root->find("accessToken").as_string();
        refresh_token = root->find("refreshToken").as_string();
        expires_in    = read_int_or_str(root->find("expiresIn"));
        account       = root->find("account").as_string();
    }

    if (access_token.empty()) {
        OBN_WARN("apply_login_info: no access token in payload (json head: %.200s)",
                 login_info_json.c_str());
        return BAMBU_NETWORK_ERR_INVALID_RESULT;
    }

    obn::auth::Session s = auth_store_->snapshot();
    s.region        = cloud_region();
    s.access_token  = access_token;
    if (!refresh_token.empty()) s.refresh_token = refresh_token;
    if (!account.empty())       s.account       = account;
    s.expires_at    = std::chrono::system_clock::now() +
                      std::chrono::seconds(expires_in > 0 ? expires_in
                                                          : 3 * 30 * 24 * 3600);
    auth_store_->set(s);

    // Skip the /my/profile round-trip when Studio already put the profile
    // into the envelope; that's the common case and halves login latency.
    // Fall back to the network fetch otherwise (shape A).
    if (have_profile_inline) {
        auth_store_->update_profile(user_id, user_name, nick_name, avatar);
        OBN_INFO("change_user: hello %s (uid=%s, inline profile)",
                 user_name.empty() ? nick_name.c_str() : user_name.c_str(),
                 user_id.c_str());
    } else {
        auto prof = obn::cloud::get_profile(s.region, s.access_token);
        if (prof.ok) {
            auth_store_->update_profile(prof.user_id, prof.user_name,
                                        prof.nick_name, prof.avatar);
            OBN_INFO("change_user: hello %s (uid=%s)",
                     prof.user_name.empty() ? prof.nick_name.c_str() : prof.user_name.c_str(),
                     prof.user_id.c_str());
        } else {
            OBN_WARN("change_user: profile fetch failed: %s", prof.error_message.c_str());
        }
    }

    if (auto cb = [this]() { std::lock_guard<std::mutex> lk(mu_); return on_user_login_; }())
        cb(0, "ok");
    return BAMBU_NETWORK_SUCCESS;
}

void Agent::clear_session()
{
    if (auth_store_) auth_store_->clear();
    if (auto cb = [this]() { std::lock_guard<std::mutex> lk(mu_); return on_user_login_; }())
        cb(1, "logout");
}

// --------------------------------------------------------------------------
// Cloud MQTT plumbing.
// --------------------------------------------------------------------------

int Agent::connect_cloud()
{
    auth::Session s;
    BBL::OnServerConnectedFn on_server;
    BBL::OnMessageFn         on_msg;
    BBL::GetSubscribeFailureFn on_sub_fail;
    BBL::QueueOnMainFn       queue;
    BBL::OnPrinterConnectedFn on_printer_connected;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!cloud_session_) cloud_session_ = std::make_unique<CloudSession>();
        on_server            = on_server_connected_;
        on_msg               = on_message_;
        on_sub_fail          = on_subscribe_failure_;
        queue                = queue_on_main_;
        on_printer_connected = on_printer_connected_;
    }

    if (!auth_store_) {
        OBN_WARN("connect_cloud: no auth store (config_dir not set yet)");
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }
    s = auth_store_->snapshot();
    if (!s.logged_in()) {
        OBN_WARN("connect_cloud: not logged in, skipping");
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }

    // Cloud TLS trust anchor:
    //   - Linux/macOS: empty here -> mqtt_client falls back to the distro
    //     trust store (/etc/ssl/certs/...), which validates *.bambulab.com
    //     properly.
    //   - Windows: vcpkg's static OpenSSL ships no default trust store,
    //     and mosquitto_tls_set() rejects (cafile=null, capath=null) with
    //     MOSQ_ERR_INVAL. We hand it Studio's BBL bundle (the same file
    //     Studio passed via set_cert_file, e.g.
    //     resources/cert/slicer_base64.cer) just so the call validates;
    //     CloudSession then sets tls_skip_chain_verify=true so the
    //     handshake doesn't actually require *.bambulab.com to chain
    //     up to that BBL CA. Documented MVP limitation -- cloud auth
    //     still rides on top of TLS via u_<userid>+token, so MITM gets
    //     opaque traffic but no usable credentials.
    std::string cloud_ca;
#if defined(_WIN32)
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!cert_folder_.empty() && !cert_filename_.empty()) {
            cloud_ca = cert_folder_;
            if (cloud_ca.back() != '/' && cloud_ca.back() != '\\') {
                cloud_ca += '\\';
            }
            cloud_ca += cert_filename_;
        }
    }
#endif
    cloud_session_->configure(cloud_region(), s.user_id, s.access_token,
                              std::move(cloud_ca));

    // Trampoline callbacks onto Studio's UI thread where one is
    // registered. The message callback is intentionally NOT queued:
    // DeviceManager::on_push_message() is thread-aware and has its own
    // fast-path handling.
    auto on_connected_cb = [this, on_server, queue, on_printer_connected]
        (int status, int reason, std::string /*msg*/)
    {
        OBN_INFO("cloud: server_connected status=%d reason=%d", status, reason);
        if (on_server) {
            auto invoke = [on_server, status, reason]() {
                on_server(status, reason);
            };
            if (queue) queue(invoke); else invoke();
        }
        // On successful CONNACK, if we already know the user's device
        // list (passed via add_subscribe earlier), fire
        // on_printer_connected with a "tunnel/" prefix for each of
        // them so Studio marks them cloud-online and requests pushall.
        if (status == 0 && on_printer_connected) {
            std::vector<std::string> devs;
            {
                std::lock_guard<std::mutex> lk(mu_);
                if (cloud_session_) {
                    // CloudSession exposes is_connected() only; mirror
                    // its subscribed set via our own copy -> we don't
                    // duplicate the state here. Instead: we rely on
                    // Studio calling add_subscribe right after
                    // connect_server, which will then call this path
                    // via the sub-success logic below.
                }
            }
            (void)devs;
        }
    };

    auto on_msg_cb = [this, on_msg, on_printer_connected]
        (std::string dev_id, std::string json)
    {
        // Mirror Bambu's plugin: the FIRST cloud report we receive
        // for a device kicks off an on_printer_connected("tunnel/<id>")
        // notification so Studio moves the device from "subscribing"
        // to "online" in its UI.
        bool first = false;
        {
            std::lock_guard<std::mutex> lk(mu_);
            first = cloud_connected_devs_.insert(dev_id).second;
        }
        if (first && on_printer_connected) {
            BBL::OnPrinterConnectedFn cb = on_printer_connected;
            BBL::QueueOnMainFn        q;
            {
                std::lock_guard<std::mutex> lk(mu_);
                q = queue_on_main_;
            }
            auto invoke = [cb, dev_id]() { cb("tunnel/" + dev_id); };
            if (q) q(invoke); else invoke();
        }
        if (on_msg) on_msg(std::move(dev_id), std::move(json));
    };

    auto on_sub_fail_cb = [this, on_sub_fail](std::string dev_id) {
        if (on_sub_fail) {
            BBL::QueueOnMainFn q;
            {
                std::lock_guard<std::mutex> lk(mu_);
                q = queue_on_main_;
            }
            auto invoke = [on_sub_fail, dev_id]() { on_sub_fail(dev_id); };
            if (q) q(invoke); else invoke();
        }
    };

    return cloud_session_->start(on_connected_cb, on_msg_cb, on_sub_fail_cb);
}

int Agent::disconnect_cloud()
{
    std::unique_ptr<CloudSession> sess;
    {
        std::lock_guard<std::mutex> lk(mu_);
        sess = std::move(cloud_session_);
        cloud_connected_devs_.clear();
    }
    if (sess) sess->stop();
    return BAMBU_NETWORK_SUCCESS;
}

bool Agent::cloud_connected() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return cloud_session_ && cloud_session_->is_connected();
}

int Agent::cloud_refresh()
{
    // Studio's DeviceManagerRefresher calls refresh_connection() on a
    // 1-second wx timer as a keep-alive / "reconnect if dropped" probe
    // (see DevManager.cpp DeviceManagerRefresher::on_timer). Doing a
    // hard disconnect+connect here produces a tight loop where every
    // tick tears down a healthy session, which Studio reports back to
    // the user as "failed to connect".
    //
    // Policy:
    //   * if we already have a live MQTT session -> no-op
    //   * otherwise -> (re)connect with the current credentials
    if (cloud_connected()) {
        return BAMBU_NETWORK_SUCCESS;
    }
    disconnect_cloud();
    return connect_cloud();
}

int Agent::cloud_add_subscribe(const std::vector<std::string>& dev_ids)
{
    CloudSession* sess = nullptr;
    {
        std::lock_guard<std::mutex> lk(mu_);
        sess = cloud_session_.get();
    }
    if (!sess) {
        OBN_WARN("cloud_add_subscribe: no active cloud session");
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }
    return sess->add_subscribe(dev_ids);
}

int Agent::cloud_del_subscribe(const std::vector<std::string>& dev_ids)
{
    CloudSession* sess = nullptr;
    {
        std::lock_guard<std::mutex> lk(mu_);
        sess = cloud_session_.get();
        for (const auto& d : dev_ids) cloud_connected_devs_.erase(d);
    }
    if (!sess) return BAMBU_NETWORK_SUCCESS;
    return sess->del_subscribe(dev_ids);
}

int Agent::cloud_send_message(const std::string& dev_id,
                              const std::string& json_str,
                              int qos)
{
    CloudSession* sess = nullptr;
    {
        std::lock_guard<std::mutex> lk(mu_);
        sess = cloud_session_.get();
    }
    if (!sess) {
        OBN_WARN("cloud_send_message: no active cloud session for %s",
                 dev_id.c_str());
        return BAMBU_NETWORK_ERR_SEND_MSG_FAILED;
    }
    return sess->publish(dev_id, json_str, qos);
}

void Agent::hydrate_session()
{
    if (!auth_store_) return;
    auto s = auth_store_->snapshot();
    if (!s.logged_in()) return;
    if (!auth_store_->needs_refresh()) {
        OBN_INFO("cloud: session for %s still fresh", s.account.c_str());
        return;
    }
    if (s.refresh_token.empty()) {
        OBN_WARN("cloud: stored session expired and no refresh_token; ignore it");
        return;
    }
    auto r = obn::cloud::refresh_token(s.region, s.refresh_token);
    if (!r.ok) {
        OBN_WARN("cloud: refresh failed: %s", r.error_message.c_str());
        return;
    }
    auth_store_->update_tokens(r.access_token,
                               r.refresh_token.empty() ? s.refresh_token : r.refresh_token,
                               std::chrono::seconds(r.expires_in > 0 ? r.expires_in : 3 * 30 * 24 * 3600));
    OBN_INFO("cloud: access_token refreshed for %s", s.account.c_str());
}

} // namespace obn
