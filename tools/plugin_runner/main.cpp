// plugin_runner: Bambu Studio shim that loads any libbambu_networking.so
// (matching the ABI_VERSION this binary was compiled against), drives the
// minimal init sequence Studio uses, and then triggers one of the four
// LAN print entry points with a user-supplied BBL::PrintParams. Real
// MQTT publishes go straight to the printer; capture them in parallel
// with tools/bambu_mqtt_spy.sh.
//
// CLI shape and field semantics are documented in tools/plugin_runner/README.md.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

#include "obn/bambu_networking.hpp"

#include "plugin_downloader.hpp"
#include "plugin_loader.hpp"
#include "print_params_io.hpp"

namespace pr = obn::plugin_runner;
using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Logging — every event the plugin pushes to a callback is rendered as one
// JSON line on stdout (and optionally mirrored to --log-out). Keeps the
// post-run analysis trivially `jq`-able without obscuring the wire data.
// ---------------------------------------------------------------------------
namespace {

std::mutex g_log_mu;
std::ofstream g_log_file;

std::string iso8601_now()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    auto secs = system_clock::to_time_t(now);
    auto us = duration_cast<microseconds>(now.time_since_epoch()).count() % 1'000'000;
    std::tm tm{};
    gmtime_r(&secs, &tm);
    std::ostringstream os;
    os << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S")
       << '.' << std::setw(6) << std::setfill('0') << us << 'Z';
    return os.str();
}

void emit_event(const std::string& kind, json payload)
{
    payload["_t"] = iso8601_now();
    payload["_kind"] = kind;
    std::string line = payload.dump();
    std::lock_guard<std::mutex> lk(g_log_mu);
    std::cout << line << '\n';
    std::cout.flush();
    if (g_log_file) {
        g_log_file << line << '\n';
        g_log_file.flush();
    }
}

void emit_text(const std::string& kind, const std::string& msg)
{
    json j;
    j["msg"] = msg;
    emit_event(kind, std::move(j));
}

} // namespace

// ---------------------------------------------------------------------------
// CLI parsing — small hand-rolled parser to keep the binary dep-free.
// ---------------------------------------------------------------------------
namespace {

struct CliArgs {
    std::string plugin_path;
    std::string params_json;
    std::string action = "send_gcode_to_sdcard";
    std::string gcode_3mf;

    // For --action send_raw: path to a JSON file whose contents are
    // forwarded verbatim to send_message_to_printer (qos=1, flag=0,
    // matching what Studio uses for printer commands). Use this to
    // bypass the entire start_*_print flow and reverse the print
    // command shape one field at a time, watching the printer's reply
    // arrive over local_message.
    std::string raw_json;
    int         raw_qos      = 1;
    int         raw_flag     = 0;
    int         raw_settle_s = 5;
    // Repeat the publish N times with this gap. Useful to probe whether
    // the LAN MQTT session quietly drops between publishes (e.g. while
    // an FTPS upload runs in parallel and the publish channel goes idle).
    int         raw_repeat            = 1;
    int         raw_repeat_interval_s = 5;

    std::string dev_id;
    std::string dev_ip;
    std::string access_code;
    std::string country = "US";
    std::string log_out;
    std::string cert_file;     // path to slicer_base64.cer; auto-resolved if empty
    // Optional payload for change_user(). Empty string keeps the
    // existing "no logged-in user" behaviour. Pass a JSON blob (or
    // @path/to/file) to fake a cloud login session — useful when a
    // plugin gates privileged MQTT publishes (project_file, etc.) on
    // is_user_login() returning true.
    // Required for --action http_probe (Studio envelope or OBN
    // obn.auth.json — see load_user_info_blob()).
    std::string user_info;

    // --action http_probe / mw_probe: cloud probes. No printer.
    // Defaults match a recent MITM sample (my/task 1114566547).
    std::string task_id      = "1114566547";
    std::string project_id;   // empty OK; stock may still answer
    std::string profile_id   = "894049654";
    int         plate_index  = 1;
    int         msg_type     = 0;
    int         msg_after    = 0;
    int         msg_limit    = 20;
    // mw_probe: MakerWorld rating / For-You. instance_id from my/task.
    int         instance_id  = 390100;
    std::string design_id    = "478834";
    int         mw_seed      = 0;
    int         mw_limit     = 10;
    // put_model_mall_rating is skipped unless --mw-put-rating is set
    // (avoids writing junk ratings during MITM discovery).
    bool        mw_put_rating = false;
    int         rating_id     = 0;
    int         rating_score  = 5;

    // --action filament_probe: Filament Manager cloud calls. The slot
    // mapping defaults describe one AMS tray; --slot-mappings-json
    // overrides the whole array for batch / multi-item captures.
    std::string slot_dev_id;
    std::string slot_ams_sn;
    std::string slot_slot_id  = "0";
    int         slot_spool_id = 0;
    std::string slot_rfid;
    int         slot_ams_id   = 0;
    int         slot_ams_type = 0;
    std::string slot_mappings_json;
    // Skip the list/config reads and only exercise the sync calls.
    bool        fil_sync_only = false;
    // Also call sync_ams_filaments with the same tray identity, so the two
    // serializers can be diffed on the wire. Off by default: it writes
    // real mount state onto the cloud catalogue.
    bool        probe_ams_sync = false;

    // --action account_bind extras (Studio BindJob defaults).
    std::string dev_model = "N7";
    std::string timezone  = "UTC+02:00";
    bool        improved  = true;

    // gap_probe: call user_logout(true) at the end under MITM to capture
    // the logout body when refresh_token is present (revokes the session).
    bool        do_logout = false;

    // For wire-format reverse-engineering: after a print action
    // finishes (Finished or ERROR latched), publish
    //   {"print":{"command":"stop","param":"","sequence_id":"…"}}
    // verbatim via send_message_to_printer. Only works on a printer
    // that's in Developer Mode (otherwise the plugin's client-side
    // filter drops the print:* publish with rc=-4). The printer flips
    // gcode_state to FAILED within ~1s — the goal is to never let an
    // experiment leave physical heat-up running.
    bool        auto_stop = false;
    bool        use_ssl_mqtt = true;
    // lan_only argument for install_device_cert during LAN bring-up.
    // Studio passes is_lan_mode_printer(), so a cloud-paired printer needs
    // false: only that branch publishes app_cert_install and gets the
    // printer's public key back. With true on a cloud-paired printer the
    // plugin has nothing to sign with and every print:* publish fails -4030.
    bool        cert_lan_only = true;
    // X-BBL-Client-Name. Honest by default, but the cloud gates some
    // endpoints on the value: POST /my/task answers 403 for anything but
    // "BambuStudio", so faithful stock captures need --client-name.
    std::string client_name = "OpenBambooNetworking";
    int         timeout_s = 90;
    int         connect_settle_ms = 800;
    bool        keep_tmpdir = false;
    // If non-empty, use this as the plugin's config dir instead of
    // mkdtemp'ing a fresh one. The killer use case: re-using a real
    // BambuStudio config dir (typically ~/.config/BambuStudio) so the
    // device cert at <config_dir>/certs/<dev_id>.pem (provisioned by
    // the real Studio when it bound the printer) is already in place
    // — install_device_cert / project_file signing both depend on it,
    // and a fresh mkdtemp can't replicate it offline.
    std::string data_dir;

    // Stock plugins keep their MQTT / asio worker threads alive until
    // their static destructors run at process exit; calling
    // destroy_agent + disconnect_printer cleanly inside main can block
    // up to ~60s waiting for those workers to drain. With --fast-exit
    // we just flush logs and `_Exit` straight after the action
    // completes. Default: true for --action none (diagnostics, you
    // already saw what you cared about), false otherwise.
    std::optional<bool> fast_exit;

    // --download-only mode: skip the agent flow, just resolve a plugin
    // for the given ABI prefix into the cache and print its absolute
    // path on stdout. Used by the wrapper script before it picks the
    // matching build dir.
    bool        download_only = false;
    std::string abi_prefix;        // MM.mm.pp
    std::string cache_dir;         // override for ~/.cache/obn-plugin-runner
    bool        force_download = false;
};

[[noreturn]] void usage(int rc)
{
    std::fputs(
R"(usage: plugin_runner --plugin-path PATH --params-json FILE --action ACTION
                     [--gcode-3mf PATH] --dev-id ID --dev-ip IP --access-code CODE
                     [--country US] [--use-ssl-mqtt 0|1]
                     [--cert-file PATH] [--timeout SECONDS]
                     [--connect-settle-ms MS] [--cert-lan-only 0|1]
                     [--client-name NAME] [--log-out PATH] [--keep-tmpdir]

       plugin_runner --action send_raw --raw-json FILE
                     --plugin-path PATH --dev-id ID --dev-ip IP --access-code CODE
                     [--raw-qos 1] [--raw-flag 0] [--raw-settle 5]

       plugin_runner --download-only --abi MM.mm.pp [--cache-dir DIR] [--force]

       plugin_runner --action http_probe --plugin-path PATH
                     --user-info @session.json [--data-dir DIR]
                     [--task-id ID] [--project-id ID] [--profile-id ID]
                     [--plate-index N] [--msg-type N] [--msg-after N]
                     [--msg-limit N] [--country US]

       plugin_runner --action mw_probe --plugin-path PATH
                     --user-info @session.json [--data-dir DIR]
                     [--task-id ID] [--instance-id N] [--design-id ID]
                     [--mw-seed N] [--mw-limit N] [--mw-put-rating]
                     [--rating-id N] [--rating-score N] [--country US]

       plugin_runner --action filament_probe --plugin-path PATH
                     --user-info @session.json [--data-dir DIR]
                     [--slot-dev-id ID] [--slot-ams-sn SN] [--slot-id N]
                     [--slot-spool-id N] [--slot-rfid HEX]
                     [--slot-ams-id N] [--slot-ams-type N]
                     [--slot-mappings-json JSON|@path] [--fil-sync-only]
                     [--country US]

       plugin_runner --action update_cert --plugin-path PATH
                     [--user-info @session.json] [--data-dir DIR]
                     [--country US]

       plugin_runner --action query_bind --plugin-path PATH
                     --user-info @session.json --dev-id ID
                     [--data-dir DIR] [--country US]

       plugin_runner --action bind_detect --plugin-path PATH
                     --dev-ip IP [--dev-id ID] [--data-dir DIR]
                     [--country US] [--timeout SECONDS]

       plugin_runner --action account_bind --plugin-path PATH
                     --user-info @session.json
                     --dev-id ID --dev-ip IP --access-code CODE
                     [--dev-model MODEL] [--timezone TZ] [--improved 0|1]
                     [--data-dir DIR] [--country US]

       plugin_runner --action gap_probe --plugin-path PATH
                     --user-info @session.json [--dev-id ID]
                     [--do-logout] [--data-dir DIR] [--country US]

       plugin_runner --action cert_probe --plugin-path PATH
                     --dev-id ID --dev-ip IP --access-code CODE
                     [--user-info @session.json] [--data-dir DIR]
                     [--country US] [--timeout SECONDS]

ACTION is one of: send_gcode_to_sdcard | local_print | sdcard_print
                | local_print_with_record | cloud_print | send_raw | none
                | http_probe | mw_probe | filament_probe | update_cert
                | query_bind | bind_detect | account_bind | gap_probe
                | cert_probe

  cloud_print: bambu_network_start_print — the pure-cloud path. Uploads
  the 3mf to S3 and dispatches through POST /my/task with
  mode=cloud_file, so it needs --user-info; the printer then downloads
  from S3 on its own. Still requires --dev-id/--dev-ip/--access-code and
  --cert-file: the stock plugin gates the send stage on having the
  device certificate and answers -3140 ENC_FLAG_NOT_READY without a live
  LAN session. Honours --auto-stop.

  none: skip the print dispatch entirely. Useful for diagnostics: just
  init + connect_printer, then sit for --timeout seconds dumping every
  callback event, then tear down cleanly.

  send_raw: skip start_*_print and call send_message_to_printer directly
  with the contents of --raw-json. The killer primitive for reverse-
  engineering printer commands: hand-craft a payload, observe the reply
  arrive over local_message during --raw-settle seconds, iterate.
  --params-json is not required for this action.

  http_probe: no printer. change_user(--user-info) then call
  get_studio_info_url / get_my_message / check_user_task_report /
  get_task_plate_index / get_slice_info and emit JSON events. Run under
  HTTPS_PROXY + mitmproxy to capture stock cloud URLs. --user-info may
  be a Studio {"data":{"token":…}} envelope or OBN obn.auth.json.

  mw_probe: no printer. change_user then call get_subtask /
  get_model_mall_detail_url / get_model_mall_rating /
  get_mw_user_preference / get_mw_user_4ulist (put_model_mall_rating
  only with --mw-put-rating). Use under MITM to capture MakerWorld URLs.

  filament_probe: no printer. change_user then call get_filament_spools
  and sync_slot_mappings (ABI >= 02.08.02). Studio drives the latter from
  the Filament Manager AMS sync: a bind carries spoolId + rfid, an unbind
  zeroes both and keeps the pre-eject amsSn/slotId/amsId/amsType. Use
  --slot-mappings-json to send a batch or an empty array; --fil-sync-only
  skips the catalogue read. Run under MITM to capture the request body.

  update_cert: no printer. Mirrors Studio GUI_App::check_cert →
  bambu_network_update_cert. Under MITM this should be the shared app
  cert fetch (GET …/user/applications/{enc_secret}/cert?aes256=…&ver=1).
  --user-info optional (stock still attaches Bearer when logged in).

  query_bind: no printer. change_user then bambu_network_query_bind_status
  ([--dev-id]) and request_bind_ticket. Use under MITM for orphan
  query_bind_status URL capture. Do NOT attach strace/gdb — stock
  anti-debug aborts with a zenity dialog.

  bind_detect: LAN only. start_discovery + bambu_network_bind_detect,
  then exit (no MQTT connect). Pair with tcpdump on udp/2021 and host
  <printer> to see SSDP vs any TCP /info.

  account_bind: change_user + bind_detect + bambu_network_bind with
  OnUpdateStatusFn progress events. Captures device-ticket cloud steps
  under MITM; pair with an MQTT logger on device/<id>/request|report.

  gap_probe: no printer. change_user then probe build_login_* /
  build_login_info, change_user JSON shapes, query_bind_status,
  connect_server + start/stop_subscribe("app") + refresh_connection +
  enable_multi_machine. Optional --do-logout calls user_logout(true)
  (revokes tokens — re-login after). Use under HTTPS_PROXY + mitmproxy;
  pair with SSLKEYLOGFILE + tcpdump on *.mqtt.bambulab.com for MQTT wire.

  cert_probe: LAN MQTT without the automatic install_device_cert, then
  call install_device_cert(lan_only=true) and (lan_only=false). Watch
  local_message for security.* / app_cert_install. Pair with tcpdump on
  host <printer> port 8883 and optional SSLKEYLOGFILE.

Driven from tools/plugin_runner.sh; see tools/plugin_runner/README.md.
)", stderr);
    std::exit(rc);
}

std::string require(const std::vector<std::string>& a, size_t i, const std::string& flag)
{
    if (i >= a.size()) {
        std::fprintf(stderr, "plugin_runner: missing value for %s\n", flag.c_str());
        usage(64);
    }
    return a[i];
}

CliArgs parse_cli(int argc, char** argv)
{
    CliArgs c;
    std::vector<std::string> a(argv + 1, argv + argc);
    for (size_t i = 0; i < a.size(); ++i) {
        const std::string& f = a[i];
        if      (f == "--plugin-path")       c.plugin_path = require(a, ++i, f);
        else if (f == "--params-json")       c.params_json = require(a, ++i, f);
        else if (f == "--action")            c.action      = require(a, ++i, f);
        else if (f == "--gcode-3mf")         c.gcode_3mf   = require(a, ++i, f);
        else if (f == "--raw-json")          c.raw_json    = require(a, ++i, f);
        else if (f == "--raw-qos")           c.raw_qos     = std::stoi(require(a, ++i, f));
        else if (f == "--raw-flag")          c.raw_flag    = std::stoi(require(a, ++i, f));
        else if (f == "--raw-settle")        c.raw_settle_s = std::stoi(require(a, ++i, f));
        else if (f == "--raw-repeat")        c.raw_repeat = std::stoi(require(a, ++i, f));
        else if (f == "--raw-repeat-interval-s") c.raw_repeat_interval_s = std::stoi(require(a, ++i, f));
        else if (f == "--dev-id")            c.dev_id      = require(a, ++i, f);
        else if (f == "--dev-ip")            c.dev_ip      = require(a, ++i, f);
        else if (f == "--access-code")       c.access_code = require(a, ++i, f);
        else if (f == "--country")           c.country     = require(a, ++i, f);
        else if (f == "--cert-file")         c.cert_file   = require(a, ++i, f);
        else if (f == "--log-out")           c.log_out     = require(a, ++i, f);
        else if (f == "--use-ssl-mqtt")      c.use_ssl_mqtt = std::stoi(require(a, ++i, f)) != 0;
        else if (f == "--timeout")           c.timeout_s   = std::stoi(require(a, ++i, f));
        else if (f == "--connect-settle-ms") c.connect_settle_ms = std::stoi(require(a, ++i, f));
        else if (f == "--cert-lan-only")     c.cert_lan_only = std::stoi(require(a, ++i, f)) != 0;
        else if (f == "--client-name")       c.client_name = require(a, ++i, f);
        else if (f == "--keep-tmpdir")       c.keep_tmpdir = true;
        else if (f == "--data-dir")          c.data_dir = require(a, ++i, f);
        else if (f == "--user-info")         c.user_info = require(a, ++i, f);
        else if (f == "--task-id")           c.task_id = require(a, ++i, f);
        else if (f == "--project-id")        c.project_id = require(a, ++i, f);
        else if (f == "--profile-id")        c.profile_id = require(a, ++i, f);
        else if (f == "--plate-index")       c.plate_index = std::stoi(require(a, ++i, f));
        else if (f == "--msg-type")          c.msg_type = std::stoi(require(a, ++i, f));
        else if (f == "--msg-after")         c.msg_after = std::stoi(require(a, ++i, f));
        else if (f == "--msg-limit")         c.msg_limit = std::stoi(require(a, ++i, f));
        else if (f == "--instance-id")       c.instance_id = std::stoi(require(a, ++i, f));
        else if (f == "--design-id")         c.design_id = require(a, ++i, f);
        else if (f == "--mw-seed")           c.mw_seed = std::stoi(require(a, ++i, f));
        else if (f == "--mw-limit")          c.mw_limit = std::stoi(require(a, ++i, f));
        else if (f == "--mw-put-rating")     c.mw_put_rating = true;
        else if (f == "--rating-id")         c.rating_id = std::stoi(require(a, ++i, f));
        else if (f == "--rating-score")      c.rating_score = std::stoi(require(a, ++i, f));
        else if (f == "--slot-dev-id")       c.slot_dev_id = require(a, ++i, f);
        else if (f == "--slot-ams-sn")       c.slot_ams_sn = require(a, ++i, f);
        else if (f == "--slot-id")           c.slot_slot_id = require(a, ++i, f);
        else if (f == "--slot-spool-id")     c.slot_spool_id = std::stoi(require(a, ++i, f));
        else if (f == "--slot-rfid")         c.slot_rfid = require(a, ++i, f);
        else if (f == "--slot-ams-id")       c.slot_ams_id = std::stoi(require(a, ++i, f));
        else if (f == "--slot-ams-type")     c.slot_ams_type = std::stoi(require(a, ++i, f));
        else if (f == "--slot-mappings-json") c.slot_mappings_json = require(a, ++i, f);
        else if (f == "--fil-sync-only")     c.fil_sync_only = true;
        else if (f == "--probe-ams-sync")    c.probe_ams_sync = true;
        else if (f == "--auto-stop")         c.auto_stop = true;
        else if (f == "--dev-model")         c.dev_model = require(a, ++i, f);
        else if (f == "--timezone")          c.timezone  = require(a, ++i, f);
        else if (f == "--improved")          c.improved  = (require(a, ++i, f) != "0");
        else if (f == "--do-logout")         c.do_logout = true;
        else if (f == "--fast-exit")         c.fast_exit = true;
        else if (f == "--no-fast-exit")      c.fast_exit = false;
        else if (f == "--download-only")     c.download_only = true;
        else if (f == "--abi")               c.abi_prefix    = require(a, ++i, f);
        else if (f == "--cache-dir")         c.cache_dir     = require(a, ++i, f);
        else if (f == "--force")             c.force_download = true;
        else if (f == "-h" || f == "--help") usage(0);
        else {
            std::fprintf(stderr, "plugin_runner: unknown flag '%s'\n", f.c_str());
            usage(64);
        }
    }
    if (c.download_only) {
        if (c.abi_prefix.empty()) {
            std::fprintf(stderr, "plugin_runner: --download-only requires --abi MM.mm.pp\n");
            usage(64);
        }
        return c;
    }
    // params_json is only mandatory for actions that consume PrintParams.
    const bool cloud_probe =
        (c.action == "http_probe" || c.action == "mw_probe" ||
         c.action == "update_cert" || c.action == "query_bind" ||
         c.action == "gap_probe" || c.action == "filament_probe");
    const bool bind_detect_only = (c.action == "bind_detect");
    const bool account_bind     = (c.action == "account_bind");
    const bool cert_probe       = (c.action == "cert_probe");
    bool needs_params = (c.action != "send_raw" && c.action != "none" &&
                         !cloud_probe && !bind_detect_only && !account_bind &&
                         !cert_probe);
    if (c.plugin_path.empty()) {
        std::fprintf(stderr, "plugin_runner: --plugin-path is required\n");
        usage(64);
    }
    if (bind_detect_only) {
        if (c.dev_ip.empty()) {
            std::fprintf(stderr, "plugin_runner: --action bind_detect requires --dev-ip\n");
            usage(64);
        }
    } else if (account_bind) {
        if (c.dev_id.empty() || c.dev_ip.empty() || c.access_code.empty() ||
            c.user_info.empty()) {
            std::fprintf(stderr, "plugin_runner: --action account_bind requires "
                                 "--dev-id --dev-ip --access-code --user-info\n");
            usage(64);
        }
    } else if (cert_probe) {
        if (c.dev_id.empty() || c.dev_ip.empty() || c.access_code.empty()) {
            std::fprintf(stderr, "plugin_runner: --action cert_probe requires "
                                 "--dev-id --dev-ip --access-code\n");
            usage(64);
        }
    } else if (!cloud_probe) {
        if (c.dev_id.empty() || c.dev_ip.empty() || c.access_code.empty()) {
            std::fprintf(stderr, "plugin_runner: --dev-id, --dev-ip and "
                                 "--access-code are all required (except "
                                 "for cloud/bind_detect probes)\n");
            usage(64);
        }
    }
    if (needs_params && c.params_json.empty()) {
        std::fprintf(stderr, "plugin_runner: --params-json is required for action '%s'\n",
                     c.action.c_str());
        usage(64);
    }
    if (c.action == "send_raw" && c.raw_json.empty()) {
        std::fprintf(stderr, "plugin_runner: --action send_raw requires --raw-json PATH\n");
        usage(64);
    }
    if ((c.action == "http_probe" || c.action == "mw_probe" ||
         c.action == "query_bind" || c.action == "gap_probe" ||
         c.action == "filament_probe") &&
        c.user_info.empty()) {
        std::fprintf(stderr, "plugin_runner: --action %s requires "
                             "--user-info JSON|@path\n", c.action.c_str());
        usage(64);
    }
    if (c.action == "query_bind" && c.dev_id.empty()) {
        std::fprintf(stderr, "plugin_runner: --action query_bind requires --dev-id\n");
        usage(64);
    }
    return c;
}

std::string default_cache_dir()
{
    const char* xdg = std::getenv("XDG_CACHE_HOME");
    if (xdg && *xdg) return std::string(xdg) + "/obn-plugin-runner";
    const char* home = std::getenv("HOME");
    if (home && *home) return std::string(home) + "/.cache/obn-plugin-runner";
    return "/tmp/obn-plugin-runner";
}

} // namespace

// ---------------------------------------------------------------------------
// Studio-mock environment: ephemeral data_dir with a 3-line BambuStudio.conf
// and a best-effort cert handoff. The stock plugin reads BambuStudio.conf
// during init for country_code/region; the rest of Studio's user state is
// LAN-irrelevant and we deliberately don't fake it.
// ---------------------------------------------------------------------------
namespace {

struct Tmpdir {
    std::string path;
    bool        keep = false;

    ~Tmpdir() {
        if (!keep && !path.empty()) {
            std::string cmd = "rm -rf -- '" + path + "'";
            int rc = std::system(cmd.c_str());
            (void)rc;
        }
    }
};

Tmpdir make_tmpdir(bool keep)
{
    char tmpl[] = "/tmp/obn-plugin-runner-XXXXXX";
    if (!mkdtemp(tmpl)) {
        throw std::runtime_error(std::string("mkdtemp failed: ") + std::strerror(errno));
    }
    Tmpdir t;
    t.path = tmpl;
    t.keep = keep;
    return t;
}

void write_min_studio_conf(const std::string& dir, const std::string& country)
{
    std::ofstream o(dir + "/BambuStudio.conf");
    if (!o) {
        throw std::runtime_error("cannot open BambuStudio.conf for writing in " + dir);
    }
    // Minimal AppConfig the stock plugin reads at init. Mirrors the tiny
    // subset of Slic3r::AppConfig that bambu_network_set_config_dir +
    // change_user flow actually inspects. Anything missing falls back to
    // documented defaults inside the plugin.
    o << "{\n"
      << "  \"app\": {\n"
      << "    \"country_code\": \"" << country << "\",\n"
      << "    \"language\":     \"en_US\",\n"
      << "    \"region\":       \"" << country << "\"\n"
      << "  }\n"
      << "}\n";
}

struct CertResolution {
    std::string folder;
    std::string filename;
};

CertResolution resolve_cert(const std::string& cli_path)
{
    CertResolution r;
    auto split = [&](const std::string& full) {
        auto slash = full.rfind('/');
        if (slash == std::string::npos) {
            r.folder = ".";
            r.filename = full;
        } else {
            r.folder   = full.substr(0, slash);
            r.filename = full.substr(slash + 1);
        }
    };
    if (!cli_path.empty()) {
        split(cli_path);
        return r;
    }
    // slicer_base64.cer is the trust anchor the stock plugin uses to verify
    // the printer's self-signed TLS certificate during MQTT handshake. With
    // an empty path the LAN MQTT connect deterministically fails with
    // status=ConnectStatusFailed, msg="-1" — surfacing as a generic OpenSSL
    // verify error inside the (encrypted) plugin log. Search a handful of
    // well-known locations so the runner just works on a typical dev
    // machine; users with non-standard layouts can still pass --cert-file.
    const char* home = std::getenv("HOME");
    std::vector<std::string> candidates;
    if (home) {
        candidates.emplace_back(std::string(home) + "/.config/BambuStudio/cert/slicer_base64.cer");
        candidates.emplace_back(std::string(home) + "/BambuStudio/resources/cert/slicer_base64.cer");
        candidates.emplace_back(std::string(home) + "/Bambu_Studio/resources/cert/slicer_base64.cer");
    }
    candidates.emplace_back("/usr/share/BambuStudio/resources/cert/slicer_base64.cer");
    candidates.emplace_back("/opt/BambuStudio/resources/cert/slicer_base64.cer");
    for (const auto& candidate : candidates) {
        struct stat st{};
        if (stat(candidate.c_str(), &st) == 0) {
            split(candidate);
            return r;
        }
    }
    return r;
}

} // namespace

// ---------------------------------------------------------------------------
// Completion latch — the print actions are async; update_fn flips the latch
// when the plugin reports PrintingStageFinished (success) or
// PrintingStageERROR (failure). main waits on this with a deadline.
// ---------------------------------------------------------------------------
namespace {

struct Latch {
    std::mutex                m;
    std::condition_variable   cv;
    bool                      done = false;
    int                       last_status = -1;
    int                       last_code = 0;
    std::string               last_msg;

    void mark(int status, int code, std::string msg) {
        {
            std::lock_guard<std::mutex> lk(m);
            last_status = status;
            last_code = code;
            last_msg = std::move(msg);
            done = true;
        }
        cv.notify_all();
    }

    bool wait_for(std::chrono::seconds dur) {
        std::unique_lock<std::mutex> lk(m);
        return cv.wait_for(lk, dur, [&]{ return done; });
    }
};

// Tiny one-shot latch used to wait for the LAN MQTT session to come up
// (set_on_local_connect_fn, status=ConnectStatusOk). connect_printer is
// async — the plugin returns rc=0 immediately and the actual TLS
// handshake takes ~5–6s. Publishing a message before this callback
// fires deterministically returns -4 / -4030 inside the plugin (paho
// reports MQTTASYNC_DISCONNECTED). Studio essentially polls
// MachineObject::is_connecting() in its event loop; we just block.
struct ReadyLatch {
    std::mutex              m;
    std::condition_variable cv;
    bool                    ready = false;

    void reset() {
        std::lock_guard<std::mutex> lk(m);
        ready = false;
    }
    void signal() {
        { std::lock_guard<std::mutex> lk(m); ready = true; }
        cv.notify_all();
    }
    bool wait_for(std::chrono::milliseconds dur) {
        std::unique_lock<std::mutex> lk(m);
        return cv.wait_for(lk, dur, [&]{ return ready; });
    }
};

const char* stage_name(int s)
{
    using namespace BBL;
    switch (s) {
        case PrintingStageCreate:      return "Create";
        case PrintingStageUpload:      return "Upload";
        case PrintingStageWaiting:     return "Waiting";
        case PrintingStageSending:     return "Sending";
        case PrintingStageRecord:      return "Record";
        case PrintingStageWaitPrinter: return "WaitPrinter";
        case PrintingStageFinished:    return "Finished";
        case PrintingStageERROR:       return "ERROR";
        default:                       return "?";
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Init order is the verbatim copy of GUI_App.cpp:3596-3618:
//   create_agent -> set_config_dir -> init_log -> set_cert_file
//   -> install all callbacks -> set_country_code -> start()
// Studio additionally calls change_user("") right after to mark the
// session as logged out — some plugins refuse LAN print until this has
// happened at least once.
// ---------------------------------------------------------------------------

int main(int argc, char** argv)
try {
    CliArgs args = parse_cli(argc, argv);

    if (args.download_only) {
        std::string cache = args.cache_dir.empty() ? default_cache_dir() : args.cache_dir;
        auto r = pr::fetch_plugin(args.abi_prefix, cache, args.force_download);
        if (!r.ok) {
            std::fprintf(stderr, "plugin_runner: download failed: %s\n",
                         r.error_message.c_str());
            return 69; // EX_UNAVAILABLE
        }
        // stdout: machine-readable single-line JSON for the wrapper to parse.
        json out;
        out["ok"]      = true;
        out["so_path"] = r.so_path;
        out["version"] = r.version;
        out["http"]    = r.http_status;
        std::cout << out.dump() << '\n';
        return 0;
    }

    if (!args.log_out.empty()) {
        g_log_file.open(args.log_out, std::ios::trunc);
        if (!g_log_file) {
            std::fprintf(stderr, "plugin_runner: cannot open --log-out '%s'\n",
                         args.log_out.c_str());
            return 73;
        }
    }

    emit_event("startup", {
        {"plugin_path", args.plugin_path},
        {"abi_version", static_cast<unsigned>(ABI_VERSION)},
        {"action",      args.action},
        {"dev_id",      args.dev_id},
        {"dev_ip",      args.dev_ip},
    });

    // Step 1: dlopen + symbol resolution
    pr::PluginExports exports = pr::load(args.plugin_path);
    emit_event("plugin_loaded", {
        {"version", exports.version},
        {"so",      exports.so_path},
    });

    // Step 2: Studio data_dir. Either reuse a real one (--data-dir, e.g.
    // ~/.config/BambuStudio so the device cert provisioned by Studio is
    // available) or mkdtemp a fresh ephemeral one. We never overwrite
    // BambuStudio.conf in a user-supplied dir.
    Tmpdir tmpdir;
    if (!args.data_dir.empty()) {
        tmpdir.path = args.data_dir;
        tmpdir.keep = true; // never wipe a user-supplied dir
        struct stat st{};
        if (stat(tmpdir.path.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
            emit_text("fatal", "--data-dir does not exist or is not a "
                               "directory: " + tmpdir.path);
            return 66;
        }
    } else {
        tmpdir = make_tmpdir(args.keep_tmpdir);
        write_min_studio_conf(tmpdir.path, args.country);
    }
    emit_event("data_dir", {
        {"path",  tmpdir.path},
        {"reuse", !args.data_dir.empty()},
    });
    CertResolution cert = resolve_cert(args.cert_file);
    if (cert.filename.empty()) {
        emit_text("warning",
            "no slicer_base64.cer resolved — LAN MQTT handshake will fail "
            "(local_connect status=1, msg=-1). Pass --cert-file PATH or copy "
            "BambuStudio/resources/cert/slicer_base64.cer into "
            "~/.config/BambuStudio/cert/.");
    } else {
        emit_event("cert_resolved", {
            {"folder", cert.folder}, {"filename", cert.filename},
        });
    }

    // Step 3: create the agent. log_dir == data_dir is what Studio passes in.
    void* agent = exports.create_agent(tmpdir.path);
    if (!agent) {
        emit_text("fatal", "create_agent returned null");
        return 70;
    }
    // RAII for the agent: any subsequent throw still tears down the
    // plugin's worker threads. Without this the dlopen'd library's
    // global destructors hit joinable std::thread members and abort
    // with "terminate called without an active exception".
    struct AgentGuard {
        pr::PluginExports* ex;
        void* a;
        ~AgentGuard() {
            if (ex && a) {
                if (ex->disconnect_printer) ex->disconnect_printer(a);
                if (ex->destroy_agent)      ex->destroy_agent(a);
            }
        }
    };
    AgentGuard guard{&exports, agent};

    // Step 4: install callbacks (each one just dumps a JSON event).
    Latch latch;
    ReadyLatch session_ready;
    std::atomic<bool> printer_connected{false};

    exports.set_on_local_message_fn(agent,
        [](std::string dev_id, std::string msg) {
            emit_event("local_message", { {"dev_id", dev_id}, {"msg", msg} });
        });
    exports.set_on_message_fn(agent,
        [](std::string dev_id, std::string msg) {
            emit_event("message", { {"dev_id", dev_id}, {"msg", msg} });
        });
    exports.set_on_user_message_fn(agent,
        [](std::string dev_id, std::string msg) {
            emit_event("user_message", { {"dev_id", dev_id}, {"msg", msg} });
        });
    exports.set_on_local_connect_fn(agent,
        [&printer_connected, &session_ready](int status, std::string dev_id, std::string msg) {
            emit_event("local_connect", {
                {"status", status}, {"dev_id", dev_id}, {"msg", msg},
            });
            using namespace BBL;
            if (status == ConnectStatusOk) {
                printer_connected.store(true);
                session_ready.signal();
            }
        });
    exports.set_on_printer_connected_fn(agent,
        [&printer_connected, &session_ready](std::string topic) {
            emit_event("printer_connected", { {"topic", topic} });
            printer_connected.store(true);
            session_ready.signal();
        });
    ReadyLatch server_ready;
    exports.set_on_server_connected_fn(agent,
        [&server_ready](int rc, int reason) {
            emit_event("server_connected", { {"rc", rc}, {"reason", reason} });
            // Stock fires this on both success and auth failure; treat any
            // callback as "connect attempt resolved" for gap_probe waits.
            server_ready.signal();
        });
    exports.set_on_http_error_fn(agent,
        [](unsigned int status, std::string body) {
            emit_event("http_error", { {"status", status}, {"body", body} });
        });
    exports.set_on_subscribe_failure_fn(agent,
        [](std::string topic) {
            emit_event("subscribe_failure", { {"topic", topic} });
        });
    {
        // get_country_code is polled by the plugin to refresh region
        // routing; we just echo back the CLI value.
        std::string country = args.country;
        exports.set_get_country_code_fn(agent, [country]() { return country; });
    }
    if (exports.set_queue_on_main_fn) {
        // Inline-execute every "post to main thread" the plugin requests.
        // No UI loop here — running on whichever worker thread queued
        // the call is safe for our LAN-print scope.
        exports.set_queue_on_main_fn(agent, [](std::function<void()> fn) {
            if (fn) fn();
        });
    }
    exports.set_server_callback(agent,
        [](std::string url, int status) {
            emit_event("server_callback", { {"url", url}, {"status", status} });
        });
    exports.set_on_ssdp_msg_fn(agent,
        [](std::string info_json) {
            emit_event("ssdp_msg", { {"info", info_json} });
        });

    // Step 5: replicate Studio's init order (GUI_App.cpp:3596-3618).
    // Order matters — set_extra_http_header lands BEFORE start() so the
    // X-BBL-* headers are already in the plugin's HTTP client by the time
    // it does its first connect / cert exchange against the printer.
    exports.set_config_dir(agent, tmpdir.path);
    exports.init_log(agent);
    exports.set_cert_file(agent, cert.folder, cert.filename);
    {
        // Studio's init_http_extra_header() — these headers propagate to
        // every outgoing HTTP request including the LAN /info ping.
        // X-BBL-Client-Version uses Studio's full SLIC3R_VERSION; we
        // pretend to be a current build so the API doesn't reject the
        // request as legacy.
        std::map<std::string, std::string> hdrs;
        hdrs["X-BBL-Client-Type"]    = "slicer";
        hdrs["X-BBL-Client-Name"]    = args.client_name;
        hdrs["X-BBL-Client-Version"] = "02.05.03.99";
        hdrs["X-BBL-OS-Type"]        = "linux";
        hdrs["X-BBL-OS-Version"]     = "1.0.0";
        hdrs["X-BBL-Language"]       = "en";
        exports.set_extra_http_header(agent, hdrs);
        emit_event("extra_http_header", { {"count", hdrs.size()} });
    }
    exports.set_country_code(agent, args.country);
    int rc_start = exports.start(agent);
    emit_event("agent_start", { {"rc", rc_start} });

    // Step 5.5: post-start init Studio always runs (GUI_App.cpp:3586-3594
    // for multi_machine, then start_discovery elsewhere). Both are
    // best-effort — failures here are not fatal but missing wires can
    // leave the plugin in a half-initialised state.
    exports.enable_multi_machine(agent, false);
    bool disc_ok = exports.start_discovery(agent, true, false);
    emit_event("post_start_init", {
        {"multi_machine", false}, {"start_discovery", disc_ok},
    });

    // Step 6: prime the plugin's user session. Empty string mirrors
    // Studio's first-frame "no logged-in user" state. A non-empty
    // --user-info value is forwarded as a Studio change_user envelope
    // (or converted from OBN obn.auth.json — see below).
    auto load_user_info_blob = [](const std::string& raw) -> std::string {
        std::string text = raw;
        if (!text.empty() && text.front() == '@') {
            std::ifstream uf(text.substr(1));
            if (!uf) {
                throw std::runtime_error("cannot open --user-info file: " +
                                         text.substr(1));
            }
            std::stringstream uss; uss << uf.rdbuf();
            text = uss.str();
        }
        if (text.empty()) return text;
        // OBN on-disk session → Studio HttpServer envelope so stock
        // plugins accept change_user the same way Studio's localhost
        // login callback does.
        try {
            auto j = json::parse(text);
            if (j.contains("access_token") && !j.contains("data")) {
                json env;
                env["data"]["token"] = j.value("access_token", "");
                env["data"]["refresh_token"] = j.value("refresh_token", "");
                env["data"]["expires_in"] = "31536000";
                env["data"]["refresh_expires_in"] = "31536000";
                json user;
                user["uid"] = j.value("user_id", "");
                user["name"] = j.value("user_name", "");
                user["account"] = j.value("account", "");
                user["avatar"] = j.value("avatar", "");
                user["nickname"] = j.value("nick_name", "");
                env["data"]["user"] = user;
                return env.dump();
            }
        } catch (...) {
            // Fall through — stock may accept the raw blob as-is.
        }
        return text;
    };

    std::string user_blob;
    try {
        user_blob = load_user_info_blob(args.user_info);
    } catch (const std::exception& e) {
        emit_text("fatal", e.what());
        return 66;
    }
    int rc_user = exports.change_user(agent, user_blob);
    bool logged = exports.is_user_login ? exports.is_user_login(agent) : false;
    emit_event("change_user", {
        {"rc",          rc_user},
        {"bytes",       user_blob.size()},
        {"is_logged_in", logged},
    });

    const bool http_probe  = (args.action == "http_probe");
    const bool mw_probe    = (args.action == "mw_probe");
    const bool update_cert_probe = (args.action == "update_cert");
    const bool query_bind_probe  = (args.action == "query_bind");
    const bool gap_probe_action  = (args.action == "gap_probe");
    const bool cert_probe_action = (args.action == "cert_probe");
    const bool bind_detect_only  = (args.action == "bind_detect");
    const bool account_bind_probe = (args.action == "account_bind");
    const bool filament_probe     = (args.action == "filament_probe");
    const bool cloud_probe =
        http_probe || mw_probe || update_cert_probe || query_bind_probe ||
        gap_probe_action || filament_probe;
    // account_bind / bind_detect call bind_detect themselves then exit
    // (or call bind()); they must not open a competing LAN MQTT session.
    const bool skip_lan_mqtt = cloud_probe || bind_detect_only || account_bind_probe;

    // Step 6.5–7.5: LAN bring-up. Skipped for cloud probes and for the
    // dedicated bind probes (those own their own detect/bind calls).
    if (!skip_lan_mqtt) {
    // bind_detect — stock probes TCP dev_ip:3000 with framed
    // {"login":{"command":"detect",…}} (not HTTP /info). Studio also
    // runs this before connect_printer (sLocalBindFunc). The plugin
    // needs detectResult cached so its MQTT layer knows whether it's
    // talking to a LAN/cloud/farm device. Skipping it makes the
    // subsequent local_connect callback fire with status=1, msg="-1"
    // even though connect_printer itself returns 0.
    {
        BBL::detectResult detect{};
        int rc_detect = exports.bind_detect(agent, args.dev_ip, "secure", detect);
        emit_event("bind_detect", {
            {"rc",           rc_detect},
            {"dev_id",       detect.dev_id},
            {"dev_name",     detect.dev_name},
            {"model_id",     detect.model_id},
            {"version",      detect.version},
            {"bind_state",   detect.bind_state},
            {"connect_type", detect.connect_type},
            {"command",      detect.command},
            {"result_msg",   detect.result_msg},
        });
    }

    // Step 7: connect the printer over LAN MQTT. connect_printer is
    // async — it returns rc=0 immediately and the actual TLS handshake +
    // subscribe completes a few seconds later. We must wait for
    // local_connect(ConnectStatusOk) before doing anything else.
    int rc_conn = exports.connect_printer(agent, args.dev_id, args.dev_ip,
                                          /*username=*/"bblp",
                                          /*password=*/args.access_code,
                                          /*use_ssl=*/args.use_ssl_mqtt);
    emit_event("connect_printer_call", { {"rc", rc_conn} });

    {
        auto cap = std::chrono::milliseconds(std::max(args.connect_settle_ms, 1000));
        bool got = session_ready.wait_for(cap);
        emit_event("session_ready", { {"got", got}, {"cap_ms", cap.count()} });
        if (!got) {
            emit_text("warning",
                "local_connect ConnectStatusOk did not fire within "
                "--connect-settle-ms; LAN MQTT publish will likely fail. "
                "Increase --connect-settle-ms or check cert / network.");
        }
    }

    // Step 7.5: replicate Studio's post-connect bring-up. Studio calls
    // start_subscribe("app") (cloud telemetry, harmless on LAN) and then
    // polls command_request_push_all() in keep_alive() until the printer
    // emits its first push_status (m_push_count > 0). The pushall is the
    // *only* publish Studio guarantees in the first second — without it
    // the printer never spontaneously sends a fresh full state, so we
    // can't tell the session is healthy. Doing it ourselves here also
    // serves as a smoke test of send_message_to_printer (any non-zero rc
    // means the LAN publish channel is broken — fail fast).
    {
        int rc_sub = exports.start_subscribe(agent, "app");
        emit_event("start_subscribe", { {"module", "app"}, {"rc", rc_sub} });
    }
    {
        // Verbatim copy of Studio's MachineObject::command_request_push_all
        // payload. sequence_id is a string in the original; we use a
        // fixed value because uniqueness only matters for response
        // matching, which we don't do.
        const std::string pushall =
            "{\"pushing\":{\"sequence_id\":\"0\",\"command\":\"pushall\","
            "\"version\":1,\"push_target\":1}}";
        int rc_push = exports.send_message_to_printer(
            agent, args.dev_id, pushall, /*qos=*/1, /*flag=*/0);
        emit_event("kickstart_pushall", {
            {"rc",    rc_push},
            {"bytes", pushall.size()},
        });
        if (rc_push != 0) {
            emit_text("warning",
                "kickstart pushall publish failed — LAN MQTT publish "
                "channel is not actually ready, downstream actions will "
                "likely also fail.");
        }

        // Mirrors MachineObject::command_get_version (publish_json
        // {"info":{"sequence_id":"…","command":"get_version"}}, qos=1).
        // The plugin doesn't gate anything on the response but Studio
        // always sends it, so we replicate to keep the printer's
        // observed sequence identical.
        const std::string get_version =
            "{\"info\":{\"sequence_id\":\"1\",\"command\":\"get_version\"}}";
        int rc_ver = exports.send_message_to_printer(
            agent, args.dev_id, get_version, /*qos=*/1, /*flag=*/0);
        emit_event("kickstart_get_version", {
            {"rc", rc_ver}, {"bytes", get_version.size()},
        });

        // Mirrors MachineObject::command_get_access_code
        // (publish_json {"system":{"sequence_id":"…","command":"get_access_code"}}).
        const std::string get_ac =
            "{\"system\":{\"sequence_id\":\"2\",\"command\":\"get_access_code\"}}";
        int rc_ac = exports.send_message_to_printer(
            agent, args.dev_id, get_ac, /*qos=*/1, /*flag=*/0);
        emit_event("kickstart_get_access_code", {
            {"rc", rc_ac}, {"bytes", get_ac.size()},
        });

        // The keystone of Studio's post-connect bring-up: provision the
        // per-printer device cert the plugin uses to RSA-sign privileged
        // MQTT commands (project_file, etc.). Skipping this is the
        // proximate cause of `start_local_print` returning -4030 ("send
        // msg failed") on the Sending stage — every `print:*` payload
        // the plugin tries to publish gets pre-flight-rejected with -4
        // because there's no cert available to sign it with. Studio passes
        // is_lan_mode_printer() here, mirrored by --cert-lan-only: only the
        // lan_only=0 branch publishes app_cert_install and receives the
        // printer_cert reply, so a cloud-paired printer needs 0.
        // cert_probe owns install_device_cert itself so the LAN bring-up
        // path must not auto-provision (would muddy lan_only true/false).
        if (!cert_probe_action) {
            if (exports.install_device_cert) {
                // Cloud-paired printers need both calls in this order:
                // lan_only=1 alone never publishes app_cert_install, and
                // lan_only=0 alone publishes nothing either. Only the pair
                // (as cert_probe issues them) puts app_cert_install on the
                // wire and brings printer_cert back, which is what the
                // plugin signs privileged publishes with.
                if (!args.cert_lan_only) {
                    exports.install_device_cert(agent, args.dev_id, /*lan_only=*/true);
                    emit_event("install_device_cert", {
                        {"dev_id", args.dev_id}, {"lan_only", true}, {"phase", "1"},
                    });
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                }
                exports.install_device_cert(agent, args.dev_id, args.cert_lan_only);
                emit_event("install_device_cert", {
                    {"dev_id", args.dev_id}, {"lan_only", args.cert_lan_only},
                });
            } else {
                emit_text("warning",
                    "plugin does not export bambu_network_install_device_cert; "
                    "privileged MQTT publishes (start_local_print, etc.) will "
                    "likely fail with -4030.");
            }
        } else {
            emit_event("install_device_cert_skipped", {
                {"reason", "cert_probe owns explicit lan_only true/false calls"},
            });
        }

        // Settle so:
        //   1) the printer's pushall reply lands in local_message
        //   2) install_device_cert finishes any async work (HTTP fetch
        //      from cloud, on-disk cert import, etc.) before we publish
        //      a privileged command. Empirically the cert provisioning
        //      path inside stock plugins can take ~3-5s on first call.
        std::this_thread::sleep_for(std::chrono::milliseconds(
            cert_probe_action ? 1500 : (args.cert_lan_only ? 3500 : 8000)));
    }
    } // !skip_lan_mqtt

    // Step 8: load PrintParams from JSON, then back-fill the LAN-required
    // fields from the CLI so the user doesn't have to encode the printer
    // identity in every experiment.json. Skipped for actions that don't
    // consume a PrintParams (send_raw, none, http_probe, mw_probe).
    BBL::PrintParams params{};
    if (!args.params_json.empty()) {
        std::vector<std::string> warns;
        pr::load_print_params_from_json(args.params_json, params, warns);
        for (auto& w : warns) emit_text("params_warning", w);
    }
    if (params.dev_id.empty())   params.dev_id   = args.dev_id;
    if (params.dev_ip.empty())   params.dev_ip   = args.dev_ip;
    if (params.username.empty()) params.username = "bblp";
    if (params.password.empty()) params.password = args.access_code;
    params.use_ssl_for_mqtt = args.use_ssl_mqtt;
    if (!args.gcode_3mf.empty()) {
        if (params.filename.empty()) params.filename = args.gcode_3mf;
        // ftp_file is the destination basename on the printer's storage;
        // default to the source basename if the user didn't override.
        if (params.ftp_file.empty()) {
            auto slash = args.gcode_3mf.rfind('/');
            params.ftp_file = (slash == std::string::npos)
                ? args.gcode_3mf : args.gcode_3mf.substr(slash + 1);
        }
    }

    auto on_update = [&latch](int status, int code, std::string msg) {
        emit_event("update_status", {
            {"status", status}, {"stage", stage_name(status)},
            {"code", code}, {"msg", msg},
        });
        using namespace BBL;
        if (status == PrintingStageFinished || status == PrintingStageERROR)
            latch.mark(status, code, std::move(msg));
    };
    auto on_cancel = []() { return false; };
    auto on_wait   = [](int status, std::string job_info) {
        emit_event("wait_status", { {"status", status}, {"info", job_info} });
        return true;
    };

    // Step 9: dispatch the requested action.
    int rc_action = -1;
    if (args.action == "query_bind") {
        auto trunc = [](const std::string& s, size_t n = 600) {
            if (s.size() <= n) return s;
            return s.substr(0, n) + "...";
        };
        emit_event("query_bind_begin", {
            {"dev_id", args.dev_id},
            {"have_query_bind_status", exports.query_bind_status != nullptr},
            {"have_request_bind_ticket", exports.request_bind_ticket != nullptr},
        });
        if (!exports.query_bind_status) {
            emit_event("query_bind_status", { {"missing", true} });
            return 70;
        }
        std::vector<std::string> qlist{args.dev_id};
        unsigned http_code = 0;
        std::string http_body;
        int rc = exports.query_bind_status(agent, qlist, &http_code, &http_body);
        emit_event("query_bind_status", {
            {"rc", rc},
            {"http_code", http_code},
            {"body_bytes", http_body.size()},
            {"body", trunc(http_body)},
        });
        // Brief settle so async HTTPS (if any) lands under MITM.
        std::this_thread::sleep_for(std::chrono::seconds(3));
        emit_event("query_bind_done", json::object());
        bool fast = args.fast_exit.value_or(true);
        if (fast) {
            emit_event("shutdown", { {"finished", true}, {"fast_exit", true} });
            std::cout.flush();
            if (g_log_file) g_log_file.flush();
            std::_Exit(rc == 0 ? 0 : 1);
        }
        rc_action = rc;
    } else if (args.action == "bind_detect") {
        // Give SSDP a moment after start_discovery before the detect wait.
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        auto t0 = std::chrono::steady_clock::now();
        BBL::detectResult detect{};
        int rc = exports.bind_detect(agent, args.dev_ip, "secure", detect);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
        emit_event("bind_detect", {
            {"rc",           rc},
            {"elapsed_ms",   ms},
            {"dev_id",       detect.dev_id},
            {"dev_name",     detect.dev_name},
            {"model_id",     detect.model_id},
            {"version",      detect.version},
            {"bind_state",   detect.bind_state},
            {"connect_type", detect.connect_type},
            {"command",      detect.command},
            {"result_msg",   detect.result_msg},
        });
        std::this_thread::sleep_for(std::chrono::seconds(1));
        bool fast = args.fast_exit.value_or(true);
        if (fast) {
            emit_event("shutdown", { {"finished", true}, {"fast_exit", true} });
            std::cout.flush();
            if (g_log_file) g_log_file.flush();
            std::_Exit(rc == 0 ? 0 : 1);
        }
        rc_action = rc;
    } else if (args.action == "account_bind") {
        if (!exports.bind) {
            emit_event("account_bind", { {"missing", true} });
            emit_text("fatal", "plugin missing bambu_network_bind");
            return 70;
        }
        // Warm detect so stock has MachineObject-like identity cached.
        {
            BBL::detectResult detect{};
            int rc_detect =
                exports.bind_detect(agent, args.dev_ip, "secure", detect);
            emit_event("bind_detect", {
                {"rc",           rc_detect},
                {"dev_id",       detect.dev_id},
                {"dev_name",     detect.dev_name},
                {"model_id",     detect.model_id},
                {"version",      detect.version},
                {"bind_state",   detect.bind_state},
                {"connect_type", detect.connect_type},
            });
        }
        emit_event("account_bind_begin", {
            {"dev_id", args.dev_id},
            {"dev_ip", args.dev_ip},
            {"dev_model", args.dev_model},
            {"timezone", args.timezone},
            {"improved", args.improved},
        });
        auto on_bind_status = [](int stage, int code, std::string info) {
            emit_event("bind_status", {
                {"stage", stage}, {"code", code}, {"info", info},
            });
        };
        int rc = exports.bind(agent,
                              args.dev_ip,
                              args.dev_id,
                              args.dev_model,
                              /*sec_link=*/"secure",
                              args.timezone,
                              args.improved,
                              on_bind_status);
        emit_event("account_bind", { {"rc", rc} });
        std::this_thread::sleep_for(std::chrono::seconds(3));
        bool fast = args.fast_exit.value_or(true);
        if (fast) {
            emit_event("shutdown", { {"finished", true}, {"fast_exit", true} });
            std::cout.flush();
            if (g_log_file) g_log_file.flush();
            std::_Exit(rc == 0 ? 0 : 1);
        }
        rc_action = rc;
    } else if (args.action == "gap_probe") {
        auto trunc = [](const std::string& s, size_t n = 800) {
            if (s.size() <= n) return s;
            return s.substr(0, n) + "...";
        };
        auto emit_login_strings = [&](const char* phase) {
            json o{{"phase", phase}};
            if (exports.build_login_cmd) {
                auto s = exports.build_login_cmd(agent);
                o["build_login_cmd"] = trunc(s);
                o["build_login_cmd_bytes"] = s.size();
            } else {
                o["build_login_cmd_missing"] = true;
            }
            if (exports.build_logout_cmd) {
                auto s = exports.build_logout_cmd(agent);
                o["build_logout_cmd"] = trunc(s);
                o["build_logout_cmd_bytes"] = s.size();
            } else {
                o["build_logout_cmd_missing"] = true;
            }
            if (exports.build_login_info) {
                auto s = exports.build_login_info(agent);
                o["build_login_info"] = trunc(s);
                o["build_login_info_bytes"] = s.size();
            } else {
                o["build_login_info_missing"] = true;
            }
            if (exports.get_user_id) {
                o["get_user_id"] = exports.get_user_id(agent);
            }
            if (exports.is_user_login) {
                o["is_user_login"] = exports.is_user_login(agent);
            }
            emit_event("login_strings", o);
        };

        emit_event("gap_probe_begin", {
            {"dev_id", args.dev_id},
            {"do_logout", args.do_logout},
            {"have_connect_server", exports.connect_server != nullptr},
            {"have_refresh", exports.refresh_connection != nullptr},
            {"have_stop_subscribe", exports.stop_subscribe != nullptr},
            {"have_user_logout", exports.user_logout != nullptr},
        });
        emit_login_strings("after_change_user");

        // Catalogue of change_user JSON shapes stock accepts. Restore
        // the Studio login_info envelope at the end of this block.
        {
            json studio_env = json::parse(user_blob);
            json data = studio_env.value("data", json::object());
            struct Shape {
                const char* name;
                std::string blob;
            };
            std::vector<Shape> shapes;
            shapes.push_back({"empty_object", "{}"});
            shapes.push_back({"empty_string", ""});
            shapes.push_back({"token_only",
                json{{"data", {{"token", data.value("token", "")}}}}.dump()});
            shapes.push_back({"studio_login_info", user_blob});
            // WebView path: change_user(j.dump()) where j has command.
            json wv = studio_env;
            wv["command"] = "user_login";
            shapes.push_back({"webview_user_login_wrapper", wv.dump()});
            // Flat token at top level (OBN-ish / mistaken).
            shapes.push_back({"flat_access_token",
                json{{"access_token", data.value("token", "")},
                     {"refresh_token", data.value("refresh_token", "")},
                     {"user_id", data.value("user", json::object()).value("uid", "")}}
                    .dump()});

            for (const auto& sh : shapes) {
                // Clear first so a no-op / parse-reject cannot leave the
                // previous session looking like "accepted".
                if (exports.user_logout) {
                    exports.user_logout(agent, /*request=*/false);
                }
                bool before =
                    exports.is_user_login ? exports.is_user_login(agent) : false;
                int rc = exports.change_user(agent, sh.blob);
                bool logged =
                    exports.is_user_login ? exports.is_user_login(agent) : false;
                emit_event("change_user_shape", {
                    {"name", sh.name},
                    {"rc", rc},
                    {"cleared_before", !before},
                    {"is_logged_in", logged},
                    {"bytes", sh.blob.size()},
                });
            }
            // Restore canonical Studio envelope for cloud MQTT / logout.
            int rc_restore = exports.change_user(agent, user_blob);
            emit_event("change_user_restore", {
                {"rc", rc_restore},
                {"is_logged_in",
                 exports.is_user_login ? exports.is_user_login(agent) : false},
            });
            emit_login_strings("after_restore");
        }

        if (!args.dev_id.empty() && exports.query_bind_status) {
            std::vector<std::string> qlist{args.dev_id};
            unsigned http_code = 0;
            std::string http_body;
            int rc = exports.query_bind_status(agent, qlist, &http_code, &http_body);
            emit_event("query_bind_status", {
                {"rc", rc},
                {"http_code", http_code},
                {"body_bytes", http_body.size()},
                {"body", trunc(http_body)},
            });
        }

        // Cloud MQTT lifecycle: connect → refresh → subscribe toggles.
        if (exports.enable_multi_machine) {
            exports.enable_multi_machine(agent, true);
            emit_event("enable_multi_machine", {{"enable", true}});
        }
        if (exports.connect_server) {
            server_ready.reset();
            int rc = exports.connect_server(agent);
            emit_event("connect_server", {{"rc", rc}});
            bool got = server_ready.wait_for(std::chrono::seconds(15));
            emit_event("server_ready", {
                {"got", got},
                {"is_server_connected",
                 exports.is_server_connected
                     ? exports.is_server_connected(agent)
                     : false},
            });
        }
        if (exports.refresh_connection) {
            for (int i = 0; i < 3; ++i) {
                int rc = exports.refresh_connection(agent);
                emit_event("refresh_connection", {{"iter", i}, {"rc", rc}});
                std::this_thread::sleep_for(std::chrono::milliseconds(400));
            }
        }
        if (exports.start_subscribe) {
            int rc = exports.start_subscribe(agent, "app");
            emit_event("start_subscribe", {{"module", "app"}, {"rc", rc}});
            std::this_thread::sleep_for(std::chrono::seconds(3));
        }
        if (exports.stop_subscribe) {
            int rc = exports.stop_subscribe(agent, "app");
            emit_event("stop_subscribe", {{"module", "app"}, {"rc", rc}});
            std::this_thread::sleep_for(std::chrono::seconds(3));
        }
        if (exports.start_subscribe) {
            int rc = exports.start_subscribe(agent, "app");
            emit_event("start_subscribe", {
                {"module", "app"}, {"rc", rc}, {"phase", "reenable"},
            });
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        if (exports.enable_multi_machine) {
            exports.enable_multi_machine(agent, false);
            emit_event("enable_multi_machine", {{"enable", false}});
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        // Extra settle so MITM / SSLKEYLOG see late HTTPS or MQTT.
        std::this_thread::sleep_for(std::chrono::seconds(3));

        if (args.do_logout && exports.user_logout) {
            // Non-empty refresh_token is already in the session from
            // change_user — this is the capture that closes §8.5.14 TODO.
            int rc = exports.user_logout(agent, /*request=*/true);
            emit_event("user_logout", {
                {"rc", rc},
                {"request", true},
                {"is_logged_in",
                 exports.is_user_login ? exports.is_user_login(agent) : false},
            });
            emit_login_strings("after_logout_request_true");
            std::this_thread::sleep_for(std::chrono::seconds(3));
        }

        emit_event("gap_probe_done", json::object());
        bool fast = args.fast_exit.value_or(true);
        if (fast) {
            emit_event("shutdown", { {"finished", true}, {"fast_exit", true} });
            std::cout.flush();
            if (g_log_file) g_log_file.flush();
            std::_Exit(0);
        }
        rc_action = 0;
    } else if (args.action == "cert_probe") {
        if (!exports.install_device_cert) {
            emit_event("cert_probe", { {"missing", true} });
            emit_text("fatal", "plugin missing bambu_network_install_device_cert");
            return 70;
        }
        emit_event("cert_probe_begin", {
            {"dev_id", args.dev_id},
            {"logged_in",
             exports.is_user_login ? exports.is_user_login(agent) : false},
        });
        // lan_only=true first (Studio LAN-mode path).
        exports.install_device_cert(agent, args.dev_id, /*lan_only=*/true);
        emit_event("install_device_cert", {
            {"dev_id", args.dev_id}, {"lan_only", true}, {"phase", "1"},
        });
        std::this_thread::sleep_for(std::chrono::seconds(6));
        // lan_only=false — cloud-paired path (may HTTP + MQTT publish).
        exports.install_device_cert(agent, args.dev_id, /*lan_only=*/false);
        emit_event("install_device_cert", {
            {"dev_id", args.dev_id}, {"lan_only", false}, {"phase", "2"},
        });
        std::this_thread::sleep_for(std::chrono::seconds(8));
        emit_event("cert_probe_done", json::object());
        bool fast = args.fast_exit.value_or(true);
        if (fast) {
            emit_event("shutdown", { {"finished", true}, {"fast_exit", true} });
            std::cout.flush();
            if (g_log_file) g_log_file.flush();
            std::_Exit(0);
        }
        rc_action = 0;
    } else if (args.action == "update_cert") {
        if (!exports.update_cert) {
            emit_event("update_cert", { {"missing", true} });
            emit_text("fatal", "plugin missing bambu_network_update_cert");
            return 70;
        }
        emit_event("update_cert_begin", json::object());
        int rc = exports.update_cert(agent);
        // Stock performs the HTTPS cert fetch asynchronously; settle so
        // mitmproxy sees the GET …/applications/…/cert before exit.
        std::this_thread::sleep_for(std::chrono::seconds(3));
        emit_event("update_cert", { {"rc", rc} });
        bool fast = args.fast_exit.value_or(true);
        if (fast) {
            emit_event("shutdown", { {"finished", true}, {"fast_exit", true} });
            std::_Exit(rc == 0 ? 0 : 1);
        }
        rc_action = rc;
    } else if (args.action == "http_probe") {
        auto trunc = [](const std::string& s, size_t n = 400) {
            if (s.size() <= n) return s;
            return s.substr(0, n) + "...";
        };
        emit_event("http_probe_begin", {
            {"task_id", args.task_id},
            {"project_id", args.project_id},
            {"profile_id", args.profile_id},
            {"plate_index", args.plate_index},
            {"msg_type", args.msg_type},
            {"msg_after", args.msg_after},
            {"msg_limit", args.msg_limit},
            {"have_studio_info_url", exports.get_studio_info_url != nullptr},
            {"have_my_message", exports.get_my_message != nullptr},
            {"have_task_report", exports.check_user_task_report != nullptr},
            {"have_plate_index", exports.get_task_plate_index != nullptr},
            {"have_slice_info", exports.get_slice_info != nullptr},
        });

        if (exports.get_studio_info_url) {
            std::string url = exports.get_studio_info_url(agent);
            emit_event("get_studio_info_url", { {"url", url} });
        } else {
            emit_event("get_studio_info_url", { {"missing", true} });
        }

        if (exports.get_my_message) {
            unsigned http_code = 0;
            std::string http_body;
            int rc = exports.get_my_message(agent, args.msg_type, args.msg_after,
                                           args.msg_limit, &http_code, &http_body);
            emit_event("get_my_message", {
                {"rc", rc}, {"http_code", http_code},
                {"body_bytes", http_body.size()},
                {"body", trunc(http_body)},
            });
        } else {
            emit_event("get_my_message", { {"missing", true} });
        }

        if (exports.check_user_task_report) {
            int task_id = -1;
            bool printable = false;
            int rc = exports.check_user_task_report(agent, &task_id, &printable);
            emit_event("check_user_task_report", {
                {"rc", rc}, {"task_id", task_id}, {"printable", printable},
            });
        } else {
            emit_event("check_user_task_report", { {"missing", true} });
        }

        if (exports.get_task_plate_index) {
            int plate = -999;
            int rc = exports.get_task_plate_index(agent, args.task_id, &plate);
            emit_event("get_task_plate_index", {
                {"rc", rc}, {"task_id", args.task_id}, {"plate_index", plate},
            });
        } else {
            emit_event("get_task_plate_index", { {"missing", true} });
        }

        if (exports.get_slice_info) {
            std::string slice_json;
            int rc = exports.get_slice_info(agent, args.project_id, args.profile_id,
                                            args.plate_index, &slice_json);
            emit_event("get_slice_info", {
                {"rc", rc},
                {"project_id", args.project_id},
                {"profile_id", args.profile_id},
                {"plate_index", args.plate_index},
                {"body_bytes", slice_json.size()},
                {"body", trunc(slice_json)},
            });
        } else {
            emit_event("get_slice_info", { {"missing", true} });
        }

        // Brief settle so any async HTTP callbacks finish under MITM.
        std::this_thread::sleep_for(std::chrono::seconds(2));
        emit_event("http_probe_done", json::object());
        bool fast = args.fast_exit.value_or(true);
        if (fast) {
            emit_event("shutdown", { {"finished", true}, {"fast_exit", true} });
            std::cout.flush();
            if (g_log_file) g_log_file.flush();
            std::_Exit(0);
        }
        guard.a = nullptr;
        if (exports.disconnect_printer) exports.disconnect_printer(agent);
        exports.destroy_agent(agent);
        pr::unload(exports);
        emit_event("shutdown", { {"finished", true}, {"fast_exit", false} });
        return 0;
    } else if (args.action == "mw_probe") {
        auto trunc = [](const std::string& s, size_t n = 600) {
            if (s.size() <= n) return s;
            return s.substr(0, n) + "...";
        };
        emit_event("mw_probe_begin", {
            {"task_id", args.task_id},
            {"instance_id", args.instance_id},
            {"design_id", args.design_id},
            {"mw_seed", args.mw_seed},
            {"mw_limit", args.mw_limit},
            {"have_get_subtask", exports.get_subtask != nullptr},
            {"have_detail_url", exports.get_model_mall_detail_url != nullptr},
            {"have_get_rating", exports.get_model_mall_rating != nullptr},
            {"have_put_rating", exports.put_model_mall_rating != nullptr},
            {"have_preference", exports.get_mw_user_preference != nullptr},
            {"have_4ulist", exports.get_mw_user_4ulist != nullptr},
        });

        if (exports.get_subtask) {
            pr::ProbeBBLModelTask task;
            task.task_id = args.task_id;
            bool cb_fired = false;
            int rc = exports.get_subtask(
                agent, &task,
                [&](pr::ProbeBBLModelTask* t) {
                    cb_fired = true;
                    if (!t) return;
                    emit_event("get_subtask_cb", {
                        {"job_id", t->job_id},
                        {"design_id", t->design_id},
                        {"profile_id", t->profile_id},
                        {"instance_id", t->instance_id},
                        {"task_id", t->task_id},
                        {"model_id", t->model_id},
                        {"model_name", t->model_name},
                        {"profile_name", t->profile_name},
                    });
                });
            // Async callbacks may fire after return; settle briefly.
            std::this_thread::sleep_for(std::chrono::seconds(3));
            emit_event("get_subtask", {
                {"rc", rc}, {"cb_fired", cb_fired},
                {"job_id", task.job_id},
                {"design_id", task.design_id},
                {"instance_id", task.instance_id},
                {"model_id", task.model_id},
                {"model_name", task.model_name},
                {"profile_name", task.profile_name},
            });
            if (task.instance_id > 0)
                args.instance_id = task.instance_id;
            if (task.design_id > 0)
                args.design_id = std::to_string(task.design_id);
        } else {
            emit_event("get_subtask", { {"missing", true} });
        }

        if (exports.get_model_mall_detail_url) {
            std::string url;
            int rc = exports.get_model_mall_detail_url(agent, &url, args.design_id);
            emit_event("get_model_mall_detail_url", {
                {"rc", rc}, {"design_id", args.design_id}, {"url", url},
            });
        } else {
            emit_event("get_model_mall_detail_url", { {"missing", true} });
        }

        if (exports.get_model_mall_rating) {
            std::string rating_result;
            unsigned http_code = 0;
            std::string http_error;
            int rc = exports.get_model_mall_rating(
                agent, args.instance_id, rating_result, http_code, http_error);
            emit_event("get_model_mall_rating", {
                {"rc", rc},
                {"instance_id", args.instance_id},
                {"http_code", http_code},
                {"http_error", http_error},
                {"body_bytes", rating_result.size()},
                {"body", trunc(rating_result)},
            });
            // Prefer rating id from body for optional put.
            try {
                auto j = json::parse(rating_result);
                if (j.contains("id") && j["id"].is_number() && args.rating_id == 0)
                    args.rating_id = j["id"].get<int>();
            } catch (...) {}
        } else {
            emit_event("get_model_mall_rating", { {"missing", true} });
        }

        if (exports.get_mw_user_preference) {
            std::string body;
            int rc = exports.get_mw_user_preference(
                agent, [&](std::string b) { body = std::move(b); });
            std::this_thread::sleep_for(std::chrono::seconds(2));
            emit_event("get_mw_user_preference", {
                {"rc", rc}, {"body_bytes", body.size()}, {"body", trunc(body)},
            });
        } else {
            emit_event("get_mw_user_preference", { {"missing", true} });
        }

        if (exports.get_mw_user_4ulist) {
            std::string body;
            int rc = exports.get_mw_user_4ulist(
                agent, args.mw_seed, args.mw_limit,
                [&](std::string b) { body = std::move(b); });
            std::this_thread::sleep_for(std::chrono::seconds(2));
            emit_event("get_mw_user_4ulist", {
                {"rc", rc}, {"seed", args.mw_seed}, {"limit", args.mw_limit},
                {"body_bytes", body.size()}, {"body", trunc(body)},
            });
        } else {
            emit_event("get_mw_user_4ulist", { {"missing", true} });
        }

        if (args.mw_put_rating && exports.put_model_mall_rating) {
            unsigned http_code = 0;
            std::string http_error;
            std::vector<std::string> images;
            int rc = exports.put_model_mall_rating(
                agent, args.rating_id, args.rating_score,
                "obn mw_probe", images, http_code, http_error);
            emit_event("put_model_mall_rating", {
                {"rc", rc}, {"rating_id", args.rating_id},
                {"score", args.rating_score},
                {"http_code", http_code}, {"http_error", http_error},
            });
        } else {
            emit_event("put_model_mall_rating", {
                {"skipped", !args.mw_put_rating},
                {"missing", exports.put_model_mall_rating == nullptr},
            });
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));
        emit_event("mw_probe_done", json::object());
        bool fast = args.fast_exit.value_or(true);
        if (fast) {
            emit_event("shutdown", { {"finished", true}, {"fast_exit", true} });
            std::cout.flush();
            if (g_log_file) g_log_file.flush();
            std::_Exit(0);
        }
        guard.a = nullptr;
        if (exports.disconnect_printer) exports.disconnect_printer(agent);
        exports.destroy_agent(agent);
        pr::unload(exports);
        emit_event("shutdown", { {"finished", true}, {"fast_exit", false} });
        return 0;
    } else if (args.action == "filament_probe") {
        auto trunc = [](const std::string& s, size_t n = 2000) {
            if (s.size() <= n) return s;
            return s.substr(0, n) + "...";
        };
        emit_event("filament_probe_begin", {
            {"have_get_spools", exports.get_filament_spools != nullptr},
            {"have_get_config", exports.get_filament_config != nullptr},
#if ABI_VERSION >= 0x020801
            {"have_sync_ams", exports.sync_ams_filaments != nullptr},
#else
            {"have_sync_ams", false},
#endif
#if ABI_VERSION >= 0x020802
            {"have_sync_slot_mappings", exports.sync_slot_mappings != nullptr},
#else
            {"have_sync_slot_mappings", false},
#endif
        });

        if (!args.fil_sync_only && exports.get_filament_spools) {
            BBL::FilamentQueryParams q{};
            q.offset = 0;
            q.limit  = 20;
            std::string body;
            int rc = exports.get_filament_spools(agent, q, &body);
            emit_event("get_filament_spools", {
                {"rc", rc}, {"body_bytes", body.size()}, {"body", trunc(body)},
            });
        } else if (!args.fil_sync_only) {
            emit_event("get_filament_spools", { {"missing", true} });
        }

#if ABI_VERSION >= 0x020801
        // Path A/B counterpart: same devId, same tray identity, so the two
        // serializers can be diffed on the wire (notably how each renders
        // empty strings and zero ints).
        if (args.probe_ams_sync && exports.sync_ams_filaments) {
            BBL::AmsSyncParams p{};
            p.devId = args.slot_dev_id.empty() ? args.dev_id : args.slot_dev_id;
            BBL::AmsSyncItem it{};
            it.RFID    = args.slot_rfid;
            it.amsSn   = args.slot_ams_sn;
            it.slotId  = args.slot_slot_id;
            it.amsId   = args.slot_ams_id;
            it.amsType = args.slot_ams_type;
            p.items.push_back(std::move(it));

            std::string body;
            int rc = exports.sync_ams_filaments(agent, p, &body);
            emit_event("sync_ams_filaments", {
                {"rc", rc}, {"body_bytes", body.size()}, {"body", trunc(body)},
            });
        }
#endif

#if ABI_VERSION >= 0x020802
        if (exports.sync_slot_mappings) {
            BBL::SlotMappingsSyncParams p{};
            p.devId = args.slot_dev_id.empty() ? args.dev_id : args.slot_dev_id;

            // --slot-mappings-json wins; it is the only way to send a batch
            // or an intentionally empty array (the negative capture).
            bool parsed_json = false;
            if (!args.slot_mappings_json.empty()) {
                try {
                    std::string raw = args.slot_mappings_json;
                    if (!raw.empty() && raw.front() == '@') {
                        std::ifstream mf(raw.substr(1));
                        if (!mf) {
                            throw std::runtime_error(
                                "cannot open --slot-mappings-json file: " +
                                raw.substr(1));
                        }
                        std::stringstream mss; mss << mf.rdbuf();
                        raw = mss.str();
                    }
                    auto j = json::parse(raw);
                    if (j.is_object() && j.contains("devId"))
                        p.devId = j.value("devId", p.devId);
                    const json& arr = j.is_array() ? j
                                    : (j.contains("mappings") ? j["mappings"] : json::array());
                    for (const auto& e : arr) {
                        BBL::SlotMappingItem it{};
                        it.amsSn   = e.value("amsSn", "");
                        it.slotId  = e.value("slotId", "");
                        it.spoolId = e.value("spoolId", 0);
                        it.rfid    = e.value("rfid", "");
                        it.amsId   = e.value("amsId", 0);
                        it.amsType = e.value("amsType", 0);
                        p.mappings.push_back(std::move(it));
                    }
                    parsed_json = true;
                } catch (const std::exception& e) {
                    emit_text("fatal", std::string("--slot-mappings-json parse failed: ")
                                       + e.what());
                    return 64;
                }
            }
            if (!parsed_json) {
                BBL::SlotMappingItem it{};
                it.amsSn   = args.slot_ams_sn;
                it.slotId  = args.slot_slot_id;
                it.spoolId = args.slot_spool_id;
                it.rfid    = args.slot_rfid;
                it.amsId   = args.slot_ams_id;
                it.amsType = args.slot_ams_type;
                p.mappings.push_back(std::move(it));
            }

            json sent = json::array();
            for (const auto& it : p.mappings) {
                sent.push_back({
                    {"amsSn", it.amsSn}, {"slotId", it.slotId},
                    {"spoolId", it.spoolId}, {"rfid", it.rfid},
                    {"amsId", it.amsId}, {"amsType", it.amsType},
                });
            }
            emit_event("sync_slot_mappings_request", {
                {"devId", p.devId}, {"mappings", sent},
            });

            std::string body;
            int rc = exports.sync_slot_mappings(agent, p, &body);
            emit_event("sync_slot_mappings", {
                {"rc", rc}, {"body_bytes", body.size()}, {"body", trunc(body)},
            });
        } else {
            emit_event("sync_slot_mappings", { {"missing", true} });
        }
#else
        emit_event("sync_slot_mappings", { {"unsupported_abi", true} });
#endif

        std::this_thread::sleep_for(std::chrono::seconds(2));
        emit_event("filament_probe_done", json::object());
        bool fast = args.fast_exit.value_or(true);
        if (fast) {
            emit_event("shutdown", { {"finished", true}, {"fast_exit", true} });
            std::cout.flush();
            if (g_log_file) g_log_file.flush();
            std::_Exit(0);
        }
        guard.a = nullptr;
        if (exports.disconnect_printer) exports.disconnect_printer(agent);
        exports.destroy_agent(agent);
        pr::unload(exports);
        emit_event("shutdown", { {"finished", true}, {"fast_exit", false} });
        return 0;
    } else if (args.action == "none") {
        emit_text("info", "action=none — sleeping for --timeout seconds and "
                          "logging callbacks; no print dispatch");
        std::this_thread::sleep_for(std::chrono::seconds(args.timeout_s));
        emit_event("idle_done", { {"seconds", args.timeout_s} });
        bool fast = args.fast_exit.value_or(true);
        if (fast) {
            emit_event("shutdown", { {"finished", true}, {"fast_exit", true} });
            std::cout.flush();
            if (g_log_file) g_log_file.flush();
            std::_Exit(0);
        }
        guard.a = nullptr;
        exports.disconnect_printer(agent);
        exports.destroy_agent(agent);
        pr::unload(exports);
        emit_event("shutdown", { {"finished", true}, {"fast_exit", false} });
        return 0;
    } else if (args.action == "send_raw") {
        // Read the JSON file verbatim and hand it to the plugin's
        // direct-publish primitive. We deliberately don't validate or
        // re-serialize: byte-for-byte control is the whole point of
        // this mode.
        std::ifstream rf(args.raw_json, std::ios::binary);
        if (!rf) {
            emit_text("fatal", "cannot open --raw-json file: " + args.raw_json);
            return 66;
        }
        std::stringstream rss;
        rss << rf.rdbuf();
        std::string payload = rss.str();
        emit_event("send_raw_call", {
            {"path",        args.raw_json},
            {"bytes",       payload.size()},
            {"qos",         args.raw_qos},
            {"flag",        args.raw_flag},
            {"settle_s",    args.raw_settle_s},
            {"repeat",      args.raw_repeat},
            {"interval_s",  args.raw_repeat_interval_s},
        });
        for (int i = 0; i < std::max(args.raw_repeat, 1); ++i) {
            int rc = exports.send_message_to_printer(
                agent, args.dev_id, payload, args.raw_qos, args.raw_flag);
            emit_event("send_raw_rc", { {"iter", i}, {"rc", rc} });
            rc_action = rc;
            if (i + 1 < args.raw_repeat) {
                std::this_thread::sleep_for(
                    std::chrono::seconds(args.raw_repeat_interval_s));
            }
        }
        // send_message_to_printer is fire-and-forget; loiter for a few
        // seconds so the printer's reply (push_status / err) lands in
        // local_message before we tear down.
        std::this_thread::sleep_for(std::chrono::seconds(args.raw_settle_s));
        // Synthesise a "finished" so the standard wait/teardown path
        // below doesn't loiter for the full --timeout.
        latch.mark(BBL::PrintingStageFinished, rc_action, "send_raw done");
    } else if (args.action == "send_gcode_to_sdcard") {
        if (!exports.start_send_gcode_to_sdcard) {
            emit_text("fatal", "plugin does not export bambu_network_start_send_gcode_to_sdcard");
            return 70;
        }
        rc_action = exports.start_send_gcode_to_sdcard(agent, params, on_update, on_cancel, on_wait);
    } else if (args.action == "local_print") {
        if (!exports.start_local_print) {
            emit_text("fatal", "plugin does not export bambu_network_start_local_print");
            return 70;
        }
        rc_action = exports.start_local_print(agent, params, on_update, on_cancel);
    } else if (args.action == "sdcard_print") {
        if (!exports.start_sdcard_print) {
            emit_text("fatal", "plugin does not export bambu_network_start_sdcard_print");
            return 70;
        }
        rc_action = exports.start_sdcard_print(agent, params, on_update, on_cancel);
    } else if (args.action == "local_print_with_record") {
        if (!exports.start_local_print_with_record) {
            emit_text("fatal", "plugin does not export bambu_network_start_local_print_with_record");
            return 70;
        }
        rc_action = exports.start_local_print_with_record(agent, params, on_update, on_cancel, on_wait);
    } else if (args.action == "cloud_print") {
        if (!exports.start_print) {
            emit_text("fatal", "plugin does not export bambu_network_start_print");
            return 70;
        }
        rc_action = exports.start_print(agent, params, on_update, on_cancel, on_wait);
    } else {
        emit_text("fatal", "unknown --action '" + args.action + "'");
        return 64;
    }
    emit_event("action_dispatched", { {"action", args.action}, {"rc", rc_action} });

    // Step 10: wait for completion or timeout.
    bool finished = latch.wait_for(std::chrono::seconds(args.timeout_s));
    if (!finished) {
        emit_event("timeout", { {"seconds", args.timeout_s} });
    } else {
        emit_event("finished", {
            {"status", latch.last_status},
            {"stage",  stage_name(latch.last_status)},
            {"code",   latch.last_code},
            {"msg",    latch.last_msg},
        });
    }

    // Step 10.5: optionally abort the print so the printer doesn't
    // actually start heating / extruding after the experiment. Mirrors
    // MachineObject::command_task_abort. Only works in Developer Mode
    // (otherwise send_message_to_printer rejects print:* with rc=-4).
    // Idempotent — sending stop to an already-FAILED job is a no-op
    // on firmware side.
    if (args.auto_stop &&
        (args.action == "local_print" ||
         args.action == "sdcard_print" ||
         args.action == "local_print_with_record" ||
         args.action == "cloud_print")) {
        const std::string stop_payload =
            "{\"print\":{\"command\":\"stop\",\"param\":\"\","
            "\"sequence_id\":\"99999\"}}";
        int rc_stop = exports.send_message_to_printer(
            agent, args.dev_id, stop_payload, /*qos=*/1, /*flag=*/0);
        emit_event("auto_stop", {
            {"rc",    rc_stop},
            {"bytes", stop_payload.size()},
        });
        if (rc_stop != 0) {
            emit_text("warning",
                "auto_stop publish failed — the printer will keep the "
                "job running. Either the printer is not in Developer "
                "Mode (the plugin's client-side filter drops print:* "
                "publishes) or the LAN MQTT session is gone. Send the "
                "stop manually from the printer UI.");
        }
        // Brief settle so the FAILED state is visible in the next
        // local_message before we tear down.
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
    }

    // Step 11: tear down. Default: graceful for real actions (so
    // destroy_agent can flush any final MQTT publishes / FTP retries).
    // Opt out with --fast-exit if you only care about events already in
    // --log-out and don't want to wait ~60s for the worker pool to drain.
    int exit_code = (!finished) ? 75
                                : (latch.last_status == BBL::PrintingStageFinished ? 0 : 1);
    bool fast = args.fast_exit.value_or(false);
    if (fast) {
        emit_event("shutdown", { {"finished", finished}, {"fast_exit", true} });
        std::cout.flush();
        if (g_log_file) g_log_file.flush();
        std::_Exit(exit_code);
    }
    guard.a = nullptr;
    exports.disconnect_printer(agent);
    exports.destroy_agent(agent);
    pr::unload(exports);
    emit_event("shutdown", { {"finished", finished}, {"fast_exit", false} });
    return exit_code;
}
catch (const std::exception& e) {
    std::fprintf(stderr, "plugin_runner: fatal: %s\n", e.what());
    return 70;
}
