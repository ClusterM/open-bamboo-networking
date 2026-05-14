// File-Transfer module implementation.
//
// Studio uses this C ABI (see src/slic3r/Utils/FileTransferUtils.hpp) for
// two paths:
//
//   1. "Is there eMMC on this printer?" pre-flight in the Print job
//      (PrintJob.cpp). URL is always bambu:///local/<ip>?port=6000.
//   2. The Send-to-Printer dialog (SendToPrinter.cpp), which tries tcp
//      (port=6000) -> tutk (cloud p2p) -> ftp in that order.
//
// We can serve all of this cleanly over FTPS (port 990), because:
//   * The semantic protocol is just "list available storages" and
//     "upload file to <storage>/<name>", both trivially expressible in
//     FTPS (CWD / STOR).
//   * The proprietary port-6000 transport needs a TLS tunnel plus a
//     JSON command framer the stock plugin ships as obfuscated code;
//     implementing it costs considerable work for no new functionality.
//
// Two modes are supported, toggled by the `OBN_FT_FTPS_FASTPATH` CMake
// option:
//
//   ON  (default): for `bambu:///local/*` URLs we open FTPS, serve
//                  cmd_type=7 (media ability) via `CWD /sdcard` and
//                  `CWD /usb` probes, and cmd_type=5 (upload) via STOR
//                  with a progress callback that becomes msg_cb({"progress":N}).
//                  For cloud/TUTK URLs we still report FT_EIO - we don't
//                  speak that transport.
//
//   OFF          : every entry point is a polite-failure stub. Studio
//                  falls back to its internal FTP send path (our
//                  `bambu_network_start_send_gcode_to_sdcard`). Same
//                  file ends up in the same place; the UI just skips
//                  the "reading storage" step and the per-percent
//                  progress comes from the fallback instead.
//
// In both modes ft_tunnel_start_connect fires its callback synchronously
// so Studio's UI state machine never hangs waiting for a completion
// that would otherwise have to cross threads.

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "obn/abi_export.hpp"
#include "obn/log.hpp"

#if OBN_FT_FTPS_FASTPATH
#include "obn/ftps.hpp"
#include "obn/json_lite.hpp"
#endif

extern "C" {

struct ft_job_result {
    int         ec;
    int         resp_ec;
    const char* json;
    const void* bin;
    uint32_t    bin_size;
};

struct ft_job_msg {
    int         kind;
    const char* json;
};

typedef enum {
    FT_OK         =   0,
    FT_EINVAL     =  -1,
    FT_ESTATE     =  -2,
    FT_EIO        =  -3,
    FT_ETIMEOUT   =  -4,
    FT_ECANCELLED =  -5,
    FT_EXCEPTION  =  -6,
    FT_EUNKNOWN   = -128
} ft_err;

using ft_tunnel_connect_cb = void (*)(void* user, int ok, int err, const char* msg);
using ft_tunnel_status_cb  = void (*)(void* user, int old_status, int new_status, int err, const char* msg);
using ft_job_result_cb     = void (*)(void* user, ft_job_result result);
using ft_job_msg_cb        = void (*)(void* user, ft_job_msg msg);

} // extern "C"

namespace {

constexpr const char* kUnsupportedMsg =
    "FileTransfer over TCP is not implemented by the open-source plugin. "
    "Studio will fall back to FTP (see README)";

// Studio keys for cmd_type.
constexpr int kCmdTypeUpload       = 5;
constexpr int kCmdTypeMediaAbility = 7;

// progress value reserved by Studio as a timeout trigger. We must skip
// this exact number (see SendToPrinter.cpp: "if (progress == 99) ...").
constexpr int kReservedProgress = 99;

#if OBN_FT_FTPS_FASTPATH
// Parsed from bambu:///local/<ip>?port=6000&user=bblp&passwd=<code>. We
// only speak the `/local/` variant; TUTK/Agora URLs keep the stub path.
struct LanUrl {
    std::string ip;
    int         port = 6000;
    std::string user = "bblp";
    std::string password;
};

std::string percent_decode(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hex2 = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
                if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
                return -1;
            };
            int hi = hex2(s[i + 1]);
            int lo = hex2(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(s[i]);
    }
    return out;
}

bool parse_lan_url(const char* raw, LanUrl& out)
{
    if (!raw) return false;
    static constexpr const char kPrefix[] = "bambu:///local/";
    std::string s = raw;
    if (s.rfind(kPrefix, 0) != 0) return false;
    s.erase(0, sizeof(kPrefix) - 1);

    std::string host_part = s;
    std::string query;
    if (auto q = s.find('?'); q != std::string::npos) {
        host_part = s.substr(0, q);
        query    = s.substr(q + 1);
    }
    out.ip = host_part;
    if (out.ip.empty()) return false;

    std::size_t i = 0;
    while (i < query.size()) {
        auto amp = query.find('&', i);
        std::string kv = query.substr(i, amp == std::string::npos ? std::string::npos : amp - i);
        i = amp == std::string::npos ? query.size() : amp + 1;

        auto eq = kv.find('=');
        if (eq == std::string::npos) continue;
        std::string key = kv.substr(0, eq);
        std::string val = percent_decode(kv.substr(eq + 1));
        if      (key == "port")   { try { out.port = std::stoi(val); } catch (...) {} }
        else if (key == "user")   { out.user = val; }
        else if (key == "passwd") { out.password = val; }
    }
    return true;
}

// Storage mounts the Bambu firmware exposes via FTPS. "sdcard" lives on
// the SD slot (X1, P1P, A1, older prints). "usb" is used by P2S (which
// has no SD slot). Listed in preference order: probes stop as soon as
// one mount is confirmed if we wanted that, but the caller likes to
// know both so the picker can show the right label.
constexpr std::array<const char*, 2> kProbePaths = {"/sdcard", "/usb"};
#endif // OBN_FT_FTPS_FASTPATH

struct FT_Tunnel {
    std::atomic<int>     refcount{1};
    ft_tunnel_connect_cb conn_cb{nullptr};
    void*                conn_user{nullptr};
    ft_tunnel_status_cb  status_cb{nullptr};
    void*                status_user{nullptr};
    std::atomic<bool>    shut_down{false};

#if OBN_FT_FTPS_FASTPATH
    // For local URLs this holds the parsed connection parameters and, once
    // start_connect succeeds, a live FTPS control channel that jobs
    // (upload, ability probe) run serially against.
    bool                         is_lan{false};
    LanUrl                       lan;
    std::mutex                   ftp_mu;         // guards `ftp` + busy
    std::unique_ptr<obn::ftps::Client> ftp;
    std::string                  ability_cache;  // JSON for cmd_type=7 (cached after first probe)
    bool                         ability_probed{false};
    // Set to true when `/sdcard` and `/usb` are both missing but the login
    // itself succeeded - the printer (P2S) exposes its single storage
    // directly at the FTPS root. Uploads then STOR to `/<dest_name>`
    // instead of `/<dest_storage>/<dest_name>`.
    bool                         root_is_storage{false};
#endif
};

struct FT_Job {
    std::atomic<int>  refcount{1};
    ft_job_result_cb  result_cb{nullptr};
    void*             result_user{nullptr};
    ft_job_msg_cb     msg_cb{nullptr};
    void*             msg_user{nullptr};
    std::atomic<bool> cancelled{false};

    std::mutex              mu;                  // guards the fields below
    std::condition_variable cv;
    bool                    finished{false};
    int                     res_ec{0};
    int                     resp_ec{0};
    std::string             res_json;

#if OBN_FT_FTPS_FASTPATH
    // Parsed ft_job_create params.
    int         cmd_type     = 0;
    std::string dest_storage;
    std::string dest_name;
    std::string file_path;
    std::string raw_params;
#endif
};

void retain(FT_Tunnel* t) { if (t) t->refcount.fetch_add(1, std::memory_order_relaxed); }
void release(FT_Tunnel* t)
{
    if (t && t->refcount.fetch_sub(1, std::memory_order_acq_rel) == 1) delete t;
}
void retain(FT_Job* j) { if (j) j->refcount.fetch_add(1, std::memory_order_relaxed); }
void release(FT_Job* j)
{
    if (j && j->refcount.fetch_sub(1, std::memory_order_acq_rel) == 1) delete j;
}

} // namespace

extern "C" {
struct FT_TunnelHandle;
struct FT_JobHandle;
} // extern "C"

OBN_ABI int ft_abi_version() { return 1; }

OBN_ABI void ft_free(void* /*p*/) {}
OBN_ABI void ft_job_result_destroy(ft_job_result* /*r*/) {}
OBN_ABI void ft_job_msg_destroy(ft_job_msg* /*m*/) {}

OBN_ABI ft_err ft_tunnel_create(const char* url, FT_TunnelHandle** out)
{
    if (!out) return FT_EINVAL;
    auto* t = new FT_Tunnel();
    OBN_INFO("ft_tunnel_create url=%s", url ? url : "(null)");

#if OBN_FT_FTPS_FASTPATH
    if (parse_lan_url(url, t->lan)) {
        t->is_lan = true;
        OBN_INFO("ft_tunnel_create: lan-fastpath ip=%s user=%s",
                       t->lan.ip.c_str(), t->lan.user.c_str());
    } else {
        OBN_INFO("ft_tunnel_create: non-local URL, will stub");
    }
#endif

    *out = reinterpret_cast<FT_TunnelHandle*>(t);
    return FT_OK;
}

OBN_ABI void ft_tunnel_retain(FT_TunnelHandle* h)
{
    retain(reinterpret_cast<FT_Tunnel*>(h));
}

OBN_ABI void ft_tunnel_release(FT_TunnelHandle* h)
{
    release(reinterpret_cast<FT_Tunnel*>(h));
}

OBN_ABI ft_err ft_tunnel_set_status_cb(FT_TunnelHandle* h, ft_tunnel_status_cb cb, void* user)
{
    auto* t = reinterpret_cast<FT_Tunnel*>(h);
    if (!t) return FT_EINVAL;
    t->status_cb   = cb;
    t->status_user = user;
    return FT_OK;
}

#if OBN_FT_FTPS_FASTPATH

namespace {

// Establish / reuse the FTPS control channel under the tunnel's mutex.
// Returns empty on success, error text otherwise.
std::string tunnel_ensure_ftp(FT_Tunnel* t)
{
    std::lock_guard<std::mutex> lk(t->ftp_mu);
    if (t->ftp) return {};

    obn::ftps::ConnectConfig cfg;
    cfg.host     = t->lan.ip;
    cfg.username = t->lan.user.empty() ? std::string{"bblp"} : t->lan.user;
    cfg.password = t->lan.password;
    // We don't have Agent's CA bundle visible from the C ABI; the
    // printer's self-signed cert can't be verified without it anyway.
    // Same trade-off the print job makes when no cert folder is set.
    cfg.ca_file  = {};

    auto c = std::make_unique<obn::ftps::Client>();
    if (std::string err = obn::ftps::connect_with_fallback(*c, cfg); !err.empty()) {
        return err;
    }
    t->ftp = std::move(c);
    return {};
}

void deliver_result(FT_Job* j, int ec, int resp_ec, std::string json_body)
{
    {
        std::lock_guard<std::mutex> lk(j->mu);
        j->finished = true;
        j->res_ec   = ec;
        j->resp_ec  = resp_ec;
        j->res_json = std::move(json_body);
    }
    j->cv.notify_all();
    if (j->result_cb) {
        ft_job_result r{};
        r.ec       = ec;
        r.resp_ec  = resp_ec;
        // Safe: Studio's tramp turns this into a std::string by value
        // before the call returns, so the temporary only needs to
        // outlive the callback itself.
        std::string body;
        {
            std::lock_guard<std::mutex> lk(j->mu);
            body = j->res_json;
        }
        r.json = body.c_str();
        r.bin      = nullptr;
        r.bin_size = 0;
        j->result_cb(j->result_user, r);
    }
}

void deliver_progress(FT_Job* j, int percent)
{
    if (!j->msg_cb) return;
    // Never send 99 - Studio arms an upload-timeout timer when it sees
    // exactly this value (SendToPrinter.cpp).
    if (percent == kReservedProgress) percent = 98;
    if (percent < 0) percent = 0;
    if (percent > 100) percent = 100;

    char buf[64];
    std::snprintf(buf, sizeof(buf), "{\"progress\":%d}", percent);
    ft_job_msg m{};
    m.kind = 0;
    m.json = buf;
    j->msg_cb(j->msg_user, m);
}

// cmd_type=7: probe which FTPS-visible storage mounts exist. We avoid
// doing LIST (which opens a data channel) - a plain CWD is enough.
void run_ability_job(FT_Tunnel* t, FT_Job* j)
{
    if (std::string err = tunnel_ensure_ftp(t); !err.empty()) {
        OBN_WARN("ft: ability: ftps connect failed: %s", err.c_str());
        deliver_result(j, FT_EIO, 0, {});
        return;
    }

    std::string body;
    {
        // Use a cached result if we already probed on this tunnel: we
        // don't want to log in / out of FTPS every time Studio opens
        // the dialog.
        std::lock_guard<std::mutex> lk(t->ftp_mu);
        if (t->ability_probed) {
            body = t->ability_cache;
        } else {
            std::vector<std::string> found;
            for (const char* p : kProbePaths) {
                if (t->ftp->cwd(p).empty()) {
                    // Strip the leading slash for Studio ("sdcard", "usb").
                    found.emplace_back(p + 1);
                }
            }
            if (found.empty()) {
                // P2S / newer A-series: FTPS root == the (only) storage
                // mount point, no /sdcard or /usb subtree. Confirm root
                // is reachable, then advertise it as "sdcard" - Studio's
                // SendToPrinter UI bifurcates on `"emmc"` vs anything
                // else, so the exact label doesn't matter as long as
                // it's not "emmc".
                std::string err = t->ftp->cwd("/");
                if (!err.empty()) {
                    OBN_WARN("ft: ability: neither /sdcard nor /usb responded and CWD / failed: %s",
                             err.c_str());
                    deliver_result(j, FT_EIO, 0, {});
                    return;
                }
                OBN_INFO("ft: ability: FTPS root is the storage mount (P2S-style), "
                         "advertising as \"sdcard\"");
                t->root_is_storage = true;
                found.emplace_back("sdcard");
            }
            body = "[";
            for (std::size_t i = 0; i < found.size(); ++i) {
                if (i) body += ",";
                body += "\"" + found[i] + "\"";
            }
            body += "]";
            t->ability_cache  = body;
            t->ability_probed = true;
        }
    }

    OBN_INFO("ft: ability: %s", body.c_str());
    deliver_result(j, 0, 0, std::move(body));
}

// cmd_type=5: STOR <file_path> to /<dest_storage>/<dest_name>.
void run_upload_job(FT_Tunnel* t, FT_Job* j)
{
    if (j->dest_storage.empty() || j->dest_name.empty() || j->file_path.empty()) {
        OBN_WARN("ft: upload: missing params (storage=%s name=%s path=%s)",
                       j->dest_storage.c_str(), j->dest_name.c_str(),
                       j->file_path.c_str());
        deliver_result(j, FT_EINVAL, 0, {});
        return;
    }
    if (std::string err = tunnel_ensure_ftp(t); !err.empty()) {
        OBN_WARN("ft: upload: ftps connect failed: %s", err.c_str());
        deliver_result(j, FT_EIO, 0, {});
        return;
    }

    std::string remote_path;
    {
        std::lock_guard<std::mutex> lk(t->ftp_mu);
        if (t->root_is_storage) {
            // FTPS root *is* the storage; ignore dest_storage. Uploads
            // must not include the fake "/sdcard" prefix that we fed to
            // Studio in the ability JSON.
            remote_path = "/" + j->dest_name;
        } else {
            remote_path = "/" + j->dest_storage + "/" + j->dest_name;
        }
    }
    OBN_INFO("ft: upload: %s -> %s", j->file_path.c_str(), remote_path.c_str());

    std::atomic<int> last_reported{-1};
    auto progress = [j, &last_reported](std::uint64_t sent, std::uint64_t total) {
        if (j->cancelled.load(std::memory_order_acquire)) return false;
        if (total == 0) return true;
        int pct = static_cast<int>(sent * 100 / total);
        if (pct < 0) pct = 0;
        if (pct > 100) pct = 100;
        if (pct == kReservedProgress) pct = 98;
        int prev = last_reported.load(std::memory_order_relaxed);
        if (pct != prev) {
            last_reported.store(pct, std::memory_order_relaxed);
            deliver_progress(j, pct);
        }
        return true;
    };

    std::lock_guard<std::mutex> lk(t->ftp_mu);
    std::string err = t->ftp->stor(j->file_path, remote_path, progress);
    if (!err.empty()) {
        if (err == "upload cancelled") {
            OBN_INFO("ft: upload: cancelled by Studio");
            deliver_result(j, FT_ECANCELLED, 0, {});
        } else {
            OBN_WARN("ft: upload: %s", err.c_str());
            deliver_result(j, FT_EIO, 0, {});
        }
        return;
    }
    // Signal the final 100% so the UI lands on the done state.
    deliver_progress(j, 100);
    deliver_result(j, 0, 0, {});
}

// Enter point for ft_tunnel_start_job when running in fast-path mode.
// Each job gets its own detached thread; tunnel/job are retained for
// the lifetime of the thread.
void spawn_job(FT_Tunnel* t, FT_Job* j)
{
    retain(t);
    retain(j);
    std::thread([t, j] {
        switch (j->cmd_type) {
        case kCmdTypeMediaAbility: run_ability_job(t, j); break;
        case kCmdTypeUpload:       run_upload_job(t, j);  break;
        default:
            OBN_WARN("ft: unknown cmd_type=%d (raw=%.200s)",
                           j->cmd_type, j->raw_params.c_str());
            deliver_result(j, FT_EIO, 0, {});
            break;
        }
        release(j);
        release(t);
    }).detach();
}

} // namespace

#endif // OBN_FT_FTPS_FASTPATH

OBN_ABI ft_err ft_tunnel_start_connect(FT_TunnelHandle* h, ft_tunnel_connect_cb cb, void* user)
{
    auto* t = reinterpret_cast<FT_Tunnel*>(h);
    if (!t) return FT_EINVAL;
    t->conn_cb   = cb;
    t->conn_user = user;

#if OBN_FT_FTPS_FASTPATH
    if (t->is_lan) {
        // We connect synchronously (FTPS handshake is < 1 s for a LAN
        // printer). Studio already treats this call as an async-style
        // start -> callback transition, so answering before returning
        // is well within contract.
        if (std::string err = tunnel_ensure_ftp(t); !err.empty()) {
            OBN_WARN("ft: start_connect: %s", err.c_str());
            if (cb) cb(user, /*ok=*/1, /*err=*/FT_EIO, err.c_str());
            if (t->status_cb) t->status_cb(t->status_user, 0, /*new=*/-1, FT_EIO, err.c_str());
            return FT_OK;
        }
        OBN_INFO("ft: start_connect: FTPS tunnel up (ip=%s)", t->lan.ip.c_str());
        if (cb) cb(user, /*ok=*/0, /*err=*/0, "ok");
        if (t->status_cb) t->status_cb(t->status_user, 0, /*new=*/1, 0, "ok");
        return FT_OK;
    }
#endif

    OBN_INFO("ft_tunnel_start_connect: reporting synthetic failure (stub)");
    if (cb) cb(user, /*ok=*/1, /*err=*/FT_EIO, kUnsupportedMsg);
    if (t->status_cb) t->status_cb(t->status_user, 0, /*new_status=*/-1, FT_EIO, kUnsupportedMsg);
    return FT_OK;
}

OBN_ABI ft_err ft_tunnel_sync_connect(FT_TunnelHandle* h)
{
    auto* t = reinterpret_cast<FT_Tunnel*>(h);
    if (!t) return FT_EINVAL;

#if OBN_FT_FTPS_FASTPATH
    if (t->is_lan) {
        std::string err = tunnel_ensure_ftp(t);
        if (err.empty()) {
            OBN_INFO("ft: sync_connect: FTPS tunnel up");
            return FT_OK;
        }
        OBN_WARN("ft: sync_connect: %s", err.c_str());
        return FT_EIO;
    }
#endif

    OBN_INFO("ft_tunnel_sync_connect: returning FT_EIO (stub)");
    return FT_EIO;
}

OBN_ABI ft_err ft_tunnel_shutdown(FT_TunnelHandle* h)
{
    auto* t = reinterpret_cast<FT_Tunnel*>(h);
    if (!t) return FT_EINVAL;
    t->shut_down.store(true, std::memory_order_release);

#if OBN_FT_FTPS_FASTPATH
    std::unique_ptr<obn::ftps::Client> drop;
    {
        std::lock_guard<std::mutex> lk(t->ftp_mu);
        drop = std::move(t->ftp);
    }
    if (drop) drop->quit();
#endif

    return FT_OK;
}

OBN_ABI ft_err ft_job_create(const char* params_json, FT_JobHandle** out)
{
    if (!out) return FT_EINVAL;
    auto* j = new FT_Job();
    OBN_INFO("ft_job_create params=%.200s", params_json ? params_json : "(null)");

#if OBN_FT_FTPS_FASTPATH
    if (params_json) {
        j->raw_params = params_json;
        std::string perr;
        auto root = obn::json::parse(j->raw_params, &perr);
        if (root) {
            j->cmd_type     = static_cast<int>(root->find("cmd_type").as_int(0));
            j->dest_storage = root->find("dest_storage").as_string();
            j->dest_name    = root->find("dest_name").as_string();
            j->file_path    = root->find("file_path").as_string();
        } else {
            OBN_WARN("ft_job_create: bad params json: %s", perr.c_str());
        }
    }
#endif

    *out = reinterpret_cast<FT_JobHandle*>(j);
    return FT_OK;
}

OBN_ABI void ft_job_retain(FT_JobHandle* h)
{
    retain(reinterpret_cast<FT_Job*>(h));
}

OBN_ABI void ft_job_release(FT_JobHandle* h)
{
    release(reinterpret_cast<FT_Job*>(h));
}

OBN_ABI ft_err ft_job_set_result_cb(FT_JobHandle* h, ft_job_result_cb cb, void* user)
{
    auto* j = reinterpret_cast<FT_Job*>(h);
    if (!j) return FT_EINVAL;
    j->result_cb   = cb;
    j->result_user = user;
    return FT_OK;
}

OBN_ABI ft_err ft_job_set_msg_cb(FT_JobHandle* h, ft_job_msg_cb cb, void* user)
{
    auto* j = reinterpret_cast<FT_Job*>(h);
    if (!j) return FT_EINVAL;
    j->msg_cb   = cb;
    j->msg_user = user;
    return FT_OK;
}

OBN_ABI ft_err ft_tunnel_start_job(FT_TunnelHandle* th, FT_JobHandle* jh)
{
    auto* t = reinterpret_cast<FT_Tunnel*>(th);
    auto* j = reinterpret_cast<FT_Job*>(jh);
    if (!t || !j) return FT_EINVAL;

#if OBN_FT_FTPS_FASTPATH
    if (t->is_lan) {
        spawn_job(t, j);
        return FT_OK;
    }
#endif

    OBN_INFO("ft_tunnel_start_job: delivering FT_EIO result (stub)");
    if (j->result_cb) {
        ft_job_result r{};
        r.ec       = FT_EIO;
        r.resp_ec  = 0;
        r.json     = nullptr;
        r.bin      = nullptr;
        r.bin_size = 0;
        j->result_cb(j->result_user, r);
    }
    std::lock_guard<std::mutex> lk(j->mu);
    j->finished = true;
    j->res_ec   = FT_EIO;
    j->cv.notify_all();
    return FT_OK;
}

OBN_ABI ft_err ft_job_get_result(FT_JobHandle* h, uint32_t timeout_ms, ft_job_result* out)
{
    auto* j = reinterpret_cast<FT_Job*>(h);
    if (!j || !out) return FT_EINVAL;
    std::memset(out, 0, sizeof(*out));

    std::unique_lock<std::mutex> lk(j->mu);
    bool done = j->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                               [j] { return j->finished; });
    if (!done) {
        out->ec = FT_ETIMEOUT;
        return FT_OK;
    }
    out->ec      = j->res_ec;
    out->resp_ec = j->resp_ec;
    out->json    = j->res_json.empty() ? nullptr : j->res_json.c_str();
    return FT_OK;
}

OBN_ABI ft_err ft_job_cancel(FT_JobHandle* h)
{
    auto* j = reinterpret_cast<FT_Job*>(h);
    if (!j) return FT_EINVAL;
    j->cancelled.store(true, std::memory_order_release);
    return FT_OK;
}

OBN_ABI ft_err ft_job_try_get_msg(FT_JobHandle* h, ft_job_msg* out)
{
    if (out) std::memset(out, 0, sizeof(*out));
    if (!h) return FT_EINVAL;
    // Progress messages are pushed through msg_cb synchronously from
    // the STOR loop; we don't also queue them for poll-style readers.
    // Returning EIO here matches what the stub used to do: Studio spins
    // a few times and then moves on.
    return FT_EIO;
}

OBN_ABI ft_err ft_job_get_msg(FT_JobHandle* h, uint32_t /*timeout_ms*/, ft_job_msg* out)
{
    if (out) std::memset(out, 0, sizeof(*out));
    if (!h) return FT_EINVAL;
    return FT_EIO;
}
