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
// LAN URLs are served over native BambuTunnelLocal (TLS :6000) when
// OBN_FT_TUNNEL_LOCAL is enabled (default). TUTK/cloud URLs return FT_EIO.
//
// In both modes ft_tunnel_start_connect fires its callback synchronously
// so Studio's UI state machine never hangs waiting for a completion
// that would otherwise have to cross threads.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>

#include "obn/abi_export.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"
#include "obn/tunnel_upload.hpp"

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

constexpr int kCmdTypeUpload       = 5;
constexpr int kCmdTypeMediaAbility = 7;

#if OBN_FT_TUNNEL_LOCAL

struct LanUrl {
    std::string ip;
    int         port = 6000;
    std::string user = "bblp";
    std::string password;
    std::string device;
    std::string cli_id;
    std::string cli_ver;
    std::string net_ver;
};

bool env_truthy(const char* name, bool default_val)
{
    const char* v = std::getenv(name);
    if (!v || !*v) return default_val;
    return v[0] != '0';
}

bool ft_tunnel_local_enabled()
{
#if OBN_FT_TUNNEL_LOCAL
    return env_truthy("OBN_FT_TUNNEL_LOCAL", true);
#else
    return env_truthy("OBN_FT_TUNNEL_LOCAL", false);
#endif
}

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
        if (!host_part.empty() && host_part.back() == '.') host_part.pop_back();
        query = s.substr(q + 1);
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
        if      (key == "port")    { try { out.port = std::stoi(val); } catch (...) {} }
        else if (key == "user")    { out.user = val; }
        else if (key == "passwd")  { out.password = val; }
        else if (key == "device")  { out.device = val; }
        else if (key == "cli_id")  { out.cli_id = val; }
        else if (key == "cli_ver") { out.cli_ver = val; }
        else if (key == "net_ver") { out.net_ver = val; }
    }
    return true;
}

obn::tunnel_upload::ConnectParams connect_params(const LanUrl& lan)
{
    obn::tunnel_upload::ConnectParams cp;
    cp.dev_ip   = lan.ip;
    cp.dev_id   = lan.device;
    cp.port     = lan.port;
    cp.username = lan.user;
    cp.password = lan.password;
    cp.client_id = lan.cli_id;
    if (!lan.cli_ver.empty()) {
        cp.client_ver = lan.cli_ver;
    } else if (!lan.net_ver.empty()) {
        cp.client_ver = lan.net_ver;
    }
    return cp;
}

#endif // OBN_FT_TUNNEL_LOCAL

struct FT_Tunnel {
    std::atomic<int>     refcount{1};
    ft_tunnel_connect_cb conn_cb{nullptr};
    void*                conn_user{nullptr};
    ft_tunnel_status_cb  status_cb{nullptr};
    void*                status_user{nullptr};
    std::atomic<bool>    shut_down{false};

#if OBN_FT_TUNNEL_LOCAL
    bool      is_lan{false};
    LanUrl    lan;
    std::unique_ptr<obn::tunnel_upload::Connection> conn;
    std::string ability_cache;
    bool        ability_probed{false};
    std::mutex  lan_mu;  // serializes connect/query/upload on one TLS session
#endif
};

struct FT_Job {
    std::atomic<int>  refcount{1};
    ft_job_result_cb  result_cb{nullptr};
    void*             result_user{nullptr};
    ft_job_msg_cb     msg_cb{nullptr};
    void*             msg_user{nullptr};
    std::atomic<bool> cancelled{false};

    std::mutex              mu;
    std::condition_variable cv;
    bool                    finished{false};
    int                     res_ec{0};
    int                     resp_ec{0};
    std::string             res_json;

#if OBN_FT_TUNNEL_LOCAL
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

#if OBN_FT_TUNNEL_LOCAL
    if (parse_lan_url(url, t->lan)) {
        t->is_lan = true;
        OBN_INFO("ft_tunnel_create: lan ip=%s user=%s", t->lan.ip.c_str(),
                 t->lan.user.c_str());
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

#if OBN_FT_TUNNEL_LOCAL

namespace {

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
        r.ec      = ec;
        r.resp_ec = resp_ec;
        std::string body;
        {
            std::lock_guard<std::mutex> lk(j->mu);
            body = j->res_json;
        }
        r.json     = body.c_str();
        r.bin      = nullptr;
        r.bin_size = 0;
        j->result_cb(j->result_user, r);
    }
}

void deliver_progress(FT_Job* j, double percent)
{
    if (!j->msg_cb) return;
    if (percent < 0.0) percent = 0.0;
    if (percent > 100.0) percent = 100.0;

    char buf[64];
    std::snprintf(buf, sizeof(buf), "{\"progress\":%.17g}", percent);
    ft_job_msg m{};
    m.kind = 0;
    m.json = buf;
    j->msg_cb(j->msg_user, m);
}

std::string connect_lan_tunnel(FT_Tunnel* t)
{
    if (!ft_tunnel_local_enabled()) {
        return "OBN_FT_TUNNEL_LOCAL disabled";
    }
    if (!t->conn) {
        t->conn = std::make_unique<obn::tunnel_upload::Connection>();
    }
    if (t->conn->is_connected()) return {};

    std::string err;
    if (t->conn->connect(connect_params(t->lan), &err) != 0) {
        OBN_WARN("ft: tunnel_local connect failed: %s", err.c_str());
        return err.empty() ? "connect failed" : err;
    }
    return {};
}

void run_ability_job(FT_Tunnel* t, FT_Job* j)
{
    std::lock_guard<std::mutex> lk(t->lan_mu);
    if (t->ability_probed) {
        OBN_INFO("ft: ability (cached): %s", t->ability_cache.c_str());
        deliver_result(j, 0, 0, t->ability_cache);
        return;
    }

    if (std::string err = connect_lan_tunnel(t); !err.empty()) {
        deliver_result(j, FT_EIO, 0, {});
        return;
    }

    auto outcome = t->conn->query_media_ability();
    if (!outcome.ok) {
        OBN_WARN("ft: ability failed: %s", outcome.error.c_str());
        deliver_result(j, FT_EIO, 0, {});
        return;
    }
    t->ability_cache  = outcome.json_body;
    t->ability_probed = true;
    OBN_INFO("ft: ability: %s", t->ability_cache.c_str());
    deliver_result(j, 0, 0, t->ability_cache);
}

void run_upload_job(FT_Tunnel* t, FT_Job* j)
{
    std::lock_guard<std::mutex> lk(t->lan_mu);
    if (std::string err = connect_lan_tunnel(t); !err.empty()) {
        OBN_WARN("ft: upload: connect failed: %s", err.c_str());
        deliver_result(j, FT_EIO, 0, {});
        return;
    }

    obn::tunnel_upload::UploadRequest req;
    req.local_path    = j->file_path;
    req.dest_storage  = j->dest_storage;
    req.dest_name     = j->dest_name;

    obn::tunnel_upload::UploadCallbacks cb;
    cb.cancelled = [j] {
        return j->cancelled.load(std::memory_order_acquire);
    };
    cb.progress = [j](int pct) {
        deliver_progress(j, static_cast<double>(pct));
    };

    auto outcome = t->conn->upload(req, cb);
    if (outcome.ok) {
        deliver_result(j, 0, outcome.wire_result, {});
        return;
    }
    if (outcome.error == "cancelled") {
        deliver_result(j, FT_ECANCELLED, 0, {});
        return;
    }
    OBN_WARN("ft: upload failed: %s", outcome.error.c_str());
    deliver_result(j, FT_EIO, outcome.wire_result >= 0 ? outcome.wire_result : 0, {});
}

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

#endif // OBN_FT_TUNNEL_LOCAL

OBN_ABI ft_err ft_tunnel_start_connect(FT_TunnelHandle* h, ft_tunnel_connect_cb cb, void* user)
{
    auto* t = reinterpret_cast<FT_Tunnel*>(h);
    if (!t) return FT_EINVAL;
    t->conn_cb   = cb;
    t->conn_user = user;

#if OBN_FT_TUNNEL_LOCAL
    if (t->is_lan) {
        std::lock_guard<std::mutex> lk(t->lan_mu);
        if (std::string err = connect_lan_tunnel(t); !err.empty()) {
            OBN_WARN("ft: start_connect: %s", err.c_str());
            if (cb) cb(user, /*ok=*/1, /*err=*/FT_EIO, err.c_str());
            if (t->status_cb) {
                t->status_cb(t->status_user, 0, /*new=*/-1, FT_EIO, err.c_str());
            }
            return FT_OK;
        }
        OBN_INFO("ft: start_connect: tunnel up (ip=%s)", t->lan.ip.c_str());
        if (cb) cb(user, /*ok=*/0, /*err=*/0, "ok");
        if (t->status_cb) t->status_cb(t->status_user, 0, /*new=*/1, 0, "ok");
        return FT_OK;
    }
#endif

    OBN_INFO("ft_tunnel_start_connect: reporting synthetic failure (stub)");
    if (cb) cb(user, /*ok=*/1, /*err=*/FT_EIO, kUnsupportedMsg);
    if (t->status_cb) {
        t->status_cb(t->status_user, 0, /*new_status=*/-1, FT_EIO, kUnsupportedMsg);
    }
    return FT_OK;
}

OBN_ABI ft_err ft_tunnel_sync_connect(FT_TunnelHandle* h)
{
    auto* t = reinterpret_cast<FT_Tunnel*>(h);
    if (!t) return FT_EINVAL;

#if OBN_FT_TUNNEL_LOCAL
    if (t->is_lan) {
        std::lock_guard<std::mutex> lk(t->lan_mu);
        OBN_INFO("ft: sync_connect: opening tunnel to %s", t->lan.ip.c_str());
        std::string err = connect_lan_tunnel(t);
        if (err.empty()) {
            OBN_INFO("ft: sync_connect: tunnel up");
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

#if OBN_FT_TUNNEL_LOCAL
    {
        std::lock_guard<std::mutex> lk(t->lan_mu);
        if (t->conn) t->conn->disconnect();
    }
#endif

    return FT_OK;
}

OBN_ABI ft_err ft_job_create(const char* params_json, FT_JobHandle** out)
{
    if (!out) return FT_EINVAL;
    auto* j = new FT_Job();
    OBN_INFO("ft_job_create params=%.200s", params_json ? params_json : "(null)");

#if OBN_FT_TUNNEL_LOCAL
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

#if OBN_FT_TUNNEL_LOCAL
    if (t->is_lan) {
        spawn_job(t, j);
        return FT_OK;
    }
#endif

    OBN_INFO("ft_tunnel_start_job: delivering FT_EIO result (stub)");
    if (j->result_cb) {
        ft_job_result r{};
        r.ec = FT_EIO;
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
    return FT_EIO;
}

OBN_ABI ft_err ft_job_get_msg(FT_JobHandle* h, uint32_t /*timeout_ms*/, ft_job_msg* out)
{
    if (out) std::memset(out, 0, sizeof(*out));
    if (!h) return FT_EINVAL;
    return FT_EIO;
}
