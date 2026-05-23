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
// OBN_FT_TUNNEL_LOCAL is enabled (default). FTPS :990 is a fallback when
// OBN_FT_FTPS_FALLBACK is enabled (default). TUTK/cloud URLs return FT_EIO.
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
#include <fstream>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <openssl/evp.h>

#include "obn/abi_export.hpp"
#include "obn/log.hpp"

#if OBN_FT_TUNNEL_LOCAL || OBN_FT_FTPS_FALLBACK
#include "obn/ftps.hpp"
#include "obn/json_lite.hpp"
#include "obn/lan_tls.hpp"
#include "obn/print_params_ftp_prefs.hpp"
#include "obn/tls_dial.hpp"
#include "obn/tunnel_local.hpp"
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

constexpr int kCmdTypeUpload       = 5;
constexpr int kCmdTypeMediaAbility = 7;

constexpr int kReservedProgress = 99;

#if OBN_FT_TUNNEL_LOCAL || OBN_FT_FTPS_FALLBACK

enum class FtTransport {
    None,
    Native6000,
    Ftps,
};

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

bool ft_ftps_fallback_enabled()
{
#if OBN_FT_FTPS_FALLBACK
    return env_truthy("OBN_FT_FTPS_FALLBACK", true);
#else
    return env_truthy("OBN_FT_FTPS_FALLBACK", false);
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

std::string random_uuid()
{
    static thread_local std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<int> dis(0, 15);
    const char* hex = "0123456789abcdef";
    std::string u = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
    for (char& c : u) {
        if (c == 'x') c = hex[dis(gen)];
        else if (c == 'y') c = hex[(dis(gen) & 0x3) | 0x8];
    }
    return u;
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

constexpr std::array<const char*, 2> kProbePaths = {"/sdcard", "/usb"};

std::string md5_finalize_lower(EVP_MD_CTX* ctx)
{
    if (!ctx) return {};
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned      len = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &len) != 1) return {};

    static const char kHex[] = "0123456789abcdef";
    std::string hex(len * 2, '\0');
    for (unsigned i = 0; i < len; ++i) {
        hex[2 * i    ] = kHex[(digest[i] >> 4) & 0xF];
        hex[2 * i + 1] = kHex[ digest[i]       & 0xF];
    }
    return hex;
}

#endif // OBN_FT_TUNNEL_LOCAL || OBN_FT_FTPS_FALLBACK

struct FT_Tunnel {
    std::atomic<int>     refcount{1};
    ft_tunnel_connect_cb conn_cb{nullptr};
    void*                conn_user{nullptr};
    ft_tunnel_status_cb  status_cb{nullptr};
    void*                status_user{nullptr};
    std::atomic<bool>    shut_down{false};

#if OBN_FT_TUNNEL_LOCAL || OBN_FT_FTPS_FALLBACK
    bool      is_lan{false};
    LanUrl    lan;
    FtTransport transport{FtTransport::None};
    std::mutex tunnel_mu;

#if OBN_FT_TUNNEL_LOCAL
    obn::os::socket_t                          fd{obn::os::kInvalidSocket};
    SSL*                                       ssl{nullptr};
    std::unique_ptr<obn::tunnel_local::Session> tl_session;
    std::uint32_t                              wire_seq{1};
#endif

#if OBN_FT_FTPS_FALLBACK
    std::unique_ptr<obn::ftps::Client> ftp;
    bool                               root_is_storage{false};
#endif

    std::string ability_cache;
    bool        ability_probed{false};
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

#if OBN_FT_TUNNEL_LOCAL || OBN_FT_FTPS_FALLBACK
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

#if OBN_FT_TUNNEL_LOCAL || OBN_FT_FTPS_FALLBACK
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

#if OBN_FT_TUNNEL_LOCAL || OBN_FT_FTPS_FALLBACK

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

#if OBN_FT_TUNNEL_LOCAL

obn::tunnel_local::Config tunnel_cfg(const FT_Tunnel* t)
{
    obn::tunnel_local::Config cfg;
    cfg.username    = t->lan.user;
    cfg.access_code = t->lan.password;
    cfg.client_id   = t->lan.cli_id.empty() ? random_uuid() : t->lan.cli_id;
    if (!t->lan.cli_ver.empty()) {
        cfg.client_ver = t->lan.cli_ver;
    } else if (!t->lan.net_ver.empty()) {
        cfg.client_ver = t->lan.net_ver;
    } else {
#ifdef OBN_VERSION_STRING
        cfg.client_ver = OBN_VERSION_STRING;
#else
        cfg.client_ver = "02.07.00.55";
#endif
    }
    return cfg;
}

const char* tls_serial_for(const FT_Tunnel* t)
{
    if (!t->lan.device.empty()) return t->lan.device.c_str();
    if (auto s = obn::lan_tls::registry_lookup_serial(t->lan.ip)) {
        return s->c_str();
    }
    return nullptr;
}

void close_native(FT_Tunnel* t)
{
#if OBN_FT_TUNNEL_LOCAL
    obn::os::socket_t fd = obn::os::kInvalidSocket;
    SSL*               ssl = nullptr;
    {
        std::lock_guard<std::mutex> lk(t->tunnel_mu);
        fd  = t->fd;
        ssl = t->ssl;
        t->fd  = obn::os::kInvalidSocket;
        t->ssl = nullptr;
        t->tl_session.reset();
    }
    obn::tls::close_tls(&fd, &ssl);
#endif
}

std::string tunnel_ensure_native(FT_Tunnel* t)
{
    {
        std::lock_guard<std::mutex> lk(t->tunnel_mu);
        if (t->ssl) return {};
    }

    OBN_INFO("ft: tunnel_local dialing tls://%s:%d", t->lan.ip.c_str(), t->lan.port);

    obn::os::socket_t fd = obn::os::kInvalidSocket;
    SSL*               ssl = nullptr;
    const char*        serial = tls_serial_for(t);
    if (obn::tls::dial_tls(t->lan.ip, t->lan.port, /*timeout_ms=*/5000,
                           &fd, &ssl, serial) != 0) {
        const char* err = obn::tls::last_error();
        return err && *err ? err : "TLS dial failed";
    }

    obn::tunnel_local::Session* session = nullptr;
    {
        std::lock_guard<std::mutex> lk(t->tunnel_mu);
        if (!t->tl_session) {
            t->tl_session = std::make_unique<obn::tunnel_local::Session>(
                static_cast<std::uint32_t>(std::rand()));
        }
        session = t->tl_session.get();
    }

    const auto cfg = tunnel_cfg(t);
    obn::tls::set_socket_io_timeout(fd, 3000);
    for (int attempt = 0; attempt < 64; ++attempt) {
        const int hs = session->handshake_step(ssl, cfg, &t->tunnel_mu);
        if (hs == 0) {
            obn::tls::clear_socket_io_timeout(fd);
            std::lock_guard<std::mutex> lk(t->tunnel_mu);
            t->fd        = fd;
            t->ssl       = ssl;
            t->transport = FtTransport::Native6000;
            OBN_INFO("ft: tunnel_local ready (pid=%s ver=%s)",
                     cfg.client_id.c_str(), cfg.client_ver.c_str());
            return {};
        }
        if (hs < 0) {
            obn::tls::clear_socket_io_timeout(fd);
            obn::tls::close_tls(&fd, &ssl);
            std::lock_guard<std::mutex> lk(t->tunnel_mu);
            t->tl_session.reset();
            return "BambuTunnelLocal handshake failed";
        }
    }
    obn::tls::clear_socket_io_timeout(fd);
    obn::tls::close_tls(&fd, &ssl);
    {
        std::lock_guard<std::mutex> lk(t->tunnel_mu);
        t->tl_session.reset();
    }
    return "BambuTunnelLocal handshake timed out";
}

int recv_json_payload(FT_Tunnel* t, std::string* json_out)
{
    std::vector<std::uint8_t> payload;
    for (;;) {
        const int rc = t->tl_session->recv_payload(t->ssl, &payload, &t->tunnel_mu);
        if (rc == 0) break;
        if (rc < 0) return -1;
    }
    std::vector<std::uint8_t> bin;
    if (!obn::tunnel_local::split_json_prefix(payload.data(), payload.size(),
                                              json_out, &bin)) {
        json_out->assign(reinterpret_cast<const char*>(payload.data()), payload.size());
    }
    return 0;
}

// Accept only replies matching cmdtype/sequence; skip stale frames left on a reused
// :6000 tunnel (e.g. DELETE or ability replies from an earlier job).
int recv_wire_json(FT_Tunnel* t, std::string* json_out, int want_cmdtype,
                   std::uint32_t want_seq, const char* phase, int max_skips = 32)
{
    auto try_accept = [&](const std::string& json) -> bool {
        const int cmd = obn::tunnel_local::parse_wire_cmdtype(json);
        const int seq = obn::tunnel_local::parse_wire_sequence(json);
        if (cmd == want_cmdtype &&
            (want_seq == 0 ||
             static_cast<std::uint32_t>(seq) == want_seq)) {
            *json_out = json;
            return true;
        }
        OBN_WARN("ft: upload (%s): skip stale reply cmd=%d seq=%d"
                 " want cmd=%d seq=%u: %.200s",
                 phase, cmd, seq, want_cmdtype, want_seq, json.c_str());
        return false;
    };

    for (const auto& pending : t->tl_session->drain_pending_wire_json()) {
        if (try_accept(pending)) return 0;
    }
    for (int i = 0; i < max_skips; ++i) {
        std::string json;
        if (recv_json_payload(t, &json) != 0) return -1;
        if (try_accept(json)) return 0;
    }
    return -1;
}

void drain_stale_wire_json(FT_Tunnel* t, const char* phase)
{
    for (const auto& pending : t->tl_session->drain_pending_wire_json()) {
        OBN_WARN("ft: upload (%s): drain buffered reply: %.200s",
                 phase, pending.c_str());
    }
}

#endif // OBN_FT_TUNNEL_LOCAL

#if OBN_FT_FTPS_FALLBACK

std::string tunnel_ensure_ftp(FT_Tunnel* t)
{
    std::lock_guard<std::mutex> lk(t->tunnel_mu);
    if (t->ftp) return {};

    const bool ftp_tls = obn::print_params_get_use_ssl_for_ftp();

    obn::ftps::ConnectConfig cfg;
    cfg.host     = t->lan.ip;
    cfg.port     = ftp_tls ? 990 : 21;
    cfg.username = t->lan.user.empty() ? std::string{"bblp"} : t->lan.user;
    cfg.password = t->lan.password;
    cfg.use_tls  = ftp_tls;
    cfg.ca_file  = obn::lan_tls::registry_ca_file();
    if (auto serial = obn::lan_tls::registry_lookup_serial(t->lan.ip)) {
        cfg.tls_verify_hostname = *serial;
    }

    auto c = std::make_unique<obn::ftps::Client>();
    if (std::string err = c->connect(cfg); !err.empty()) {
        return err;
    }
    t->ftp       = std::move(c);
    t->transport = FtTransport::Ftps;
    return {};
}

#endif // OBN_FT_FTPS_FALLBACK

std::string connect_lan_tunnel(FT_Tunnel* t)
{
    std::string err;

#if OBN_FT_TUNNEL_LOCAL
    if (ft_tunnel_local_enabled()) {
        err = tunnel_ensure_native(t);
        if (err.empty()) return {};
        OBN_WARN("ft: tunnel_local connect failed: %s", err.c_str());
    }
#endif

#if OBN_FT_FTPS_FALLBACK
    if (ft_ftps_fallback_enabled()) {
        const std::string ftp_err = tunnel_ensure_ftp(t);
        if (ftp_err.empty()) return {};
        if (err.empty()) err = ftp_err;
        else err += "; FTPS: " + ftp_err;
        OBN_WARN("ft: FTPS fallback failed: %s", ftp_err.c_str());
    }
#endif

    if (err.empty()) err = "no ft_* transport enabled";
    return err;
}

#if OBN_FT_TUNNEL_LOCAL

// Returns true if the job is finished (result delivered). False means try FTPS.
bool run_ability_job_native(FT_Tunnel* t, FT_Job* j)
{
    {
        std::lock_guard<std::mutex> lk(t->tunnel_mu);
        if (t->ability_probed) {
            OBN_INFO("ft: ability (native): %s", t->ability_cache.c_str());
            deliver_result(j, 0, 0, t->ability_cache);
            return true;
        }
    }

    std::uint32_t seq = 0;
    {
        std::lock_guard<std::mutex> lk(t->tunnel_mu);
        seq = t->wire_seq++;
    }
    const std::string req = obn::tunnel_local::build_media_ability_abi(seq);
    OBN_INFO("ft: ability (native): send %s",
             obn::tunnel_local::wrap_ctrl_abi(req).c_str());
    if (t->tl_session->send_abi_json(t->ssl, req, &t->tunnel_mu) != 0) {
        deliver_result(j, FT_EIO, 0, {});
        return true;
    }
    std::string wire_json;
    if (recv_json_payload(t, &wire_json) != 0) {
        deliver_result(j, FT_EIO, 0, {});
        return true;
    }
    std::string body = obn::tunnel_local::parse_ability_reply_to_ft_json(wire_json);
    if (body.empty()) {
        OBN_WARN("ft: ability: bad wire reply: %.200s", wire_json.c_str());
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(t->tunnel_mu);
        t->ability_cache  = body;
        t->ability_probed = true;
    }
    OBN_INFO("ft: ability (native): %s", body.c_str());
    deliver_result(j, 0, 0, std::move(body));
    return true;
}

// Returns true when the job result was delivered to Studio.
bool run_upload_job_native(FT_Tunnel* t, FT_Job* j)
{
    if (j->dest_storage.empty() || j->dest_name.empty() || j->file_path.empty()) {
        deliver_result(j, FT_EINVAL, 0, {});
        return true;
    }

    std::ifstream in(j->file_path, std::ios::binary | std::ios::ate);
    if (!in) {
        OBN_WARN("ft: upload: cannot open %s", j->file_path.c_str());
        deliver_result(j, FT_EIO, 0, {});
        return true;
    }
    const auto fsize = static_cast<std::uint64_t>(in.tellg());
    in.seekg(0, std::ios::beg);

    drain_stale_wire_json(t, "pre-init");

    std::uint32_t seq = 0;
    {
        std::lock_guard<std::mutex> lk(t->tunnel_mu);
        seq = t->wire_seq++;
    }

    const std::string init_abi = obn::tunnel_local::build_file_upload_init_abi(
        seq, j->dest_storage, j->dest_name, fsize);

    OBN_INFO("ft: upload (native): init %s",
             obn::tunnel_local::wrap_ctrl_abi(init_abi).c_str());
    OBN_INFO("ft: upload (native): %s -> %s/%s (%llu bytes)",
             j->file_path.c_str(), j->dest_storage.c_str(), j->dest_name.c_str(),
             static_cast<unsigned long long>(fsize));

    obn::os::socket_t upload_fd = obn::os::kInvalidSocket;
    SSL* upload_ssl = nullptr;
    {
        std::lock_guard<std::mutex> lk(t->tunnel_mu);
        upload_fd = t->fd;
        upload_ssl = t->ssl;
    }
    if (obn::os::socket_valid(upload_fd)) {
        obn::tls::set_socket_io_timeout(upload_fd, 120000);
    }

    if (t->tl_session->send_abi_json(upload_ssl, init_abi, &t->tunnel_mu) != 0) {
        OBN_WARN("ft: upload: init send failed (%s)",
                 obn::tunnel_local::describe_ssl_io_error(upload_ssl));
        if (obn::os::socket_valid(upload_fd)) obn::tls::clear_socket_io_timeout(upload_fd);
        return false;
    }

    std::string wire_json;
    if (recv_wire_json(t, &wire_json, obn::tunnel_local::kCmdFileUpload, seq,
                       "init") != 0) {
        OBN_WARN("ft: upload: init recv failed (%s)",
                 obn::tunnel_local::describe_ssl_io_error(upload_ssl));
        if (obn::os::socket_valid(upload_fd)) obn::tls::clear_socket_io_timeout(upload_fd);
        return false;
    }
    OBN_DEBUG("ft: upload (native): init reply %.200s", wire_json.c_str());

    std::uint32_t chunk_size_kb = 0;
    std::uint64_t offset = 0;
    int init_result = -1;
    if (!obn::tunnel_local::parse_upload_init_reply(
            wire_json, &chunk_size_kb, &offset, &init_result)) {
        OBN_WARN("ft: upload: bad init reply result=%d wire=%.200s",
                 init_result, wire_json.c_str());
        if (obn::os::socket_valid(upload_fd)) {
            obn::tls::clear_socket_io_timeout(upload_fd);
        }
        deliver_result(j, FT_EIO, init_result >= 0 ? init_result : 0, {});
        return true;
    }

    const std::size_t buffer_size =
        static_cast<std::size_t>(chunk_size_kb) * 1024;
    OBN_INFO("ft: upload (native): chunk_size=%u KB offset=%llu",
             chunk_size_kb, static_cast<unsigned long long>(offset));

    if (offset > 0) {
        in.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    }

    std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> md5_ctx(
        EVP_MD_CTX_new(),
        [](EVP_MD_CTX* c) { if (c) EVP_MD_CTX_free(c); });
    if (!md5_ctx || EVP_DigestInit_ex(md5_ctx.get(), EVP_md5(), nullptr) != 1) {
        if (obn::os::socket_valid(upload_fd)) obn::tls::clear_socket_io_timeout(upload_fd);
        deliver_result(j, FT_EIO, 0, {});
        return true;
    }

    std::vector<char> buffer(buffer_size);
    std::uint32_t frag_id = 0;
    int last_reported_pct = -1;

    // P2S firmware expects all chunk frames pipelined on the wire before any
    // chunk reply is read (stock libbambu_networking / tcpdump on :6000).
    // Waiting for per-chunk ACK after the first frame yields result -9203.
    while (offset < fsize) {
        if (j->cancelled.load(std::memory_order_acquire)) {
            if (obn::os::socket_valid(upload_fd)) obn::tls::clear_socket_io_timeout(upload_fd);
            deliver_result(j, FT_ECANCELLED, 0, {});
            return true;
        }

        const std::uint64_t remaining = fsize - offset;
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(remaining, buffer_size));
        in.read(buffer.data(), static_cast<std::streamsize>(want));
        const std::streamsize got = in.gcount();
        if (got <= 0) {
            OBN_WARN("ft: upload: read error at offset %llu",
                     static_cast<unsigned long long>(offset));
            if (obn::os::socket_valid(upload_fd)) obn::tls::clear_socket_io_timeout(upload_fd);
            deliver_result(j, FT_EIO, 0, {});
            return true;
        }
        const auto read_size = static_cast<std::uint32_t>(got);
        if (EVP_DigestUpdate(md5_ctx.get(), buffer.data(), read_size) != 1) {
            if (obn::os::socket_valid(upload_fd)) obn::tls::clear_socket_io_timeout(upload_fd);
            deliver_result(j, FT_EIO, 0, {});
            return true;
        }

        const bool last_chunk = (offset + read_size >= fsize);
        std::string file_md5;
        if (last_chunk) {
            file_md5 = md5_finalize_lower(md5_ctx.get());
            md5_ctx.reset();
        }

        const std::string chunk_abi =
            obn::tunnel_local::build_file_upload_chunk_abi(
                seq, frag_id, offset, read_size, file_md5);

        if (t->tl_session->send_abi_json_with_binary(
                upload_ssl, chunk_abi, buffer.data(), read_size,
                &t->tunnel_mu, /*poll_rx_after_send=*/false) != 0) {
            OBN_WARN("ft: upload: chunk %u send failed (%s)", frag_id,
                     obn::tunnel_local::describe_ssl_io_error(upload_ssl));
            if (obn::os::socket_valid(upload_fd)) obn::tls::clear_socket_io_timeout(upload_fd);
            return false;
        }

        offset += read_size;
        ++frag_id;

        if (fsize > 0) {
            const int pct = static_cast<int>((offset * 100) / fsize);
            if (pct != last_reported_pct) {
                last_reported_pct = pct;
                const double progress =
                    static_cast<double>(pct);
                OBN_INFO("ft: upload (native): progress %.1f%%", progress);
                deliver_progress(j, progress);
            }
        }
    }

    int result_code = -1;
    for (int attempt = 0; attempt < 32; ++attempt) {
        wire_json.clear();
        if (recv_wire_json(t, &wire_json, obn::tunnel_local::kCmdFileUpload,
                           seq, "final") != 0) {
            OBN_WARN("ft: upload: final recv failed (%s)",
                     obn::tunnel_local::describe_ssl_io_error(upload_ssl));
            if (obn::os::socket_valid(upload_fd)) {
                obn::tls::clear_socket_io_timeout(upload_fd);
            }
            return false;
        }
        OBN_DEBUG("ft: upload (native): final reply %.200s", wire_json.c_str());
        result_code = obn::tunnel_local::parse_wire_result(wire_json);
        if (result_code == 1) continue; // CONTINUE / in-progress
        break;
    }
    if (result_code == 0 || result_code == 19) {
        if (obn::os::socket_valid(upload_fd)) obn::tls::clear_socket_io_timeout(upload_fd);
        deliver_progress(j, 100.0);
        deliver_result(j, 0, result_code, {});
        OBN_INFO("ft: upload (native): done result=%d", result_code);
        return true;
    }

    OBN_WARN("ft: upload failed after pipelined send result=%d wire=%.200s",
             result_code, wire_json.c_str());
    if (obn::os::socket_valid(upload_fd)) obn::tls::clear_socket_io_timeout(upload_fd);
    deliver_result(j, FT_EIO, result_code >= 0 ? result_code : 0, {});
    return true;
}

#endif // OBN_FT_TUNNEL_LOCAL

#if OBN_FT_FTPS_FALLBACK

void run_ability_job_ftp(FT_Tunnel* t, FT_Job* j)
{
    std::string body;
    {
        std::lock_guard<std::mutex> lk(t->tunnel_mu);
        if (t->ability_probed) {
            body = t->ability_cache;
        } else {
            std::vector<std::string> found;
            for (const char* p : kProbePaths) {
                if (t->ftp->cwd(p).empty()) found.emplace_back(p + 1);
            }
            if (found.empty()) {
                std::string err = t->ftp->cwd("/");
                if (!err.empty()) {
                    deliver_result(j, FT_EIO, 0, {});
                    return;
                }
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
    OBN_INFO("ft: ability (FTPS): %s", body.c_str());
    deliver_result(j, 0, 0, std::move(body));
}

void run_upload_job_ftp(FT_Tunnel* t, FT_Job* j)
{
    if (j->dest_storage.empty() || j->dest_name.empty() || j->file_path.empty()) {
        deliver_result(j, FT_EINVAL, 0, {});
        return;
    }

    std::string remote_path;
    {
        std::lock_guard<std::mutex> lk(t->tunnel_mu);
        if (t->root_is_storage) {
            remote_path = "/" + j->dest_name;
        } else {
            remote_path = "/" + j->dest_storage + "/" + j->dest_name;
        }
    }

    OBN_INFO("ft: upload (FTPS): %s -> %s", j->file_path.c_str(), remote_path.c_str());

    std::atomic<int> last_reported{-1};
    auto progress = [j, &last_reported](std::uint64_t sent, std::uint64_t total) {
        if (j->cancelled.load(std::memory_order_acquire)) return false;
        if (total == 0) return true;
        int pct = static_cast<int>(sent * 100 / total);
        if (pct == kReservedProgress) pct = 98;
        const int prev = last_reported.load(std::memory_order_relaxed);
        if (pct != prev) {
            last_reported.store(pct, std::memory_order_relaxed);
            deliver_progress(j, static_cast<double>(pct));
        }
        return true;
    };

    std::lock_guard<std::mutex> lk(t->tunnel_mu);
    std::string err = t->ftp->stor(j->file_path, remote_path, progress);
    if (!err.empty()) {
        OBN_WARN("ft: upload (FTPS): stor failed: %s", err.c_str());
        if (err == "upload cancelled") {
            deliver_result(j, FT_ECANCELLED, 0, {});
        } else {
            deliver_result(j, FT_EIO, 0, {});
        }
        return;
    }
    deliver_progress(j, 100.0);
    deliver_result(j, 0, 0, {});
}

#endif // OBN_FT_FTPS_FALLBACK

void run_ability_job(FT_Tunnel* t, FT_Job* j)
{
    if (std::string err = connect_lan_tunnel(t); !err.empty()) {
        OBN_WARN("ft: ability: connect failed: %s", err.c_str());
        deliver_result(j, FT_EIO, 0, {});
        return;
    }
#if OBN_FT_TUNNEL_LOCAL
    if (t->transport == FtTransport::Native6000) {
        if (run_ability_job_native(t, j)) return;
        OBN_WARN("ft: ability: native :6000 failed, trying FTPS fallback");
    }
#endif
#if OBN_FT_FTPS_FALLBACK
    {
        const std::string ftp_err = tunnel_ensure_ftp(t);
        if (ftp_err.empty()) {
            run_ability_job_ftp(t, j);
            return;
        }
        OBN_WARN("ft: ability: FTPS fallback failed: %s", ftp_err.c_str());
    }
#endif
    deliver_result(j, FT_EIO, 0, {});
}

void run_upload_job(FT_Tunnel* t, FT_Job* j)
{
    if (std::string err = connect_lan_tunnel(t); !err.empty()) {
        OBN_WARN("ft: upload: connect failed: %s", err.c_str());
        deliver_result(j, FT_EIO, 0, {});
        return;
    }
#if OBN_FT_TUNNEL_LOCAL
    if (t->transport == FtTransport::Native6000) {
        if (run_upload_job_native(t, j)) return;
        OBN_WARN("ft: upload: native :6000 failed, trying FTPS fallback");
    }
#endif
#if OBN_FT_FTPS_FALLBACK
    {
        const std::string ftp_err = tunnel_ensure_ftp(t);
        if (ftp_err.empty()) {
            run_upload_job_ftp(t, j);
            return;
        }
        OBN_WARN("ft: upload: FTPS fallback failed: %s", ftp_err.c_str());
    }
#endif
    deliver_result(j, FT_EIO, 0, {});
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

#endif // OBN_FT_TUNNEL_LOCAL || OBN_FT_FTPS_FALLBACK

OBN_ABI ft_err ft_tunnel_start_connect(FT_TunnelHandle* h, ft_tunnel_connect_cb cb, void* user)
{
    auto* t = reinterpret_cast<FT_Tunnel*>(h);
    if (!t) return FT_EINVAL;
    t->conn_cb   = cb;
    t->conn_user = user;

#if OBN_FT_TUNNEL_LOCAL || OBN_FT_FTPS_FALLBACK
    if (t->is_lan) {
        if (std::string err = connect_lan_tunnel(t); !err.empty()) {
            OBN_WARN("ft: start_connect: %s", err.c_str());
            if (cb) cb(user, /*ok=*/1, /*err=*/FT_EIO, err.c_str());
            if (t->status_cb) {
                t->status_cb(t->status_user, 0, /*new=*/-1, FT_EIO, err.c_str());
            }
            return FT_OK;
        }
        OBN_INFO("ft: start_connect: tunnel up (ip=%s transport=%d)",
                 t->lan.ip.c_str(), static_cast<int>(t->transport));
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

#if OBN_FT_TUNNEL_LOCAL || OBN_FT_FTPS_FALLBACK
    if (t->is_lan) {
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

#if OBN_FT_TUNNEL_LOCAL || OBN_FT_FTPS_FALLBACK
    std::lock_guard<std::mutex> lk(t->tunnel_mu);
#if OBN_FT_TUNNEL_LOCAL
    if (t->ssl) {
        obn::os::socket_t fd = t->fd;
        SSL* ssl = t->ssl;
        t->fd  = obn::os::kInvalidSocket;
        t->ssl = nullptr;
        t->tl_session.reset();
        obn::tls::close_tls(&fd, &ssl);
    }
#endif
#if OBN_FT_FTPS_FALLBACK
    if (t->ftp) {
        t->ftp->quit();
        t->ftp.reset();
    }
#endif
    t->transport = FtTransport::None;
#endif

    return FT_OK;
}

OBN_ABI ft_err ft_job_create(const char* params_json, FT_JobHandle** out)
{
    if (!out) return FT_EINVAL;
    auto* j = new FT_Job();
    OBN_INFO("ft_job_create params=%.200s", params_json ? params_json : "(null)");

#if OBN_FT_TUNNEL_LOCAL || OBN_FT_FTPS_FALLBACK
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

#if OBN_FT_TUNNEL_LOCAL || OBN_FT_FTPS_FALLBACK
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
