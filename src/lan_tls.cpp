#include "obn/lan_tls.hpp"

#include "obn/lan_tls_env.hpp"
#include "obn/log.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <atomic>

#include <filesystem>

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <cerrno>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

namespace obn::lan_tls {
namespace {

std::mutex g_mu;
std::string g_config_dir;
std::string g_ca_file;
std::unordered_map<std::string, std::string> g_ip_to_serial;
std::unordered_map<std::string, std::string> g_ip_to_peer_cert;
std::atomic<bool> g_skip_warn_logged{false};

#if defined(_WIN32)
bool set_env_var(const char* key, const char* value)
{
    if (!key) return false;
    if (!value) value = "";
    const bool ok = ::SetEnvironmentVariableA(key, value) != 0;
    (void)::_putenv_s(key, value); // best-effort CRT sync for legacy getenv callers
    return ok;
}
#else
bool set_env_var(const char* key, const char* value)
{
    if (!key) return false;
    if (!value) value = "";
    return ::setenv(key, value, /*overwrite=*/1) == 0;
}
#endif

const char* env_var_get_os(const char* key)
{
    if (!key || !*key) return nullptr;
#if defined(_WIN32)
    thread_local std::string buf;
    buf.assign(32768, '\0');
    const DWORD n = ::GetEnvironmentVariableA(
        key, buf.data(), static_cast<DWORD>(buf.size()));
    if (n == 0 || n >= buf.size()) return nullptr;
    buf.resize(n);
    return buf.c_str();
#else
    const char* v = std::getenv(key);
    return (v && *v) ? v : nullptr;
#endif
}

bool is_lan_tls_ipc_key(const char* key)
{
    return key && std::strncmp(key, "OBN_LAN_TLS_", 12) == 0;
}

std::string config_dir_snapshot()
{
    std::lock_guard<std::mutex> lk(g_mu);
    return g_config_dir;
}

std::vector<std::filesystem::path> state_file_search_paths()
{
    std::vector<std::filesystem::path> out;
    auto add = [&](const std::filesystem::path& base) {
        if (base.empty()) return;
        out.push_back(base / kLanTlsStateFile);
    };
    if (const std::string cfg = config_dir_snapshot(); !cfg.empty()) add(cfg);
    if (const char* cfg = env_var_get_os(kEnvConfigDir)) add(cfg);
#if defined(_WIN32)
    if (const char* appdata = std::getenv("APPDATA")) {
        add(std::filesystem::path(appdata) / "OrcaSlicer");
        add(std::filesystem::path(appdata) / "BambuStudio");
    }
#else
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME")) {
        add(std::filesystem::path(xdg) / "OrcaSlicer");
        add(std::filesystem::path(xdg) / "BambuStudio");
    }
    if (const char* home = std::getenv("HOME")) {
        add(std::filesystem::path(home) / ".config" / "OrcaSlicer");
        add(std::filesystem::path(home) / ".config" / "BambuStudio");
    }
#endif
    return out;
}

bool apply_state_line(const std::string& line)
{
    if (line.empty() || line[0] == '#') return false;
    const auto eq = line.find('=');
    if (eq == std::string::npos || eq == 0) return false;
    const std::string key = line.substr(0, eq);
    const std::string val = line.substr(eq + 1);
    if (key.empty()) return false;
    if (key != kEnvConfigDir && !is_lan_tls_ipc_key(key.c_str())) return false;
    return set_env_var(key.c_str(), val.c_str());
}

#if !defined(_WIN32)
void restrict_user_readwrite(const std::filesystem::path& path)
{
    if (path.empty()) return;
    if (::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        OBN_WARN("lan_tls: chmod(0600) failed on %s: %s",
                 path.c_str(), std::strerror(errno));
    }
}
#endif

void hydrate_env_from_state_file_once()
{
    static std::once_flag once;
    std::call_once(once, []() {
        for (const auto& path : state_file_search_paths()) {
            std::error_code ec;
            if (!std::filesystem::is_regular_file(path, ec)) continue;
            std::ifstream in(path);
            if (!in) continue;
            std::string line;
            while (std::getline(in, line)) {
                (void)apply_state_line(line);
            }
            OBN_INFO("lan_tls: hydrated env from %s", path.string().c_str());
            return;
        }
    });
}

void write_state_file_locked()
{
    if (g_config_dir.empty()) return;
    namespace fs = std::filesystem;
    const fs::path out = fs::path(g_config_dir) / kLanTlsStateFile;
    const fs::path tmp = out.string() + ".tmp";
    std::ofstream f(tmp, std::ios::binary);
    if (!f) {
        OBN_WARN("lan_tls: cannot write %s", tmp.string().c_str());
        return;
    }
    f << "# Open Bamboo Networking LAN TLS IPC (auto-generated)\n";
    if (!g_ca_file.empty()) {
        f << kEnvCaFile << '=' << g_ca_file << '\n';
    }
    for (const auto& [ip, serial] : g_ip_to_serial) {
        if (serial.empty()) continue;
        f << env_key_for_ip(ip) << '=' << serial << '\n';
    }
    for (const auto& [ip, path] : g_ip_to_peer_cert) {
        if (path.empty()) continue;
        f << peer_env_key_for_ip(ip) << '=' << path << '\n';
    }
    if (!f) {
        OBN_WARN("lan_tls: write failed for %s", tmp.string().c_str());
        f.close();
        std::error_code rmec;
        fs::remove(tmp, rmec);
        return;
    }
    f.close();
    std::error_code ec;
#if defined(_WIN32)
    fs::remove(out, ec);
#endif
    fs::rename(tmp, out, ec);
    if (ec) {
        OBN_WARN("lan_tls: rename %s -> %s failed", tmp.string().c_str(),
                 out.string().c_str());
        std::error_code rmec;
        fs::remove(tmp, rmec);
        return;
    }
#if !defined(_WIN32)
    restrict_user_readwrite(out);
#endif
    OBN_TRACE("lan_tls: wrote %s", out.string().c_str());
}

void sync_ca_env_locked()
{
    if (g_ca_file.empty()) {
        (void)set_env_var(kEnvCaFile, "");
        return;
    }
    if (!set_env_var(kEnvCaFile, g_ca_file.c_str())) {
        OBN_WARN("lan_tls: setenv(%s) failed", kEnvCaFile);
    }
}

void sync_ip_env_locked(const std::string& ip, const std::string& serial)
{
    const std::string key = env_key_for_ip(ip);
    if (!set_env_var(key.c_str(), serial.c_str())) {
        OBN_WARN("lan_tls: setenv(%s) failed", key.c_str());
    }
}

void sync_peer_env_locked(const std::string& ip, const std::string& path)
{
    const std::string key = peer_env_key_for_ip(ip);
    if (!set_env_var(key.c_str(), path.c_str())) {
        OBN_WARN("lan_tls: setenv(%s) failed", key.c_str());
    }
}

void sync_registry_locked()
{
    sync_ca_env_locked();
    for (const auto& [ip, serial] : g_ip_to_serial) sync_ip_env_locked(ip, serial);
    for (const auto& [ip, path] : g_ip_to_peer_cert) sync_peer_env_locked(ip, path);
    write_state_file_locked();
}

void warn_skip_once()
{
    if (g_skip_warn_logged.exchange(true)) return;
    OBN_WARN("OBN_SKIP_TLS_VERIFY set — printer TLS verification disabled");
}

} // namespace

const char* env_var_get(const char* key)
{
    if (!key || !*key) return nullptr;
    if (const char* v = env_var_get_os(key)) return v;
    if (!is_lan_tls_ipc_key(key)) return nullptr;
    hydrate_env_from_state_file_once();
    return env_var_get_os(key);
}

bool verify_enabled()
{
    if (skip_verify_from_env()) {
        warn_skip_once();
        return false;
    }
    return true;
}

void registry_set_config_dir(const std::string& dir)
{
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_config_dir == dir) return;
    g_config_dir = dir;
    if (!dir.empty()) {
        (void)set_env_var(kEnvConfigDir, dir.c_str());
    }
    sync_registry_locked();
    OBN_DEBUG("lan_tls: config_dir=%s", dir.c_str());
}

void registry_set_ca_file(const std::string& path)
{
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_ca_file == path) return;
    g_ca_file = path;
    sync_ca_env_locked();
    write_state_file_locked();
    if (path.empty()) {
        OBN_WARN("lan_tls: ca_file empty (printer.cer missing?)");
    } else {
        OBN_INFO("lan_tls: ca_file=%s", path.c_str());
    }
}

void registry_put_ip_serial(const std::string& ip, const std::string& serial)
{
    if (ip.empty() || serial.empty()) return;
    std::lock_guard<std::mutex> lk(g_mu);
    const auto it = g_ip_to_serial.find(ip);
    if (it != g_ip_to_serial.end() && it->second == serial) return;
    g_ip_to_serial[ip] = serial;
    sync_ip_env_locked(ip, serial);
    write_state_file_locked();
    OBN_DEBUG("lan_tls: ip=%s serial=%s", ip.c_str(), serial.c_str());
}

void registry_set_peer_cert(const std::string& ip, const std::string& path)
{
    if (ip.empty()) return;
    std::lock_guard<std::mutex> lk(g_mu);
    if (path.empty()) {
        if (g_ip_to_peer_cert.erase(ip) == 0) return;
    } else {
        const auto it = g_ip_to_peer_cert.find(ip);
        if (it != g_ip_to_peer_cert.end() && it->second == path) return;
        g_ip_to_peer_cert[ip] = path;
    }
    sync_peer_env_locked(ip, path);
    write_state_file_locked();
    OBN_DEBUG("lan_tls: ip=%s peer_cert=%s", ip.c_str(), path.c_str());
}

bool configure_lan_ssl_verify(SSL_CTX*           ctx,
                              const std::string& ca_file,
                              const std::string& peer_cert_file,
                              std::string*       err)
{
    if (!ctx) {
        if (err) *err = "null SSL_CTX";
        return false;
    }
    if (ca_file.empty()) {
        if (err) *err = "empty ca_file";
        return false;
    }
    if (::SSL_CTX_load_verify_locations(ctx, ca_file.c_str(), nullptr) != 1) {
        if (err) *err = "load_verify_locations(ca)";
        return false;
    }
    if (!peer_cert_file.empty()) {
        if (::SSL_CTX_load_verify_locations(ctx, peer_cert_file.c_str(), nullptr) != 1) {
            if (err) *err = "load_verify_locations(peer)";
            return false;
        }
    }
    if (X509_VERIFY_PARAM* vpm = ::SSL_CTX_get0_param(ctx)) {
        const unsigned long flags = ::X509_VERIFY_PARAM_get_flags(vpm);
        ::X509_VERIFY_PARAM_set_flags(vpm, flags | X509_V_FLAG_PARTIAL_CHAIN);
    }
    ::SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    return true;
}

std::string read_pem_file(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::string merged_trust_bundle_path(const std::string& ca_file,
                                     const std::string& peer_cert_file)
{
    if (peer_cert_file.empty()) return ca_file;
    std::error_code ec;
    if (!std::filesystem::is_regular_file(ca_file, ec)
        || !std::filesystem::is_regular_file(peer_cert_file, ec)) {
        return ca_file;
    }
    const std::string ca   = read_pem_file(ca_file);
    const std::string peer = read_pem_file(peer_cert_file);
    if (ca.empty() || peer.empty()) return ca_file;

    std::ostringstream name;
    name << "obn-trust-"
#if !defined(_WIN32)
         << ::getpid() << '-'
#endif
         << std::chrono::steady_clock::now().time_since_epoch().count() << ".pem";
    std::filesystem::path out =
        std::filesystem::temp_directory_path(ec) / name.str();
    if (out.empty()) return ca_file;

    std::ofstream f(out, std::ios::binary);
    if (!f) return ca_file;
    f << ca;
    if (!ca.empty() && ca.back() != '\n') f << '\n';
    f << peer;
    if (!peer.empty() && peer.back() != '\n') f << '\n';
    if (!f) return ca_file;
    return out.string();
}

std::string registry_ca_file()
{
    std::lock_guard<std::mutex> lk(g_mu);
    return g_ca_file;
}

std::optional<std::string> registry_lookup_serial(const std::string& ip)
{
    std::lock_guard<std::mutex> lk(g_mu);
    auto it = g_ip_to_serial.find(ip);
    if (it == g_ip_to_serial.end()) return std::nullopt;
    return it->second;
}

const char* resolve_lan_ca_file()
{
    return env_var_get(kEnvCaFile);
}

const char* resolve_lan_peer_cert(const char* ip, const char* /*serial*/)
{
    return peer_cert_path_for_ip(ip);
}

} // namespace obn::lan_tls
