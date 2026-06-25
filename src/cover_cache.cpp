#include "obn/cover_cache.hpp"

#include "obn/log.hpp"
#include "obn/tunnel_upload.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace obn::cover_cache {

namespace {

std::uint32_t fnv1a_32(const std::string& s)
{
    std::uint32_t h = 2166136261u;
    for (unsigned char c : s) { h ^= c; h *= 16777619u; }
    return h;
}

std::mutex                      g_inflight_mu;
std::unordered_set<std::string> g_inflight;

using SteadyClock = std::chrono::steady_clock;
constexpr auto kNegCacheTimeout = std::chrono::seconds(60);

std::unordered_map<std::string, SteadyClock::time_point> g_neg_cache;

std::string inflight_key(const std::string& name, int plate, const std::string& version)
{
    return std::to_string(plate) + "\x01" + name + "\x01" + version;
}

bool claim_inflight(const std::string& key)
{
    std::lock_guard<std::mutex> lk(g_inflight_mu);
    return g_inflight.insert(key).second;
}

void release_inflight(const std::string& key)
{
    std::lock_guard<std::mutex> lk(g_inflight_mu);
    g_inflight.erase(key);
}

bool write_atomic(const fs::path& final_path,
                  const std::vector<std::uint8_t>& bytes)
{
    fs::path tmp = final_path;
    tmp += ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        if (!f) return false;
    }
    std::error_code ec;
    fs::rename(tmp, final_path, ec);
    if (ec) {
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

void mark_neg_cache(const std::string& key)
{
    std::lock_guard<std::mutex> lk(g_inflight_mu);
    g_neg_cache[key] = SteadyClock::now();
}

bool is_neg_cached(const std::string& key)
{
    auto it = g_neg_cache.find(key);
    if (it == g_neg_cache.end()) return false;
    if (SteadyClock::now() - it->second >= kNegCacheTimeout) {
        g_neg_cache.erase(it);
        return false;
    }
    return true;
}

void fetch_worker(obn::tunnel_upload::ConnectParams cp,
                  std::string subtask_name,
                  int         plate_idx,
                  std::string version,
                  std::string inflight)
{
    struct ScopeRelease {
        std::string key;
        ~ScopeRelease() { release_inflight(key); }
    } release{inflight};

    // TODO: add FTPS fallback — when :6000 is unreachable (A1 Mini and
    // other printers that don't expose the BambuTunnel port), download
    // /cache/<subtask_name>.gcode.3mf via FTPS RETR and extract
    // Metadata/plate_N.png from the zip archive instead.
    obn::tunnel_upload::Connection conn;
    std::string err;
    if (conn.connect(cp, &err) != 0) {
        OBN_DEBUG("cover_cache: :6000 connect %s: %s", cp.dev_ip.c_str(), err.c_str());
        mark_neg_cache(inflight);
        return;
    }

    const obn::tunnel_upload::ModelThumbnailOutcome thumb =
        conn.fetch_model_tile_thumbnail(subtask_name, plate_idx);
    if (!thumb.ok) {
        OBN_DEBUG("cover_cache: %s for '%s'",
                  thumb.error.c_str(), subtask_name.c_str());
        mark_neg_cache(inflight);
        return;
    }

    fs::path out = path_for(subtask_name, plate_idx, version);
    if (!write_atomic(out, thumb.data)) {
        OBN_DEBUG("cover_cache: write %s failed", out.string().c_str());
        mark_neg_cache(inflight);
        return;
    }
    OBN_INFO("cover_cache: wrote %s (%zu bytes) from %s",
             out.string().c_str(), thumb.data.size(), thumb.path.c_str());
}

} // namespace

std::string temp_dir()
{
    if (const char* v = std::getenv("OBN_COVER_DIR")) {
        if (*v) return v;
    }
    std::error_code ec;
    fs::path base = fs::temp_directory_path(ec);
    if (ec || base.empty()) {
#ifdef _WIN32
        base = "C:\\Windows\\Temp";
#else
        base = "/tmp";
#endif
    }
    fs::path dir = base / "obn-covers";
    fs::create_directories(dir, ec);
    return dir.string();
}

std::string path_for(const std::string& subtask_name,
                     int                plate_idx,
                     const std::string& version)
{
    if (subtask_name.empty()) return {};
    std::string keyed = subtask_name;
    if (!version.empty()) {
        keyed.push_back('\x01');
        keyed.append(version);
    }
    std::uint32_t h = fnv1a_32(keyed);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "cover-%08x-p%d.png", h,
                  plate_idx > 0 ? plate_idx : 1);
    return (fs::path(temp_dir()) / buf).string();
}

void ensure(const std::string& host,
            const std::string& dev_id,
            const std::string& user,
            const std::string& password,
            const std::string& subtask_name,
            int                plate_idx,
            const std::string& version)
{
    if (host.empty() || subtask_name.empty()) return;

    std::string target = path_for(subtask_name, plate_idx, version);
    if (target.empty()) return;
    std::error_code ec;
    if (fs::exists(target, ec) && !ec) {
        auto sz = fs::file_size(target, ec);
        if (!ec && sz > 0) return;
    }

    std::string key = inflight_key(subtask_name, plate_idx, version);
    {
        std::lock_guard<std::mutex> lk(g_inflight_mu);
        if (is_neg_cached(key)) return;
    }
    if (!claim_inflight(key)) return;

    obn::tunnel_upload::ConnectParams cp;
    cp.dev_ip   = host;
    cp.dev_id   = dev_id;
    cp.password = password;
    cp.username = user.empty() ? "bblp" : user;

    std::thread(fetch_worker, std::move(cp), subtask_name, plate_idx, version,
                std::move(key)).detach();
}

} // namespace obn::cover_cache
