#include "obn/cover_cache.hpp"

#include "obn/log.hpp"
#include "obn/tunnel_upload.hpp"
#include "obn/zip_read.hpp"

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

// Bounds how long another job of the same name and plate gets a staged image.
constexpr auto kStagedMaxAge = std::chrono::hours(3);

// Plate PNGs are tens of KB; the cap keeps an odd archive from pinning memory.
constexpr std::size_t kMaxLocalThumbnailBytes = std::size_t{4} << 20;

struct StagedCover {
    std::vector<std::uint8_t> png;
    std::string               source;  // "<3mf>#<entry>", for the log
    SteadyClock::time_point   staged_at;
};

// Not used up when written: the project_file ack (task_id "0") fetches its
// own cover file before the job's task_id is reported.
std::mutex                                   g_staged_mu;
std::unordered_map<std::string, StagedCover> g_staged;

std::string staged_key(const std::string& dev_id,
                       const std::string& subtask_name,
                       int                plate_idx)
{
    return dev_id + "\x01" + subtask_name + "\x01" +
           std::to_string(plate_idx > 0 ? plate_idx : 1);
}

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

// After a failed :6000 fetch; true when a staged image became the cover.
bool write_staged(const std::string& dev_id,
                  const std::string& subtask_name,
                  int                plate_idx,
                  const std::string& version)
{
    StagedCover staged;
    {
        std::lock_guard<std::mutex> lk(g_staged_mu);
        const auto it = g_staged.find(staged_key(dev_id, subtask_name, plate_idx));
        if (it == g_staged.end()) return false;
        if (SteadyClock::now() - it->second.staged_at >= kStagedMaxAge) {
            g_staged.erase(it);
            return false;
        }
        staged = it->second;
    }
    const fs::path out = path_for(subtask_name, plate_idx, version);
    if (!write_atomic(out, staged.png)) {
        OBN_DEBUG("cover_cache: write %s failed", out.string().c_str());
        return false;
    }
    OBN_INFO("cover_cache: wrote %s (%zu bytes) from staged %s",
             out.string().c_str(), staged.png.size(), staged.source.c_str());
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
    const auto fetch_failed = [&] {
        if (!write_staged(cp.dev_id, subtask_name, plate_idx, version)) {
            mark_neg_cache(inflight);
        }
    };

    // TODO: add FTPS fallback — when :6000 is unreachable (A1 Mini and
    // other printers that don't expose the BambuTunnel port), download
    // /cache/<subtask_name>.gcode.3mf via FTPS RETR and extract
    // Metadata/plate_N.png from the zip archive instead.
    obn::tunnel_upload::Connection conn;
    std::string err;
    if (conn.connect(cp, &err) != 0) {
        OBN_DEBUG("cover_cache: :6000 connect %s: %s", cp.dev_ip.c_str(), err.c_str());
        fetch_failed();
        return;
    }

    const obn::tunnel_upload::ModelThumbnailOutcome thumb =
        conn.fetch_model_tile_thumbnail(subtask_name, plate_idx);
    if (!thumb.ok) {
        OBN_DEBUG("cover_cache: %s for '%s'",
                  thumb.error.c_str(), subtask_name.c_str());
        fetch_failed();
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

bool read_local_thumbnail(const std::string&         path_3mf,
                          int                        plate_idx,
                          std::vector<std::uint8_t>* png,
                          std::string*               entry,
                          std::string*               err)
{
    if (!png) return false;
    if (plate_idx < 1) plate_idx = 1;
    const std::string n = std::to_string(plate_idx);
    // Same order as tile_thumbnail_sub_paths() in tunnel_upload.cpp,
    // minus the printer-side "#thumbnail" alias.
    std::vector<std::string> names = {
        "Metadata/plate_" + n + ".png",
        "Metadata/plate_no_light_" + n + ".png",
    };
    if (plate_idx != 1) {
        names.push_back("Metadata/plate_1.png");
        names.push_back("Metadata/plate_no_light_1.png");
    }
    std::string first_err;
    for (const std::string& name : names) {
        std::vector<std::uint8_t> data;
        std::string               e;
        if (obn::zip::read_entry(path_3mf, name, kMaxLocalThumbnailBytes,
                                 &data, &e) && !data.empty()) {
            *png = std::move(data);
            if (entry) *entry = name;
            return true;
        }
        if (first_err.empty()) {
            first_err = name + ": " + (e.empty() ? "empty entry" : e);
        }
    }
    if (err) *err = first_err;
    return false;
}

bool stage_from_3mf(const std::string& dev_id,
                    const std::string& subtask_name,
                    const std::string& path_3mf,
                    int                plate_idx)
{
    if (subtask_name.empty()) return false;
    StagedCover staged;
    std::string entry, err;
    const bool have = !path_3mf.empty() &&
        read_local_thumbnail(path_3mf, plate_idx, &staged.png, &entry, &err);
    const auto now = SteadyClock::now();
    {
        std::lock_guard<std::mutex> lk(g_staged_mu);
        for (auto it = g_staged.begin(); it != g_staged.end();) {
            if (now - it->second.staged_at >= kStagedMaxAge) {
                it = g_staged.erase(it);
            } else {
                ++it;
            }
        }
        const std::string key = staged_key(dev_id, subtask_name, plate_idx);
        if (!have) {
            // An image staged for an earlier print of the name must not
            // become this print's cover.
            g_staged.erase(key);
        } else {
            staged.source    = path_3mf + "#" + entry;
            staged.staged_at = now;
            g_staged[key]    = staged;
        }
    }
    if (!have) {
        OBN_DEBUG("cover_cache: no plate image in %s (%s) for '%s'",
                  path_3mf.c_str(), err.c_str(), subtask_name.c_str());
        return false;
    }
    OBN_INFO("cover_cache: staged %zu bytes from %s for '%s'",
             staged.png.size(), staged.source.c_str(), subtask_name.c_str());
    return true;
}

void unstage(const std::string& dev_id,
             const std::string& subtask_name,
             int                plate_idx)
{
    std::lock_guard<std::mutex> lk(g_staged_mu);
    if (g_staged.erase(staged_key(dev_id, subtask_name, plate_idx)))
        OBN_DEBUG("cover_cache: dropped the staged image for '%s'",
                  subtask_name.c_str());
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

#ifdef OBN_TESTING
// Test hooks: one fetch run on the calling thread (ensure() runs it on a
// thread of its own), and a way to age staged images without sleeping.
void test_fetch(const obn::tunnel_upload::ConnectParams& cp,
                const std::string&                       subtask_name,
                int                                      plate_idx,
                const std::string&                       version)
{
    fetch_worker(cp, subtask_name, plate_idx, version,
                 inflight_key(subtask_name, plate_idx, version));
}

void test_age_staged(std::chrono::seconds by)
{
    std::lock_guard<std::mutex> lk(g_staged_mu);
    for (auto& kv : g_staged) kv.second.staged_at -= by;
}

std::chrono::seconds test_staged_max_age()
{
    return std::chrono::duration_cast<std::chrono::seconds>(kStagedMaxAge);
}
#endif

} // namespace obn::cover_cache
