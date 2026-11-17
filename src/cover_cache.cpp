#include "obn/cover_cache.hpp"

#include "obn/ftps.hpp"
#include "obn/log.hpp"
#include "obn/tunnel_upload.hpp"
#include "obn/zip_read.hpp"

#include <algorithm>
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

// True when a staged image became the cover.
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

long long ms_since(SteadyClock::time_point t0)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               SteadyClock::now() - t0).count();
}

// FTPS fallback for printers whose :6000 CTRL service is gone (P1S
// firmware 01.10.00.15 reports file.local=none and closes the session):
// download the print's .3mf over FTPS and pull this plate's image out of
// the zip. Returns empty when no candidate file is on the printer or the
// archive carries no plate image.
std::vector<std::uint8_t> ftps_fetch_plate_png(
    const obn::tunnel_upload::ConnectParams& cp,
    const std::string&                       ca_file,
    const std::string&                       model_key,
    const std::string&                       subtask_name,
    int                                      plate_idx,
    SteadyClock::time_point                  t0)
{
    obn::ftps::ConnectConfig cfg;
    cfg.host     = cp.dev_ip;
    cfg.port     = 990;
    cfg.username = cp.username.empty() ? std::string{"bblp"} : cp.username;
    cfg.password = cp.password;
    cfg.ca_file             = ca_file;
    cfg.tls_verify_hostname = cp.dev_id;
    cfg.use_tls             = true;

    obn::ftps::Client cli;
    std::string err = cli.connect(cfg);
    if (!err.empty()) {
        // Some units expose plain FTP only (see obn/ftps.hpp).
        cfg.use_tls = false;
        cfg.port    = 21;
        std::string plain = cli.connect(cfg);
        if (!plain.empty()) {
            OBN_DEBUG("cover_cache: FTPS connect %s failed (tls: %s, plain: %s)",
                      cp.dev_ip.c_str(), err.c_str(), plain.c_str());
            return {};
        }
    }

    // Where dispatched prints live: FTPS root (hybrid LAN prints) and
    // /cache (cloud-dispatched downloads).
    std::vector<std::string> names;
    if (!model_key.empty()) names.push_back(model_key);
    if (!subtask_name.empty()) {
        names.push_back(subtask_name + ".gcode.3mf");
        names.push_back(subtask_name);
    }
    std::vector<std::string> candidates;
    for (const char* dir : {"", "/cache"}) {
        for (const auto& name : names) {
            std::string p = std::string(dir) + "/" + name;
            if (std::find(candidates.begin(), candidates.end(), p) ==
                candidates.end())
                candidates.push_back(std::move(p));
        }
    }

    constexpr std::uint64_t kMaxBytes = 512ull * 1024 * 1024;
    for (const auto& path : candidates) {
        std::uint64_t sz = 0;
        if (cli.size(path, &sz).empty() && sz > kMaxBytes) {
            OBN_DEBUG("cover_cache: FTPS %s is %llu bytes, skipping",
                      path.c_str(), static_cast<unsigned long long>(sz));
            continue;
        }
        const fs::path tmp =
            fs::path(temp_dir()) /
            ("ftps-" + std::to_string(fnv1a_32(path)) + "-" +
             std::to_string(plate_idx) + ".3mf");
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) continue;
        std::uint64_t total   = 0;
        bool          too_big = false;
        std::string   rerr =
            cli.retr(path, [&](const void* data, std::size_t len) {
                total += len;
                if (total > kMaxBytes) {
                    too_big = true;
                    return false;
                }
                out.write(static_cast<const char*>(data),
                          static_cast<std::streamsize>(len));
                return out.good();
            });
        out.close();
        if (!rerr.empty() || too_big) {
            fs::remove(tmp);
            if (too_big) {
                OBN_DEBUG("cover_cache: FTPS %s over %llu bytes, skipping",
                          path.c_str(),
                          static_cast<unsigned long long>(kMaxBytes));
            }
            continue;
        }
        std::vector<std::uint8_t> png;
        std::string               entry, eerr;
        if (read_local_thumbnail(tmp.string(), plate_idx, &png, &entry,
                                 &eerr) &&
            !png.empty()) {
            OBN_DEBUG("cover_cache: FTPS %s -> %s (%zu bytes) in %lld ms",
                      path.c_str(), entry.c_str(), png.size(), ms_since(t0));
            fs::remove(tmp);
            cli.quit();
            return png;
        }
        OBN_DEBUG("cover_cache: FTPS %s downloaded but has no plate image: %s",
                  path.c_str(), eerr.c_str());
        fs::remove(tmp);
    }
    cli.quit();
    return {};
}

// Sources, best first: the archive this plugin uploaded for the print (no
// network, always this plate's image), the printer's copy over :6000, then
// the printer's copy over FTPS (firmware that dropped the :6000 CTRL
// service, e.g. P1S 01.10.00.15).
void fetch_worker(obn::tunnel_upload::ConnectParams cp,
                  std::string ca_file,
                  std::string subtask_name,
                  std::string model_key,
                  int         plate_idx,
                  std::string version,
                  std::string inflight)
{
    struct ScopeRelease {
        std::string key;
        ~ScopeRelease() { release_inflight(key); }
    } release{inflight};
    const auto t0 = SteadyClock::now();

    if (write_staged(cp.dev_id, subtask_name, plate_idx, version)) return;

    OBN_DEBUG("cover_cache: fetching '%s' plate %d ver=%s from %s over :6000",
              subtask_name.c_str(), plate_idx,
              version.empty() ? "-" : version.c_str(), cp.dev_ip.c_str());
    std::vector<std::uint8_t> png;
    std::string               src;
    {
        obn::tunnel_upload::Connection conn;
        std::string                    err;
        if (conn.connect(cp, &err) != 0) {
            OBN_DEBUG("cover_cache: :6000 connect %s failed after %lld ms: %s",
                      cp.dev_ip.c_str(), ms_since(t0), err.c_str());
        } else {
            // COVER-01: match the listing on the chosen model_key (gcode_file
            // basename when the frame carried one); empty falls back to
            // subtask_name, i.e. the pre-COVER-01 behavior. The cache identity
            // below (path_for, inflight key) stays keyed on subtask_name.
            const obn::tunnel_upload::ModelThumbnailOutcome thumb =
                conn.fetch_model_tile_thumbnail(
                    model_key.empty() ? subtask_name : model_key, plate_idx);
            if (thumb.ok) {
                png = thumb.data;
                src = thumb.path;
            } else {
                OBN_DEBUG("cover_cache: %s for '%s' (model_key '%s') plate %d "
                          "after %lld ms",
                          thumb.error.c_str(), subtask_name.c_str(),
                          model_key.c_str(), plate_idx, ms_since(t0));
            }
        }
    }

    if (png.empty()) {
        png = ftps_fetch_plate_png(cp, ca_file, model_key, subtask_name,
                                   plate_idx, t0);
        if (!png.empty()) src = "FTPS";
    }

    if (png.empty()) {
        OBN_DEBUG("cover_cache: no cover for '%s' for the next %lld s",
                  subtask_name.c_str(),
                  static_cast<long long>(kNegCacheTimeout.count()));
        mark_neg_cache(inflight);
        return;
    }

    fs::path out = path_for(subtask_name, plate_idx, version);
    if (!write_atomic(out, png)) {
        OBN_DEBUG("cover_cache: write %s failed", out.string().c_str());
        mark_neg_cache(inflight);
        return;
    }
    OBN_INFO("cover_cache: wrote %s (%zu bytes) from %s in %lld ms",
             out.string().c_str(), png.size(), src.c_str(), ms_since(t0));
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
    // Same order as plate_image_sub_paths() in tunnel_upload.cpp. Only this
    // plate's images: another plate's would be the wrong cover.
    const std::vector<std::string> names = {
        "Metadata/plate_" + n + ".png",
        "Metadata/plate_no_light_" + n + ".png",
    };
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
            const std::string& model_key,
            int                plate_idx,
            const std::string& version,
            const std::string& ca_file)
{
    // Unchanged guard: identity (subtask_name) must exist for the cache
    // path, inflight key and Studio URL — model_key never widens this.
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

    std::thread(fetch_worker, std::move(cp), ca_file, subtask_name, model_key,
                plate_idx, version, std::move(key)).detach();
}

#ifdef OBN_TESTING
// Test hooks: one fetch run on the calling thread (ensure() runs it on a
// thread of its own), and a way to age staged images without sleeping.
void test_fetch(const obn::tunnel_upload::ConnectParams& cp,
                const std::string&                       subtask_name,
                int                                      plate_idx,
                const std::string&                       version)
{
    fetch_worker(cp, /*ca_file=*/{}, subtask_name, /*model_key=*/"",
                 plate_idx, version,
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
