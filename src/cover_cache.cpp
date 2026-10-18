#include "obn/cover_cache.hpp"

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

// Covers staged by stage_from_3mf(), keyed by dev_id + '\x01' +
// subtask_name.
//
// A stage is for exactly one job: the one its project_file starts. The
// printer names that job only in its reports, by task_id. The task_ids it
// reported before the stage was made are earlier jobs (the baseline; an
// idle printer reports its last job's, or "" after a restart, which LAN
// reports pass to note_no_task_id() as a fresh report that adds no id).
// Every LAN or cloud report with a task_id goes through note_task_id():
// once the stage is active (project_file published), the first task_id
// outside the baseline is the job's and becomes the stage's owner; a
// second new one means the owner ended without taking its cover, and the
// stage is retired. A report with the owner's task_id and this name and
// plate takes the image, under that report's cache file (also when the
// write fails, the stage is used up). Reports without a task_id never take
// it: they cannot be told apart from another job's, and Studio asks for the
// cover of the report that carries the task_id (on an H2C the push right
// after this plugin's project_file still has task_id "0"; the next one has
// the new id).
//
// Whenever the owner can no longer be told, the stage becomes a tombstone
// (no image, never bound or taken) that also keeps further submissions of
// the name from staging for kStageTtl from the latest such event, since a
// report could belong to any of them: at activation without a fresh
// baseline (no report with a task_id, empty included, within
// kBaselineMaxAge: reconnect, quiet printer) or after a new task_id
// seen while project_file was being signed and sent; before an owner is
// known, on a LAN disconnect (reports_interrupted()), a gap of more than
// kBaselineMaxAge in the printer's reports, or kOwnerDeadline without the
// job's task_id (its refusal was lost); on another submission of the name
// while a stage or tombstone of it exists; on a submission without a usable
// image. A pending stage only latches ambiguity and is dropped at
// activation. The case left: the first task_id outside the baseline within
// kOwnerDeadline belongs to another job of the same name and plate (another
// client's, say, while this submission's refusal went missing).
//
// A refusal of that project_file drops the stage (drop_submission()), also
// before activation. kStageTtl bounds how long a stage waits: for its job's
// first report (refusal not seen), or, once owned (an owned stage survives
// a reconnect), for a report with its name and plate.
constexpr auto kStageTtl = std::chrono::minutes(2);

// An H2C sends a full push_status about once a second, idle or printing,
// and reports a new job's task_id within about two seconds of its
// project_file.
constexpr auto kBaselineMaxAge = std::chrono::seconds(10);
constexpr auto kOwnerDeadline  = std::chrono::seconds(30);

// Studio and Orca write 512x512 plate PNGs (tens of KB); the cap only
// keeps an odd archive from pinning memory in the stage.
constexpr std::size_t kMaxLocalThumbnailBytes = std::size_t{4} << 20;

struct StagedCover {
    std::vector<std::uint8_t> png;
    std::string               source;  // "<3mf>#<entry>", for the log
    int                       plate_idx = 1;
    // task_ids the printer had reported when the stage was made: earlier
    // jobs, never this one.
    std::vector<std::string>  stale_task_ids;
    bool                      active = false;     // project_file published
    bool                      ambiguous = false;  // new task_id or reports interrupted
    bool                      blocked = false;    // tombstone, see below
    std::string               owner;              // the job's task_id
    std::string               sequence_id;        // of that project_file
    SteadyClock::time_point   staged_at;
    SteadyClock::time_point   activated_at;
};

void make_tombstone(StagedCover* st, SteadyClock::time_point now)
{
    *st           = StagedCover{};
    st->blocked   = true;
    st->staged_at = now;
}

std::mutex                                   g_stage_mu;
std::unordered_map<std::string, StagedCover> g_staged;
// Recent task_ids per printer (note_task_id()), whatever the subtask name,
// and when the printer last sent a report with a task_id, empty included.
struct TaskHistory {
    std::vector<std::string> ids;
    SteadyClock::time_point  last_report;
};
std::unordered_map<std::string, TaskHistory> g_task_history;
constexpr std::size_t kMaxSeenPrinters = 64;
constexpr std::size_t kMaxSeenIdsPerPrinter = 8;

bool is_stage_of(const std::string& key, const std::string& dev_id)
{
    return key.compare(0, dev_id.size() + 1, dev_id + "\x01") == 0;
}

// Serialises the final rename of a cover so a staged image and a :6000
// fetch for the same file cannot interleave.
std::mutex g_publish_mu;

std::string stage_key(const std::string& dev_id, const std::string& name)
{
    return dev_id + "\x01" + name;
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
                  const std::vector<std::uint8_t>& bytes,
                  const char* tmp_suffix = ".tmp")
{
    fs::path tmp = final_path;
    tmp += tmp_suffix;
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

// Gives the staged cover for (dev_id, subtask_name) to this report if it
// carries the stage owner's task_id (see StagedCover): writes it to
// `target` unless a cover is already there, and retires the stage. Returns
// true when the cover is in place (written or kept); false when the report
// is not the owner's or the write failed (the stage is retired then too,
// the job's own :6000 fetch may still find a cover). The image is written
// while the stage is still held, so drop_submission() cannot race a write,
// and it takes precedence over a :6000 fetch finishing for the same file.
bool take_stage(const std::string& dev_id,
                const std::string& subtask_name,
                int                plate_idx,
                const std::string& task_id,
                const std::string& target,
                bool               target_exists)
{
    if (task_id.empty()) return false;
    std::lock_guard<std::mutex> lk(g_stage_mu);
    auto it = g_staged.find(stage_key(dev_id, subtask_name));
    if (it == g_staged.end()) return false;
    const StagedCover& st = it->second;
    if (SteadyClock::now() - st.staged_at >= kStageTtl) {
        g_staged.erase(it);
        return false;
    }
    if (!st.active || st.owner != task_id) return false;
    if (st.plate_idx != (plate_idx > 0 ? plate_idx : 1)) return false;
    bool in_place = true;
    if (!target_exists) {
        std::lock_guard<std::mutex> plk(g_publish_mu);
        in_place = write_atomic(target, st.png, ".staged.tmp");
        if (in_place) {
            OBN_INFO("cover_cache: wrote %s (%zu bytes) from %s",
                     target.c_str(), st.png.size(), st.source.c_str());
        } else {
            OBN_DEBUG("cover_cache: write %s failed, stage dropped",
                      target.c_str());
        }
    }
    g_staged.erase(it);
    return in_place;
}

// Final write of a fetched cover. Keeps a cover that is already there,
// i.e. a staged one written while the fetch was running. Returns 1 when it
// wrote, 0 when it kept the existing file, -1 on a write error.
int publish_fetched(const fs::path& out, const std::vector<std::uint8_t>& data)
{
    std::lock_guard<std::mutex> lk(g_publish_mu);
    std::error_code ec;
    if (fs::exists(out, ec) && !ec && fs::file_size(out, ec) > 0 && !ec) {
        return 0;
    }
    return write_atomic(out, data) ? 1 : -1;
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
    const int published = publish_fetched(out, thumb.data);
    if (published < 0) {
        OBN_DEBUG("cover_cache: write %s failed", out.string().c_str());
        mark_neg_cache(inflight);
        return;
    }
    if (published == 0) {
        OBN_DEBUG("cover_cache: kept %s written meanwhile", out.string().c_str());
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
                    int                plate_idx,
                    const std::string& sequence_id)
{
    if (subtask_name.empty()) return false;
    const std::string key = stage_key(dev_id, subtask_name);
    StagedCover staged;
    std::string entry, err;
    if (path_3mf.empty() || sequence_id.empty() ||
        !read_local_thumbnail(path_3mf, plate_idx, &staged.png, &entry, &err)) {
        OBN_DEBUG("cover_cache: no plate image in %s (%s) for '%s'",
                  path_3mf.c_str(), err.c_str(), subtask_name.c_str());
        // This submission is not staged, but its job reports like any:
        // neither an earlier stage of the name nor a later one may go to it.
        std::lock_guard<std::mutex> lk(g_stage_mu);
        make_tombstone(&g_staged[key], SteadyClock::now());
        return false;
    }
    staged.source      = path_3mf + "#" + entry;
    staged.plate_idx   = plate_idx > 0 ? plate_idx : 1;
    staged.sequence_id = sequence_id;
    staged.staged_at   = SteadyClock::now();
    OBN_INFO("cover_cache: staged %zu bytes from %s for '%s'",
             staged.png.size(), staged.source.c_str(), subtask_name.c_str());

    std::lock_guard<std::mutex> lk(g_stage_mu);
    for (auto it = g_staged.begin(); it != g_staged.end();) {
        if (staged.staged_at - it->second.staged_at >= kStageTtl) {
            it = g_staged.erase(it);
        } else {
            ++it;
        }
    }
    // An earlier submission of the name still waiting for its job (or a
    // tombstone of several): a report could belong to any of them.
    const auto earlier = g_staged.find(key);
    if (earlier != g_staged.end()) {
        OBN_DEBUG("cover_cache: '%s' submitted again before its cover was "
                  "placed, no staged cover until %lld s from now",
                  subtask_name.c_str(),
                  static_cast<long long>(
                      std::chrono::duration_cast<std::chrono::seconds>(kStageTtl)
                          .count()));
        make_tombstone(&earlier->second, staged.staged_at);
        return false;
    }
    const auto seen = g_task_history.find(dev_id);
    if (seen != g_task_history.end()) staged.stale_task_ids = seen->second.ids;
    g_staged[key] = std::move(staged);
    return true;
}

void activate_stage(const std::string& dev_id, const std::string& subtask_name,
                    const std::string& sequence_id)
{
    std::lock_guard<std::mutex> lk(g_stage_mu);
    const auto it = g_staged.find(stage_key(dev_id, subtask_name));
    if (it == g_staged.end() || it->second.sequence_id != sequence_id) return;
    const auto seen = g_task_history.find(dev_id);
    // Without a recent report the remembered task_ids may be out of date.
    const char* why = nullptr;
    if (it->second.ambiguous) {
        why = "a new task_id or reports interrupted while project_file was sent";
    } else if (seen == g_task_history.end() ||
               SteadyClock::now() - seen->second.last_report > kBaselineMaxAge) {
        why = "no recent task_id report";
    }
    const auto now = SteadyClock::now();
    if (why) {
        OBN_DEBUG("cover_cache: stage for '%s' dropped: %s", subtask_name.c_str(),
                  why);
        make_tombstone(&it->second, now);
        return;
    }
    it->second.active       = true;
    it->second.activated_at = now;
}

void drop_submission(const std::string& dev_id, const std::string& sequence_id)
{
    if (sequence_id.empty()) return;
    std::lock_guard<std::mutex> lk(g_stage_mu);
    for (auto it = g_staged.begin(); it != g_staged.end(); ++it) {
        if (it->second.sequence_id == sequence_id && is_stage_of(it->first, dev_id)) {
            OBN_DEBUG("cover_cache: stage of project_file %s dropped",
                      sequence_id.c_str());
            g_staged.erase(it);
            return;
        }
    }
}

void note_project_file(const std::string& dev_id, const std::string& subtask_name,
                       const std::string& sequence_id)
{
    if (subtask_name.empty()) return;
    std::lock_guard<std::mutex> lk(g_stage_mu);
    const std::string key = stage_key(dev_id, subtask_name);
    const auto it = g_staged.find(key);
    if (it != g_staged.end() && !it->second.blocked && !sequence_id.empty() &&
        it->second.sequence_id == sequence_id) {
        return;  // the submission this stage was made for
    }
    make_tombstone(&g_staged[key], SteadyClock::now());
}

void reports_interrupted(const std::string& dev_id)
{
    std::lock_guard<std::mutex> lk(g_stage_mu);
    const auto now = SteadyClock::now();
    for (auto& kv : g_staged) {
        StagedCover& st = kv.second;
        if (!is_stage_of(kv.first, dev_id) || st.blocked || !st.owner.empty()) {
            continue;
        }
        if (st.active) {
            OBN_DEBUG("cover_cache: reports interrupted before the job's task_id, "
                      "stage dropped");
            make_tombstone(&st, now);
        } else {
            st.ambiguous = true;
        }
    }
    // The task_ids seen so far may be out of date: the next stage needs a
    // report received after this before it can be activated.
    const auto h = g_task_history.find(dev_id);
    if (h != g_task_history.end()) h->second.last_report = SteadyClock::time_point{};
}

namespace {

// One report of `dev_id`: the timing rules for every report, then, when it
// carries a task_id, the owner rules.
void note_report(const std::string& dev_id, const std::string& task_id)
{
    std::lock_guard<std::mutex> lk(g_stage_mu);
    const auto now  = SteadyClock::now();
    const auto prev = g_task_history.find(dev_id);
    const bool gap  = prev == g_task_history.end() ||
                     now - prev->second.last_report > kBaselineMaxAge;
    for (auto it = g_staged.begin(); it != g_staged.end();) {
        StagedCover& st = it->second;
        const auto& stale = st.stale_task_ids;
        if (!is_stage_of(it->first, dev_id) || st.blocked) {
            ++it;
        } else if (st.owner.empty() && st.active &&
                   (gap || now - st.activated_at > kOwnerDeadline)) {
            OBN_DEBUG("cover_cache: %s before the job's task_id, stage dropped",
                      gap ? "report gap" : "no new task_id in time");
            make_tombstone(&st, now);
            ++it;
        } else if (gap && st.owner.empty()) {
            st.ambiguous = true;
            ++it;
        } else if (task_id.empty()) {
            ++it;
        } else if (st.owner == task_id ||
                   std::find(stale.begin(), stale.end(), task_id) != stale.end()) {
            ++it;
        } else if (!st.active) {
            st.ambiguous = true;
            ++it;
        } else if (st.owner.empty()) {
            st.owner = task_id;
            ++it;
        } else {
            OBN_DEBUG("cover_cache: task %s followed %s before its cover was "
                      "placed, stage dropped", task_id.c_str(), st.owner.c_str());
            it = g_staged.erase(it);
        }
    }
    if (g_task_history.size() >= kMaxSeenPrinters &&
        !g_task_history.count(dev_id)) {
        g_task_history.clear();
    }
    TaskHistory& h = g_task_history[dev_id];
    h.last_report = now;
    if (task_id.empty()) return;
    if (std::find(h.ids.begin(), h.ids.end(), task_id) != h.ids.end()) return;
    if (h.ids.size() >= kMaxSeenIdsPerPrinter) h.ids.erase(h.ids.begin());
    h.ids.push_back(task_id);
}

} // namespace

void note_task_id(const std::string& dev_id, const std::string& task_id)
{
    if (!task_id.empty()) note_report(dev_id, task_id);
}

void note_no_task_id(const std::string& dev_id)
{
    note_report(dev_id, {});
}

void ensure(const std::string& host,
            const std::string& dev_id,
            const std::string& user,
            const std::string& password,
            const std::string& subtask_name,
            int                plate_idx,
            const std::string& version,
            const std::string& task_id)
{
    if (host.empty() || subtask_name.empty()) return;

    std::string target = path_for(subtask_name, plate_idx, version);
    if (target.empty()) return;
    std::error_code ec;
    bool have = false;
    if (fs::exists(target, ec) && !ec) {
        auto sz = fs::file_size(target, ec);
        have = !ec && sz > 0;
    }
    note_task_id(dev_id, task_id);
    const bool staged = take_stage(dev_id, subtask_name, plate_idx, task_id,
                                   target, have);
    if (staged || have) return;

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
// Test hooks: the stage hand-over on its own (ensure() falls through to a
// :6000 fetch when it does not apply), the fetch-side final write, and a
// way to age staged covers without sleeping.
bool test_take_stage(const std::string& dev_id,
                     const std::string& subtask_name,
                     int                plate_idx,
                     const std::string& task_id,
                     const std::string& target,
                     bool               target_exists)
{
    return take_stage(dev_id, subtask_name, plate_idx, task_id, target,
                      target_exists);
}

int test_publish_fetched(const std::string& target,
                         const std::vector<std::uint8_t>& data)
{
    return publish_fetched(target, data);
}

void test_age_staged(std::chrono::seconds by)
{
    std::lock_guard<std::mutex> lk(g_stage_mu);
    for (auto& kv : g_staged) kv.second.staged_at -= by;
}

void test_age_task_reports(const std::string& dev_id, std::chrono::seconds by)
{
    std::lock_guard<std::mutex> lk(g_stage_mu);
    const auto it = g_task_history.find(dev_id);
    if (it != g_task_history.end()) it->second.last_report -= by;
}

std::chrono::seconds test_baseline_max_age()
{
    return std::chrono::duration_cast<std::chrono::seconds>(kBaselineMaxAge);
}

void test_age_activation(std::chrono::seconds by)
{
    std::lock_guard<std::mutex> lk(g_stage_mu);
    for (auto& kv : g_staged) kv.second.activated_at -= by;
}

std::chrono::seconds test_owner_deadline()
{
    return std::chrono::duration_cast<std::chrono::seconds>(kOwnerDeadline);
}

std::chrono::seconds test_stage_ttl()
{
    return std::chrono::duration_cast<std::chrono::seconds>(kStageTtl);
}
#endif

} // namespace obn::cover_cache
