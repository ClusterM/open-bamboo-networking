// Tests for the .3mf entry reader (zip_read.cpp) and the Device-tab cover
// staged from the archive of a print this plugin starts (cover_cache.cpp).
// Archives are built in-process with zlib; covers go to a temp
// OBN_COVER_DIR. The code paths under test open no sockets.

#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/cover_cache.hpp"
#include "obn/print_job.hpp"
#include "obn/zip_read.hpp"

#include <zlib.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <unistd.h>

namespace fs = std::filesystem;

namespace obn::cover_cache {
bool test_take_stage(const std::string& dev_id,
                     const std::string& subtask_name,
                     int                plate_idx,
                     const std::string& task_id,
                     const std::string& target,
                     bool               target_exists);
int  test_publish_fetched(const std::string& target,
                          const std::vector<std::uint8_t>& data);
void test_age_staged(std::chrono::seconds by);
std::chrono::seconds test_stage_ttl();
void test_age_task_reports(const std::string& dev_id, std::chrono::seconds by);
std::chrono::seconds test_baseline_max_age();
void test_age_activation(std::chrono::seconds by);
std::chrono::seconds test_owner_deadline();
} // namespace obn::cover_cache

static int fail_count = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "FAIL %s:%d: %s\n",                      \
                         __FILE__, __LINE__, #cond);                       \
            ++fail_count;                                                  \
        }                                                                  \
    } while (0)

using Bytes = std::vector<std::uint8_t>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static fs::path g_dir;

static Bytes bytes_of(const std::string& s) { return Bytes(s.begin(), s.end()); }

// Deterministic stand-in for a PNG: the reader never looks inside.
static Bytes fake_png(const std::string& tag, std::size_t size = 9016)
{
    Bytes b = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    for (std::size_t i = b.size(); i < size; ++i) {
        b.push_back(static_cast<std::uint8_t>(tag[i % tag.size()] + i % 7));
    }
    return b;
}

static void put16(Bytes& b, std::uint32_t v)
{
    b.push_back(static_cast<std::uint8_t>(v & 0xff));
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
}

static void put32(Bytes& b, std::uint32_t v)
{
    put16(b, v & 0xffff);
    put16(b, v >> 16);
}

static void put_str(Bytes& b, const std::string& s)
{
    b.insert(b.end(), s.begin(), s.end());
}

// Raw deflate; with `sync_every` > 0 the input is flushed (Z_SYNC_FLUSH)
// every that many bytes, as streaming writers do, which can make the
// output larger than compressBound().
static Bytes deflate_raw(const Bytes& in, std::size_t sync_every = 0)
{
    z_stream zs{};
    deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8,
                 Z_DEFAULT_STRATEGY);
    Bytes out(compressBound(static_cast<uLong>(in.size())) + 16 +
              (sync_every ? 8 * (in.size() / sync_every + 1) : 0));
    zs.next_out  = out.data();
    zs.avail_out = static_cast<uInt>(out.size());
    std::size_t pos = 0;
    int rc = Z_OK;
    do {
        const std::size_t n =
            sync_every ? std::min(sync_every, in.size() - pos) : in.size() - pos;
        zs.next_in  = const_cast<Bytef*>(in.data() + pos);
        zs.avail_in = static_cast<uInt>(n);
        pos += n;
        rc = deflate(&zs, pos < in.size() ? Z_SYNC_FLUSH : Z_FINISH);
    } while (pos < in.size());
    out.resize(zs.total_out);
    deflateEnd(&zs);
    CHECK(rc == Z_STREAM_END);
    return out;
}

struct Entry {
    std::string   name;
    Bytes         data;
    std::uint16_t method      = 0;     // 0 stored, 8 deflate
    bool          descriptor  = true;  // Studio sets flag bit 3 on every entry
    std::uint16_t extra_flags = 0;
    bool          bad_crc     = false;
    int           method_tag  = -1;    // >= 0: method written to the headers
    std::size_t   sync_every  = 0;     // deflate: Z_SYNC_FLUSH interval
};

// Writes entries the way Bambu Studio's 3MF export lays them out: local
// header with zero sizes + 4-byte extra field, data, data descriptor; the
// central directory carries the real sizes.
static Bytes make_zip(const std::vector<Entry>& entries,
                      const std::string& comment = {},
                      bool zip64_marker = false)
{
    Bytes z, cd;
    for (const Entry& e : entries) {
        const Bytes packed =
            e.method == 8 ? deflate_raw(e.data, e.sync_every) : e.data;
        std::uint32_t crc = static_cast<std::uint32_t>(
            crc32(crc32(0L, Z_NULL, 0), e.data.data(),
                  static_cast<uInt>(e.data.size())));
        if (e.bad_crc) crc ^= 1u;
        const std::uint16_t flags = static_cast<std::uint16_t>(
            (e.descriptor ? 0x8 : 0) | 0x800 | e.extra_flags);
        const std::uint16_t method = e.method_tag >= 0
            ? static_cast<std::uint16_t>(e.method_tag) : e.method;
        const std::uint32_t off = static_cast<std::uint32_t>(z.size());
        const auto csize = static_cast<std::uint32_t>(packed.size());
        const auto usize = static_cast<std::uint32_t>(e.data.size());

        put32(z, 0x04034b50); put16(z, 20); put16(z, flags); put16(z, method);
        put16(z, 0); put16(z, 0);
        put32(z, e.descriptor ? 0 : crc);
        put32(z, e.descriptor ? 0 : csize);
        put32(z, e.descriptor ? 0 : usize);
        put16(z, static_cast<std::uint32_t>(e.name.size())); put16(z, 4);
        put_str(z, e.name);
        put16(z, 0xcafe); put16(z, 0);  // extra field only in the local header
        z.insert(z.end(), packed.begin(), packed.end());
        if (e.descriptor) {
            put32(z, 0x08074b50); put32(z, crc); put32(z, csize); put32(z, usize);
        }

        put32(cd, 0x02014b50); put16(cd, 20); put16(cd, 20); put16(cd, flags);
        put16(cd, method); put16(cd, 0); put16(cd, 0);
        put32(cd, crc); put32(cd, csize); put32(cd, usize);
        put16(cd, static_cast<std::uint32_t>(e.name.size()));
        put16(cd, 0); put16(cd, 0); put16(cd, 0); put16(cd, 0); put32(cd, 0);
        put32(cd, off);
        put_str(cd, e.name);
    }
    const std::uint32_t cd_off = static_cast<std::uint32_t>(z.size());
    z.insert(z.end(), cd.begin(), cd.end());
    put32(z, 0x06054b50); put16(z, 0); put16(z, 0);
    put16(z, static_cast<std::uint32_t>(entries.size()));
    put16(z, static_cast<std::uint32_t>(entries.size()));
    put32(z, static_cast<std::uint32_t>(cd.size()));
    put32(z, zip64_marker ? 0xffffffffu : cd_off);
    put16(z, static_cast<std::uint32_t>(comment.size()));
    put_str(z, comment);
    return z;
}

static std::string write_file(const std::string& name, const Bytes& data)
{
    const fs::path p = g_dir / name;
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    return p.string();
}

static Bytes read_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

// Mirrors a Studio print archive: plate images first, then the model,
// configs and the deflated G-code.
static std::vector<Entry> studio_entries(const Bytes& plate_png)
{
    return {
        {"Metadata/plate_1.png", plate_png},
        {"Metadata/plate_1_small.png", fake_png("small", 4154)},
        {"Metadata/plate_no_light_1.png", fake_png("nolight", 3782)},
        {"Metadata/top_1.png", fake_png("top", 7209)},
        {"3D/3dmodel.model", bytes_of(std::string(1081, 'm')), 8},
        {"Metadata/plate_1.gcode", bytes_of(std::string(200000, 'G')), 8},
        {"Metadata/slice_info.config", bytes_of(std::string(1685, 's')), 8},
    };
}

// ---------------------------------------------------------------------------
// zip_read
// ---------------------------------------------------------------------------

static void test_zip_reads_stored_entry_with_data_descriptor()
{
    const Bytes png = fake_png("plate1");
    const std::string path = write_file("studio.3mf", make_zip(studio_entries(png)));
    Bytes out;
    std::string err;
    CHECK(obn::zip::read_entry(path, "Metadata/plate_1.png", 1 << 20, &out, &err));
    CHECK(out == png);
    CHECK(err.empty());
}

static void test_zip_reads_deflated_entry()
{
    const std::string path = write_file("studio.3mf",
                                        make_zip(studio_entries(fake_png("p"))));
    Bytes out;
    CHECK(obn::zip::read_entry(path, "Metadata/plate_1.gcode", 1 << 20, &out));
    CHECK(out == bytes_of(std::string(200000, 'G')));
}

// A streaming writer's sync flushes can make a valid entry larger than
// compressBound(); size checks must not reject it.
static void test_zip_reads_sync_flushed_entry()
{
    const Bytes png = fake_png("flushed", 69);
    Entry e{"Metadata/plate_1.png", png, 8};
    e.sync_every = 1;
    const Bytes packed = deflate_raw(png, 1);
    CHECK(packed.size() > compressBound(static_cast<uLong>(png.size())));
    const std::string path = write_file("flushed.3mf", make_zip({e}));
    Bytes out;
    std::string err;
    CHECK(obn::zip::read_entry(path, "Metadata/plate_1.png", 1 << 20, &out, &err));
    CHECK(out == png);
}

static void test_zip_reads_empty_deflated_entry()
{
    const std::string path = write_file("empty.zip",
        make_zip({{"empty.txt", Bytes{}, 8}}));
    Bytes out = bytes_of("sentinel");
    CHECK(obn::zip::read_entry(path, "empty.txt", 16, &out));
    CHECK(out.empty());
}

static void test_zip_reads_archive_with_comment()
{
    // The comment contains an end-of-central-directory signature whose
    // comment length does not run to the end of the file.
    const std::string comment = std::string("PK\x05\x06", 4) + std::string(40, 'c');
    const Bytes png = fake_png("comment");
    const std::string path = write_file("comment.3mf",
        make_zip({{"Metadata/plate_1.png", png}}, comment));
    Bytes out;
    CHECK(obn::zip::read_entry(path, "Metadata/plate_1.png", 1 << 20, &out));
    CHECK(out == png);
}

static void expect_reject(const std::string& path, const std::string& name,
                          std::size_t max_size, const std::string& why)
{
    Bytes out = bytes_of("sentinel");
    std::string err;
    CHECK(!obn::zip::read_entry(path, name, max_size, &out, &err));
    CHECK(out == bytes_of("sentinel"));
    if (err != why) {
        std::fprintf(stderr, "  %s: expected '%s', got '%s'\n",
                     path.c_str(), why.c_str(), err.c_str());
    }
    CHECK(err == why);
}

static void test_zip_rejects_bad_input()
{
    const Bytes png = fake_png("x");
    const std::string ok = write_file("ok.3mf", make_zip(studio_entries(png)));
    expect_reject(ok, "Metadata/plate_2.png", 1 << 20, "entry not found");
    expect_reject(ok, "metadata/plate_1.png", 1 << 20, "entry not found");
    expect_reject(ok, "Metadata/plate_1.png", png.size() - 1, "entry too large");

    expect_reject(write_file("crc.3mf",
                      make_zip({{"Metadata/plate_1.png", png, 0, true, 0, true}})),
                  "Metadata/plate_1.png", 1 << 20, "crc mismatch");
    expect_reject(write_file("crc8.3mf",
                      make_zip({{"Metadata/plate_1.png", png, 8, true, 0, true}})),
                  "Metadata/plate_1.png", 1 << 20, "crc mismatch");
    expect_reject(write_file("enc.3mf",
                      make_zip({{"Metadata/plate_1.png", png, 0, true, 0x1}})),
                  "Metadata/plate_1.png", 1 << 20, "encrypted entry");
    expect_reject(write_file("bzip2.3mf",
                      make_zip({{"Metadata/plate_1.png", png, 0, true, 0, false, 12}})),
                  "Metadata/plate_1.png", 1 << 20, "unsupported compression method");
    expect_reject(write_file("zip64.3mf",
                      make_zip({{"Metadata/plate_1.png", png}}, {}, true)),
                  "Metadata/plate_1.png", 1 << 20, "zip64 archive");

    Bytes truncated = make_zip(studio_entries(png));
    truncated.resize(truncated.size() - 10);
    expect_reject(write_file("truncated.3mf", truncated),
                  "Metadata/plate_1.png", 1 << 20,
                  "no end of central directory record");
    expect_reject(write_file("text.3mf", bytes_of(std::string(4096, 't'))),
                  "Metadata/plate_1.png", 1 << 20,
                  "no end of central directory record");
    expect_reject(write_file("tiny.3mf", bytes_of("PK")),
                  "Metadata/plate_1.png", 1 << 20, "not a zip archive");
    expect_reject((g_dir / "missing.3mf").string(),
                  "Metadata/plate_1.png", 1 << 20, "cannot open archive");
}

// ---------------------------------------------------------------------------
// read_local_thumbnail
// ---------------------------------------------------------------------------

static void test_local_thumbnail_priority()
{
    const Bytes p2 = fake_png("plate2"), nl2 = fake_png("nolight2");
    const Bytes p1 = fake_png("plate1"), nl1 = fake_png("nolight1");
    Bytes png;
    std::string entry;

    const std::string all = write_file("all.3mf", make_zip({
        {"Metadata/plate_no_light_2.png", nl2}, {"Metadata/plate_1.png", p1},
        {"Metadata/plate_2.png", p2}}));
    CHECK(obn::cover_cache::read_local_thumbnail(all, 2, &png, &entry));
    CHECK(png == p2);
    CHECK(entry == "Metadata/plate_2.png");

    const std::string no_lit = write_file("nolit.3mf", make_zip({
        {"Metadata/plate_1.png", p1}, {"Metadata/plate_no_light_2.png", nl2}}));
    CHECK(obn::cover_cache::read_local_thumbnail(no_lit, 2, &png, &entry));
    CHECK(png == nl2);
    CHECK(entry == "Metadata/plate_no_light_2.png");

    const std::string only1 = write_file("only1.3mf", make_zip({
        {"Metadata/plate_no_light_1.png", nl1}, {"Metadata/plate_1.png", p1}}));
    CHECK(obn::cover_cache::read_local_thumbnail(only1, 2, &png, &entry));
    CHECK(png == p1);
    CHECK(entry == "Metadata/plate_1.png");
    // Plate index 0 (Orca's "plate_0") means plate 1.
    CHECK(obn::cover_cache::read_local_thumbnail(only1, 0, &png, &entry));
    CHECK(entry == "Metadata/plate_1.png");

    // Plate 1 never falls back to another plate's image.
    const std::string only2 = write_file("only2.3mf",
        make_zip({{"Metadata/plate_2.png", p2}}));
    Bytes untouched = bytes_of("sentinel");
    std::string err;
    CHECK(!obn::cover_cache::read_local_thumbnail(only2, 1, &untouched, &entry, &err));
    CHECK(untouched == bytes_of("sentinel"));
    CHECK(err == "Metadata/plate_1.png: entry not found");

    // A zero-byte image counts as missing.
    const std::string empty = write_file("emptypng.3mf", make_zip({
        {"Metadata/plate_1.png", Bytes{}}, {"Metadata/plate_no_light_1.png", nl1}}));
    CHECK(obn::cover_cache::read_local_thumbnail(empty, 1, &png, &entry));
    CHECK(entry == "Metadata/plate_no_light_1.png");
}

// ---------------------------------------------------------------------------
// Staged cover
// ---------------------------------------------------------------------------


static std::string stage_job(const std::string& name, const Bytes& png,
                             int plate = 1, const std::string& seq = {})
{
    const std::string path = write_file(name + ".3mf", make_zip(studio_entries(png)));
    CHECK(obn::cover_cache::stage_from_3mf("DEV1", name, path, plate,
                                           seq.empty() ? "seq-" + name : seq));
    return path;
}

static void activate(const std::string& name, const std::string& seq = {})
{
    obn::cover_cache::activate_stage("DEV1", name, seq.empty() ? "seq-" + name : seq);
}

// A report the printer sends for a job, through the production entry point
// (192.0.2.1 is TEST-NET-1: a fetch would never be answered, and none is
// expected where a cover file already exists or the stage applies).
static void report(const std::string& name, const std::string& version,
                   const std::string& task_id, int plate = 1,
                   const std::string& dev = "DEV1")
{
    obn::cover_cache::ensure("192.0.2.1", dev, "bblp", "unused", name, plate,
                             version, task_id);
}

// The stage hand-over alone, without the task_id bookkeeping every report
// goes through first.
static bool raw_take(const std::string& name, const std::string& task_id,
                     int plate = 1, const std::string& dev = "DEV1")
{
    return obn::cover_cache::test_take_stage(
        dev, name, plate, task_id,
        obn::cover_cache::path_for(name, plate, task_id), false);
}

// Lets tombstones (and any stage) expire.
static void expire_stages()
{
    obn::cover_cache::test_age_staged(obn::cover_cache::test_stage_ttl());
}

// A LAN report with task_id "": DEV1's baseline is fresh (and adds no id).
static void fresh_baseline(const std::string& dev = "DEV1")
{
    obn::cover_cache::note_no_task_id(dev);
}

// A report of `task_id` reaching the hand-over, as from agent.cpp.
static bool take(const std::string& name, const std::string& task_id,
                 int plate = 1, const std::string& dev = "DEV1")
{
    obn::cover_cache::note_task_id(dev, task_id);
    return raw_take(name, task_id, plate, dev);
}

// What the H2C reported for a reprint of the same project: the
// previous job's task id while uploading, after project_file the new job's
// subtask name without a task id, then with the new task id.
static void test_staged_cover_goes_to_the_new_job()
{
    const Bytes png = fake_png("staged");
    const std::string old_key = obn::cover_cache::path_for("job_a", 1, "7012");
    { std::ofstream(old_key, std::ios::binary) << "old"; }
    report("job_a", "7012", "7012");  // cached: noted, nothing fetched
    fs::remove(old_key);
    stage_job("job_a", png);

    // Not before project_file is out.
    CHECK(!raw_take("job_a", "4905"));
    activate("job_a");

    // A report without a task id does not take it ...
    const std::string bare = obn::cover_cache::path_for("job_a", 1, "");
    { std::ofstream(bare, std::ios::binary) << "x"; }  // no fetch either
    report("job_a", "", "");
    CHECK(read_file(bare) == bytes_of("x"));
    // ... nor a late report of the previous job ...
    CHECK(!take("job_a", "7012"));
    CHECK(!fs::exists(old_key));
    // ... the new job's first report with its task id does ...
    const std::string mine = obn::cover_cache::path_for("job_a", 1, "4905");
    report("job_a", "4905", "4905");
    CHECK(read_file(mine) == png);
    // ... and that retires the stage.
    CHECK(!take("job_a", "4906"));
}

// task ids reported before the stage, under any name of that printer, are
// earlier jobs.
static void test_stage_skips_task_ids_reported_before_upload()
{
    for (const auto& [name, id] : std::vector<std::pair<std::string, std::string>>{
             {"job_k", "11"}, {"other_job", "12"}}) {
        const std::string f = obn::cover_cache::path_for(name, 1, id);
        { std::ofstream(f, std::ios::binary) << "x"; }
        report(name, id, id);
        fs::remove(f);
    }
    stage_job("job_k", fake_png("k2"));
    activate("job_k");
    CHECK(!take("job_k", "11"));
    CHECK(!take("job_k", "12"));
    CHECK(take("job_k", "13"));
}

static void test_stage_scoped_to_printer_name_and_plate()
{
    stage_job("job_b", fake_png("s"), 2);
    activate("job_b");
    CHECK(!take("job_b", "b1", 2, "DEV2"));
    CHECK(!take("job_b_other", "b1", 2));
    CHECK(!take("Job_b", "b1", 2));
    CHECK(!take("job_b", "b1", 1));
    CHECK(!take("job_b", "b1", 3));
    CHECK(take("job_b", "b1", 2));
    CHECK(fs::exists(obn::cover_cache::path_for("job_b", 2, "b1")));
}

static void test_reports_without_task_id_never_take_the_stage()
{
    stage_job("job_l", fake_png("l"));
    activate("job_l");
    for (const char* version : {"", "1792339660"}) {
        CHECK(!obn::cover_cache::test_take_stage(
            "DEV1", "job_l", 1, "", obn::cover_cache::path_for("job_l", 1, version),
            false));
    }
    CHECK(take("job_l", "l77"));
}

// The job is the first new task_id, whatever report carried it: only that
// one takes the stage, and a second new one retires it (the job ended
// without taking its cover, e.g. its task id came in a report without the
// subtask name and it was aborted).
static void test_stage_owned_by_the_first_new_task_id()
{
    stage_job("job_g", fake_png("g"));
    activate("job_g");
    obn::cover_cache::note_task_id("DEV1", "g1");  // delta / cloud report
    CHECK(!take("job_g", "g1", 2));                // other plate: kept
    CHECK(raw_take("job_g", "g1"));

    stage_job("job_g", fake_png("g"));
    activate("job_g");
    obn::cover_cache::note_task_id("DEV1", "g2");
    obn::cover_cache::note_task_id("DEV1", "g2");  // repeated: still the owner
    obn::cover_cache::note_task_id("DEV1", "g3");  // another job
    CHECK(!raw_take("job_g", "g3"));
    CHECK(!raw_take("job_g", "g2"));
}

static void test_stage_expires()
{
    stage_job("job_c", fake_png("e"));
    activate("job_c");
    obn::cover_cache::test_age_staged(obn::cover_cache::test_stage_ttl());
    CHECK(!take("job_c", "c1"));
    // A new upload of the same project stages again.
    stage_job("job_c", fake_png("e"));
    activate("job_c");
    CHECK(take("job_c", "c2"));
}

// A second submission of the name while the first one's stage still waits
// for its job: a report could be either's, so neither gets one, nor does a
// third before the tombstone expires.
static void test_resubmission_while_unresolved_drops_both()
{
    stage_job("job_d", fake_png("first"));
    const Bytes second = fake_png("second");
    const std::string b = write_file("second.3mf", make_zip(studio_entries(second)));
    CHECK(!obn::cover_cache::stage_from_3mf("DEV1", "job_d", b, 1, "seq-job_d2"));
    CHECK(!obn::cover_cache::stage_from_3mf("DEV1", "job_d", b, 1, "seq-job_d3"));
    for (const char* seq : {"seq-job_d", "seq-job_d2", "seq-job_d3"}) {
        activate("job_d", seq);
    }
    obn::cover_cache::activate_stage("DEV1", "job_d", "");  // tombstone has none
    CHECK(!take("job_d", "d9"));
    CHECK(!fs::exists(obn::cover_cache::path_for("job_d", 1, "d9")));
    // Once it has expired, the next submission stages normally.
    obn::cover_cache::test_age_staged(obn::cover_cache::test_stage_ttl());
    CHECK(obn::cover_cache::stage_from_3mf("DEV1", "job_d", b, 1, "seq-job_d4"));
    activate("job_d", "seq-job_d4");
    CHECK(take("job_d", "d10"));
    CHECK(read_file(obn::cover_cache::path_for("job_d", 1, "d10")) == second);
}

// Before the job's task_id is known, a gap in the printer's reports
// (reconnect) means the next new task_id may be anyone's.
static void test_report_gap_before_the_owner()
{
    const auto past =
        obn::cover_cache::test_baseline_max_age() + std::chrono::seconds(1);
    stage_job("job_v", fake_png("v"));
    activate("job_v");
    obn::cover_cache::test_age_task_reports("DEV1", past);
    CHECK(!take("job_v", "v1"));
    CHECK(!fs::exists(obn::cover_cache::path_for("job_v", 1, "v1")));

    // While still pending: even a known task_id after the gap.
    expire_stages();
    stage_job("job_v", fake_png("v"));
    obn::cover_cache::test_age_task_reports("DEV1", past);
    obn::cover_cache::note_task_id("DEV1", "v1");
    activate("job_v");
    CHECK(!take("job_v", "v2"));

    // An owner known before the gap keeps the stage.
    expire_stages();
    stage_job("job_v", fake_png("v"));
    activate("job_v");
    obn::cover_cache::note_task_id("DEV1", "v3");
    obn::cover_cache::test_age_task_reports("DEV1", past);
    CHECK(take("job_v", "v3"));
}

// The job's task_id has to show up within kOwnerDeadline of activation
// (its refusal may have been lost), and before the report stream breaks.
static void test_owner_deadline_and_interrupted_reports()
{
    stage_job("job_n", fake_png("n"));
    activate("job_n");
    obn::cover_cache::test_age_activation(
        obn::cover_cache::test_owner_deadline() + std::chrono::seconds(1));
    CHECK(!take("job_n", "n1"));

    expire_stages();
    stage_job("job_n", fake_png("n"));
    activate("job_n");
    obn::cover_cache::reports_interrupted("DEV2");  // another printer's
    {
        // Session teardown (agent: printer switch, disconnect_printer).
        obn::LanSession session("DEV1", "192.0.2.1", "bblp", "unused", true, "");
        session.disconnect();
    }
    CHECK(!take("job_n", "n2"));

    // Pending at the disconnect: dropped at activation.
    expire_stages();
    stage_job("job_n", fake_png("n"));
    obn::cover_cache::reports_interrupted("DEV1");
    activate("job_n");
    CHECK(!take("job_n", "n3"));

    // Owner known: kept.
    expire_stages();
    stage_job("job_n", fake_png("n"));
    activate("job_n");
    obn::cover_cache::note_task_id("DEV1", "n4");
    obn::cover_cache::reports_interrupted("DEV1");
    obn::cover_cache::test_age_activation(
        obn::cover_cache::test_owner_deadline() + std::chrono::seconds(1));
    CHECK(take("job_n", "n4"));

    // After a disconnect the next stage needs a report received after it:
    // the old baseline may be out of date.
    expire_stages();
    obn::cover_cache::note_task_id("DEV1", "n4");
    obn::cover_cache::reports_interrupted("DEV1");
    stage_job("job_n", fake_png("n"));
    activate("job_n");
    CHECK(!take("job_n", "n5"));
}

// Every project_file this plugin publishes goes through Agent's egress
// (SD-card prints, the generic send_message ABIs): one that is not the
// staged submission blocks the name; the staged one does not.
static void test_other_project_file_blocks_the_name()
{
    obn::Agent agent(g_dir.string());
    const auto project_file = [](const std::string& name, const std::string& seq) {
        return R"({"print":{"command":"project_file","sequence_id":")" + seq +
               R"(","subtask_name":")" + name +
               R"(","param":"Metadata/plate_1.gcode"}})";
    };
    stage_job("job_sd", fake_png("sd"), 1, "sd-1");
    activate("job_sd", "sd-1");
    agent.send_message_to_printer("DEV1", project_file("job_sd", "sd-1"), 0);
    agent.send_message_to_printer("DEV1", project_file("other", "sd-2"), 0);
    CHECK(take("job_sd", "sd5"));

    stage_job("job_sd", fake_png("sd"), 1, "sd-3");
    activate("job_sd", "sd-3");
    agent.send_message_to_printer("DEV1", project_file("job_sd", "sd-4"), 0);
    CHECK(!take("job_sd", "sd6"));
    const std::string sd7 =
        write_file("sd7.3mf", make_zip(studio_entries(fake_png("s"))));
    CHECK(!obn::cover_cache::stage_from_3mf("DEV1", "job_sd", sd7, 1, "sd-7"));

    // Also when the command is spelled with escapes.
    expire_stages();
    stage_job("job_sd", fake_png("sd"), 1, "sd-8");
    activate("job_sd", "sd-8");
    agent.send_message_to_printer("DEV1",
        R"({"print":{"command":"\u0070roject_file","sequence_id":"sd-9",)"
        R"("subtask_name":"job_sd"}})", 0);
    CHECK(!take("job_sd", "sd10"));

    // The same over the cloud.
    stage_job("job_cl", fake_png("cl"), 1, "cl-1");
    activate("job_cl", "cl-1");
    agent.cloud_send_message("DEV1", project_file("job_cl", "cl-2"), 0);
    CHECK(!take("job_cl", "cl5"));
}

static void test_upload_without_image_drops_previous_stage()
{
    stage_job("job_h", fake_png("h"));
    activate("job_h");
    const std::string no_png = write_file("noimage.3mf", make_zip({
        {"3D/3dmodel.model", bytes_of("model"), 8}}));
    CHECK(!obn::cover_cache::stage_from_3mf("DEV1", "job_h", no_png, 1, "seq-job_h2"));
    CHECK(!take("job_h", "h1"));
    CHECK(!fs::exists(obn::cover_cache::path_for("job_h", 1, "h1")));
    // Both submissions are pending: a third one gets no stage either.
    const std::string with_png =
        write_file("job_h3.3mf", make_zip(studio_entries(fake_png("h3"))));
    CHECK(!obn::cover_cache::stage_from_3mf("DEV1", "job_h", with_png, 1,
                                            "seq-job_h3"));
    // The other order: a submission without an image first.
    CHECK(!obn::cover_cache::stage_from_3mf("DEV1", "job_hh", no_png, 1, "seq-hh1"));
    CHECK(!obn::cover_cache::stage_from_3mf("DEV1", "job_hh", with_png, 1, "seq-hh2"));
}

static void test_failed_submit_drops_only_its_own_stage()
{
    stage_job("job_i", fake_png("i"));
    obn::cover_cache::drop_submission("DEV1", "seq-job_i");
    // No stage left to activate.
    activate("job_i");
    CHECK(!take("job_i", "i1"));

    // Another submission giving up leaves this one's.
    stage_job("job_x", fake_png("x1"), 1, "71");
    stage_job("job_x2", fake_png("x2"), 1, "72");
    obn::cover_cache::drop_submission("DEV1", "71");
    activate("job_x2", "72");
    CHECK(take("job_x2", "x1"));
    CHECK(read_file(obn::cover_cache::path_for("job_x2", 1, "x1")) == fake_png("x2"));
    CHECK(!raw_take("job_x", "x1"));
}

static void test_stage_without_image_is_a_no_op()
{
    const std::string no_png = write_file("noimage.3mf", make_zip({
        {"3D/3dmodel.model", bytes_of("model"), 8}}));
    CHECK(!obn::cover_cache::stage_from_3mf("DEV1", "job_e", no_png, 1, "1"));
    CHECK(!obn::cover_cache::stage_from_3mf("DEV1", "job_e",
                                            (g_dir / "gone.3mf").string(), 1, "1"));
    CHECK(!obn::cover_cache::stage_from_3mf("DEV1", "", no_png, 1, "1"));
    CHECK(!take("job_e", "e1"));
}

// The printer refusing that project_file drops the stage; another
// printer's or another submission's refusal does not.
static void test_refused_submission_drops_the_stage()
{
    // Another printer's refusal, another submission's, or one without a
    // sequence id leave the stage in place ...
    for (const auto& [dev, seq] : std::vector<std::pair<std::string, std::string>>{
             {"DEV2", "777"}, {"DEV1", "778"}, {"DEV1", ""}}) {
        stage_job("job_m", fake_png("m"), 1, "777");
        activate("job_m", "777");
        obn::cover_cache::drop_submission(dev, seq);
        CHECK(take("job_m", "m" + seq + dev));
    }
    // ... its own drops it.
    stage_job("job_m", fake_png("m"), 1, "777");
    activate("job_m", "777");
    obn::cover_cache::drop_submission("DEV1", "777");
    CHECK(!take("job_m", "m2"));
}

// The refusal can arrive before run_local_print_job activates the stage
// (MQTT thread vs the publishing one): the stage is gone for good.
// Activation is for the stage's own submission only.
static void test_refusal_before_activation_drops_the_stage()
{
    stage_job("job_r", fake_png("r"), 1, "901");
    obn::cover_cache::drop_submission("DEV1", "901");
    activate("job_r", "901");
    CHECK(!take("job_r", "r1"));

    stage_job("job_s", fake_png("s"), 1, "902");
    activate("job_s", "903");
    CHECK(!take("job_s", "s1"));  // still pending: s1 makes it ambiguous
    activate("job_s", "902");
    CHECK(!take("job_s", "s1"));
    expire_stages();
    stage_job("job_s", fake_png("s"), 1, "904");
    activate("job_s", "904");
    CHECK(take("job_s", "s2"));
}

// The same through the printer's report path: Agent::notify_local_message
// sees the project_file ack.
static void test_project_file_refusal_reported_by_the_printer()
{
    obn::Agent agent(g_dir.string());
    stage_job("job_o", fake_png("o"), 1, "20116");
    activate("job_o", "20116");
    // A success ack keeps the stage ...
    agent.notify_local_message("DEV1",
        R"({"print":{"command":"project_file","sequence_id":"20116",)"
        R"("result":"SUCCESS","reason":"SUCCESS"}})");
    stage_job("job_p", fake_png("p"), 1, "20117");
    activate("job_p", "20117");
    // ... a failure ack drops its own stage only.
    agent.notify_local_message("DEV1",
        R"({"print":{"command":"project_file","sequence_id":"20117",)"
        R"("result":"fail","reason":"invalid nozzle_diameter"}})");
    CHECK(take("job_o", "o5"));
    CHECK(!take("job_p", "o5"));

    // The fields come from the print object, not the first match in the
    // frame: another section ahead of it neither hides a refusal ...
    stage_job("job_t", fake_png("t"), 1, "20118");
    activate("job_t", "20118");
    agent.notify_local_message("DEV1",
        R"({"info":{"command":"get_version","sequence_id":"1"},)"
        R"("print":{"command":"project_file","sequence_id":"20118",)"
        R"("result":"fail"}})");
    CHECK(!take("job_t", "t5"));
    // ... nor turns a success into one.
    stage_job("job_u", fake_png("u"), 1, "20119");
    activate("job_u", "20119");
    agent.notify_local_message("DEV1",
        R"({"camera":{"result":"fail"},"print":{"command":"project_file",)"
        R"("sequence_id":"20119","result":"success"}})");
    CHECK(take("job_u", "u5"));
}

// A task_id first reported while the stage waits for its project_file
// (the signing wait in send_message) may be another job's or this one's
// ahead of activation: the stage is dropped, whether that report went
// through a cover lookup or not.
static void test_new_task_id_during_submission_drops_the_stage()
{
    obn::Agent agent(g_dir.string());
    stage_job("job_q", fake_png("q"));
    const std::string f = obn::cover_cache::path_for("job_q", 1, "31");
    { std::ofstream(f, std::ios::binary) << "x"; }
    report("job_q", "31", "31");  // cover lookup: cached, nothing fetched
    fs::remove(f);
    activate("job_q");
    CHECK(!take("job_q", "q13"));
    // The name stays blocked meanwhile.
    CHECK(!obn::cover_cache::stage_from_3mf(
        "DEV1", "job_q", write_file("q2.3mf", make_zip(studio_entries(fake_png("q")))),
        1, "seq-q2"));

    expire_stages();
    stage_job("job_q", fake_png("q"));
    agent.notify_local_message("DEV1",
        R"({"print":{"command":"push_status","task_id":"5001","subtask_name":"x"}})");
    activate("job_q");
    CHECK(!take("job_q", "5002"));

    // Already known ids do not.
    expire_stages();
    stage_job("job_q", fake_png("q"));
    { std::ofstream(f, std::ios::binary) << "x"; }
    report("job_q", "31", "31");
    fs::remove(f);
    activate("job_q");
    CHECK(take("job_q", "5003"));
}

// Without any report from the printer, or without a recent one, there is
// no baseline to tell the previous job from this one.
static void test_no_report_baseline_drops_the_stage()
{
    const std::string path =
        write_file("job_y.3mf", make_zip(studio_entries(fake_png("y"))));
    CHECK(obn::cover_cache::stage_from_3mf("DEV9", "job_y", path, 1, "81"));
    obn::cover_cache::activate_stage("DEV9", "job_y", "81");
    CHECK(!take("job_y", "7012", 1, "DEV9"));

    expire_stages();
    CHECK(obn::cover_cache::stage_from_3mf("DEV9", "job_y", path, 1, "82"));
    obn::cover_cache::activate_stage("DEV9", "job_y", "82");
    CHECK(!take("job_y", "7012", 1, "DEV9"));
    CHECK(take("job_y", "4905", 1, "DEV9"));

    CHECK(obn::cover_cache::stage_from_3mf("DEV9", "job_y", path, 1, "83"));
    obn::cover_cache::test_age_task_reports(
        "DEV9", obn::cover_cache::test_baseline_max_age() + std::chrono::seconds(1));
    obn::cover_cache::activate_stage("DEV9", "job_y", "83");
    CHECK(!take("job_y", "y3", 1, "DEV9"));

    // No sequence id, no stage.
    CHECK(!obn::cover_cache::stage_from_3mf("DEV9", "job_y", path, 1, ""));
}

// After a restart the printer reports task_id "" (an H2C until its first
// job): a LAN report saying so is a fresh report that adds no id. The ack
// and the first push of the new job carry task_id 0, which never binds.
static void test_empty_task_id_report_is_a_fresh_baseline()
{
    obn::Agent agent(g_dir.string());
    const std::string path =
        write_file("job_e.3mf", make_zip(studio_entries(fake_png("e"))));
    const auto past =
        obn::cover_cache::test_baseline_max_age() + std::chrono::seconds(1);
    agent.notify_local_message("DEV8",
        R"({"print":{"command":"push_status","task_id":"","subtask_name":""}})");
    CHECK(obn::cover_cache::stage_from_3mf("DEV8", "job_e", path, 1, "91"));
    obn::cover_cache::activate_stage("DEV8", "job_e", "91");
    agent.notify_local_message("DEV8",
        R"({"print":{"command":"project_file","sequence_id":"91",)"
        R"("result":"SUCCESS","task_id":0}})");
    agent.notify_local_message("DEV8",
        R"({"print":{"command":"push_status","task_id":"0","subtask_name":"job_e"}})");
    CHECK(take("job_e", "193", 1, "DEV8"));

    // A frame without a task_id field (an ack) does not refresh it.
    obn::cover_cache::test_age_task_reports("DEV8", past);
    agent.notify_local_message("DEV8",
        R"({"print":{"command":"gcode_line","sequence_id":"5","result":"success"}})");
    CHECK(obn::cover_cache::stage_from_3mf("DEV8", "job_e", path, 1, "92"));
    obn::cover_cache::activate_stage("DEV8", "job_e", "92");
    CHECK(!take("job_e", "194", 1, "DEV8"));

    // The gap rule holds for empty reports too.
    expire_stages();
    agent.notify_local_message("DEV8",
        R"({"print":{"command":"push_status","task_id":""}})");
    CHECK(obn::cover_cache::stage_from_3mf("DEV8", "job_e", path, 1, "93"));
    obn::cover_cache::activate_stage("DEV8", "job_e", "93");
    obn::cover_cache::test_age_task_reports("DEV8", past);
    agent.notify_local_message("DEV8",
        R"({"print":{"command":"push_status","task_id":"0"}})");
    CHECK(!take("job_e", "195", 1, "DEV8"));

    // task_id 0 sent as a number is an empty report too.
    expire_stages();
    obn::cover_cache::test_age_task_reports("DEV8", past);
    agent.notify_local_message("DEV8",
        R"({"print":{"command":"push_status","task_id":0}})");
    CHECK(obn::cover_cache::stage_from_3mf("DEV8", "job_e", path, 1, "94"));
    obn::cover_cache::activate_stage("DEV8", "job_e", "94");
    CHECK(take("job_e", "196", 1, "DEV8"));

    // After a report gap, an empty report does not make the old baseline
    // good for a pending stage.
    expire_stages();
    agent.notify_local_message("DEV8",
        R"({"print":{"command":"push_status","task_id":""}})");
    CHECK(obn::cover_cache::stage_from_3mf("DEV8", "job_e", path, 1, "95"));
    obn::cover_cache::test_age_task_reports("DEV8", past);
    agent.notify_local_message("DEV8",
        R"({"print":{"command":"push_status","task_id":""}})");
    obn::cover_cache::activate_stage("DEV8", "job_e", "95");
    CHECK(!take("job_e", "197", 1, "DEV8"));
}

// An empty report adds no id (the eight remembered ones stay the baseline)
// and never ends an owned stage; a cover lookup without a task_id is no report.
static void test_empty_report_keeps_ids_and_owner()
{
    const std::string path =
        write_file("job_k8.3mf", make_zip(studio_entries(fake_png("k8"))));
    for (int i = 1; i <= 8; ++i)
        obn::cover_cache::note_task_id("DEV7", "k" + std::to_string(i));
    obn::cover_cache::note_no_task_id("DEV7");
    CHECK(obn::cover_cache::stage_from_3mf("DEV7", "job_k8", path, 1, "96"));
    obn::cover_cache::activate_stage("DEV7", "job_k8", "96");
    CHECK(!take("job_k8", "k1", 1, "DEV7"));      // still remembered
    obn::cover_cache::note_task_id("DEV7", "k9");  // owner, not taken yet
    obn::cover_cache::note_no_task_id("DEV7");
    CHECK(raw_take("job_k8", "k9", 1, "DEV7"));

    const std::string bare = obn::cover_cache::path_for("job_k8", 1, "");
    { std::ofstream(bare, std::ios::binary) << "x"; }  // no fetch
    obn::cover_cache::test_age_task_reports(
        "DEV7", obn::cover_cache::test_baseline_max_age() + std::chrono::seconds(1));
    report("job_k8", "", "", 1, "DEV7");
    CHECK(obn::cover_cache::stage_from_3mf("DEV7", "job_k8", path, 1, "97"));
    obn::cover_cache::activate_stage("DEV7", "job_k8", "97");
    CHECK(!take("job_k8", "k10", 1, "DEV7"));
}

// 30 s after activation without the job's task_id, an empty report drops
// the stage too, and the name stays blocked for two minutes from that report.
static void test_empty_report_after_the_owner_deadline_blocks_the_name()
{
    const std::string path =
        write_file("job_d6.3mf", make_zip(studio_entries(fake_png("d6"))));
    obn::cover_cache::note_no_task_id("DEV6");
    CHECK(obn::cover_cache::stage_from_3mf("DEV6", "job_d6", path, 1, "61"));
    obn::cover_cache::activate_stage("DEV6", "job_d6", "61");
    obn::cover_cache::test_age_staged(std::chrono::seconds(90));
    obn::cover_cache::test_age_activation(
        obn::cover_cache::test_owner_deadline() + std::chrono::seconds(1));
    obn::cover_cache::note_no_task_id("DEV6");  // the tombstone starts here
    obn::cover_cache::test_age_staged(std::chrono::seconds(40));
    CHECK(!obn::cover_cache::stage_from_3mf("DEV6", "job_d6", path, 1, "62"));
}

// The ids come from the print object, not the first "task_id" in the
// frame, and may be numbers.
static void test_task_id_and_ack_read_from_the_print_object()
{
    obn::Agent agent(g_dir.string());
    agent.notify_local_message("DEV1",
        R"({"print":{"command":"push_status","upload":{"task_id":"upload-1"},)"
        R"("task_id":"14","subtask_name":"other"}})");
    agent.notify_local_message("DEV1",
        R"({"print":{"command":"push_status","task_id":15,"subtask_name":"other"}})");
    stage_job("job_z", fake_png("z"));
    activate("job_z");
    CHECK(!take("job_z", "14"));
    CHECK(!take("job_z", "15"));
    CHECK(take("job_z", "upload-1"));

    stage_job("job_z", fake_png("z"), 1, "20120");
    activate("job_z", "20120");
    agent.notify_local_message("DEV1",
        R"({"print":{"command":"project_file","sequence_id":20120,"result":"FAIL"}})");
    CHECK(!take("job_z", "z16"));
}

// The report that qualifies retires the stage even when the image cannot
// be written; the job does not get a second try.
static void test_failed_write_retires_the_stage()
{
    stage_job("job_w", fake_png("w"));
    activate("job_w");
    obn::cover_cache::note_task_id("DEV1", "w8");
    CHECK(!obn::cover_cache::test_take_stage(
        "DEV1", "job_w", 1, "w8", (g_dir / "missing" / "cover.png").string(), false));
    CHECK(!raw_take("job_w", "w8"));
    CHECK(!fs::exists(obn::cover_cache::path_for("job_w", 1, "w8")));
}

// The job's cover file is already there: kept, and the stage is used up.
static void test_existing_cover_is_kept_and_retires_the_stage()
{
    stage_job("job_f", fake_png("k"));
    activate("job_f");
    const std::string target = obn::cover_cache::path_for("job_f", 1, "f5");
    { std::ofstream(target, std::ios::binary) << "cached"; }
    report("job_f", "f5", "f5");
    CHECK(read_file(target) == bytes_of("cached"));
    CHECK(!raw_take("job_f", "f5"));
}

// A :6000 fetch that finishes after the staged image was written keeps it.
static void test_fetch_result_does_not_replace_staged_cover()
{
    const Bytes png = fake_png("mine");
    stage_job("job_j", png);
    activate("job_j");
    CHECK(take("job_j", "40"));
    const std::string target = obn::cover_cache::path_for("job_j", 1, "40");
    CHECK(obn::cover_cache::test_publish_fetched(target, fake_png("printer")) == 0);
    CHECK(read_file(target) == png);

    const std::string fresh = obn::cover_cache::path_for("job_j", 1, "77");
    CHECK(obn::cover_cache::test_publish_fetched(fresh, fake_png("printer")) == 1);
    CHECK(read_file(fresh) == fake_png("printer"));
}

// The stage key and the subtask_name the printer echoes back come from
// the same helper.
static void test_stage_name_matches_project_file()
{
    BBL::PrintParams p{};
    p.project_name = "proj";
    p.task_name    = "task";
    p.plate_index  = 1;
    obn::print_job::ProjectFileOpts opts;
    opts.file_path = "proj.gcode.3mf";
    opts.url       = "brtc://emmc/proj.gcode.3mf";
    opts.md5       = "from_sd_card";
    std::string json = obn::print_job::build_project_file_json(p, opts);
    CHECK(obn::print_job::subtask_name_for(p) == "proj");
    CHECK(json.find("\"subtask_name\":\"proj\"") != std::string::npos);

    p.project_name.clear();
    json = obn::print_job::build_project_file_json(p, opts);
    CHECK(obn::print_job::subtask_name_for(p) == "task");
    CHECK(json.find("\"subtask_name\":\"task\"") != std::string::npos);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    g_dir = fs::temp_directory_path() /
            ("obn-cover-cache-test-" + std::to_string(::getpid()));
    std::error_code ec;
    fs::remove_all(g_dir, ec);
    fs::create_directories(g_dir / "covers");
    ::setenv("OBN_COVER_DIR", (g_dir / "covers").string().c_str(), 1);

    // .3mf entry reader.
    test_zip_reads_stored_entry_with_data_descriptor();
    test_zip_reads_deflated_entry();
    test_zip_reads_sync_flushed_entry();
    test_zip_reads_empty_deflated_entry();
    test_zip_reads_archive_with_comment();
    test_zip_rejects_bad_input();

    // Plate image selection.
    test_local_thumbnail_priority();

    // Cover staged for prints this plugin starts. Each case starts right
    // after a report of DEV1; cases that need a stale one age it themselves.
    for (void (*staged_case)() : {
             test_staged_cover_goes_to_the_new_job,
             test_stage_skips_task_ids_reported_before_upload,
             test_stage_scoped_to_printer_name_and_plate,
             test_reports_without_task_id_never_take_the_stage,
             test_stage_owned_by_the_first_new_task_id,
             test_stage_expires,
             test_resubmission_while_unresolved_drops_both,
             test_report_gap_before_the_owner,
             test_owner_deadline_and_interrupted_reports,
             test_other_project_file_blocks_the_name,
             test_upload_without_image_drops_previous_stage,
             test_failed_submit_drops_only_its_own_stage,
             test_stage_without_image_is_a_no_op,
             test_refused_submission_drops_the_stage,
             test_refusal_before_activation_drops_the_stage,
             test_project_file_refusal_reported_by_the_printer,
             test_new_task_id_during_submission_drops_the_stage,
             test_no_report_baseline_drops_the_stage,
             test_empty_task_id_report_is_a_fresh_baseline,
             test_empty_report_keeps_ids_and_owner,
             test_empty_report_after_the_owner_deadline_blocks_the_name,
             test_task_id_and_ack_read_from_the_print_object,
             test_failed_write_retires_the_stage,
             test_existing_cover_is_kept_and_retires_the_stage,
             test_fetch_result_does_not_replace_staged_cover,
             test_stage_name_matches_project_file,
         }) {
        fresh_baseline();
        staged_case();
    }

    fs::remove_all(g_dir, ec);
    if (fail_count) {
        std::fprintf(stderr, "%d test(s) failed\n", fail_count);
        return 1;
    }
    std::fprintf(stdout, "cover_cache_test: ok\n");
    return 0;
}
