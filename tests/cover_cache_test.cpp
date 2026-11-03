// Tests for the .3mf entry reader (zip_read.cpp) and the Device-tab cover
// staged from the archive of a print this plugin starts (cover_cache.cpp).
// Archives are built in-process with zlib; covers go to a temp
// OBN_COVER_DIR. Nothing here needs the Agent.

#include "obn/cover_cache.hpp"
#include "obn/tunnel_upload.hpp"
#include "obn/zip_read.hpp"

#include "zip_fixture.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace obn::cover_cache {
void test_fetch(const obn::tunnel_upload::ConnectParams& cp,
                const std::string&                       subtask_name,
                int                                      plate_idx,
                const std::string&                       version);
void test_age_staged(std::chrono::seconds by);
std::chrono::seconds test_staged_max_age();
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

using obn_test::Bytes;
using obn_test::Entry;
using obn_test::make_zip;
using obn_test::deflate_raw;

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
static std::vector<Entry> studio_entries(const Bytes& plate_png, int plate = 1)
{
    const std::string n = std::to_string(plate);
    return {
        {"Metadata/plate_" + n + ".png", plate_png},
        {"Metadata/plate_" + n + "_small.png", fake_png("small", 4154)},
        {"Metadata/plate_no_light_" + n + ".png", fake_png("nolight", 3782)},
        {"Metadata/top_" + n + ".png", fake_png("top", 7209)},
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
    // Plate index 0 (Orca's "plate_0") means plate 1.
    CHECK(obn::cover_cache::read_local_thumbnail(only1, 0, &png, &entry));
    CHECK(entry == "Metadata/plate_1.png");

    // No plate ever falls back to another plate's image.
    Bytes untouched = bytes_of("sentinel");
    std::string err;
    CHECK(!obn::cover_cache::read_local_thumbnail(only1, 2, &untouched, &entry, &err));
    CHECK(untouched == bytes_of("sentinel"));
    CHECK(err == "Metadata/plate_2.png: entry not found");
    const std::string only2 = write_file("only2.3mf",
        make_zip({{"Metadata/plate_2.png", p2}}));
    CHECK(!obn::cover_cache::read_local_thumbnail(only2, 1, &untouched, &entry, &err));
    CHECK(err == "Metadata/plate_1.png: entry not found");

    // A zero-byte image counts as missing.
    const std::string empty = write_file("emptypng.3mf", make_zip({
        {"Metadata/plate_1.png", Bytes{}}, {"Metadata/plate_no_light_1.png", nl1}}));
    CHECK(obn::cover_cache::read_local_thumbnail(empty, 1, &png, &entry));
    CHECK(entry == "Metadata/plate_no_light_1.png");
}

// ---------------------------------------------------------------------------
// Staged cover: the first source a fetch tries, before :6000
// ---------------------------------------------------------------------------

using obn::cover_cache::stage_from_3mf;

// Runs one cover fetch for a printer that never answers (nothing listens
// on port 1; without a LAN CA configured it fails even before dialing)
// and returns the cover file it left, empty when there is none.
static Bytes fetch_failing(const std::string& dev_id, const std::string& name,
                           int plate, const std::string& version)
{
    obn::tunnel_upload::ConnectParams cp;
    cp.dev_ip   = "127.0.0.1";
    cp.dev_id   = dev_id;
    cp.port     = 1;
    cp.password = "12345678";
    const std::string out = obn::cover_cache::path_for(name, plate, version);
    std::error_code ec;
    fs::remove(out, ec);
    obn::cover_cache::test_fetch(cp, name, plate, version);
    return read_file(out);
}

static std::string studio_3mf(const std::string& file, const Bytes& plate_png,
                              int plate = 1)
{
    return write_file(file, make_zip(studio_entries(plate_png, plate)));
}

static void test_fetch_writes_the_staged_image()
{
    const Bytes png = fake_png("cube");
    CHECK(stage_from_3mf("DEV1", "Cube", studio_3mf("cube.3mf", png), 1));
    // The project_file ack (task_id still "0") asks for a cover file of its
    // own before the job's task_id is reported: both get the image.
    CHECK(fetch_failing("DEV1", "Cube", 1, "") == png);
    CHECK(fetch_failing("DEV1", "Cube", 1, "8442") == png);
    // Nothing staged for the name and no printer: no cover.
    CHECK(fetch_failing("DEV1", "Sphere", 1, "8443").empty());
}

static void test_newer_stage_replaces_the_older_one()
{
    const Bytes v1 = fake_png("bracket-v1"), v2 = fake_png("bracket-v2");
    CHECK(stage_from_3mf("DEV1", "Bracket", studio_3mf("bracket1.3mf", v1), 1));
    CHECK(stage_from_3mf("DEV1", "Bracket", studio_3mf("bracket2.3mf", v2), 1));
    CHECK(fetch_failing("DEV1", "Bracket", 1, "9001") == v2);

    // A later print of the name whose archive has no plate image removes
    // the entry.
    const std::string bare = write_file("bare.3mf",
        make_zip({{"3D/3dmodel.model", bytes_of(std::string(64, 'm')), 8}}));
    CHECK(!stage_from_3mf("DEV1", "Bracket", bare, 1));
    CHECK(fetch_failing("DEV1", "Bracket", 1, "9002").empty());
}

static void test_unstage_drops_only_that_entry()
{
    // project_file could not be published: that print never started, so
    // its image must not reach a later job of the name.
    const Bytes p1 = fake_png("hinge-p1"), p2 = fake_png("hinge-p2");
    CHECK(stage_from_3mf("DEV1", "Hinge", studio_3mf("hinge1.3mf", p1), 1));
    CHECK(stage_from_3mf("DEV1", "Hinge", studio_3mf("hinge2.3mf", p2, 2), 2));
    obn::cover_cache::unstage("DEV1", "Hinge", 1);
    CHECK(fetch_failing("DEV1", "Hinge", 1, "5001").empty());
    CHECK(fetch_failing("DEV1", "Hinge", 2, "5001") == p2);
}

static void test_expired_stage_is_ignored()
{
    const Bytes png = fake_png("old");
    CHECK(stage_from_3mf("DEV1", "Old", studio_3mf("old.3mf", png), 1));
    const auto max_age = obn::cover_cache::test_staged_max_age();
    obn::cover_cache::test_age_staged(max_age - std::chrono::seconds(60));
    CHECK(fetch_failing("DEV1", "Old", 1, "7001") == png);
    obn::cover_cache::test_age_staged(std::chrono::seconds(60));
    CHECK(fetch_failing("DEV1", "Old", 1, "7002").empty());
}

static void test_stage_is_per_printer_name_and_plate()
{
    const Bytes png = fake_png("gear");
    CHECK(stage_from_3mf("DEV1", "Gear", studio_3mf("gear.3mf", png, 2), 2));
    CHECK(fetch_failing("DEV2", "Gear", 2, "6001").empty());
    CHECK(fetch_failing("DEV1", "Gear", 1, "6001").empty());
    CHECK(fetch_failing("DEV1", "Gear box", 2, "6001").empty());
    CHECK(fetch_failing("DEV1", "Gear", 2, "6001") == png);

    // Plate 0 (Orca's "plate_0") is plate 1, as for the cover file.
    CHECK(stage_from_3mf("DEV1", "Nut", studio_3mf("nut.3mf", png), 0));
    CHECK(fetch_failing("DEV1", "Nut", 1, "6002") == png);
}

static void set_cover_dir(const fs::path& dir)
{
#ifdef _WIN32
    _putenv_s("OBN_COVER_DIR", dir.string().c_str());
#else
    setenv("OBN_COVER_DIR", dir.string().c_str(), 1);
#endif
}

int main()
{
    g_dir = fs::temp_directory_path() /
            ("obn-cover-cache-test-" + std::to_string(std::random_device{}()));
    std::error_code ec;
    fs::remove_all(g_dir, ec);
    fs::create_directories(g_dir / "covers");
    set_cover_dir(g_dir / "covers");

    // .3mf entry reader.
    test_zip_reads_stored_entry_with_data_descriptor();
    test_zip_reads_deflated_entry();
    test_zip_reads_sync_flushed_entry();
    test_zip_reads_empty_deflated_entry();
    test_zip_reads_archive_with_comment();
    test_zip_rejects_bad_input();

    // Plate image selection.
    test_local_thumbnail_priority();

    // Staged cover for prints this plugin starts.
    test_fetch_writes_the_staged_image();
    test_newer_stage_replaces_the_older_one();
    test_unstage_drops_only_that_entry();
    test_expired_stage_is_ignored();
    test_stage_is_per_printer_name_and_plate();

    fs::remove_all(g_dir, ec);
    if (fail_count) {
        std::fprintf(stderr, "%d test(s) failed\n", fail_count);
        return 1;
    }
    std::fprintf(stdout, "cover_cache_test: ok\n");
    return 0;
}
