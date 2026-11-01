// Cover lookup by 3MF title (tunnel_upload.cpp), with a scripted reader; no sockets.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using Files = std::vector<std::tuple<std::string, std::string, std::int64_t>>;
using Read  = std::function<std::pair<bool, std::string>(const std::string&,
                                                         const std::string&)>;
using Tile  = std::function<bool(const std::string&, const std::string&,
                                 std::string*)>;

namespace obn::tunnel_upload {
std::string test_model_title_from_3dmodel(const std::string& xml);
bool test_title_refusal_is_final(int result);
std::string test_find_model_entry_by_title(const Files& files,
                                           const std::string& list_storage,
                                           const std::string& scope,
                                           const std::string& model_name,
                                           int* reads_left, const Read& read,
                                           bool* transport);
std::string test_match_model_by_title(
    const std::vector<std::pair<std::string, Files>>& listings,
    const std::string& printer, const std::string& model_name,
    const Read& read, const Tile& tile, std::string* error);
void test_clear_title_cache();
std::size_t test_title_cache_size(const std::string& scope);
} // namespace obn::tunnel_upload

static int fail_count = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "FAIL %s:%d: %s\n",                      \
                         __FILE__, __LINE__, #cond);                       \
            ++fail_count;                                                  \
        }                                                                  \
    } while (0)

using obn::tunnel_upload::test_clear_title_cache;
using obn::tunnel_upload::test_model_title_from_3dmodel;

// ---------------------------------------------------------------------------
// <metadata name="Title">
// ---------------------------------------------------------------------------

// Shape of the 3D/3dmodel.model Bambu Studio writes into a sliced project.
static std::string studio_model(const std::string& title_element)
{
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
           "<model unit=\"millimeter\" xml:lang=\"en-US\" "
           "xmlns=\"http://schemas.microsoft.com/3dmanufacturing/core/2015/02\">\n"
           " <metadata name=\"Application\">BambuStudio-02.08.02.61</metadata>\n"
           " <metadata name=\"Description\"></metadata>\n"
           " <metadata name=\"ProfileTitle\">0.2mm layer</metadata>\n"
           " " + title_element + "\n"
           " <resources>\n  <object id=\"1\" type=\"model\"/>\n </resources>\n"
           "</model>\n";
}

static std::string title_of(const std::string& element)
{
    return test_model_title_from_3dmodel(studio_model(element));
}

static void test_title_plain()
{
    CHECK(title_of("<metadata name=\"Title\">Shelf bracket</metadata>") ==
          "Shelf bracket");
}

static void test_title_entities()
{
    CHECK(title_of("<metadata name=\"Title\">Nuts &amp; bolts &lt;M3&gt; "
                   "&quot;v2&quot; &apos;x&apos;</metadata>") ==
          "Nuts & bolts <M3> \"v2\" 'x'");
    CHECK(title_of("<metadata name=\"Title\">&#20013;&#x6587; &#xe9;</metadata>") ==
          "\xe4\xb8\xad\xe6\x96\x87 \xc3\xa9");
    // Not entities: kept verbatim.
    CHECK(title_of("<metadata name=\"Title\">A &nbsp; B &#0; C &#xd800; D & E"
                   "</metadata>") == "A &nbsp; B &#0; C &#xd800; D & E");
    // CDATA is literal.
    CHECK(title_of("<metadata name=\"Title\"><![CDATA[a &amp; <b>]]> c</metadata>") ==
          "a &amp; <b> c");
}

static void test_title_attribute_shapes()
{
    CHECK(title_of("<metadata type=\"xs:string\" name='Title'>Quoted</metadata>") ==
          "Quoted");
    CHECK(title_of("<metadata name = \"Title\">Spaced</metadata>") == "Spaced");
    CHECK(title_of("<metadata note=\"a>b\" name=\"Title\">After gt</metadata>") ==
          "After gt");
    // Look-alike names, attributes and values must not count.
    CHECK(title_of("<metadata name=\"SubTitle\">no</metadata>").empty());
    CHECK(title_of("<metadata xname=\"Title\">no</metadata>").empty());
    CHECK(title_of("<metadata type=\"x name='Title'\">no</metadata>").empty());
    CHECK(test_model_title_from_3dmodel(
              "<metadatagroup name=\"Title\">no</metadatagroup>"
              "<metadata name=\"Title\">yes</metadata>") == "yes");
}

static void test_title_skips_comments()
{
    CHECK(test_model_title_from_3dmodel(
              "<model><!-- <metadata name=\"Title\">Wrong</metadata> -->"
              "<metadata name=\"Title\">Actual</metadata></model>") == "Actual");
    CHECK(test_model_title_from_3dmodel(
              "<model><![CDATA[<metadata name=\"Title\">Wrong</metadata>]]>"
              "<metadata name=\"Title\">Actual</metadata></model>") == "Actual");
    CHECK(title_of("<metadata name=\"Title\">Act<!-- x -->ual</metadata>") == "Actual");
}

static void test_title_missing_or_empty()
{
    CHECK(title_of("<metadata name=\"Title\"></metadata>").empty());
    CHECK(title_of("<metadata name=\"Title\"/>").empty());
    CHECK(title_of("").empty());
    CHECK(test_model_title_from_3dmodel("").empty());
    CHECK(test_model_title_from_3dmodel("<metadata name=\"Title\">cut off").empty());
    CHECK(test_model_title_from_3dmodel("<metadata name=\"Title\"").empty());
    CHECK(test_model_title_from_3dmodel("<!-- <metadata name=\"Title\">x").empty());
}

// ---------------------------------------------------------------------------
// Per-listing matcher
// ---------------------------------------------------------------------------

struct Reader {
    std::map<std::string, std::pair<bool, std::string>> answers;  // by path
    std::vector<std::string> calls;
    std::vector<std::string> storages;
    Read fn()
    {
        return [this](const std::string& path, const std::string& storage) {
            calls.push_back(path);
            storages.push_back(storage);
            const auto it = answers.find(path);
            return it == answers.end() ? std::make_pair(true, std::string{})
                                       : it->second;
        };
    }
};

static std::string match(const Files& files, const std::string& name, Reader& r,
                         int reads = 32, const std::string& scope = "P1",
                         bool* transport_out = nullptr)
{
    bool transport = false;
    const std::string hit = obn::tunnel_upload::test_find_model_entry_by_title(
        files, "", scope, name, &reads, r.fn(), &transport);
    if (transport_out) *transport_out = transport;
    return hit;
}

static void test_match_by_title_when_names_differ()
{
    test_clear_title_cache();
    const Files files = {
        {"benchy.gcode.3mf", "/media/usb0/benchy.gcode.3mf", 100},
        {"model_v3_plate_1.gcode.3mf", "/media/usb0/model_v3_plate_1.gcode.3mf", 50},
    };
    Reader r;
    r.answers["/media/usb0/benchy.gcode.3mf"] = {true, "3DBenchy"};
    r.answers["/media/usb0/model_v3_plate_1.gcode.3mf"] = {true, "Cable clip"};
    CHECK(match(files, "Cable clip", r) == "/media/usb0/model_v3_plate_1.gcode.3mf");
    CHECK(r.calls.size() == 2);
    CHECK(match(files, "cable clip", r).empty());  // exact, case-sensitive
    CHECK(r.calls.size() == 2);                    // cached
}

static void test_newest_first_and_stop_after_match()
{
    test_clear_title_cache();
    // A project sent twice under different names: the newest wins, older ones unread.
    const Files files = {
        {"old.gcode.3mf", "/media/usb0/old.gcode.3mf", 10},
        {"renamed.gcode.3mf", "/media/usb0/renamed.gcode.3mf", 30},
        {"other.gcode.3mf", "/media/usb0/other.gcode.3mf", 20},
    };
    Reader r;
    r.answers["/media/usb0/old.gcode.3mf"] = {true, "Hook"};
    r.answers["/media/usb0/renamed.gcode.3mf"] = {true, "Hook"};
    r.answers["/media/usb0/other.gcode.3mf"] = {true, "Other"};
    CHECK(match(files, "Hook", r) == "/media/usb0/renamed.gcode.3mf");
    CHECK(r.calls == std::vector<std::string>({"/media/usb0/renamed.gcode.3mf"}));
}

static void test_pick_does_not_depend_on_cache_history()
{
    test_clear_title_cache();
    const Files files = {
        {"new.gcode.3mf", "/media/usb0/new.gcode.3mf", 30},
        {"mid.gcode.3mf", "/media/usb0/mid.gcode.3mf", 20},
        {"old.gcode.3mf", "/media/usb0/old.gcode.3mf", 10},
    };
    Reader r;
    r.answers["/media/usb0/new.gcode.3mf"] = {true, "T"};
    r.answers["/media/usb0/mid.gcode.3mf"] = {true, "U"};
    r.answers["/media/usb0/old.gcode.3mf"] = {true, "T"};
    // Warm only the older files (a listing that did not show the newest yet) ...
    CHECK(match({files[1], files[2]}, "T", r) == "/media/usb0/old.gcode.3mf");
    // ... and with no budget left, the newest unknown title is not skipped.
    CHECK(match(files, "T", r, 0).empty());
    CHECK(match(files, "T", r, 1) == "/media/usb0/new.gcode.3mf");
}

static void test_read_budget_and_progress()
{
    test_clear_title_cache();
    const Files files = {
        {"a.gcode.3mf", "/sdcard/a.gcode.3mf", 3},
        {"b.gcode.3mf", "/sdcard/b.gcode.3mf", 2},
        {"c.gcode.3mf", "/sdcard/c.gcode.3mf", 1},
    };
    Reader r;
    r.answers["/sdcard/c.gcode.3mf"] = {true, "Target"};
    CHECK(match(files, "Target", r, 2).empty());  // budget spent before c
    CHECK(r.calls.size() == 2);
    // Next retry: a and b come from the cache, only c is read.
    CHECK(match(files, "Target", r, 2) == "/sdcard/c.gcode.3mf");
    CHECK(r.calls.size() == 3);
    CHECK(r.calls.back() == "/sdcard/c.gcode.3mf");
    CHECK(match(files, "Target", r, 0) == "/sdcard/c.gcode.3mf");
    CHECK(r.calls.size() == 3);
}

static void test_long_listing_reaches_every_candidate()
{
    test_clear_title_cache();
    // 600 files, newest first by time; only the newest 64 are candidates.
    Files files;
    for (int i = 0; i < 600; ++i) {
        const std::string n = "f" + std::to_string(i) + ".gcode.3mf";
        files.emplace_back(n, "/media/usb0/" + n, 1000 - i);
    }
    Reader r;
    r.answers["/media/usb0/f63.gcode.3mf"] = {true, "Deep"};     // 64th newest
    r.answers["/media/usb0/f64.gcode.3mf"] = {true, "Too old"};  // 65th
    std::string hit;
    int fetches = 0;
    while (hit.empty() && fetches < 10) {
        hit = match(files, "Deep", r, 32);
        ++fetches;
    }
    CHECK(hit == "/media/usb0/f63.gcode.3mf");
    CHECK(fetches == 2);
    CHECK(r.calls.size() == 64);
    // The 65th newest is never read, however often it is retried.
    for (int i = 0; i < 5; ++i) CHECK(match(files, "Too old", r, 32).empty());
    CHECK(r.calls.size() == 64);
}

static void test_cache_is_per_printer_and_storage()
{
    test_clear_title_cache();
    const Files files = {{"p.gcode.3mf", "/media/usb0/p.gcode.3mf", 7}};
    Reader a, b;
    a.answers["/media/usb0/p.gcode.3mf"] = {true, "From A"};
    b.answers["/media/usb0/p.gcode.3mf"] = {true, "From B"};
    CHECK(match(files, "From A", a, 32, "PRINTER-A") == "/media/usb0/p.gcode.3mf");
    // Same path and time on another printer: read again, not taken from A.
    CHECK(match(files, "From A", b, 32, "PRINTER-B").empty());
    CHECK(b.calls.size() == 1);
    CHECK(match(files, "From B", b, 32, "PRINTER-B") == "/media/usb0/p.gcode.3mf");
    // A cached refusal on one printer does not hide the file on another.
    Reader refuse, c;
    refuse.answers["/media/usb0/q.gcode.3mf"] = {true, ""};
    c.answers["/media/usb0/q.gcode.3mf"] = {true, "Q"};
    const Files q = {{"q.gcode.3mf", "/media/usb0/q.gcode.3mf", 1}};
    CHECK(match(q, "Q", refuse, 32, "PRINTER-A").empty());
    CHECK(match(q, "Q", c, 32, "PRINTER-C") == "/media/usb0/q.gcode.3mf");
}

static void test_refusal_cached_transport_error_not()
{
    test_clear_title_cache();
    const Files files = {
        {"x.gcode.3mf", "/userdata/model/x.gcode.3mf", 9},
        {"y.gcode.3mf", "/userdata/model/y.gcode.3mf", 8},
    };
    Reader r;
    // x refused (cached, no title); y incomplete (uncached, reported, reading stops).
    r.answers["/userdata/model/x.gcode.3mf"] = {true, ""};
    r.answers["/userdata/model/y.gcode.3mf"] = {false, ""};
    bool transport = false;
    CHECK(match(files, "Y", r, 32, "P1", &transport).empty());
    CHECK(transport);
    CHECK(r.calls.size() == 2);

    r.answers["/userdata/model/y.gcode.3mf"] = {true, "Y"};
    CHECK(match(files, "Y", r, 32, "P1", &transport) == "/userdata/model/y.gcode.3mf");
    CHECK(!transport);
    CHECK(r.calls.size() == 3);  // x not asked again
}

static void test_cache_holds_only_current_candidates()
{
    test_clear_title_cache();
    const Files three = {
        {"a.gcode.3mf", "/media/usb0/a.gcode.3mf", 3},
        {"b.gcode.3mf", "/media/usb0/b.gcode.3mf", 2},
        {"c.gcode.3mf", "/media/usb0/c.gcode.3mf", 1},
    };
    Reader r;
    CHECK(match(three, "none", r).empty());
    CHECK(obn::tunnel_upload::test_title_cache_size("P1") == 3);
    // Two files deleted from the drive: their titles leave the cache.
    CHECK(match({three[0]}, "none", r).empty());
    CHECK(obn::tunnel_upload::test_title_cache_size("P1") == 1);
    CHECK(r.calls.size() == 3);
}

static void test_rewritten_file_is_read_again()
{
    test_clear_title_cache();
    Reader r;
    r.answers["/media/usb0/p.gcode.3mf"] = {true, "First"};
    CHECK(match({{"p.gcode.3mf", "/media/usb0/p.gcode.3mf", 1}}, "First", r) ==
          "/media/usb0/p.gcode.3mf");
    r.answers["/media/usb0/p.gcode.3mf"] = {true, "Second"};
    // Same path, new modification time: the cached title is not reused.
    CHECK(match({{"p.gcode.3mf", "/media/usb0/p.gcode.3mf", 2}}, "Second", r) ==
          "/media/usb0/p.gcode.3mf");
    CHECK(r.calls.size() == 2);
}

static void test_only_3mf_entries_are_read()
{
    test_clear_title_cache();
    const Files files = {
        {"timelapse.mp4", "/media/usb0/timelapse.mp4", 5},
        {"raw.gcode", "/media/usb0/raw.gcode", 4},
        {"part.3mf", "/media/usb0/part.3mf", 3},
    };
    Reader r;
    r.answers["/media/usb0/part.3mf"] = {true, "Part"};
    CHECK(match(files, "Part", r) == "/media/usb0/part.3mf");
    CHECK(r.calls == std::vector<std::string>({"/media/usb0/part.3mf"}));
}

// A file the printer never answers (too big for a raw reply) stops blocking the pass.
static void test_second_timeout_caches_untitled()
{
    test_clear_title_cache();
    const Files files = {
        {"big.3mf", "/media/usb0/big.3mf", 20},
        {"target.gcode.3mf", "/media/usb0/target.gcode.3mf", 10},
    };
    Reader r;
    r.answers["/media/usb0/big.3mf"] = {false, "timeout"};
    r.answers["/media/usb0/target.gcode.3mf"] = {true, "Target"};
    bool transport = false;
    for (int fetch = 0; fetch < 2; ++fetch) {
        CHECK(match(files, "Target", r, 64, "P1", &transport).empty());
        CHECK(transport);
    }
    CHECK(r.calls == std::vector<std::string>(2, "/media/usb0/big.3mf"));
    CHECK(match(files, "Target", r, 64, "P1", &transport) ==
          "/media/usb0/target.gcode.3mf");
    CHECK(!transport);
    CHECK(r.calls.size() == 3);  // big.3mf not asked again
    CHECK(obn::tunnel_upload::test_title_cache_size("P1") == 2);

    // A file that leaves the listing forgets its first timeout.
    test_clear_title_cache();
    Reader r2;
    r2.answers["/media/usb0/big.3mf"] = {false, "timeout"};
    CHECK(match(files, "Target", r2, 64).empty());
    CHECK(match({files[1]}, "None", r2, 64).empty());
    CHECK(match(files, "Target", r2, 64).empty());
    CHECK(match(files, "Target", r2, 64).empty());
    CHECK(r2.calls == std::vector<std::string>({"/media/usb0/big.3mf",
                                                "/media/usb0/target.gcode.3mf",
                                                "/media/usb0/big.3mf",
                                                "/media/usb0/big.3mf"}));
}

// Refusals that may pass and broken connections never count as a timeout.
static void test_only_timeouts_cache_unanswered()
{
    test_clear_title_cache();
    const Files files = {{"x.gcode.3mf", "/media/usb0/x.gcode.3mf", 1}};
    Reader r;
    r.answers["/media/usb0/x.gcode.3mf"] = {false, ""};
    for (int fetch = 0; fetch < 3; ++fetch) CHECK(match(files, "X", r).empty());
    CHECK(r.calls.size() == 3);
    CHECK(obn::tunnel_upload::test_title_cache_size("P1") == 0);
    // One timeout, then an answer: the title is read and used.
    r.answers["/media/usb0/x.gcode.3mf"] = {false, "timeout"};
    CHECK(match(files, "X", r).empty());
    r.answers["/media/usb0/x.gcode.3mf"] = {true, "X"};
    CHECK(match(files, "X", r) == "/media/usb0/x.gcode.3mf");
    CHECK(r.calls.size() == 5);
}

// A title another fetch reads while this fetch's read times out is kept.
static void test_late_timeout_keeps_a_title_read_meanwhile()
{
    test_clear_title_cache();
    const Files files = {{"x.gcode.3mf", "/media/usb0/x.gcode.3mf", 1}};
    Reader first;
    first.answers["/media/usb0/x.gcode.3mf"] = {false, "timeout"};
    CHECK(match(files, "X", first).empty());  // one timeout so far
    // Fetch A misses the cache; fetch B reads the title before A's read times out.
    Reader b;
    b.answers["/media/usb0/x.gcode.3mf"] = {true, "X"};
    bool b_hit = false;
    const Read slow = [&](const std::string&, const std::string&) {
        b_hit = match(files, "X", b) == "/media/usb0/x.gcode.3mf";
        return std::make_pair(false, std::string("timeout"));
    };
    bool transport = false;
    int reads = 32;
    CHECK(obn::tunnel_upload::test_find_model_entry_by_title(
              files, "", "P1", "X", &reads, slow, &transport).empty());
    CHECK(b_hit && transport);
    Reader none;
    CHECK(match(files, "X", none) == "/media/usb0/x.gcode.3mf");
    CHECK(none.calls.empty());
}

// File refusals are cached; printer-state ones and no numeric result are retried.
static void test_transient_refusals_are_not_final()
{
    using obn::tunnel_upload::test_title_refusal_is_final;
    for (int code : {-1, 3, 4, 5, 6, 17, 20, 25}) {
        CHECK(!test_title_refusal_is_final(code));
    }
    for (int code : {2, 10, 11, 12, 13, 14, 15, 16, 18, 19, 21, 22, 23, 24, 26, 99}) {
        CHECK(test_title_refusal_is_final(code));
    }
}

// ---------------------------------------------------------------------------
// Pass over the unmatched listings
// ---------------------------------------------------------------------------

// Fails and notes the attempt, as tunnel_upload.cpp notes each failed label.
static bool failing_tile(const std::string& path, const std::string& st,
                         std::string* failures)
{
    if (!failures->empty()) failures->append("; ");
    failures->append("'" + st + "': " + path);
    return false;
}

static void test_title_hit_without_tile_tries_next_listing()
{
    test_clear_title_cache();
    // "Target" on USB has no tile; another "Target" on internal storage has one.
    const std::vector<std::pair<std::string, Files>> listings = {
        {"", {{"usb.gcode.3mf", "/media/usb0/usb.gcode.3mf", 5}}},
        {"internal", {{"mmc.gcode.3mf", "/userdata/model/mmc.gcode.3mf", 4}}},
    };
    Reader r;
    r.answers["/media/usb0/usb.gcode.3mf"] = {true, "Target"};
    r.answers["/userdata/model/mmc.gcode.3mf"] = {true, "Target"};
    std::vector<std::string> tiles;
    const auto tile = [&tiles](const std::string& path, const std::string& st,
                               std::string* failures) {
        tiles.push_back(st + ":" + path);
        if (path == "/userdata/model/mmc.gcode.3mf") return true;
        return failing_tile(path, st, failures);
    };
    std::string error;
    CHECK(obn::tunnel_upload::test_match_model_by_title(listings, "P1", "Target",
                                                        r.fn(), tile, &error) ==
          "/userdata/model/mmc.gcode.3mf");
    CHECK(tiles == std::vector<std::string>(
                       {":/media/usb0/usb.gcode.3mf",
                        "internal:/userdata/model/mmc.gcode.3mf"}));
    CHECK(r.storages == std::vector<std::string>({"", "internal"}));
    CHECK(error.empty());

    // No tile anywhere: a thumbnail error listing every listing's attempts.
    test_clear_title_cache();
    error.clear();
    CHECK(obn::tunnel_upload::test_match_model_by_title(
              listings, "P1", "Target", r.fn(), failing_tile, &error).empty());
    CHECK(error == "SUB_FILE thumbnail failed ('': /media/usb0/usb.gcode.3mf; "
                   "'internal': /userdata/model/mmc.gcode.3mf)");

    // No title match at all: no error, the caller reports the missing model.
    error.clear();
    CHECK(obn::tunnel_upload::test_match_model_by_title(
              listings, "P1", "Nothing", r.fn(), tile, &error).empty());
    CHECK(error.empty());
}

static void test_transport_failure_ends_the_pass()
{
    test_clear_title_cache();
    const std::vector<std::pair<std::string, Files>> listings = {
        {"", {{"a.gcode.3mf", "/media/usb0/a.gcode.3mf", 5}}},
        {"internal", {{"b.gcode.3mf", "/userdata/model/b.gcode.3mf", 4}}},
    };
    Reader r;
    r.answers["/media/usb0/a.gcode.3mf"] = {false, ""};
    r.answers["/userdata/model/b.gcode.3mf"] = {true, "B"};
    std::string error;
    CHECK(obn::tunnel_upload::test_match_model_by_title(
              listings, "P1", "B", r.fn(),
              [](const std::string&, const std::string&, std::string*) {
                  return true;
              },
              &error).empty());
    CHECK(error == "3MF title read failed");
    CHECK(r.calls.size() == 1);

    // A failed tile on an earlier listing does not reach the read error.
    test_clear_title_cache();
    Reader r2;
    r2.answers["/media/usb0/a.gcode.3mf"] = {true, "B"};
    r2.answers["/userdata/model/b.gcode.3mf"] = {false, ""};
    error.clear();
    CHECK(obn::tunnel_upload::test_match_model_by_title(
              listings, "P1", "B", r2.fn(), failing_tile, &error).empty());
    CHECK(error == "3MF title read failed");
    CHECK(r2.calls.size() == 2);
}

static void test_read_budget_is_shared_by_the_listings()
{
    test_clear_title_cache();
    Files usb, mmc;
    for (int i = 0; i < 70; ++i) {  // 64 candidates spend the whole budget
        const std::string n = "u" + std::to_string(i) + ".gcode.3mf";
        usb.emplace_back(n, "/media/usb0/" + n, 100 - i);
    }
    mmc.emplace_back("m.gcode.3mf", "/userdata/model/m.gcode.3mf", 1);
    Reader r;
    r.answers["/userdata/model/m.gcode.3mf"] = {true, "M"};
    std::string error;
    const auto tile = [](const std::string&, const std::string&, std::string*) {
        return true;
    };
    CHECK(obn::tunnel_upload::test_match_model_by_title(
              {{"", usb}, {"internal", mmc}}, "P1", "M", r.fn(), tile, &error)
              .empty());
    CHECK(r.calls.size() == 64);
    CHECK(obn::tunnel_upload::test_match_model_by_title(
              {{"", usb}, {"internal", mmc}}, "P1", "M", r.fn(), tile, &error) ==
          "/userdata/model/m.gcode.3mf");
    CHECK(r.calls.size() == 65);
}

// A cold first listing is read in one fetch, in time for Studio's one request.
static void test_first_listing_resolves_in_one_fetch()
{
    test_clear_title_cache();
    Files usb;
    for (int i = 0; i < 64; ++i) {
        const std::string n = "u" + std::to_string(i) + ".gcode.3mf";
        usb.emplace_back(n, "/media/usb0/" + n, 100 - i);
    }
    Reader r;
    r.answers["/media/usb0/u63.gcode.3mf"] = {true, "Oldest"};
    std::string error;
    const auto tile = [](const std::string&, const std::string&, std::string*) {
        return true;
    };
    CHECK(obn::tunnel_upload::test_match_model_by_title({{"", usb}}, "P1", "Oldest",
                                                        r.fn(), tile, &error) ==
          "/media/usb0/u63.gcode.3mf");
    CHECK(r.calls.size() == 64);
}

// An unfinished listing ends the pass: a cached later listing must not win.
static void test_unfinished_listing_ends_the_pass()
{
    Files usb;  // 64 untitled candidates spend the whole budget
    for (int i = 0; i < 64; ++i) {
        const std::string n = "u" + std::to_string(i) + ".gcode.3mf";
        usb.emplace_back(n, "/media/usb0/" + n, 200 - i);
    }
    const Files mmc = {{"first.gcode.3mf", "/userdata/model/first.gcode.3mf", 2}};
    const Files emmc = {{"later.gcode.3mf", "/userdata/model/later.gcode.3mf", 1}};
    const auto tile = [](const std::string&, const std::string&, std::string*) {
        return true;
    };
    for (const bool warm_emmc : {false, true}) {
        test_clear_title_cache();
        Reader r;
        r.answers["/userdata/model/first.gcode.3mf"] = {true, "Same"};
        r.answers["/userdata/model/later.gcode.3mf"] = {true, "Same"};
        std::string error;
        if (warm_emmc) {
            CHECK(obn::tunnel_upload::test_match_model_by_title(
                      {{"emmc", emmc}}, "P1", "Same", r.fn(), tile, &error) ==
                  "/userdata/model/later.gcode.3mf");
        }
        // First fetch: the budget runs out before "internal" is read -> no pick.
        CHECK(obn::tunnel_upload::test_match_model_by_title(
                  {{"", usb}, {"internal", mmc}, {"emmc", emmc}}, "P1", "Same",
                  r.fn(), tile, &error).empty());
        CHECK(error.empty());
        // Retry: the "internal" file wins, cold or warm.
        CHECK(obn::tunnel_upload::test_match_model_by_title(
                  {{"", usb}, {"internal", mmc}, {"emmc", emmc}}, "P1", "Same",
                  r.fn(), tile, &error) == "/userdata/model/first.gcode.3mf");
    }
}

// Earlier tile failures stay the error when a later listing picks nothing.
static void test_tile_failure_then_no_pick()
{
    const Files usb = {{"usb.gcode.3mf", "/media/usb0/usb.gcode.3mf", 5}};
    Files unknown;  // more unknown titles than the budget left after usb
    for (int i = 0; i < 70; ++i) {
        const std::string n = "m" + std::to_string(i) + ".gcode.3mf";
        unknown.emplace_back(n, "/userdata/model/" + n, 100 - i);
    }
    const Files other = {{"o.gcode.3mf", "/userdata/model/o.gcode.3mf", 4}};
    for (const Files& second : {unknown, other}) {
        test_clear_title_cache();
        Reader r;
        r.answers["/media/usb0/usb.gcode.3mf"] = {true, "Target"};
        r.answers["/userdata/model/o.gcode.3mf"] = {true, "Other"};
        std::string error;
        CHECK(obn::tunnel_upload::test_match_model_by_title(
                  {{"", usb}, {"internal", second}}, "P1", "Target", r.fn(),
                  failing_tile, &error).empty());
        CHECK(error == "SUB_FILE thumbnail failed ('': /media/usb0/usb.gcode.3mf)");
        CHECK(r.calls.size() == (second.size() > 1 ? 64u : 2u));
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    test_title_plain();
    test_title_entities();
    test_title_attribute_shapes();
    test_title_skips_comments();
    test_title_missing_or_empty();

    test_match_by_title_when_names_differ();
    test_newest_first_and_stop_after_match();
    test_pick_does_not_depend_on_cache_history();
    test_read_budget_and_progress();
    test_long_listing_reaches_every_candidate();
    test_cache_is_per_printer_and_storage();
    test_refusal_cached_transport_error_not();
    test_cache_holds_only_current_candidates();
    test_rewritten_file_is_read_again();
    test_only_3mf_entries_are_read();
    test_second_timeout_caches_untitled();
    test_only_timeouts_cache_unanswered();
    test_late_timeout_keeps_a_title_read_meanwhile();
    test_transient_refusals_are_not_final();

    test_title_hit_without_tile_tries_next_listing();
    test_transport_failure_ends_the_pass();
    test_first_listing_resolves_in_one_fetch();
    test_read_budget_is_shared_by_the_listings();
    test_unfinished_listing_ends_the_pass();
    test_tile_failure_then_no_pick();

    if (fail_count) {
        std::fprintf(stderr, "%d test(s) failed\n", fail_count);
        return 1;
    }
    std::fprintf(stdout, "model_title_test: ok\n");
    return 0;
}
