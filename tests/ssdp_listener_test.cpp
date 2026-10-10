// DOC-01 golden-fixture suite for the SSDP parser (D-05).
//
// Every vendored packet under tests/fixtures/ssdp/ (tests/fixtures/README.md
// inventory, 12 files, D-02) is read at runtime, pushed through the
// production obn::ssdp::parse, and the emitted device-info JSON is asserted
// field by field (D-10 — never whole-string equality). D-11 coverage depth:
// start-line acceptance + header bag + JSON for both spoof dialects.
//
// Style: plain main() + CHECK, same as json_lite_test.cpp — the rest of the
// suite never pulls a test framework into the configure step.
//
// Scope: this suite locks parse() + to_device_info_json(), the bare parser.
// It says nothing about what Studio receives: Discovery's recv loop drops
// packets whose USN or DevModel is missing/empty (src/ssdp.cpp:337-339) and
// fills the sender IP when Location is absent (src/ssdp.cpp:343-347), so the
// empty-identity / empty-dev_ip outputs pinned below never reach the slicer
// through the listener path. Where an observation differs from what the bare
// parser does, the comment carries a `GAP` marker. No production behavior is
// changed to satisfy a fixture — that is absolute this phase.
//
// The live UDP sniffer that used to live in this file was moved verbatim to
// tools/ssdp_sniffer/main.cpp (D-05/D-07); it is not a test and is
// deliberately unregistered in ctest.

#include "obn/json_lite.hpp"
#include "obn/ssdp.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

static int fail_count = 0;

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, \
                         #cond);                                        \
            ++fail_count;                                               \
        }                                                               \
    } while (0)

namespace {

// D-08: a missing or renamed fixture must fail loudly — print FAIL with
// the absolute path (the ctest working directory is tests/fixtures, and
// the workspace path contains a space) and count the failure so the
// suite can never go green on a silent skip.
bool read_fixture_impl(const char* rel, std::string& out, int line)
{
    std::ifstream in(rel, std::ios::binary);
    if (!in) {
        std::error_code ec;
        const std::string abs = std::filesystem::absolute(rel, ec).string();
        std::fprintf(stderr, "FAIL %s:%d: cannot open fixture: %s (absolute path: %s)\n",
                     __FILE__, line, rel, abs.c_str());
        ++fail_count;
        out.clear();
        return false;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

// Shared post-parse step: to_device_info_json -> obn::json::parse.
bool device_doc(const obn::ssdp::Headers& h, std::string& storage,
                obn::json::Value& out)
{
    storage = obn::ssdp::to_device_info_json(h);
    auto doc = obn::json::parse(storage);
    if (!doc.has_value()) {
        std::fprintf(stderr, "FAIL %s: emitted device JSON does not parse\n", __FILE__);
        ++fail_count;
        return false;
    }
    out = *doc;
    return true;
}

} // namespace

// Call sites keep the read_fixture(rel, out) shape the plan specifies;
// the line number for the loud-failure message comes from the call site.
#define read_fixture(rel, out) read_fixture_impl(rel, out, __LINE__)

// --------------------------------------------------------------------------
// DOC-01 mandated behaviors
// --------------------------------------------------------------------------

// NOTIFY + NT dialect (D-11): start line accepted, NT survives verbatim,
// field-level JSON emitted from the header bag.
static void test_notify_nt_golden()
{
    std::string buf;
    if (!read_fixture("ssdp/synthetic-notify-x1c.txt", buf)) return;

    obn::ssdp::Headers h;
    CHECK(obn::ssdp::parse(buf.data(), buf.size(), h));

    // Header bag: NOTIFY dialect, NT must survive verbatim.
    CHECK(h.value("nt") == "urn:bambulab-com:device:3dprinter:1");
    CHECK(h.value("location") == "192.168.0.2");

    // Field-level JSON checks (D-10). Pinned to the values this fixture
    // actually carries — the plan quoted the colonless fixture's values
    // for the tracer, pin-observed per D-12.
    std::string json;
    obn::json::Value doc;
    if (!device_doc(h, json, doc)) return;
    CHECK(doc.find("dev_id").as_string() == "00M09A000000000");
    CHECK(doc.find("dev_ip").as_string() == "192.168.0.2");
    CHECK(doc.find("dev_type").as_string() == "3DPrinter-X1-Carbon");
    CHECK(doc.find("dev_name").as_string() == "REDACTED-NAME");
    CHECK(doc.find("connect_type").as_string() == "lan");
    CHECK(doc.find("bind_state").as_string() == "free");
}

// HTTP/1.1 200 OK + ST dialect (D-11): response start line accepted, ST
// captured into the header bag, plus field-level JSON.
static void test_search_response_st_dialect()
{
    std::string buf;
    if (!read_fixture("ssdp/synthetic-search-response-p1s.txt", buf)) return;

    obn::ssdp::Headers h;
    CHECK(obn::ssdp::parse(buf.data(), buf.size(), h)); // start line accepted

    CHECK(h.value("st") == "urn:bambulab-com:device:3dprinter:1");
    CHECK(h.value("location") == "192.168.0.3");

    std::string json;
    obn::json::Value doc;
    if (!device_doc(h, json, doc)) return;
    CHECK(doc.find("dev_id").as_string() == "01P00A000000000");
    CHECK(doc.find("dev_ip").as_string() == "192.168.0.3");
    CHECK(doc.find("dev_type").as_string() == "C12");
    CHECK(doc.find("dev_name").as_string() == "REDACTED-NAME");
    CHECK(doc.find("connect_type").as_string() == "lan");
    CHECK(doc.find("bind_state").as_string() == "free");
}

// LF-only line endings + lowercase header names (DOC-01 mandated): keys are
// lowercased on ingest anyway (obn::ssdp::Headers contract), values verbatim.
static void test_lf_lowercase_headers()
{
    std::string buf;
    if (!read_fixture("ssdp/synthetic-notify-lf-lowercase-a1mini.txt", buf)) return;
    CHECK(buf.find("\r") == std::string::npos); // fixture is genuinely LF-only

    obn::ssdp::Headers h;
    CHECK(obn::ssdp::parse(buf.data(), buf.size(), h));

    CHECK(h.value("host") == "239.255.255.250:2021");
    CHECK(h.value("nt") == "urn:bambulab-com:device:3dprinter:1");
    CHECK(h.value("location") == "192.168.0.4");

    std::string json;
    obn::json::Value doc;
    if (!device_doc(h, json, doc)) return;
    CHECK(doc.find("dev_id").as_string() == "03900A000000000");
    CHECK(doc.find("dev_ip").as_string() == "192.168.0.4");
    CHECK(doc.find("dev_type").as_string() == "N1");
    CHECK(doc.find("dev_name").as_string() == "REDACTED-NAME");
    CHECK(doc.find("connect_type").as_string() == "lan");
    CHECK(doc.find("bind_state").as_string() == "free");
}

// Colonless header line (DOC-01 mandated): the line is dropped from the
// bag (src/ssdp.cpp:133 skips lines without ':'), every other header
// still parses.
static void test_colonless_line_dropped()
{
    std::string buf;
    if (!read_fixture("ssdp/synthetic-notify-colonless-header.txt", buf)) return;

    obn::ssdp::Headers h;
    CHECK(obn::ssdp::parse(buf.data(), buf.size(), h));

    // Dropped at src/ssdp.cpp:133 — absent from the bag, not "".
    CHECK(h.get("this-line-has-no-colon") == nullptr);

    // Surrounding headers survive.
    CHECK(h.value("host") == "239.255.255.250:2021");
    CHECK(h.value("location") == "192.168.0.8");
    CHECK(h.value("usn") == "01P00A000000000");
    CHECK(h.value("devmodel.bambu.com") == "C12");

    std::string json;
    obn::json::Value doc;
    if (!device_doc(h, json, doc)) return;
    CHECK(doc.find("dev_id").as_string() == "01P00A000000000");
    CHECK(doc.find("dev_ip").as_string() == "192.168.0.8");
    CHECK(doc.find("dev_type").as_string() == "C12");
}

// No Location header (DOC-01 mandated): the bare parser emits dev_ip="".
static void test_no_location_parser_dev_ip_empty()
{
    std::string buf;
    if (!read_fixture("ssdp/synthetic-notify-no-location-h2d.txt", buf)) return;

    obn::ssdp::Headers h;
    CHECK(obn::ssdp::parse(buf.data(), buf.size(), h));

    CHECK(h.get("location") == nullptr);
    CHECK(h.value("nt") == "urn:bambulab-com:device:3dprinter:1");

    std::string json;
    obn::json::Value doc;
    if (!device_doc(h, json, doc)) return;
    // GAP (bare parser only): with no Location header, dev_ip is "" — the
    // sender-address fallback lives in Discovery's recv loop
    // (src/ssdp.cpp:343-347) and is unreachable from the pure
    // parse/to_device_info_json API. The listener fills the real source IP
    // before anything reaches Studio, so this pins the parser, not the
    // slicer (D-09, Pitfall 9). PandaSpy fills the sender IP the same way.
    CHECK(doc.find("dev_ip").as_string() == "");
    CHECK(doc.find("dev_id").as_string() == "09400A000000000");
    CHECK(doc.find("dev_type").as_string() == "O1D");
    CHECK(doc.find("dev_name").as_string() == "REDACTED-NAME");
}

// --------------------------------------------------------------------------
// Non-mandated extras — pinned observed behavior (D-12: pin now + annotate,
// never fix)
// --------------------------------------------------------------------------

// M-SEARCH probe echoed on the socket: accepted (start line has HTTP/1.),
// but carries no USN/Location/DevModel, so the emitted device JSON is all
// empty strings.
static void test_msearch_probe_accepted()
{
    std::string buf;
    if (!read_fixture("ssdp/synthetic-msearch-echo.txt", buf)) return;

    obn::ssdp::Headers h;
    CHECK(obn::ssdp::parse(buf.data(), buf.size(), h));

    CHECK(h.value("st") == "urn:bambulab-com:device:3dprinter:1");
    CHECK(h.value("man") == "\"ssdp:discover\"");

    std::string json;
    obn::json::Value doc;
    if (!device_doc(h, json, doc)) return;
    // GAP (bare parser only): a discovery probe (not an advertisement) still
    // yields a Studio-shaped device JSON with empty identity fields — pinned
    // as-is (D-12). The listener path never forwards it: Discovery drops
    // packets without USN/DevModel (src/ssdp.cpp:337-339).
    CHECK(doc.find("dev_id").as_string() == "");
    CHECK(doc.find("dev_ip").as_string() == "");
    CHECK(doc.find("dev_type").as_string() == "");
}

// Non-SSDP chatter on UDP :2021: no HTTP/1. in the start line -> rejected.
static void test_non_ssdp_rejected()
{
    std::string buf;
    if (!read_fixture("ssdp/synthetic-not-ssdp.txt", buf)) return;

    obn::ssdp::Headers h;
    CHECK(!obn::ssdp::parse(buf.data(), buf.size(), h)); // start line gate, src/ssdp.cpp:121
}

// https:// Location: accepted and passed through to dev_ip verbatim.
static void test_https_location_verbatim()
{
    std::string buf;
    if (!read_fixture("ssdp/synthetic-notify-https-location.txt", buf)) return;

    obn::ssdp::Headers h;
    CHECK(obn::ssdp::parse(buf.data(), buf.size(), h));
    CHECK(h.value("location") == "https://192.168.0.11:8883/desc");

    std::string json;
    obn::json::Value doc;
    if (!device_doc(h, json, doc)) return;
    // GAP: dev_ip is the raw Location string, not an extracted host — the
    // parser never URL-parses Location (src/ssdp.cpp:154). Studio receives
    // "https://192.168.0.11:8883/desc" where it expects a bare IP; pinned
    // as-is (D-12). (Location IS present, so the Discovery source-IP
    // fallback does not apply here.)
    CHECK(doc.find("dev_ip").as_string() == "https://192.168.0.11:8883/desc");
    CHECK(doc.find("dev_id").as_string() == "05A00A000000000");
    CHECK(doc.find("dev_type").as_string() == "N2S");
    // No DevName header in this packet.
    CHECK(doc.find("dev_name").as_string() == "");
}

// http:// URL Location with port: same verbatim pass-through as above.
static void test_url_location_verbatim()
{
    std::string buf;
    if (!read_fixture("ssdp/synthetic-notify-url-location.txt", buf)) return;

    obn::ssdp::Headers h;
    CHECK(obn::ssdp::parse(buf.data(), buf.size(), h));

    std::string json;
    obn::json::Value doc;
    if (!device_doc(h, json, doc)) return;
    // GAP: raw URL lands in dev_ip (see https-location case) — pinned, not
    // fixed (D-12).
    CHECK(doc.find("dev_ip").as_string() == "http://192.168.0.7:8883/desc");
    CHECK(doc.find("dev_id").as_string() == "01S00A000000000");
    CHECK(doc.find("dev_type").as_string() == "C11");
    CHECK(doc.find("dev_name").as_string() == "REDACTED-NAME");
}

// Advertisement with NT+Location but no USN/DevModel/DevName at all.
static void test_missing_identity_headers()
{
    std::string buf;
    if (!read_fixture("ssdp/synthetic-notify-names-nothing.txt", buf)) return;

    obn::ssdp::Headers h;
    CHECK(obn::ssdp::parse(buf.data(), buf.size(), h));
    CHECK(h.value("nt") == "urn:bambulab-com:device:3dprinter:1");

    std::string json;
    obn::json::Value doc;
    if (!device_doc(h, json, doc)) return;
    // GAP (bare parser only): an advertisement with no USN/model/name still
    // emits a complete device JSON with empty identity instead of being
    // dropped — pinned as-is (D-12). Discovery filters it out before the
    // callback (src/ssdp.cpp:337-339), so Studio never keys on "".
    CHECK(doc.find("dev_id").as_string() == "");
    CHECK(doc.find("dev_ip").as_string() == "192.168.0.9");
    CHECK(doc.find("dev_type").as_string() == "");
    CHECK(doc.find("dev_name").as_string() == "");
}

// Unknown model string: parser is model-agnostic, passes it through.
static void test_unknown_model_passthrough()
{
    std::string buf;
    if (!read_fixture("ssdp/synthetic-notify-unknown-model.txt", buf)) return;

    obn::ssdp::Headers h;
    CHECK(obn::ssdp::parse(buf.data(), buf.size(), h));

    std::string json;
    obn::json::Value doc;
    if (!device_doc(h, json, doc)) return;
    // GAP: no model validation — "3DPrinter-X9-Hyper" passes the listener's
    // non-empty DevModel check and reaches Studio verbatim with no
    // unknown-model flag (D-12 pin).
    CHECK(doc.find("dev_type").as_string() == "3DPrinter-X9-Hyper");
    CHECK(doc.find("dev_id").as_string() == "0XX00A000000000");
    CHECK(doc.find("dev_ip").as_string() == "192.168.0.9");
    CHECK(doc.find("dev_name").as_string() == "REDACTED-NAME");
}

// HTTP error response. Pitfall 10: the start-line gate is a substring
// check for "HTTP/1." (src/ssdp.cpp:121), so a 404 is ACCEPTED.
static void test_404_response_accepted()
{
    std::string buf;
    if (!read_fixture("ssdp/synthetic-search-response-404.txt", buf)) return;

    obn::ssdp::Headers h;
    CHECK(obn::ssdp::parse(buf.data(), buf.size(), h)); // accepted, not rejected
    CHECK(h.value("host") == "239.255.255.250:2021");

    std::string json;
    obn::json::Value doc;
    if (!device_doc(h, json, doc)) return;
    // GAP (bare parser only): an HTTP error response parses and emits
    // empty-identity device JSON instead of being rejected — pin accepted
    // (src/ssdp.cpp:121, Pitfall 10, D-12). This fixture carries no
    // USN/DevModel, so the listener drops it at src/ssdp.cpp:337-339 and
    // nothing reaches Studio.
    CHECK(doc.find("dev_id").as_string() == "");
    CHECK(doc.find("dev_ip").as_string() == "");
    CHECK(doc.find("dev_type").as_string() == "");
}

int main()
{
    test_notify_nt_golden();
    test_search_response_st_dialect();
    test_lf_lowercase_headers();
    test_colonless_line_dropped();
    test_no_location_parser_dev_ip_empty();
    test_msearch_probe_accepted();
    test_non_ssdp_rejected();
    test_https_location_verbatim();
    test_url_location_verbatim();
    test_missing_identity_headers();
    test_unknown_model_passthrough();
    test_404_response_accepted();

    // D-08 guard: read_fixture increments fail_count and prints an absolute
    // path on a missing/renamed file; any non-zero count means the suite
    // would otherwise report success without executing assertions.
    CHECK(fail_count == 0);

    if (fail_count == 0)
        std::printf("ssdp_listener_test: ok\n");
    return fail_count == 0 ? 0 : 1;
}
