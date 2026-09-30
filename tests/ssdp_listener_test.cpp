// DOC-01 golden-fixture suite for the SSDP parser (D-05).
//
// Every vendored packet under tests/fixtures/ssdp/ (tests/fixtures/README.md
// inventory, 12 files, D-02) is read at runtime, pushed through the
// production obn::ssdp::parse, and the emitted device-info JSON is asserted
// field by field (D-10 — never whole-string equality). D-11 coverage depth:
// start-line acceptance + header bag + JSON for both spoof dialects.
//
// Pin-and-annotate (D-09/D-12): expectations record what the parser does
// TODAY; wherever that observation differs from what PandaSpy would do, the
// comment carries a `GAP` marker naming the gap. No production behavior is
// changed to satisfy a fixture — that is absolute this phase.
//
// The live UDP sniffer that used to live in this file was moved verbatim to
// tools/ssdp_sniffer/main.cpp (D-05/D-07); it is not a test and is
// deliberately unregistered in ctest.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "obn/json_lite.hpp"
#include "obn/ssdp.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace {

// D-08: a missing or renamed fixture must fail loudly — print FAIL with
// the absolute path (the ctest working directory is tests/fixtures, and
// the workspace path contains a space) and count the failure so the
// suite can never go green on a silent skip.
int fail_count = 0;

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

// Shared post-parse step: to_device_info_json -> obn::json::parse. The
// REQUIRE lives in the caller's TEST_CASE context so a malformed emit
// fails the right test.
obn::json::Value device_json(const obn::ssdp::Headers& h, std::string& storage)
{
    storage = obn::ssdp::to_device_info_json(h);
    auto doc = obn::json::parse(storage);
    REQUIRE(doc.has_value());
    return *doc;
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
TEST_CASE("ssdp/synthetic-notify-x1c.txt: NOTIFY+NT golden parse", "[ssdp][notify][nt]")
{
    std::string buf;
    REQUIRE(read_fixture("ssdp/synthetic-notify-x1c.txt", buf));

    obn::ssdp::Headers h;
    REQUIRE(obn::ssdp::parse(buf.data(), buf.size(), h));

    // Header bag: NOTIFY dialect, NT must survive verbatim.
    CHECK(h.value("nt") == "urn:bambulab-com:device:3dprinter:1");
    CHECK(h.value("location") == "192.168.0.2");

    // Field-level JSON checks (D-10). Pinned to the values this fixture
    // actually carries — the plan quoted the colonless fixture's values
    // for the tracer, pin-observed per D-12.
    std::string json;
    auto        doc = device_json(h, json);
    CHECK(doc.find("dev_id").as_string() == "00M09A000000000");
    CHECK(doc.find("dev_ip").as_string() == "192.168.0.2");
    CHECK(doc.find("dev_type").as_string() == "3DPrinter-X1-Carbon");
    CHECK(doc.find("dev_name").as_string() == "REDACTED-NAME");
    CHECK(doc.find("connect_type").as_string() == "lan");
    CHECK(doc.find("bind_state").as_string() == "free");
}

// HTTP/1.1 200 OK + ST dialect (D-11): response start line accepted, ST
// captured into the header bag, plus field-level JSON.
TEST_CASE("ssdp/synthetic-search-response-p1s.txt: 200 OK+ST dialect", "[ssdp][response][st]")
{
    std::string buf;
    REQUIRE(read_fixture("ssdp/synthetic-search-response-p1s.txt", buf));

    obn::ssdp::Headers h;
    REQUIRE(obn::ssdp::parse(buf.data(), buf.size(), h)); // start line accepted

    CHECK(h.value("st") == "urn:bambulab-com:device:3dprinter:1");
    CHECK(h.value("location") == "192.168.0.3");

    std::string json;
    auto        doc = device_json(h, json);
    CHECK(doc.find("dev_id").as_string() == "01P00A000000000");
    CHECK(doc.find("dev_ip").as_string() == "192.168.0.3");
    CHECK(doc.find("dev_type").as_string() == "C12");
    CHECK(doc.find("dev_name").as_string() == "REDACTED-NAME");
    CHECK(doc.find("connect_type").as_string() == "lan");
    CHECK(doc.find("bind_state").as_string() == "free");
}

// LF-only line endings + lowercase header names (DOC-01 mandated): keys are
// lowercased on ingest anyway (obn::ssdp::Headers contract), values verbatim.
TEST_CASE("ssdp/synthetic-notify-lf-lowercase-a1mini.txt: LF-only + lowercase headers", "[ssdp][notify][lf]")
{
    std::string buf;
    REQUIRE(read_fixture("ssdp/synthetic-notify-lf-lowercase-a1mini.txt", buf));
    REQUIRE(buf.find("\r") == std::string::npos); // fixture is genuinely LF-only

    obn::ssdp::Headers h;
    REQUIRE(obn::ssdp::parse(buf.data(), buf.size(), h));

    CHECK(h.value("host") == "239.255.255.250:2021");
    CHECK(h.value("nt") == "urn:bambulab-com:device:3dprinter:1");
    CHECK(h.value("location") == "192.168.0.4");

    std::string json;
    auto        doc = device_json(h, json);
    CHECK(doc.find("dev_id").as_string() == "03900A000000000");
    CHECK(doc.find("dev_ip").as_string() == "192.168.0.4");
    CHECK(doc.find("dev_type").as_string() == "N1");
    CHECK(doc.find("dev_name").as_string() == "REDACTED-NAME");
    CHECK(doc.find("connect_type").as_string() == "lan");
    CHECK(doc.find("bind_state").as_string() == "free");
}

// Colonless header line (DOC-01 mandated): the line is dropped from the
// bag (src/ssdp.cpp:133-138 skips lines without ':'), every other header
// still parses.
TEST_CASE("ssdp/synthetic-notify-colonless-header.txt: colonless line dropped", "[ssdp][notify][malformed]")
{
    std::string buf;
    REQUIRE(read_fixture("ssdp/synthetic-notify-colonless-header.txt", buf));

    obn::ssdp::Headers h;
    REQUIRE(obn::ssdp::parse(buf.data(), buf.size(), h));

    // Dropped at src/ssdp.cpp:133-138 — absent from the bag, not "".
    CHECK(h.get("this-line-has-no-colon") == nullptr);

    // Surrounding headers survive.
    CHECK(h.value("host") == "239.255.255.250:2021");
    CHECK(h.value("location") == "192.168.0.8");
    CHECK(h.value("usn") == "01P00A000000000");
    CHECK(h.value("devmodel.bambu.com") == "C12");

    std::string json;
    auto        doc = device_json(h, json);
    CHECK(doc.find("dev_id").as_string() == "01P00A000000000");
    CHECK(doc.find("dev_ip").as_string() == "192.168.0.8");
    CHECK(doc.find("dev_type").as_string() == "C12");
}

// No Location header (DOC-01 mandated): dev_ip is pinned to "".
TEST_CASE("ssdp/synthetic-notify-no-location-h2d.txt: no Location -> dev_ip empty", "[ssdp][notify][gap]")
{
    std::string buf;
    REQUIRE(read_fixture("ssdp/synthetic-notify-no-location-h2d.txt", buf));

    obn::ssdp::Headers h;
    REQUIRE(obn::ssdp::parse(buf.data(), buf.size(), h));

    CHECK(h.get("location") == nullptr);
    CHECK(h.value("nt") == "urn:bambulab-com:device:3dprinter:1");

    std::string json;
    auto        doc = device_json(h, json);
    // GAP: no-Location packets emit dev_ip="" here. The sender-address
    // fallback lives only in the socket loop (src/ssdp.cpp:343-347) and is
    // unreachable from the pure parse/to_device_info_json API, so a
    // hermetic test can only pin "" (D-09, Pitfall 9). PandaSpy fills the
    // real sender IP in this case.
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
TEST_CASE("ssdp/synthetic-msearch-echo.txt: M-SEARCH probe accepted", "[ssdp][msearch]")
{
    std::string buf;
    REQUIRE(read_fixture("ssdp/synthetic-msearch-echo.txt", buf));

    obn::ssdp::Headers h;
    REQUIRE(obn::ssdp::parse(buf.data(), buf.size(), h));

    CHECK(h.value("st") == "urn:bambulab-com:device:3dprinter:1");
    CHECK(h.value("man") == "\"ssdp:discover\"");

    std::string json;
    auto        doc = device_json(h, json);
    // GAP: a discovery probe (not an advertisement) still yields a
    // Studio-shaped device JSON with empty identity fields instead of
    // being ignored — pinned as-is (D-12).
    CHECK(doc.find("dev_id").as_string() == "");
    CHECK(doc.find("dev_ip").as_string() == "");
    CHECK(doc.find("dev_type").as_string() == "");
}

// Non-SSDP chatter on UDP :2021: no HTTP/1. in the start line -> rejected.
TEST_CASE("ssdp/synthetic-not-ssdp.txt: non-SSDP chatter rejected", "[ssdp][negative]")
{
    std::string buf;
    REQUIRE(read_fixture("ssdp/synthetic-not-ssdp.txt", buf));

    obn::ssdp::Headers h;
    CHECK(!obn::ssdp::parse(buf.data(), buf.size(), h)); // start line gate, src/ssdp.cpp:121
}

// https:// Location: accepted and passed through to dev_ip verbatim.
TEST_CASE("ssdp/synthetic-notify-https-location.txt: https Location passed verbatim", "[ssdp][notify][gap]")
{
    std::string buf;
    REQUIRE(read_fixture("ssdp/synthetic-notify-https-location.txt", buf));

    obn::ssdp::Headers h;
    REQUIRE(obn::ssdp::parse(buf.data(), buf.size(), h));
    CHECK(h.value("location") == "https://192.168.0.11:8883/desc");

    std::string json;
    auto        doc = device_json(h, json);
    // GAP: dev_ip is the raw Location string, not an extracted host — the
    // parser never URL-parses Location (src/ssdp.cpp:154). Studio receives
    // "https://192.168.0.11:8883/desc" where it expects a bare IP; pinned
    // as-is (D-12).
    CHECK(doc.find("dev_ip").as_string() == "https://192.168.0.11:8883/desc");
    CHECK(doc.find("dev_id").as_string() == "05A00A000000000");
    CHECK(doc.find("dev_type").as_string() == "N2S");
    // No DevName header in this packet.
    CHECK(doc.find("dev_name").as_string() == "");
}

// http:// URL Location with port: same verbatim pass-through as above.
TEST_CASE("ssdp/synthetic-notify-url-location.txt: URL Location passed verbatim", "[ssdp][notify][gap]")
{
    std::string buf;
    REQUIRE(read_fixture("ssdp/synthetic-notify-url-location.txt", buf));

    obn::ssdp::Headers h;
    REQUIRE(obn::ssdp::parse(buf.data(), buf.size(), h));

    std::string json;
    auto        doc = device_json(h, json);
    // GAP: raw URL lands in dev_ip (see https-location case) — pinned, not
    // fixed (D-12).
    CHECK(doc.find("dev_ip").as_string() == "http://192.168.0.7:8883/desc");
    CHECK(doc.find("dev_id").as_string() == "01S00A000000000");
    CHECK(doc.find("dev_type").as_string() == "C11");
    CHECK(doc.find("dev_name").as_string() == "REDACTED-NAME");
}

// Advertisement with NT+Location but no USN/DevModel/DevName at all.
TEST_CASE("ssdp/synthetic-notify-names-nothing.txt: missing identity headers", "[ssdp][notify][gap]")
{
    std::string buf;
    REQUIRE(read_fixture("ssdp/synthetic-notify-names-nothing.txt", buf));

    obn::ssdp::Headers h;
    REQUIRE(obn::ssdp::parse(buf.data(), buf.size(), h));
    CHECK(h.value("nt") == "urn:bambulab-com:device:3dprinter:1");

    std::string json;
    auto        doc = device_json(h, json);
    // GAP: an advertisement with no USN/model/name still emits a complete
    // device JSON with empty identity instead of being dropped — Studio
    // would key it on "" (D-12 pin).
    CHECK(doc.find("dev_id").as_string() == "");
    CHECK(doc.find("dev_ip").as_string() == "192.168.0.9");
    CHECK(doc.find("dev_type").as_string() == "");
    CHECK(doc.find("dev_name").as_string() == "");
}

// Unknown model string: parser is model-agnostic, passes it through.
TEST_CASE("ssdp/synthetic-notify-unknown-model.txt: unknown model passed through", "[ssdp][notify][gap]")
{
    std::string buf;
    REQUIRE(read_fixture("ssdp/synthetic-notify-unknown-model.txt", buf));

    obn::ssdp::Headers h;
    REQUIRE(obn::ssdp::parse(buf.data(), buf.size(), h));

    std::string json;
    auto        doc = device_json(h, json);
    // GAP: no model validation — "3DPrinter-X9-Hyper" reaches Studio
    // verbatim with no unknown-model flag (D-12 pin).
    CHECK(doc.find("dev_type").as_string() == "3DPrinter-X9-Hyper");
    CHECK(doc.find("dev_id").as_string() == "0XX00A000000000");
    CHECK(doc.find("dev_ip").as_string() == "192.168.0.9");
    CHECK(doc.find("dev_name").as_string() == "REDACTED-NAME");
}

// HTTP error response. Pitfall 10: the start-line gate is a substring
// check for "HTTP/1." (src/ssdp.cpp:121), so a 404 is ACCEPTED.
TEST_CASE("ssdp/synthetic-search-response-404.txt: 404 response accepted", "[ssdp][response][gap]")
{
    std::string buf;
    REQUIRE(read_fixture("ssdp/synthetic-search-response-404.txt", buf));

    obn::ssdp::Headers h;
    REQUIRE(obn::ssdp::parse(buf.data(), buf.size(), h)); // accepted, not rejected
    CHECK(h.value("host") == "239.255.255.250:2021");

    std::string json;
    auto        doc = device_json(h, json);
    // GAP: an HTTP error response is treated like a printer advertisement
    // and emits empty-identity device JSON instead of being rejected —
    // pin accepted (src/ssdp.cpp:121, Pitfall 10, D-12).
    CHECK(doc.find("dev_id").as_string() == "");
    CHECK(doc.find("dev_ip").as_string() == "");
    CHECK(doc.find("dev_type").as_string() == "");
}

// --------------------------------------------------------------------------
// D-08 guard
// --------------------------------------------------------------------------

TEST_CASE("fixture reads never fail silently", "[ssdp][d08]")
{
    // read_fixture increments fail_count and prints an absolute path on
    // a missing/renamed file; any non-zero count here means the suite
    // would otherwise be reporting success without executing assertions.
    CHECK(fail_count == 0);
}
