// DOC-01 golden-fixture suite for the SSDP parser (D-05).
//
// Every vendored packet under tests/fixtures/ssdp/ is read at runtime,
// pushed through the production obn::ssdp::parse, and the emitted
// device-info JSON is asserted field by field (D-10 — never whole-string
// equality). The live UDP sniffer that used to live in this file was
// moved verbatim to tools/ssdp_sniffer/main.cpp (D-05/D-07); it is not a
// test and is deliberately unregistered in ctest.

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

} // namespace

// Call sites keep the read_fixture(rel, out) shape the plan specifies;
// the line number for the loud-failure message comes from the call site.
#define read_fixture(rel, out) read_fixture_impl(rel, out, __LINE__)

TEST_CASE("ssdp/synthetic-notify-x1c.txt: NOTIFY+NT golden parse", "[ssdp]")
{
    std::string buf;
    REQUIRE(read_fixture("ssdp/synthetic-notify-x1c.txt", buf));

    obn::ssdp::Headers h;
    REQUIRE(obn::ssdp::parse(buf.data(), buf.size(), h));

    // Header bag: NOTIFY dialect, NT must survive verbatim.
    CHECK(h.value("nt") == "urn:bambulab-com:device:3dprinter:1");
    CHECK(h.value("location") == "192.168.0.2");

    // Field-level JSON checks (D-10). Pinned to the values this fixture
    // actually carries — the plan quoted the colonless fixture's values,
    // pin-observed per D-12.
    const std::string json = obn::ssdp::to_device_info_json(h);
    auto              doc  = obn::json::parse(json);
    REQUIRE(doc.has_value());
    CHECK(doc->find("dev_id").as_string() == "00M09A000000000");
    CHECK(doc->find("dev_ip").as_string() == "192.168.0.2");
    CHECK(doc->find("dev_type").as_string() == "3DPrinter-X1-Carbon");
    CHECK(doc->find("dev_name").as_string() == "REDACTED-NAME");
    CHECK(doc->find("connect_type").as_string() == "lan");
    CHECK(doc->find("bind_state").as_string() == "free");
}

TEST_CASE("fixture reads never fail silently", "[ssdp][d08]")
{
    // read_fixture increments fail_count and prints an absolute path on
    // a missing/renamed file; any non-zero count here means the suite
    // would otherwise be reporting success without executing assertions.
    CHECK(fail_count == 0);
}
