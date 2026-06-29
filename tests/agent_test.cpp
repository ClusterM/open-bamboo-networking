// Tests for agent.cpp — covers SSDP model-tracking, bind-detect lookup,
// firmware JSON rendering, and synthetic subtask id minting.
// All tests run entirely in-process with no network connections.

#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/json_lite.hpp"

#include <cstdio>
#include <string>
#include <vector>

static int fail_count = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "FAIL %s:%d: %s\n",                      \
                         __FILE__, __LINE__, #cond);                       \
            ++fail_count;                                                  \
        }                                                                  \
    } while (0)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Minimal SSDP alive JSON that cache_ssdp_json_for_bind() understands.
static std::string ssdp_alive(const std::string& ip,
                               const std::string& dev_id,
                               const std::string& dev_type,
                               const std::string& dev_name = "TestPrinter")
{
    return R"({"dev_ip":")" + ip +
           R"(","dev_id":")" + dev_id +
           R"(","dev_type":")" + dev_type +
           R"(","dev_name":")" + dev_name + R"("})";
}

// Inject a JSON string through notify_local_message and return the (possibly
// patched) payload that the on_local_message_ callback received.
static std::string run_local_msg(obn::Agent& a,
                                 const std::string& dev_id,
                                 const std::string& json)
{
    std::string out;
    a.set_on_local_message_fn([&out](std::string, std::string j) {
        out = std::move(j);
    });
    a.notify_local_message(dev_id, json);
    a.set_on_local_message_fn(nullptr);
    return out;
}

// ---------------------------------------------------------------------------
// SSDP model-tracking (our change to cache_ssdp_json_for_bind)
// ---------------------------------------------------------------------------

static void test_ssdp_caches_model()
{
    obn::Agent a(".");
    a.cache_ssdp_json_for_bind(ssdp_alive("192.168.1.10", "DEV001", "3DPrinter-H2D-AMS2"));
    CHECK(a.test_model_for("DEV001") == "3DPrinter-H2D-AMS2");
}

static void test_ssdp_empty_dev_type_not_stored()
{
    obn::Agent a(".");
    // JSON without dev_type field.
    a.cache_ssdp_json_for_bind(R"({"dev_ip":"192.168.1.11","dev_id":"DEV002"})");
    CHECK(a.test_model_for("DEV002") == "");
}

static void test_ssdp_empty_dev_id_not_stored()
{
    obn::Agent a(".");
    // JSON without dev_id field.
    a.cache_ssdp_json_for_bind(R"({"dev_ip":"192.168.1.12","dev_type":"3DPrinter-P2S"})");
    // Nothing should be stored under any key.
    CHECK(a.test_model_for("") == "");
    CHECK(a.test_model_for("3DPrinter-P2S") == "");
}

static void test_ssdp_missing_dev_ip_is_noop()
{
    obn::Agent a(".");
    // JSON without dev_ip: cache_ssdp_json_for_bind returns early.
    a.cache_ssdp_json_for_bind(R"({"dev_id":"DEV003","dev_type":"3DPrinter-A1"})");
    CHECK(a.test_model_for("DEV003") == "");
}

static void test_ssdp_later_packet_overwrites_model()
{
    obn::Agent a(".");
    a.cache_ssdp_json_for_bind(ssdp_alive("192.168.1.13", "DEV004", "3DPrinter-P2S"));
    CHECK(a.test_model_for("DEV004") == "3DPrinter-P2S");
    a.cache_ssdp_json_for_bind(ssdp_alive("192.168.1.13", "DEV004", "3DPrinter-H2D"));
    CHECK(a.test_model_for("DEV004") == "3DPrinter-H2D");
}

// ---------------------------------------------------------------------------
// SSDP bind-detect lookup
// ---------------------------------------------------------------------------

static void test_lookup_bind_detect_success()
{
    obn::Agent a(".");
    a.cache_ssdp_json_for_bind(
        ssdp_alive("192.168.1.20", "DEV010", "3DPrinter-X1C", "My X1 Carbon"));
    BBL::detectResult out{};
    int rc = a.lookup_bind_detect("192.168.1.20", out, /*wait_ms=*/0);
    CHECK(rc == 0);
    CHECK(out.dev_id   == "DEV010");
    CHECK(out.model_id == "3DPrinter-X1C");
    CHECK(out.dev_name == "My X1 Carbon");
    CHECK(out.command  == "bind_detect");
    CHECK(out.result_msg == "ok");
}

static void test_lookup_bind_detect_timeout_when_no_cache()
{
    obn::Agent a(".");
    BBL::detectResult out{};
    int rc = a.lookup_bind_detect("10.0.0.99", out, /*wait_ms=*/0);
    CHECK(rc == -3);
}

static void test_lookup_bind_detect_trims_ip_whitespace()
{
    obn::Agent a(".");
    a.cache_ssdp_json_for_bind(ssdp_alive("192.168.1.21", "DEV011", "3DPrinter-A1"));
    BBL::detectResult out{};
    // Surrounding whitespace and a trailing newline on the query IP.
    int rc = a.lookup_bind_detect("  192.168.1.21\n", out, 0);
    CHECK(rc == 0);
    CHECK(out.dev_id == "DEV011");
}

static void test_device_display_name_from_ssdp()
{
    obn::Agent a(".");
    a.cache_ssdp_json_for_bind(
        ssdp_alive("192.168.1.22", "DEV012", "3DPrinter-P2S", "Studio P2S"));
    CHECK(a.device_display_name_for_ip("192.168.1.22") == "Studio P2S");
    // Unknown IP: empty.
    CHECK(a.device_display_name_for_ip("192.168.1.99") == "");
}

// ---------------------------------------------------------------------------
// Firmware JSON rendering via notify_local_message
// ---------------------------------------------------------------------------

static void test_render_fw_empty_device()
{
    obn::Agent a(".");
    const std::string fw = a.render_firmware_json("unknown_dev");
    // Must be valid JSON with the expected outer structure.
    CHECK(fw.find("\"devices\"") != std::string::npos);
    CHECK(fw.find("\"firmware\"") != std::string::npos);
    // No modules → firmware array is empty.
    CHECK(fw.find("\"firmware\":[]") != std::string::npos);
}

static void test_render_fw_from_get_version()
{
    obn::Agent a(".");
    const std::string msg = R"({
        "info":{
            "command":"get_version",
            "module":[
                {"name":"ota","sw_ver":"01.08.01.00","product_name":"P2S"},
                {"name":"ams/0","sw_ver":"00.00.06.49"}
            ]
        }
    })";
    run_local_msg(a, "dev_gv", msg);
    const std::string fw = a.render_firmware_json("dev_gv");
    CHECK(fw.find("01.08.01.00") != std::string::npos);
    CHECK(fw.find("00.00.06.49") != std::string::npos);
}

static void test_render_fw_new_ver_from_upgrade_state()
{
    obn::Agent a(".");
    // Seed current version via get_version.
    run_local_msg(a, "dev_up", R"({
        "info":{"command":"get_version","module":[
            {"name":"ota","sw_ver":"01.08.01.00","product_name":"X1-Carbon"}
        ]}
    })");
    // A push from upgrade_state with a newer version available.
    run_local_msg(a, "dev_up", R"({
        "print":{"upgrade_state":{"new_ver_list":[
            {"name":"ota","cur_ver":"01.08.01.00","new_ver":"01.09.01.00"}
        ]}}
    })");
    const std::string fw = a.render_firmware_json("dev_up");
    CHECK(fw.find("01.08.01.00") != std::string::npos);
    CHECK(fw.find("01.09.01.00") != std::string::npos);
}

static void test_render_fw_no_extra_entry_when_ver_equal()
{
    obn::Agent a(".");
    // sw_ver == sw_new_ver: the new-version entry must NOT be emitted.
    run_local_msg(a, "dev_eq", R"({
        "info":{"command":"get_version","module":[
            {"name":"ota","sw_ver":"01.08.01.00",
             "sw_new_ver":"01.08.01.00","product_name":"A1"}
        ]}
    })");
    const std::string fw = a.render_firmware_json("dev_eq");
    // "01.08.01.00" should appear exactly once (the cur entry), not twice.
    std::size_t count = 0;
    for (std::size_t p = 0;
         (p = fw.find("01.08.01.00", p)) != std::string::npos;
         ++p) {
        ++count;
    }
    CHECK(count == 1);
}

// ---------------------------------------------------------------------------
// Synthetic subtask minting (push_status id-rewriting)
// ---------------------------------------------------------------------------

static void test_synthetic_subtask_created_for_zero_ids()
{
    obn::Agent a(".");
    const std::string payload = R"({
        "print":{
            "subtask_name":"bunny.gcode.3mf",
            "task_id":"0",
            "subtask_id":"0",
            "project_id":"0",
            "profile_id":"0",
            "gcode_start_time":"1700000001"
        }
    })";
    const std::string out = run_local_msg(a, "dev_sp", payload);
    CHECK(!out.empty());

    // The rewritten subtask_id must have the "lan-" prefix.
    auto parsed = obn::json::parse(out);
    CHECK(parsed);
    const std::string synth_id = parsed->find("print.subtask_id").as_string();
    CHECK(synth_id.rfind("lan-", 0) == 0);

    // The agent must be able to resolve the id back to the original name.
    obn::Agent::SubtaskCoverInfo info{};
    CHECK(a.lookup_synthetic_subtask(synth_id, &info));
    CHECK(info.subtask_name == "bunny.gcode.3mf");
    CHECK(info.plate_idx == 1);
}

static void test_synthetic_subtask_not_created_without_name()
{
    obn::Agent a(".");
    // No subtask_name in the payload: rewrite must not fire.
    run_local_msg(a, "dev_nn", R"({
        "print":{"task_id":"0","subtask_id":"0"}
    })");
    obn::Agent::SubtaskCoverInfo info{};
    CHECK(!a.lookup_synthetic_subtask("lan-00000000", &info));
}

static void test_synthetic_subtask_not_created_for_sentinel_name()
{
    obn::Agent a(".");
    // subtask_name == "-1" is a sentinel meaning "no active print".
    run_local_msg(a, "dev_sn", R"({
        "print":{"subtask_name":"-1","task_id":"0","subtask_id":"0",
                 "project_id":"0","profile_id":"0"}
    })");
    obn::Agent::SubtaskCoverInfo info{};
    CHECK(!a.lookup_synthetic_subtask("lan-00000000", &info));
}

static void test_synthetic_subtask_id_is_deterministic()
{
    // Same (subtask_name, gcode_start_time) must yield the same id regardless
    // of which Agent instance produces it.
    auto get_id = [](const std::string& name, const std::string& ts) {
        obn::Agent a(".");
        const std::string payload =
            R"({"print":{"subtask_name":")" + name +
            R"(","task_id":"0","subtask_id":"0","project_id":"0",)"
            R"("profile_id":"0","gcode_start_time":")" + ts + R"("}})";
        const std::string out = run_local_msg(a, "dev", payload);
        auto parsed = obn::json::parse(out);
        return parsed ? parsed->find("print.subtask_id").as_string() : std::string{};
    };

    const std::string id1 = get_id("rocket.gcode.3mf", "1700001234");
    const std::string id2 = get_id("rocket.gcode.3mf", "1700001234");
    CHECK(!id1.empty());
    CHECK(id1 == id2);
}

static void test_synthetic_subtask_id_varies_with_timestamp()
{
    // Different gcode_start_time must produce a different id so that
    // a same-named re-print invalidates the cover cache.
    auto get_id = [](const std::string& ts) {
        obn::Agent a(".");
        const std::string payload = std::string(
            R"({"print":{"subtask_name":"boat.gcode.3mf","task_id":"0",)"
            R"("subtask_id":"0","project_id":"0","profile_id":"0",)"
            R"("gcode_start_time":")") + ts + R"("}})";
        const std::string out = run_local_msg(a, "dev", payload);
        auto parsed = obn::json::parse(out);
        return parsed ? parsed->find("print.subtask_id").as_string() : std::string{};
    };

    const std::string id1 = get_id("1700000001");
    const std::string id2 = get_id("1700000002");
    CHECK(!id1.empty());
    CHECK(!id2.empty());
    CHECK(id1 != id2);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    // SSDP model tracking.
    test_ssdp_caches_model();
    test_ssdp_empty_dev_type_not_stored();
    test_ssdp_empty_dev_id_not_stored();
    test_ssdp_missing_dev_ip_is_noop();
    test_ssdp_later_packet_overwrites_model();

    // Bind-detect lookup.
    test_lookup_bind_detect_success();
    test_lookup_bind_detect_timeout_when_no_cache();
    test_lookup_bind_detect_trims_ip_whitespace();
    test_device_display_name_from_ssdp();

    // Firmware JSON rendering.
    test_render_fw_empty_device();
    test_render_fw_from_get_version();
    test_render_fw_new_ver_from_upgrade_state();
    test_render_fw_no_extra_entry_when_ver_equal();

    // Synthetic subtask id minting.
    test_synthetic_subtask_created_for_zero_ids();
    test_synthetic_subtask_not_created_without_name();
    test_synthetic_subtask_not_created_for_sentinel_name();
    test_synthetic_subtask_id_is_deterministic();
    test_synthetic_subtask_id_varies_with_timestamp();

    if (fail_count) {
        std::fprintf(stderr, "%d test(s) failed\n", fail_count);
        return 1;
    }
    std::fprintf(stdout, "agent_test: ok\n");
    return 0;
}
