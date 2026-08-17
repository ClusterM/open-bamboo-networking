// Tests for cloud_print.cpp — covers ams_mapping2_for_cloud() and
// build_task_body(). All tests are pure-function (no HTTP, no network).
// Built with -DOBN_TESTING which promotes those functions to
// obn::cloud_print::test_ams_mapping2 / test_build_task_body.

#include "obn/bambu_networking.hpp"
#include "obn/json_lite.hpp"
#include "obn/print_job.hpp"

#include <cstdio>
#include <string>

namespace obn::cloud_print {
    std::string test_ams_mapping2(const BBL::PrintParams& p);
    std::string test_build_task_body(const BBL::PrintParams& p,
                                     const std::string& project_id,
                                     const std::string& model_id,
                                     const std::string& profile_id,
                                     bool use_lan_channel);
}

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

static BBL::PrintParams default_params()
{
    BBL::PrintParams p{};
    p.dev_id       = "DEV001";
    p.task_name    = "test_print";
    p.project_name = "TestProject";
    p.plate_index  = 1;
    p.ams_mapping  = "[-1]";
    return p;
}

static std::string field(const std::string& json, const std::string& key)
{
    auto v = obn::json::parse(json);
    if (!v) return {};
    return v->find(key).as_string();
}

static double field_num(const std::string& json, const std::string& key)
{
    auto v = obn::json::parse(json);
    if (!v) return -1;
    return v->find(key).as_number();
}

// ---------------------------------------------------------------------------
// ams_mapping2_for_cloud
// ---------------------------------------------------------------------------

static void test_ams_mapping2_sentinel_from_flat()
{
    BBL::PrintParams p = default_params();
    p.ams_mapping  = "[-1]";
    p.ams_mapping2 = "";
    const std::string out = obn::cloud_print::test_ams_mapping2(p);
    // External-spool sentinel is {amsId:255,slotId:0} (not slotId:255); #48.
    CHECK(out == "[{\"amsId\":255,\"slotId\":0}]");
}

static void test_ams_mapping2_index_from_flat()
{
    BBL::PrintParams p = default_params();
    p.ams_mapping  = "[0,1,4,-1]";
    p.ams_mapping2 = "";
    const std::string out = obn::cloud_print::test_ams_mapping2(p);
    auto v = obn::json::parse(out);
    CHECK(v);
    const auto& arr = v->as_array();
    CHECK(arr.size() == 4);
    CHECK(static_cast<int>(arr[0].find("amsId").as_number())  == 0);
    CHECK(static_cast<int>(arr[0].find("slotId").as_number()) == 0);
    CHECK(static_cast<int>(arr[1].find("amsId").as_number())  == 0);
    CHECK(static_cast<int>(arr[1].find("slotId").as_number()) == 1);
    CHECK(static_cast<int>(arr[2].find("amsId").as_number())  == 1);
    CHECK(static_cast<int>(arr[2].find("slotId").as_number()) == 0);
    CHECK(static_cast<int>(arr[3].find("amsId").as_number())  == 255);
    CHECK(static_cast<int>(arr[3].find("slotId").as_number()) == 0);
}

static void test_ams_mapping2_snake_case_converted_to_camel()
{
    BBL::PrintParams p = default_params();
    p.ams_mapping2 = R"([{"ams_id":0,"slot_id":2},{"ams_id":1,"slot_id":0}])";
    const std::string out = obn::cloud_print::test_ams_mapping2(p);
    CHECK(out.find("amsId")   != std::string::npos);
    CHECK(out.find("slotId")  != std::string::npos);
    CHECK(out.find("ams_id")  == std::string::npos);
    CHECK(out.find("slot_id") == std::string::npos);
    auto v = obn::json::parse(out);
    CHECK(v);
    const auto& arr = v->as_array();
    CHECK(arr.size() == 2);
    CHECK(static_cast<int>(arr[0].find("amsId").as_number())  == 0);
    CHECK(static_cast<int>(arr[0].find("slotId").as_number()) == 2);
    CHECK(static_cast<int>(arr[1].find("amsId").as_number())  == 1);
    CHECK(static_cast<int>(arr[1].find("slotId").as_number()) == 0);
}

static void test_ams_mapping2_camel_case_passthrough()
{
    BBL::PrintParams p = default_params();
    p.ams_mapping2 = R"([{"amsId":2,"slotId":3}])";
    const std::string out = obn::cloud_print::test_ams_mapping2(p);
    auto v = obn::json::parse(out);
    CHECK(v);
    const auto& arr = v->as_array();
    CHECK(arr.size() == 1);
    CHECK(static_cast<int>(arr[0].find("amsId").as_number())  == 2);
    CHECK(static_cast<int>(arr[0].find("slotId").as_number()) == 3);
}

static void test_ams_mapping2_empty_falls_back_to_flat()
{
    BBL::PrintParams p = default_params();
    p.ams_mapping  = "[0]";
    p.ams_mapping2 = "[]";
    const std::string out = obn::cloud_print::test_ams_mapping2(p);
    auto v = obn::json::parse(out);
    CHECK(v);
    const auto& arr = v->as_array();
    CHECK(arr.size() == 1);
    CHECK(static_cast<int>(arr[0].find("amsId").as_number())  == 0);
    CHECK(static_cast<int>(arr[0].find("slotId").as_number()) == 0);
}

// ---------------------------------------------------------------------------
// build_task_body
// ---------------------------------------------------------------------------

static void test_task_body_mode_lan()
{
    const std::string body = obn::cloud_print::test_build_task_body(
        default_params(), "proj1", "model1", "42", /*use_lan_channel=*/true);
    CHECK(field(body, "mode") == "lan_file");
}

static void test_task_body_mode_cloud()
{
    const std::string body = obn::cloud_print::test_build_task_body(
        default_params(), "proj1", "model1", "42", /*use_lan_channel=*/false);
    CHECK(field(body, "mode") == "cloud_file");
}

static void test_task_body_plate_index_clamps_zero_to_one()
{
    BBL::PrintParams p = default_params();
    p.plate_index = 0;
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(static_cast<int>(field_num(body, "plateIndex")) == 1);
}

static void test_task_body_plate_index_positive()
{
    BBL::PrintParams p = default_params();
    p.plate_index = 3;
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(static_cast<int>(field_num(body, "plateIndex")) == 3);
}

static void test_task_body_device_id()
{
    BBL::PrintParams p = default_params();
    p.dev_id = "ABCDEF123";
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "", "", "0", false);
    CHECK(field(body, "deviceId") == "ABCDEF123");
}

static void test_task_body_title_prefers_project_name()
{
    BBL::PrintParams p = default_params();
    p.project_name = "MyProject";
    p.task_name    = "fallback";
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "", "", "0", false);
    CHECK(field(body, "title") == "MyProject");
}

static void test_task_body_title_falls_back_to_task_name()
{
    BBL::PrintParams p = default_params();
    p.project_name = "";
    p.task_name    = "fallback_task";
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "", "", "0", false);
    CHECK(field(body, "title") == "fallback_task");
}

static void test_task_body_bed_type_defaults_to_auto()
{
    BBL::PrintParams p = default_params();
    p.task_bed_type = "";
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "", "", "0", false);
    CHECK(field(body, "bedType") == "auto");
}

static void test_task_body_bed_type_set()
{
    BBL::PrintParams p = default_params();
    p.task_bed_type = "pei";
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "", "", "0", false);
    CHECK(field(body, "bedType") == "pei");
}

static void test_task_body_model_id_and_profile_id()
{
    const std::string body = obn::cloud_print::test_build_task_body(
        default_params(), "proj1", "model_xyz", "99", false);
    CHECK(field(body, "modelId") == "model_xyz");
    CHECK(body.find("\"profileId\":99") != std::string::npos);
}

static void test_task_body_profile_id_zero_fallback()
{
    const std::string body = obn::cloud_print::test_build_task_body(
        default_params(), "proj1", "model_xyz", "", false);
    CHECK(body.find("\"profileId\":0") != std::string::npos);
}

static void test_task_body_sequence_id_is_20001()
{
    // Stock numbers each POST attempt within one create_task call starting at
    // 20001; we never retry, so 20001 is the only value we emit.
    const std::string body = obn::cloud_print::test_build_task_body(
        default_params(), "", "", "0", false);
    CHECK(field(body, "sequence_id") == "20001");
}

static void test_task_body_boolean_fields()
{
    BBL::PrintParams p = default_params();
    p.task_use_ams          = true;
    p.task_bed_leveling     = false;
    p.task_flow_cali        = true;
    p.task_layer_inspect    = false;
    p.task_record_timelapse = true;
    p.task_vibration_cali   = false;
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "", "", "0", false);
    CHECK(body.find("\"useAms\":true")         != std::string::npos);
    CHECK(body.find("\"bedLeveling\":false")   != std::string::npos);
    CHECK(body.find("\"flowCali\":true")       != std::string::npos);
    CHECK(body.find("\"layerInspect\":false")  != std::string::npos);
    CHECK(body.find("\"timelapse\":true")      != std::string::npos);
    CHECK(body.find("\"vibrationCali\":false") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Optional keys in build_task_body.
//
// Stock 02.08.02.54 leaves a whole group of keys out rather than sending a
// default, and the gate is the individual PrintParams field — not task_use_ams.
// Probed one field at a time; see research/08.08-print-abi.md §8.8.8.
// ---------------------------------------------------------------------------

static void test_task_body_ams_keys_omitted_without_mapping()
{
    BBL::PrintParams p = default_params();
    p.ams_mapping  = "";
    p.ams_mapping2 = "";
    p.task_use_ams = true; // on its own this does NOT bring the keys back
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(body.find("\"amsMapping\"")  == std::string::npos);
    CHECK(body.find("\"amsMapping2\"") == std::string::npos);
    CHECK(body.find("\"useAms\":true") != std::string::npos);

    // An empty array conveys no mapping either.
    p.ams_mapping  = "[]";
    p.ams_mapping2 = "[]";
    const std::string empty_arrays = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(empty_arrays.find("\"amsMapping\"")  == std::string::npos);
    CHECK(empty_arrays.find("\"amsMapping2\"") == std::string::npos);
}

static void test_task_body_ams_keys_gated_per_field_not_by_use_ams()
{
    BBL::PrintParams p = default_params();
    p.task_use_ams = false; // stock still emits both when the strings are set
    p.ams_mapping  = "[3,-1]";
    p.ams_mapping2 = R"([{"ams_id":2,"slot_id":3},{"ams_id":255,"slot_id":0}])";
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(body.find("\"amsMapping\":[3,-1]") != std::string::npos);
    CHECK(body.find("\"amsMapping2\":[{\"amsId\":2,\"slotId\":3},"
                    "{\"amsId\":255,\"slotId\":0}]") != std::string::npos);
    CHECK(body.find("\"useAms\":false") != std::string::npos);
}

static void test_task_body_nozzle_mapping_optional()
{
    BBL::PrintParams p = default_params();
    p.nozzle_mapping = "";
    const std::string bare = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(bare.find("\"nozzleMapping\"") == std::string::npos);

    p.nozzle_mapping = "[7,9]";
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(body.find("\"nozzleMapping\":[7,9]") != std::string::npos);
    // Stock orders the body alphabetically, so nozzleMapping sits between
    // nozzleInfos and nozzleOffsetCali.
    CHECK(body.find("\"nozzleInfos\"") < body.find("\"nozzleMapping\""));
    CHECK(body.find("\"nozzleMapping\"") < body.find("\"nozzleOffsetCali\""));
}

static void test_task_body_design_id_omitted_when_zero()
{
    BBL::PrintParams p = default_params();
    p.stl_design_id = 0;
    const std::string bare = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(bare.find("\"designId\"") == std::string::npos);

    p.stl_design_id = 333444;
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(body.find("\"designId\":333444") != std::string::npos);
}

#if ABI_VERSION >= 0x020400
static void test_task_body_extrude_cali_manual_mode_omitted_when_unset()
{
    BBL::PrintParams p = default_params();
    p.extruder_cali_manual_mode = -1; // Studio's "not set"
    const std::string bare = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(bare.find("\"extrudeCaliManualMode\"") == std::string::npos);

    for (int mode : {0, 1}) {
        p.extruder_cali_manual_mode = mode;
        const std::string body = obn::cloud_print::test_build_task_body(
            p, "proj1", "model1", "42", false);
        CHECK(body.find("\"extrudeCaliManualMode\":" + std::to_string(mode))
              != std::string::npos);
    }
}
#endif

static void test_task_body_cfg_bitmask()
{
    BBL::PrintParams p = default_params();
    p.task_ext_change_assist = false;
    p.task_record_timelapse  = true; // rides in `timelapse`, not in cfg
    #if ABI_VERSION >= 0x020503
        p.task_timelapse_use_internal = false;
    #endif
    const std::string zero = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(field(zero, "cfg") == "0");

    p.task_ext_change_assist = true;
    const std::string bit0 = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(field(bit0, "cfg") == "1");

    #if ABI_VERSION >= 0x020503
        p.task_ext_change_assist      = false;
        p.task_timelapse_use_internal = true;
        const std::string bit2 = obn::cloud_print::test_build_task_body(
            p, "proj1", "model1", "42", false);
        CHECK(field(bit2, "cfg") == "4");

        p.task_ext_change_assist = true;
        const std::string both = obn::cloud_print::test_build_task_body(
            p, "proj1", "model1", "42", false);
        CHECK(field(both, "cfg") == "5");
    #endif
}

#if ABI_VERSION >= 0x020802
// Byte-for-byte pin against the stock 02.08.02.54 body captured with every
// PrintParams field this ABI exposes filled with sentinels (probe C1). The one
// liberty taken with the inputs: nested objects are written with their keys
// already sorted, because stock re-serialises them through a JSON object while
// we forward the caller's string verbatim.
static void test_task_body_matches_stock_capture()
{
    BBL::PrintParams p = default_params();
    p.dev_id                      = "22E8BJ610801473";
    p.project_name                = "obn-probe-C1";
    p.plate_index                 = 1;
    p.nozzle_mapping              = "[7,9]";
    p.ams_mapping                 = "[3,-1]";
    p.ams_mapping2                = R"([{"ams_id":2,"slot_id":3},{"ams_id":255,"slot_id":0}])";
    p.ams_mapping_info            = R"([{"ams":"OBNAMS7","filament_id":"GFL77","filament_type":"PLA"}])";
    p.nozzles_info                = R"([{"diameter":0.6,"flow_type":1,"id":0,"type":"hardened_steel"}])";
    p.origin_model_id             = "OBNORIMODELAAA";
    p.origin_profile_id           = 111222;
    p.stl_design_id               = 333444;
    p.task_bed_type               = "textured_plate";
    p.task_bed_leveling           = true;
    p.task_flow_cali              = true;
    p.task_vibration_cali         = true;
    p.task_layer_inspect          = true;
    p.task_record_timelapse       = true;
    p.task_timelapse_use_internal = true;
    p.task_use_ams                = true;
    p.task_ext_change_assist      = true;
    p.auto_bed_leveling           = 2;
    p.auto_flow_cali              = 3;
    p.auto_offset_cali            = 4;
    p.extruder_cali_manual_mode   = 1;

    const std::string expected =
        R"({"amsDetailMapping":[{"ams":"OBNAMS7","filament_id":"GFL77","filament_type":"PLA"}])"
        R"(,"amsMapping":[3,-1])"
        R"(,"amsMapping2":[{"amsId":2,"slotId":3},{"amsId":255,"slotId":0}])"
        R"(,"autoBedLeveling":2,"bedLeveling":true,"bedType":"textured_plate")"
        R"(,"cfg":"5","cover":"","designId":333444,"deviceId":"22E8BJ610801473")"
        R"(,"extrudeCaliFlag":3,"extrudeCaliManualMode":1,"filamentSettingIds":[])"
        R"(,"flowCali":true,"layerInspect":true,"mode":"lan_file")"
        R"(,"modelId":"US49f1dba5797715")"
        R"(,"nozzleInfos":[{"diameter":0.6,"flow_type":1,"id":0,"type":"hardened_steel"}])"
        R"(,"nozzleMapping":[7,9],"nozzleOffsetCali":4)"
        R"(,"oriModelId":"OBNORIMODELAAA","oriProfileId":111222,"plateIndex":1)"
        R"(,"profileId":939259728,"sequence_id":"20001","timelapse":true)"
        R"(,"title":"obn-probe-C1","useAms":true,"vibrationCali":true})";

    const std::string body = obn::cloud_print::test_build_task_body(
        p, "959541104", "US49f1dba5797715", "939259728", /*use_lan_channel=*/true);
    CHECK(body == expected);
}

// The other end of the range, and the one that actually matters in production:
// a plain no-AMS cloud print with nothing but the defaults. Pinned against the
// stock 02.08.02.54 body for probe P0.
static void test_task_body_matches_stock_capture_minimal()
{
    BBL::PrintParams p = default_params();
    p.dev_id       = "22E8BJ610801473";
    p.project_name = "obn-probe-P0";
    p.plate_index  = 1;
    p.task_bed_type = "auto";
    p.ams_mapping.clear();

    const std::string expected =
        R"({"amsDetailMapping":[],"autoBedLeveling":0,"bedLeveling":false)"
        R"(,"bedType":"auto","cfg":"0","cover":"","deviceId":"22E8BJ610801473")"
        R"(,"extrudeCaliFlag":0,"filamentSettingIds":[],"flowCali":false)"
        R"(,"layerInspect":false,"mode":"cloud_file","modelId":"USdaf6eef3b8f575")"
        R"(,"nozzleInfos":[],"nozzleOffsetCali":0,"oriModelId":"","oriProfileId":0)"
        R"(,"plateIndex":1,"profileId":938888546,"sequence_id":"20001")"
        R"(,"timelapse":false,"title":"obn-probe-P0","useAms":false)"
        R"(,"vibrationCali":false})";

    const std::string body = obn::cloud_print::test_build_task_body(
        p, "", "USdaf6eef3b8f575", "938888546", /*use_lan_channel=*/false);
    CHECK(body == expected);
}
#endif

static void test_task_body_is_valid_json()
{
    BBL::PrintParams p = default_params();
    p.ams_mapping  = "[0,-1]";
    p.ams_mapping2 = R"([{"ams_id":0,"slot_id":0},{"ams_id":255,"slot_id":255}])";
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "proj", "model", "77", true);
    auto v = obn::json::parse(body);
    CHECK(v);
    CHECK(v->find("mode").kind()        == obn::json::Value::Kind::String);
    CHECK(v->find("amsMapping").kind()  == obn::json::Value::Kind::Array);
    CHECK(v->find("amsMapping2").kind() == obn::json::Value::Kind::Array);
    CHECK(v->find("deviceId").kind()    == obn::json::Value::Kind::String);
    CHECK(v->find("plateIndex").kind()  == obn::json::Value::Kind::Number);
}

// ---------------------------------------------------------------------------
// project_file payload builder: always emits cleartext url; url_enc is added
// later by signing::maybe_sign on the cloud MQTT publish path.
// ---------------------------------------------------------------------------

static void test_lan_project_file_is_plaintext()
{
    // LAN-first print trigger: the printer fetches from its own storage over a
    // local URL, so the payload must carry a cleartext `url` and NO `url_enc`
    // (mirrors run_local_print_job).
    BBL::PrintParams p = default_params();
    obn::print_job::ProjectFileOpts opts;
    opts.file_path  = "TestProject.gcode.3mf";
    opts.url        = "ftp:///TestProject.gcode.3mf";
    opts.md5        = "abc123";
    opts.project_id = "proj1";
    opts.profile_id = "42";
    opts.task_id    = "task9";

    const std::string json = obn::print_job::build_project_file_json(p, opts);
    auto v = obn::json::parse(json);
    CHECK(v);
    CHECK(json.find("\"url_enc\"") == std::string::npos);
    CHECK(field(json, "print.url") == "ftp:///TestProject.gcode.3mf");
    CHECK(field(json, "print.command") == "project_file");
}

static void test_cloud_project_file_builder_also_plaintext()
{
    // Cloud channel also builds cleartext `url`; encryption to `url_enc`
    // happens in maybe_sign (covered by signing_test), not in the builder.
    BBL::PrintParams p = default_params();
    obn::print_job::ProjectFileOpts opts;
    opts.file_path  = "slot.3mf";
    opts.url        = "https://s3.example/obj?sig=1";
    opts.md5        = "abc123";
    opts.project_id = "proj1";
    opts.profile_id = "42";
    opts.task_id    = "task9";

    const std::string json = obn::print_job::build_project_file_json(p, opts);
    auto v = obn::json::parse(json);
    CHECK(v);
    CHECK(json.find("\"url_enc\"") == std::string::npos);
    CHECK(field(json, "print.url") == "https://s3.example/obj?sig=1");
    CHECK(field(json, "print.command") == "project_file");
}

static void test_project_file_cfg_bitmask()
{
    // Same bitmask as the /my/task body: stock 02.08.02.54 published
    // cfg="1" in project_file for task_ext_change_assist alone.
    BBL::PrintParams p = default_params();
    obn::print_job::ProjectFileOpts opts;
    opts.file_path = "slot.3mf";
    opts.url       = "ftp:///slot.3mf";

    p.task_ext_change_assist = false;
    CHECK(field(obn::print_job::build_project_file_json(p, opts),
                "print.cfg") == "0");

    p.task_ext_change_assist = true;
    CHECK(field(obn::print_job::build_project_file_json(p, opts),
                "print.cfg") == "1");

    #if ABI_VERSION >= 0x020503
        p.task_timelapse_use_internal = true;
        CHECK(field(obn::print_job::build_project_file_json(p, opts),
                    "print.cfg") == "5");
    #endif
}

static int seq_id_as_int(const std::string& json)
{
    const std::string s = field(json, "print.sequence_id");
    if (s.empty()) return -1;
    return std::stoi(s);
}

static void test_project_file_sequence_id_in_studio_range()
{
    BBL::PrintParams p = default_params();
    obn::print_job::ProjectFileOpts opts;
    opts.file_path = "slot.3mf";
    opts.url       = "ftp:///slot.3mf";
    const std::string a = obn::print_job::build_project_file_json(p, opts);
    const std::string b = obn::print_job::build_project_file_json(p, opts);
    const int sa = seq_id_as_int(a);
    const int sb = seq_id_as_int(b);
    CHECK(sa >= 20000 && sa < 30000);
    CHECK(sb >= 20000 && sb < 30000);
    CHECK(sa != sb);
}

static void test_project_file_ams_mapping_empty_is_array_even_with_use_ams()
{
    // Stock 02.08.02.54 / 02.05.03.63 both emit [] when the string is
    // empty, including with task_use_ams=true. The old [0] fallback was
    // a guess.
    BBL::PrintParams p = default_params();
    p.ams_mapping.clear();
    p.task_use_ams = true;
    obn::print_job::ProjectFileOpts opts;
    opts.file_path = "slot.3mf";
    opts.md5       = "from_sd_card";
    const std::string json = obn::print_job::build_project_file_json(p, opts);
    CHECK(json.find("\"ams_mapping\":[]") != std::string::npos);
    CHECK(json.find("\"use_ams\":true") != std::string::npos);
}

static void test_project_file_omits_url_when_empty_and_md5_is_literal()
{
    BBL::PrintParams p = default_params();
    p.project_name = "obn-probe-L2";
    p.ams_mapping.clear();
    obn::print_job::ProjectFileOpts opts;
    opts.file_path = "obn-probe-L2.gcode.3mf";
    opts.url       = "";
    opts.md5       = "from_sd_card";
    const std::string json = obn::print_job::build_project_file_json(p, opts);
    CHECK(json.find("\"url\"") == std::string::npos);
    CHECK(json.find("\"url_enc\"") == std::string::npos);
    CHECK(field(json, "print.md5") == "from_sd_card");
    CHECK(field(json, "print.file") == "obn-probe-L2.gcode.3mf");
}

#if ABI_VERSION >= 0x020400
// Field-level pin against the stock 02.08.02.54 L1 sdcard_print capture
// (max sentinel). sequence_id is excluded: we seed it randomly in the
// same 20000–29999 window rather than hardcoding 20001.
static void test_project_file_matches_stock_l1()
{
    BBL::PrintParams p = default_params();
    p.project_name                = "obn-probe-L1";
    p.plate_index                 = 2;
    p.ams_mapping                 = "[3,-1]";
    p.ams_mapping2                = R"([{"ams_id":2,"slot_id":3},{"ams_id":255,"slot_id":0}])";
    p.task_bed_type               = "textured_plate";
    p.task_bed_leveling           = true;
    p.task_flow_cali              = true;
    p.task_vibration_cali         = true;
    p.task_layer_inspect          = true;
    p.task_record_timelapse       = true;
    p.task_use_ams                = true;
    p.task_ext_change_assist      = true;
    p.auto_bed_leveling           = 2;
    p.auto_flow_cali              = 3;
    p.auto_offset_cali            = 4;
    p.extruder_cali_manual_mode   = 1;
#if ABI_VERSION >= 0x020503
    p.task_timelapse_use_internal = true;
#endif
#if ABI_VERSION >= 0x020801
    p.slicer_uid                  = "OBNUIDAAAA1111";
#endif

    obn::print_job::ProjectFileOpts opts;
    opts.file_path = "obn-probe-L1.gcode.3mf";
    opts.url       = "";
    opts.md5       = "from_sd_card";

    const std::string json = obn::print_job::build_project_file_json(p, opts);
    CHECK(field(json, "print.command") == "project_file");
    CHECK(field(json, "print.file") == "obn-probe-L1.gcode.3mf");
    CHECK(field(json, "print.md5") == "from_sd_card");
    CHECK(field(json, "print.param") == "Metadata/plate_2.gcode");
    CHECK(field(json, "print.bed_type") == "textured_plate");
#if ABI_VERSION >= 0x020503
    CHECK(field(json, "print.cfg") == "5");
#else
    CHECK(field(json, "print.cfg") == "1");
#endif
    CHECK(json.find("\"ams_mapping\":[3,-1]") != std::string::npos);
    CHECK(json.find("\"ams_mapping2\":[{\"ams_id\":2,\"slot_id\":3},{\"ams_id\":255,\"slot_id\":0}]")
          != std::string::npos);
    CHECK(json.find("\"bed_leveling\":true") != std::string::npos);
    CHECK(json.find("\"flow_cali\":true") != std::string::npos);
    CHECK(json.find("\"vibration_cali\":true") != std::string::npos);
    CHECK(json.find("\"layer_inspect\":true") != std::string::npos);
    CHECK(json.find("\"timelapse\":true") != std::string::npos);
    CHECK(json.find("\"use_ams\":true") != std::string::npos);
    CHECK(json.find("\"auto_bed_leveling\":2") != std::string::npos);
    CHECK(json.find("\"extrude_cali_flag\":3") != std::string::npos);
    CHECK(json.find("\"nozzle_offset_cali\":4") != std::string::npos);
    CHECK(json.find("\"extrude_cali_manual_mode\":1") != std::string::npos);
    CHECK(json.find("\"url\"") == std::string::npos);
#if ABI_VERSION >= 0x020801
    CHECK(field(json, "print.slicer_uid") == "OBNUIDAAAA1111");
#endif
    const int seq = seq_id_as_int(json);
    CHECK(seq >= 20000 && seq < 30000);
}
#endif

// ---------------------------------------------------------------------------
// slicer_uid / queue_plate_id / svc_context routing
//
// These three PrintParams fields each go to exactly one destination, pinned
// here against a stock 02.08.02.54 sentinel capture (research/08.08-print-abi.md
// §8.8.1): slicer_uid to the LAN project_file only, queue_plate_id and
// svc_context to POST /my/task only.
// ---------------------------------------------------------------------------

#if ABI_VERSION >= 0x020801
static void test_slicer_uid_in_project_file()
{
    BBL::PrintParams p = default_params();
    p.slicer_uid = "OBNUIDAAAA1111";
    obn::print_job::ProjectFileOpts opts;
    opts.file_path = "slot.3mf";
    opts.url       = "ftp:///slot.3mf";

    const std::string json = obn::print_job::build_project_file_json(p, opts);
    CHECK(field(json, "print.slicer_uid") == "OBNUIDAAAA1111");

    // Empty drops the key entirely rather than sending "".
    p.slicer_uid.clear();
    const std::string bare = obn::print_job::build_project_file_json(p, opts);
    CHECK(bare.find("\"slicer_uid\"") == std::string::npos);
}

static void test_slicer_uid_absent_from_task_body()
{
    BBL::PrintParams p = default_params();
    p.slicer_uid = "OBNUIDAAAA1111";
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(body.find("OBNUIDAAAA1111") == std::string::npos);
    CHECK(body.find("slicerUid") == std::string::npos);
}
#endif

#if ABI_VERSION >= 0x020701
static void test_svc_context_in_task_body()
{
    BBL::PrintParams p = default_params();
    p.svc_context = "OBNSVCCCC3333";
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(field(body, "svcContext") == "OBNSVCCCC3333");

    p.svc_context.clear();
    const std::string bare = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(bare.find("\"svcContext\"") == std::string::npos);
}

static void test_svc_context_absent_from_project_file()
{
    BBL::PrintParams p = default_params();
    p.svc_context = "OBNSVCCCC3333";
    obn::print_job::ProjectFileOpts opts;
    opts.file_path = "slot.3mf";
    opts.url       = "ftp:///slot.3mf";
    const std::string json = obn::print_job::build_project_file_json(p, opts);
    CHECK(json.find("OBNSVCCCC3333") == std::string::npos);
}
#endif

#if ABI_VERSION >= 0x020802
static void test_queue_plate_id_is_numeric_in_task_body()
{
    BBL::PrintParams p = default_params();
    // Exceeds 32 bits on purpose: stock emitted this verbatim as a number.
    p.queue_plate_id = "9988776655";
    const std::string body = obn::cloud_print::test_build_task_body(
        p, "proj1", "model1", "42", false);
    CHECK(body.find("\"plateId\":9988776655") != std::string::npos);
}

static void test_queue_plate_id_dropped_when_unusable()
{
    BBL::PrintParams p = default_params();
    for (const char* bad : {"", "OBNQPIDBBBB2222", "0", "12abc"}) {
        p.queue_plate_id = bad;
        const std::string body = obn::cloud_print::test_build_task_body(
            p, "proj1", "model1", "42", false);
        CHECK(body.find("\"plateId\"") == std::string::npos);
    }
}

static void test_queue_plate_id_absent_from_project_file()
{
    BBL::PrintParams p = default_params();
    p.queue_plate_id = "9988776655";
    obn::print_job::ProjectFileOpts opts;
    opts.file_path = "slot.3mf";
    opts.url       = "ftp:///slot.3mf";
    const std::string json = obn::print_job::build_project_file_json(p, opts);
    CHECK(json.find("9988776655") == std::string::npos);
}
#endif

static void test_format_upload_info_matches_stock()
{
    // Values from stock_hybrid.mitm (2026-07-19): main 1195684, config 241613.
    CHECK(obn::print_job::format_upload_info(0, 1195684) == "0.0K/1.1M");
    CHECK(obn::print_job::format_upload_info(1195684, 1195684) == "1.1M/1.1M");
    CHECK(obn::print_job::format_upload_info(0, 241613) == "0.0K/0.2M");
    CHECK(obn::print_job::format_upload_info(241613, 241613) == "0.2M/0.2M");
    CHECK(obn::print_job::format_upload_info(104857, 1195684) == "0.1M/1.1M");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    test_ams_mapping2_sentinel_from_flat();
    test_ams_mapping2_index_from_flat();
    test_ams_mapping2_snake_case_converted_to_camel();
    test_ams_mapping2_camel_case_passthrough();
    test_ams_mapping2_empty_falls_back_to_flat();

    test_task_body_mode_lan();
    test_task_body_mode_cloud();
    test_task_body_plate_index_clamps_zero_to_one();
    test_task_body_plate_index_positive();
    test_task_body_device_id();
    test_task_body_title_prefers_project_name();
    test_task_body_title_falls_back_to_task_name();
    test_task_body_bed_type_defaults_to_auto();
    test_task_body_bed_type_set();
    test_task_body_model_id_and_profile_id();
    test_task_body_profile_id_zero_fallback();
    test_task_body_sequence_id_is_20001();
    test_task_body_boolean_fields();
    test_task_body_ams_keys_omitted_without_mapping();
    test_task_body_ams_keys_gated_per_field_not_by_use_ams();
    test_task_body_nozzle_mapping_optional();
    test_task_body_design_id_omitted_when_zero();
#if ABI_VERSION >= 0x020400
    test_task_body_extrude_cali_manual_mode_omitted_when_unset();
#endif
    test_task_body_cfg_bitmask();
#if ABI_VERSION >= 0x020802
    test_task_body_matches_stock_capture();
    test_task_body_matches_stock_capture_minimal();
#endif
    test_task_body_is_valid_json();

    test_lan_project_file_is_plaintext();
    test_cloud_project_file_builder_also_plaintext();
    test_project_file_cfg_bitmask();
    test_project_file_sequence_id_in_studio_range();
    test_project_file_ams_mapping_empty_is_array_even_with_use_ams();
    test_project_file_omits_url_when_empty_and_md5_is_literal();
#if ABI_VERSION >= 0x020400
    test_project_file_matches_stock_l1();
#endif

#if ABI_VERSION >= 0x020801
    test_slicer_uid_in_project_file();
    test_slicer_uid_absent_from_task_body();
#endif
#if ABI_VERSION >= 0x020701
    test_svc_context_in_task_body();
    test_svc_context_absent_from_project_file();
#endif
#if ABI_VERSION >= 0x020802
    test_queue_plate_id_is_numeric_in_task_body();
    test_queue_plate_id_dropped_when_unusable();
    test_queue_plate_id_absent_from_project_file();
#endif

    test_format_upload_info_matches_stock();

    if (fail_count) {
        std::fprintf(stderr, "%d test(s) failed\n", fail_count);
        return 1;
    }
    std::fprintf(stdout, "cloud_print_test: ok\n");
    return 0;
}
