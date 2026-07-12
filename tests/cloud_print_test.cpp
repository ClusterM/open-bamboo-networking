// Tests for cloud_print.cpp — covers ams_mapping2_for_cloud() and
// build_task_body(). All tests are pure-function (no HTTP, no network).
// Built with -DOBN_TESTING which promotes those functions to
// obn::cloud_print::test_ams_mapping2 / test_build_task_body.

#include "obn/bambu_networking.hpp"
#include "obn/json_lite.hpp"

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

static void test_task_body_sequence_id_is_20000()
{
    const std::string body = obn::cloud_print::test_build_task_body(
        default_params(), "", "", "0", false);
    CHECK(field(body, "sequence_id") == "20000");
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
    test_task_body_sequence_id_is_20000();
    test_task_body_boolean_fields();
    test_task_body_is_valid_json();

    if (fail_count) {
        std::fprintf(stderr, "%d test(s) failed\n", fail_count);
        return 1;
    }
    std::fprintf(stdout, "cloud_print_test: ok\n");
    return 0;
}
