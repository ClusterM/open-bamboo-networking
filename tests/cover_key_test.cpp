// Framework: repo convention (int main() + CHECK, first failure returns 1).
//
// COVER-01 unit test for obn::cover_model_key — pure string/JSON logic,
// no sockets, no agent. The forcing case is SC3: a fixture MISSING the
// primary key (a MakerWorld print reports its profile title in
// subtask_name and no gcode_file) must fall back to that title
// byte-for-byte; the primary-present fixture proves the basename rule
// that name_matches_model accepts as plate_1.gcode.3mf.

#include "obn/cover_key.hpp"

#include <iostream>
#include <string>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << ": " #cond "\n"; \
        return 1; \
    } \
} while (0)

namespace {

// (a) primary present: gcode_file basename with the trailing .gcode
// stripped — /data/Metadata/plate_1.gcode -> plate_1.
int test_primary_present()
{
    const std::string payload = R"({
        "print":{
            "subtask_name":"bunny.gcode.3mf",
            "gcode_file":"/data/Metadata/plate_1.gcode",
            "task_id":"0",
            "subtask_id":"0"
        }
    })";
    CHECK(obn::cover_model_key(payload) == "plate_1");
    return 0;
}

// (a2) the same primary key read from a root-level (non-print) payload,
// so both lookup shapes the helper supports stay pinned.
int test_primary_present_root_level()
{
    const std::string payload =
        R"({"gcode_file":"/data/Metadata/plate_1.gcode","task_id":"0"})";
    CHECK(obn::cover_model_key(payload) == "plate_1");
    return 0;
}

// (b) SC3 fixture MISSING the primary key: an inline push_status frame
// whose subtask_name is the MakerWorld profile title (spaces, commas,
// percent sign) and which carries no gcode_file at all. The key must be
// that title byte-for-byte — the fallback leg COVER-01 exists for.
int test_fallback_to_subtask_name_when_primary_missing()
{
    const std::string payload = R"({
        "print":{
            "subtask_name":"PETG 0.2mm layer, 2 walls, 15% infill",
            "task_id":"0",
            "subtask_id":"0",
            "project_id":"0",
            "profile_id":"0"
        }
    })";
    CHECK(obn::cover_model_key(payload) ==
          "PETG 0.2mm layer, 2 walls, 15% infill");
    return 0;
}

// (c) degenerate: gcode_file present but an empty string — must fall
// back to subtask_name, never return a partial key.
int test_empty_gcode_file_falls_back()
{
    const std::string payload = R"({
        "print":{
            "subtask_name":"bunny.gcode.3mf",
            "gcode_file":""
        }
    })";
    CHECK(obn::cover_model_key(payload) == "bunny.gcode.3mf");
    return 0;
}

// (d) degenerate: neither field present -> empty key (the caller's
// fetch falls back to subtask_name on empty; nothing crashes).
int test_neither_field_yields_empty()
{
    const std::string payload = R"({
        "print":{"task_id":"0","subtask_id":"0","gcode_start_time":"1700000001"}
    })";
    CHECK(obn::cover_model_key(payload).empty());
    return 0;
}

// (e) round-trip stability: the profile title with spaces, commas and a
// percent sign comes back identical to the source field, byte-for-byte.
int test_profile_title_round_trip()
{
    const std::string title = "PETG 0.2mm layer, 2 walls, 15% infill";
    const std::string payload = std::string(R"({"print":{"subtask_name":")") +
                                title + R"(","task_id":"0"}})";
    const std::string key = obn::cover_model_key(payload);
    CHECK(key == title);
    CHECK(key.size() == title.size());
    return 0;
}

// Suffix discipline: only a trailing ".gcode" is stripped — a path
// without the suffix passes through unchanged (no partial stripping).
int test_suffix_stripped_only_when_present()
{
    const std::string payload =
        R"({"print":{"gcode_file":"/data/Metadata/plate_1"}})";
    CHECK(obn::cover_model_key(payload) == "plate_1");
    const std::string payload2 =
        R"({"print":{"gcode_file":"/data/Metadata/plate_1.gc"}})";
    CHECK(obn::cover_model_key(payload2) == "plate_1.gc");
    return 0;
}

} // namespace

int main()
{
    if (test_primary_present() != 0) return 1;
    if (test_primary_present_root_level() != 0) return 1;
    if (test_fallback_to_subtask_name_when_primary_missing() != 0) return 1;
    if (test_empty_gcode_file_falls_back() != 0) return 1;
    if (test_neither_field_yields_empty() != 0) return 1;
    if (test_profile_title_round_trip() != 0) return 1;
    if (test_suffix_stripped_only_when_present() != 0) return 1;
    std::cout << "cover_key_test: ok\n";
    return 0;
}
