// TEST-02 executable spec: the 3-rule push_status delta-merge, replayed
// over the 7 vendored p1s-print-lifecycle frames (D-13, D-14, D-16).
//
// D-15 no-sites audit (recorded 2026-09-29): no JSON-level push_status
// accumulator exists in this repo today, so this test is an executable
// spec for FUTURE accumulation code — any real accumulator must satisfy
// these assertions:
//  - tools/plugin_runner/main.cpp:836 keeps only a scalar latch:
//    `int last_status = -1;` — it never accumulates the JSON payload.
//  - src/agent.cpp:637 rewrites incoming LAN push_status frames in place
//    ("These rewrite incoming LAN push_status frames in place.") — again
//    no accumulated state.
//  - The Python plugin (open-bambu-networking-plugin) has no
//    merge/accumulator hits (repo-wide grep).
//
// The spec (PandaSpy merge.rs, upstream `merge.rs` doc comment):
//   absent        — the delta does not mention the key: old value kept.
//   present null  — the delta explicitly nulls the key: the value is
//                   CLEARED by inserting null with the key RETAINED
//                   (map count stays 1 and the value is_null()).
//   present       — objects merge recursively; everything else
//                   (arrays, scalars, type changes) replaces wholesale.
//
// Presence is always checked at map level — std::map count()/find() on
// as_object() plus is_null() on the mapped value — NEVER via Value::find,
// which collapses any miss to null (include/obn/json_lite.hpp:79) and
// would make absent-vs-null, the load-bearing distinction, untestable
// (Pitfall 11).
//
// Framework: repo convention (int main() + fail_count + CHECK, as in
// json_lite_test.cpp) — the OQ-1 checkpoint decision (02-02, route b2,
// Catch2) applied to the converted ssdp_listener_test.cpp; the research
// default for this new file is the repo's own macro skeleton.

#include "obn/json_lite.hpp"

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

// D-08: fixtures load by runtime file read (the ctest WORKING_DIRECTORY
// is tests/fixtures). A missing or renamed frame must fail loudly — print
// FAIL with the absolute path and count the failure, never skip silently.
bool read_fixture_impl(const char* rel, std::string& out, int line)
{
    std::ifstream in(rel, std::ios::binary);
    if (!in) {
        std::error_code ec;
        const std::string abs = std::filesystem::absolute(rel, ec).string();
        std::fprintf(stderr,
                     "FAIL %s:%d: cannot open fixture: %s (absolute path: %s)\n",
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

// Test-local reference accumulator (D-13): the 3-rule merge over
// obn::json::Value. Implemented entirely in this test file — no production
// merge or accumulator helper exists or may be introduced this phase.
// Presence uses std::map find() on the Object copy, never Value::find.
void deep_merge(obn::json::Value& base, const obn::json::Value& delta)
{
    if (!base.is_object() || !delta.is_object()) {
        // Scalars, arrays, nulls and type changes replace wholesale
        // (a present null therefore clears the value; see below for the
        // key-retained case).
        base = delta;
        return;
    }
    // as_object() is const-only, so merge through a local mutable copy of
    // the map and write it back — zero production-header changes.
    obn::json::Object b = base.as_object();
    const obn::json::Object& d = delta.as_object();
    for (const auto& kv : d) {
        const std::string& k = kv.first;
        const obn::json::Value& dv = kv.second;
        auto it = b.find(k);
        if (it == b.end()) {
            // Absent-in-base: take the delta value (rule 1 on empty base;
            // keys the delta never mentions are simply not touched below,
            // which is the "absent keeps" half of rule 1).
            b.emplace(k, dv);
        } else if (it->second.is_object() && dv.is_object()) {
            deep_merge(it->second, dv);  // objects merge recursively
        } else {
            // Present and not object+object: replace wholesale (rule 3),
            // which includes present-null => null inserted, KEY RETAINED.
            it->second = dv;
        }
    }
    base = obn::json::Value(std::move(b));
}

// D-03: the 7 vendored frames, replayed in this exact order — never
// cherry-picked, never reordered, never edited (tests/fixtures/README.md
// inventory, byte-exact under .gitattributes -text).
const char* const kFrames[] = {
    "sequences/p1s-print-lifecycle/00-pushall.json",
    "sequences/p1s-print-lifecycle/01-delta-temps.json",
    "sequences/p1s-print-lifecycle/02-delta-progress.json",
    "sequences/p1s-print-lifecycle/03-delta-tray-switch.json",
    "sequences/p1s-print-lifecycle/04-delta-null-clears-wifi.json",
    "sequences/p1s-print-lifecycle/05-delta-pause.json",
    "sequences/p1s-print-lifecycle/06-delta-finish.json",
};
constexpr int kFrameCount = sizeof(kFrames) / sizeof(kFrames[0]);

// Step-00 oracle (D-14, tracer scope): the full pushall establishes the
// baseline accumulated state.
void assert_step_00(const obn::json::Value& state)
{
    CHECK(state.is_object());
    const obn::json::Object& obj = state.as_object();

    // wifi_signal lands as the "-52dBm" string (present and non-null).
    CHECK(obj.count("wifi_signal") == 1);
    CHECK(obj.at("wifi_signal").is_string());
    CHECK(!obj.at("wifi_signal").is_null());
    CHECK(obj.at("wifi_signal").as_string() == "-52dBm");

    // hms present as an empty array.
    CHECK(obj.count("hms") == 1);
    CHECK(obj.at("hms").is_array());
    CHECK(obj.at("hms").as_array().empty());

    // subtask_name lands as "benchy".
    CHECK(obj.count("subtask_name") == 1);
    CHECK(obj.at("subtask_name").as_string() == "benchy");
}

// Step-01 oracle (D-14): temps advance via replace; wifi_signal is ABSENT
// from this delta and must keep its step-00 value — "absent keeps"
// executed against a named key.
void assert_step_01(const obn::json::Value& state)
{
    CHECK(state.is_object());
    const obn::json::Object& obj = state.as_object();

    // absent-keeps: delta 01 never mentions wifi_signal -> old value.
    CHECK(obj.count("wifi_signal") == 1);
    CHECK(obj.at("wifi_signal").is_string());
    CHECK(!obj.at("wifi_signal").is_null());
    CHECK(obj.at("wifi_signal").as_string() == "-52dBm");

    // present scalars replace wholesale (rule 3 on scalars).
    CHECK(obj.count("bed_temper") == 1);
    CHECK(obj.at("bed_temper").as_number() == 60.1);
    CHECK(obj.count("nozzle_temper") == 1);
    CHECK(obj.at("nozzle_temper").as_number() == 220.2);
}

// Step-02 oracle: progress counters replace; keys from earlier deltas
// survive because this delta never mentions them.
void assert_step_02(const obn::json::Value& state)
{
    CHECK(state.is_object());
    const obn::json::Object& obj = state.as_object();

    CHECK(obj.count("mc_percent") == 1);
    CHECK(obj.at("mc_percent").as_number() == 42);
    CHECK(obj.count("mc_remaining_time") == 1);
    CHECK(obj.at("mc_remaining_time").as_number() == 96);
    CHECK(obj.count("layer_num") == 1);
    CHECK(obj.at("layer_num").as_number() == 57);

    // absent-keeps: temps from step 01 survive delta 02 untouched.
    CHECK(obj.count("bed_temper") == 1);
    CHECK(obj.at("bed_temper").as_number() == 60.1);
    CHECK(obj.count("wifi_signal") == 1);
    CHECK(obj.at("wifi_signal").as_string() == "-52dBm");
}

// Step-03 oracle: the nested `ams` OBJECT merges recursively — keys the
// sub-delta mentions are replaced, keys it never mentions are kept.
void assert_step_03(const obn::json::Value& state)
{
    CHECK(state.is_object());
    const obn::json::Object& obj = state.as_object();

    CHECK(obj.count("stg_cur") == 1);
    CHECK(obj.at("stg_cur").as_number() == 4);

    CHECK(obj.count("ams") == 1);
    CHECK(obj.at("ams").is_object());
    const obn::json::Object& ams = obj.at("ams").as_object();
    // replaced by the sub-delta:
    CHECK(ams.count("tray_now") == 1);
    CHECK(ams.at("tray_now").as_string() == "2");
    CHECK(ams.at("tray_pre").as_string() == "1");
    CHECK(ams.at("tray_tar").as_string() == "2");
    // absent-keeps INSIDE the recursion: unmentioned ams keys survive
    // (object recursion, not wholesale object replacement).
    CHECK(ams.count("ams_exist_bits") == 1);
    CHECK(ams.at("ams_exist_bits").as_string() == "1");
    CHECK(ams.count("ams") == 1);  // the nested ams list survived too

    // top-level absent-keeps continues to hold
    CHECK(obj.count("wifi_signal") == 1);
    CHECK(obj.at("wifi_signal").as_string() == "-52dBm");
}

// Step-04 oracle (the load-bearing rule): wifi_signal is PRESENT-AND-NULL
// in this delta — the value clears while the KEY IS RETAINED. Presence is
// discriminated at map level (count + is_null), never Value::find
// (Pitfall 11), and a neighbouring key must survive.
void assert_step_04(const obn::json::Value& state)
{
    CHECK(state.is_object());
    const obn::json::Object& obj = state.as_object();

    // present-null-clears: key retained (count == 1) AND value is null.
    CHECK(obj.count("wifi_signal") == 1);
    CHECK(obj.at("wifi_signal").is_null());

    // neighbouring key survived the null-clear (absent from delta 04).
    CHECK(obj.count("sdcard") == 1);
    CHECK(obj.at("sdcard").is_bool());
    CHECK(obj.at("sdcard").as_bool());
    CHECK(obj.count("subtask_name") == 1);
    CHECK(obj.at("subtask_name").as_string() == "benchy");

    // present scalar in the same delta still replaces
    CHECK(obj.count("stg_cur") == 1);
    CHECK(obj.at("stg_cur").as_number() == 0);
}

// Step-05 oracle: pause state replaces; wifi_signal is absent from this
// delta, so the CLEARED (null) value is kept — absent-keeps applies to
// nulls as much as to strings.
void assert_step_05(const obn::json::Value& state)
{
    CHECK(state.is_object());
    const obn::json::Object& obj = state.as_object();

    CHECK(obj.count("gcode_state") == 1);
    CHECK(obj.at("gcode_state").as_string() == "PAUSE");
    CHECK(obj.count("stg_cur") == 1);
    CHECK(obj.at("stg_cur").as_number() == 16);

    // absent-keeps of the cleared value: still present, still null.
    CHECK(obj.count("wifi_signal") == 1);
    CHECK(obj.at("wifi_signal").is_null());
}

// Step-06 oracle: the finish delta lands.
void assert_step_06(const obn::json::Value& state)
{
    CHECK(state.is_object());
    const obn::json::Object& obj = state.as_object();

    CHECK(obj.count("gcode_state") == 1);
    CHECK(obj.at("gcode_state").as_string() == "FINISH");
    CHECK(obj.count("stg_cur") == 1);
    CHECK(obj.at("stg_cur").as_number() == -1);
    CHECK(obj.count("mc_percent") == 1);
    CHECK(obj.at("mc_percent").as_number() == 100);
    CHECK(obj.count("mc_remaining_time") == 1);
    CHECK(obj.at("mc_remaining_time").as_number() == 0);
    CHECK(obj.count("layer_num") == 1);
    CHECK(obj.at("layer_num").as_number() == 137);

    // the clear from step 04 is still in effect (delta 06 omits it)
    CHECK(obj.count("wifi_signal") == 1);
    CHECK(obj.at("wifi_signal").is_null());
}

} // namespace

// Call sites keep the read_fixture(rel, out) shape; the line number in the
// loud-failure message comes from the call site (same pattern as
// ssdp_listener_test.cpp).
#define read_fixture(rel, out) read_fixture_impl(rel, out, __LINE__)

int main()
{
    // Accumulated state starts as an empty object; each frame's "print"
    // envelope merges into it, in kFrames order.
    obn::json::Value state(obn::json::Object{});

    for (int i = 0; i < kFrameCount; ++i) {
        const char* rel = kFrames[i];

        std::string frame_text;
        const bool opened = read_fixture(rel, frame_text);
        CHECK(opened);  // frame-open CHECK: a missing file fails loudly
        if (!opened) continue;

        std::string err;
        auto doc = obn::json::parse(frame_text, &err);
        if (!doc) {
            std::fprintf(stderr, "FAIL %s:%d: cannot parse frame %s: %s\n",
                         __FILE__, __LINE__, rel, err.c_str());
            ++fail_count;
            continue;
        }

        // Envelope: {"print": { ...delta... }} — extract at map level
        // (never Value::find).
        if (!doc->is_object()) {
            std::fprintf(stderr, "FAIL %s:%d: frame %s is not an object\n",
                         __FILE__, __LINE__, rel);
            ++fail_count;
            continue;
        }
        const obn::json::Object& env = doc->as_object();
        auto print_it = env.find("print");
        if (print_it == env.end() || !print_it->second.is_object()) {
            std::fprintf(stderr,
                         "FAIL %s:%d: frame %s has no object \"print\" envelope\n",
                         __FILE__, __LINE__, rel);
            ++fail_count;
            continue;
        }

        deep_merge(state, print_it->second);

        // Per-step oracle (D-14): assert the hand-derived expected state
        // after EVERY frame — never final-state-only.
        switch (i) {
            case 0: assert_step_00(state); break;
            case 1: assert_step_01(state); break;
            case 2: assert_step_02(state); break;
            case 3: assert_step_03(state); break;
            case 4: assert_step_04(state); break;
            case 5: assert_step_05(state); break;
            case 6: assert_step_06(state); break;
            default: break;
        }
    }

    // ---- TEST-LOCAL supplemental array proof — NOT a vendored fixture ----
    // (Pitfall 12 / OQ-3: the 7 upstream deltas carry no array keys, so
    // "arrays replace wholesale" never executes from the sequence alone.)
    // Both deltas below are literal strings inside this test file; no
    // fixture is added, edited, or reordered — the 7 vendored frames stay
    // byte-exact (D-03).
    {
        std::string arr_err;

        // Replacement 1: hms (an array since frame 00) is replaced
        // wholesale with a NON-EMPTY array.
        auto arr_delta1 = obn::json::parse(
            R"({"hms": [{"code": "0500_0002_0002"}, {"code": "0500_0003_0002"}]})",
            &arr_err);
        CHECK(arr_delta1.has_value());
        if (arr_delta1) {
            deep_merge(state, *arr_delta1);
            const obn::json::Object& obj1 = state.as_object();
            CHECK(obj1.count("hms") == 1);
            CHECK(obj1.at("hms").is_array());
            CHECK(obj1.at("hms").as_array().size() == 2);
        }

        // Replacement 2: the same key is then replaced wholesale with [].
        auto arr_delta2 = obn::json::parse(R"({"hms": []})", &arr_err);
        CHECK(arr_delta2.has_value());
        if (arr_delta2) {
            deep_merge(state, *arr_delta2);
            const obn::json::Object& obj2 = state.as_object();
            CHECK(obj2.count("hms") == 1);
            CHECK(obj2.at("hms").is_array());
            CHECK(obj2.at("hms").as_array().empty());
            // replacement is per-key: neighbours survive both swaps
            CHECK(obj2.count("sdcard") == 1);
            CHECK(obj2.at("sdcard").as_bool());
            CHECK(obj2.count("wifi_signal") == 1);
            CHECK(obj2.at("wifi_signal").is_null());
        }
    }

    if (fail_count != 0) {
        std::fprintf(stderr, "push_status_merge: %d check(s) FAILED\n", fail_count);
        return 1;
    }
    std::printf("push_status_merge: all checks passed\n");
    return 0;
}
