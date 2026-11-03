// Pins the minors query and response parsing against the stock 02.09.01.54
// MITM capture (real responses plus forged ones to probe stock's parser),
// and checks the block_cloud / logged-out short-circuits.

#include "obn/agent.hpp"
#include "obn/config.hpp"
#include "obn/minors.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#if ABI_VERSION >= 0x020901
extern "C" int bambu_network_get_minors_decisions(
    void* agent,
    const std::vector<std::string>& scene_codes,
    std::vector<BBL::MinorsDecisionResult>* decisions);
extern "C" int bambu_network_get_child_registration_key(void* agent, std::string* http_body);
#endif

static int fail_count = 0;

#define CHECK_EQ(actual, expected)                                          \
    do {                                                                    \
        const std::string a_ = (actual);                                    \
        const std::string e_ = (expected);                                  \
        if (a_ != e_) {                                                     \
            std::fprintf(stderr, "FAIL %s:%d\n  expected: %s\n  actual:   %s\n", \
                         __FILE__, __LINE__, e_.c_str(), a_.c_str());       \
            ++fail_count;                                                   \
        }                                                                   \
    } while (0)

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #cond);                                            \
            ++fail_count;                                                   \
        }                                                                   \
    } while (0)

#if ABI_VERSION >= 0x020901

using Scenes = std::vector<std::string>;

static const Scenes kLoginScenes = {
    BBL::MINORS_SCENE_REMOTE_CONTROL_PRINTER,
    BBL::MINORS_SCENE_JOIN_USER_EXPERIENCE_PROGRAM,
    BBL::MINORS_SCENE_ACCESS_MAKER_WORLD,
    BBL::MINORS_SCENE_ACCESS_MAKER_LAB,
    BBL::MINORS_SCENE_ACCESS_MAKER_SUPPLY,
};

static std::string entry(const std::string& scene, const std::string& decision,
                         bool fl_enable = false, const std::string& fl_decision = "")
{
    return R"({"sceneCode":")" + scene + R"(","familyLinkEnable":)" +
           (fl_enable ? "true" : "false") + R"(,"familyLinkDecision":")" + fl_decision +
           R"(","decision":)" + decision + "}";
}

static bool parses(const std::string& body, const Scenes& scenes)
{
    std::vector<BBL::MinorsDecisionResult> out(1);
    const bool ok = obn::detail::parse_minors_decisions(body, scenes, &out);
    if (!ok) CHECK(out.empty());
    return ok;
}

static void test_query()
{
    CHECK_EQ(obn::detail::build_minors_decisions_query(kLoginScenes),
             "?sceneCodes=REMOTE_CONTROL_PRINTER&sceneCodes=JOIN_USER_EXPERIENCE_PROGRAM"
             "&sceneCodes=ACCESS_MAKER_WORLD&sceneCodes=ACCESS_MAKER_LAB"
             "&sceneCodes=ACCESS_MAKER_SUPPLY");
    CHECK_EQ(obn::detail::build_minors_decisions_query({"A B&c=d/\xC3\xA9"}),
             "?sceneCodes=A%20B%26c%3Dd/%C3%A9");
}

// Stock answered -61 without a request for [] and for a repeated code;
// unknown and lower-case codes went out and the server echoed them.
static void test_scene_validation()
{
    CHECK(!obn::detail::minors_scene_codes_valid({}));
    CHECK(!obn::detail::minors_scene_codes_valid({"ACCESS_MAKER_WORLD", "ACCESS_MAKER_WORLD"}));
    CHECK(obn::detail::minors_scene_codes_valid({"FOO_BAR", "ACCESS_MAKER_WORLD"}));
    CHECK(obn::detail::minors_scene_codes_valid({"access_maker_lab"}));
    CHECK(obn::detail::minors_scene_codes_valid(kLoginScenes));
}

// Real 200 for the login scene set. The server sorts by scene code; stock
// hands Studio the results in request order and keeps NO_CONFIG upper-case.
static void test_parse_live_response()
{
    const std::string body =
        R"({"decisions":[)" + entry("ACCESS_MAKER_LAB", R"("ALLOW")") + "," +
        entry("ACCESS_MAKER_SUPPLY", R"("ALLOW")") + "," +
        entry("ACCESS_MAKER_WORLD", R"("ALLOW")") + "," +
        entry("JOIN_USER_EXPERIENCE_PROGRAM", R"("ALLOW")", true, "NO_CONFIG") + "," +
        entry("REMOTE_CONTROL_PRINTER", R"("ALLOW")") + "]}";
    std::vector<BBL::MinorsDecisionResult> out;
    CHECK(obn::detail::parse_minors_decisions(body, kLoginScenes, &out));
    CHECK(out.size() == kLoginScenes.size());
    for (size_t i = 0; i < out.size() && i < kLoginScenes.size(); ++i) {
        CHECK_EQ(out[i].scene_code, kLoginScenes[i]);
        CHECK(out[i].decision == BBL::MinorDecision::Allow);
    }
    if (out.size() == kLoginScenes.size()) {
        CHECK(out[1].family_link_enable);
        CHECK_EQ(out[1].family_link_decision, "NO_CONFIG");
        CHECK(!out[0].family_link_enable);
        CHECK_EQ(out[0].family_link_decision, "");
    }
}

static void test_parse_decision_values()
{
    const Scenes scenes = {"S_DENY", "S_NEEDIDV", "S_FL_NOCFG"};
    const std::string body =
        R"({"decisions":[)" + entry("S_DENY", R"("DENY")", true, "DENY") + "," +
        entry("S_NEEDIDV", R"("NEED_IDV")") + "," +
        entry("S_FL_NOCFG", R"("DENY")", true, "no_config") + "]}";
    std::vector<BBL::MinorsDecisionResult> out;
    CHECK(obn::detail::parse_minors_decisions(body, scenes, &out));
    CHECK(out.size() == 3);
    if (out.size() == 3) {
        CHECK(out[0].decision == BBL::MinorDecision::Deny);
        CHECK_EQ(out[0].family_link_decision, "DENY");
        CHECK(out[1].decision == BBL::MinorDecision::NeedIdv);
        CHECK(out[2].decision == BBL::MinorDecision::Deny);
        CHECK_EQ(out[2].family_link_decision, "no_config");
    }
}

// Each of these made stock 02.09.01.54 return -61 with no decisions.
static void test_parse_rejects()
{
    const Scenes one = {"S"};
    auto wrap = [](const std::string& entries) { return R"({"decisions":[)" + entries + "]}"; };

    CHECK(!parses(wrap(entry("S", R"("deny")")), one));
    CHECK(!parses(wrap(entry("S", "1")), one));
    CHECK(!parses(wrap(entry("S", R"("WHATEVER")")), one));
    CHECK(!parses(wrap(R"({"sceneCode":"S","familyLinkEnable":false,"familyLinkDecision":""})"), one));
    CHECK(!parses(wrap(R"({"sceneCode":"S","decision":"ALLOW"})"), one));
    CHECK(!parses(wrap(R"({"sceneCode":"S","familyLinkEnable":null,"familyLinkDecision":null,"decision":"ALLOW"})"), one));
    CHECK(!parses(wrap(R"({"sceneCode":"S","familyLinkEnable":"true","familyLinkDecision":"","decision":"ALLOW"})"), one));
    CHECK(!parses(wrap(entry("S", R"("ALLOW")") + "," + entry("S", R"("ALLOW")")), one));
    CHECK(!parses(wrap(entry("S", R"("ALLOW")") + "," + entry("S_EXTRA", R"("DENY")")), one));
    CHECK(!parses(wrap(entry("S", R"("ALLOW")")), {"S_ABSENT", "S"}));
    CHECK(!parses(R"({"decisions":{}})", one));
    CHECK(!parses("{}", one));
    CHECK(!parses("not json", one));

    CHECK(parses(wrap(entry("S", R"("ALLOW")")), one));
}

// block_cloud is on by default. Point the API hosts at a closed port so a
// missing gate would fail the call instead of reaching Bambu.
static void write_config(const std::filesystem::path& dir, bool block_cloud)
{
    std::filesystem::create_directories(dir);
    std::ofstream out(dir / obn::config::kConfigFileName);
    out << "block_cloud = " << (block_cloud ? 1 : 0) << "\n"
        << "cloud_global_api_host = http://127.0.0.1:1\n"
        << "cloud_cn_api_host = http://127.0.0.1:1\n";
}

static void test_block_cloud_skips_network()
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "obn-minors-test";
    fs::remove_all(dir);
    write_config(dir, true);
    (void)obn::config::load_or_create(dir.string());
    CHECK(obn::config::current().block_cloud);

    std::vector<BBL::MinorsDecisionResult> decisions(2);
    CHECK(bambu_network_get_minors_decisions(nullptr, kLoginScenes, &decisions) == 0);
    CHECK(decisions.empty());

    std::string body = "stale";
    CHECK(bambu_network_get_child_registration_key(nullptr, &body) == 0);
    CHECK(body.empty());
    fs::remove_all(dir);
}

// Logged out, stock fails both calls locally: -61 / -62, nothing sent.
static void test_logged_out_fails_locally()
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "obn-minors-test-logout";
    fs::remove_all(dir);
    write_config(dir, false);
    (void)obn::config::load_or_create(dir.string());
    CHECK(!obn::config::current().block_cloud);

    CHECK(bambu_network_get_minors_decisions(nullptr, kLoginScenes, nullptr) ==
          BAMBU_NETWORK_ERR_INVALID_HANDLE);
    {
        obn::Agent agent(dir.string());
        std::vector<BBL::MinorsDecisionResult> decisions(1);
        CHECK(bambu_network_get_minors_decisions(&agent, kLoginScenes, &decisions) ==
              BAMBU_NETWORK_ERR_GET_MINORS_DECISIONS_FAILED);
        CHECK(decisions.empty());
        CHECK(bambu_network_get_minors_decisions(&agent, {}, &decisions) ==
              BAMBU_NETWORK_ERR_GET_MINORS_DECISIONS_FAILED);

        std::string body = "stale";
        CHECK(bambu_network_get_child_registration_key(&agent, &body) ==
              BAMBU_NETWORK_ERR_GET_CHILD_REGISTRATION_KEY_FAILED);
        CHECK(body.empty());
    }
    fs::remove_all(dir);
}

#endif

int main()
{
#if ABI_VERSION >= 0x020901
    test_query();
    test_scene_validation();
    test_parse_live_response();
    test_parse_decision_values();
    test_parse_rejects();
    test_block_cloud_skips_network();
    test_logged_out_fails_locally();
#endif
    if (fail_count) {
        std::fprintf(stderr, "minors_test: %d failure(s)\n", fail_count);
        return 1;
    }
    std::puts("minors_test: all checks passed");
    return 0;
}
