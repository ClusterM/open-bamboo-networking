// Tests for try_filter_hms_code — removal of an HMS code from report frames.

#include "obn/agent.hpp"
#include "obn/json_lite.hpp"

#include <cstddef>
#include <iostream>
#include <string>

#define CHECK(cond) do {                                                    \
    if (!(cond)) {                                                          \
        std::cerr << "FAIL " << __FILE__ << ":" << __LINE__                \
                  << ": " #cond "\n";                                       \
        return 1;                                                           \
    }                                                                       \
} while (0)

static std::size_t hms_size(const std::string& json)
{
    auto val = obn::json::parse(json);
    if (!val) return static_cast<std::size_t>(-1);
    return val->find("hms").as_array().size();
}

int main()
{
    // 1. Strips the matching code, keeps every other entry and field.
    {
        std::string json =
            R"({"print":{"command":"push_status"},"hms":[{"code":65543,"msg":"MQTT verification failure"},{"code":12345,"msg":"keep"}]})";
        obn::try_filter_hms_code(json, 65543);
        CHECK(json.find("65543") == std::string::npos);
        CHECK(json.find("12345") != std::string::npos);
        CHECK(json.find("push_status") != std::string::npos);
        CHECK(hms_size(json) == 1);
        CHECK(obn::json::parse(json).has_value());
    }

    // 2. Non-object entries survive; only objects are code-matched.
    {
        std::string json = R"({"hms":[42,{"code":65543}]})";
        obn::try_filter_hms_code(json, 65543);
        CHECK(hms_size(json) == 1);
        auto val = obn::json::parse(json);
        CHECK(val.has_value());
        CHECK(val->find("hms[0]").is_number());
        CHECK(val->find("hms[0]").as_int() == 42);
    }

    // 3. No-op when the frame carries no matching code.
    {
        const std::string json = R"({"hms":[{"code":12345}]})";
        std::string copy = json;
        obn::try_filter_hms_code(copy, 65543);
        CHECK(copy == json);
    }

    // 4. No-op when the frame has no hms key at all.
    {
        const std::string json = R"({"print":{"code":65543}})";
        std::string copy = json;
        obn::try_filter_hms_code(copy, 65543);
        CHECK(copy == json);
    }

    // 5. No-op on an unterminated array — never rewrites blindly.
    {
        const std::string json = R"({"hms":[{"code":65543)";
        std::string copy = json;
        obn::try_filter_hms_code(copy, 65543);
        CHECK(copy == json);
    }

    // 6. Removing the last entry leaves an empty array, still valid JSON.
    {
        std::string json = R"({"hms":[{"code":65543}]})";
        obn::try_filter_hms_code(json, 65543);
        CHECK(hms_size(json) == 0);
        CHECK(obn::json::parse(json).has_value());
    }

    // 7. A nested array must not truncate the span or the trailing field.
    {
        std::string json =
            R"({"hms":[[],{"code":65543}],"tail":1})";
        obn::try_filter_hms_code(json, 65543);
        auto val = obn::json::parse(json);
        CHECK(val.has_value());
        CHECK(hms_size(json) == 1);
        CHECK(val->find("hms[0]").is_array());
        CHECK(val->find("tail").as_int() == 1);
    }

    // 8. A ']' inside a string is not the end of the array.
    {
        std::string json =
            R"({"hms":[{"code":65543,"note":"a]b"},{"code":9,"note":"keep]"}],"after":1})";
        obn::try_filter_hms_code(json, 65543);
        auto val = obn::json::parse(json);
        CHECK(val.has_value());
        CHECK(hms_size(json) == 1);
        CHECK(val->find("hms[0].code").as_int() == 9);
        CHECK(val->find("hms[0].note").as_string() == "keep]");
        CHECK(val->find("after").as_int() == 1);
    }

    // 9. A string value "hms" before the real key is not the array.
    {
        std::string json = R"({"note":"hms","hms":[{"code":65543}],"after":1})";
        obn::try_filter_hms_code(json, 65543);
        auto val = obn::json::parse(json);
        CHECK(val.has_value());
        CHECK(hms_size(json) == 0);
        CHECK(val->find("note").as_string() == "hms");
        CHECK(val->find("after").as_int() == 1);
    }

    std::cout << "all passed\n";
    return 0;
}
