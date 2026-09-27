#include "obn/json_lite.hpp"

#include <cstdint>
#include <cstdio>
#include <limits>
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

std::string nested_arrays(int depth)
{
    return std::string(depth, '[') + std::string(depth, ']');
}

std::string nested_objects(int depth)
{
    std::string s;
    for (int i = 0; i < depth; ++i) s += R"({"a":)";
    s += "1";
    s += std::string(depth, '}');
    return s;
}

bool parses(const std::string& s, std::string* err = nullptr)
{
    std::string e;
    const bool ok = obn::json::parse(s, &e).has_value();
    if (err) *err = e;
    return ok;
}

// Must match kMaxNestingDepth in src/json_lite.cpp.
constexpr int kMaxDepth = 128;

void test_nesting_limit()
{
    std::string err;
    CHECK(parses(nested_arrays(kMaxDepth)));
    CHECK(!parses(nested_arrays(kMaxDepth + 1), &err));
    CHECK(err == "max nesting depth exceeded");

    CHECK(parses(nested_objects(kMaxDepth)));
    CHECK(!parses(nested_objects(kMaxDepth + 1), &err));
    CHECK(err == "max nesting depth exceeded");

    // Mixed containers count toward the same budget.
    std::string mixed;
    for (int i = 0; i < kMaxDepth + 1; ++i) mixed += (i % 2) ? "[" : R"({"k":)";
    CHECK(!parses(mixed));

    // A hostile payload far past the limit is rejected, not a stack overflow.
    CHECK(!parses(nested_arrays(1000000)));
}

void test_depth_is_per_path()
{
    // Siblings must not accumulate depth: 1000 shallow elements side by side.
    std::string wide = "[";
    for (int i = 0; i < 1000; ++i) wide += (i ? ",[[1]]" : "[[1]]");
    wide += "]";
    CHECK(parses(wide));

    // Leaving a container gives its level back: two branches that each reach
    // the limit parse, which fails if depth only ever grows.
    const std::string branch = nested_arrays(kMaxDepth - 1);
    CHECK(parses("[" + branch + "," + branch + "]"));
    CHECK(!parses("[" + branch + "," + nested_arrays(kMaxDepth) + "]"));
}

void test_as_int_clamps()
{
    using lim = std::numeric_limits<std::int64_t>;
    auto as_int = [](const char* s) {
        auto v = obn::json::parse(s);
        return v ? v->as_int(-7) : -7;
    };
    CHECK(as_int("255") == 255);
    CHECK(as_int("-1") == -1);
    CHECK(as_int("3.9") == 3);
    CHECK(as_int("-3.9") == -3);
    CHECK(as_int("1e300") == lim::max());
    CHECK(as_int("-1e300") == lim::min());
    CHECK(as_int("9223372036854775807") == lim::max());   // rounds to 2^63
    CHECK(as_int("-9223372036854775808") == lim::min());  // exactly -2^63
    CHECK(as_int(R"("12")") == -7);                       // not a number
}

} // namespace

int main()
{
    test_nesting_limit();
    test_depth_is_per_path();
    test_as_int_clamps();
    if (fail_count) {
        std::fprintf(stderr, "%d test(s) failed\n", fail_count);
        return 1;
    }
    std::printf("json_lite_test: all passed\n");
    return 0;
}
