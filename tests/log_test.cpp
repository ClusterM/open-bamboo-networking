// Unit tests for obn::log::hexdump and the set_forward hook.

#include "obn/log.hpp"

#include <cstdio>
#include <string>
#include <vector>

static int fail_count = 0;

#define CHECK_EQ(got, want)                                                  \
    do {                                                                     \
        const std::string g_ = (got), w_ = (want);                           \
        if (g_ != w_) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d:\n  got:  %s\n  want: %s\n",    \
                         __FILE__, __LINE__, g_.c_str(), w_.c_str());        \
            ++fail_count;                                                    \
        }                                                                    \
    } while (0)

static std::vector<std::string> g_forwarded;
static obn::log::Level          g_forward_level = obn::log::LVL_DEBUG;

static void forward_emit(obn::log::Level, const char* msg) { g_forwarded.emplace_back(msg); }
static obn::log::Level forward_threshold() { return g_forward_level; }

int main()
{
    using obn::log::hexdump;

    const std::string json = R"({"cmdtype":1,"sequence":2})";
    CHECK_EQ(hexdump(json.data(), json.size()), json);
    CHECK_EQ(hexdump("line1\nline2", 11), "line1\nline2");
    const std::string utf8 = "{\"name\":\"D\xc3\xbc" "beln\"}";
    CHECK_EQ(hexdump(utf8.data(), utf8.size()), utf8);

    const unsigned char frame[] = {0x3f, 0x01, 0x01, 0x01, 0x00, 0xff};
    CHECK_EQ(hexdump(frame, sizeof(frame)), "3f01010100ff");
    CHECK_EQ(hexdump(frame, sizeof(frame), 2), "3f01...");
    CHECK_EQ(hexdump(json.data(), json.size(), 5), "{\"cmd...");
    CHECK_EQ(hexdump(nullptr, 4), "");
    CHECK_EQ(hexdump(frame, 0), "");

    obn::log::set_forward(forward_emit, forward_threshold);
    OBN_DEBUG("forwarded %d", 1);
    OBN_TRACE("below threshold");
    g_forward_level = obn::log::LVL_TRACE;
    OBN_TRACE("now %s", "visible");
    CHECK_EQ(std::to_string(g_forwarded.size()), "2");
    if (g_forwarded.size() == 2) {
        CHECK_EQ(g_forwarded[0], "forwarded 1");
        CHECK_EQ(g_forwarded[1], "now visible");
    }

    if (fail_count) {
        std::fprintf(stderr, "log_test: %d failure(s)\n", fail_count);
        return 1;
    }
    std::printf("log_test: ok\n");
    return 0;
}
