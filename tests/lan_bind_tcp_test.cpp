#include "obn/lan_bind_tcp.hpp"

#include <cstdio>
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

static void test_round_trip()
{
    const std::string json = R"({"login":{"command":"detect"}})";
    const std::string frame = obn::lan_bind_tcp::encode_frame(json);
    CHECK(frame.size() == json.size() + 6);
    CHECK(static_cast<unsigned char>(frame[0]) == 0xA5);
    CHECK(static_cast<unsigned char>(frame[1]) == 0xA5);
    CHECK(static_cast<unsigned char>(frame[frame.size() - 2]) == 0xA7);
    CHECK(static_cast<unsigned char>(frame[frame.size() - 1]) == 0xA7);

    std::string buf = "noise" + frame + frame;
    auto payloads = obn::lan_bind_tcp::drain_frames(buf);
    CHECK(payloads.size() == 2);
    CHECK(payloads[0] == json);
    CHECK(payloads[1] == json);
    CHECK(buf.empty());
}

static void test_partial_frame()
{
    const std::string json = "{\"a\":1}";
    const std::string frame = obn::lan_bind_tcp::encode_frame(json);
    std::string buf = frame.substr(0, 4);
    auto payloads = obn::lan_bind_tcp::drain_frames(buf);
    CHECK(payloads.empty());
    CHECK(buf.size() == 4);
    buf += frame.substr(4);
    payloads = obn::lan_bind_tcp::drain_frames(buf);
    CHECK(payloads.size() == 1);
    CHECK(payloads[0] == json);
}

int main()
{
    test_round_trip();
    test_partial_frame();
    if (fail_count) {
        std::fprintf(stderr, "%d checks failed\n", fail_count);
        return 1;
    }
    std::printf("lan_bind_tcp_test: ok\n");
    return 0;
}
