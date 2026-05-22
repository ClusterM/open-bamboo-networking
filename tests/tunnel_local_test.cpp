#include "obn/tunnel_local.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int fail_count = 0;

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, \
                         #cond);                                        \
            ++fail_count;                                               \
        }                                                               \
    } while (0)

static void test_frame_header()
{
    const auto hdr = obn::tunnel_local::build_frame_header(102, 0x0102013Fu, 42u);
    obn::tunnel_local::FrameHeader parsed{};
    CHECK(obn::tunnel_local::parse_frame_header(hdr.data(), hdr.size(), &parsed));
    CHECK(parsed.payload_len == 102u);
    CHECK(parsed.magic == 0x0102013Fu);
    CHECK(parsed.seq == 42u);
}

static void test_wrap_ctrl_abi()
{
    const std::string abi =
        R"({"cmdtype":1,"sequence":25,"req":{"type":"timelapse"}})";
    const std::string wire = obn::tunnel_local::wrap_ctrl_abi(abi);
    CHECK(wire.find("\"mtype\":12289") != std::string::npos);
    CHECK(wire.find("\"cmdtype\":1") != std::string::npos);
    CHECK(wire[0] == '{');
}

static void test_consume_frames()
{
    const std::string payload = R"({"mtype":12289,"result":0})";
    const auto hdr = obn::tunnel_local::build_frame_header(
        static_cast<std::uint32_t>(payload.size()),
        obn::tunnel_local::kMagicCtrlServer, 1u);
    std::vector<std::uint8_t> buf(hdr.begin(), hdr.end());
    buf.insert(buf.end(), payload.begin(), payload.end());

    std::vector<std::vector<std::uint8_t>> bodies;
    const std::size_t consumed =
        obn::tunnel_local::consume_frames(buf.data(), buf.size(), &bodies);
    CHECK(consumed == buf.size());
    CHECK(bodies.size() == 1u);
    CHECK(bodies[0].size() == payload.size());
    CHECK(std::memcmp(bodies[0].data(), payload.data(), payload.size()) == 0);
}

static void test_login_payload()
{
    const std::string login =
        obn::tunnel_local::build_login_payload("bblp", "ABCD1234");
    CHECK(login.size() == 16u);
    CHECK(std::memcmp(login.data(), "bblp", 4) == 0);
    CHECK(std::memcmp(login.data() + 8, "ABCD1234", 8) == 0);
}

int main()
{
    test_frame_header();
    test_wrap_ctrl_abi();
    test_consume_frames();
    test_login_payload();
    if (fail_count) {
        std::fprintf(stderr, "%d test(s) failed\n", fail_count);
        return 1;
    }
    std::fprintf(stderr, "tunnel_local_test: ok\n");
    return 0;
}
