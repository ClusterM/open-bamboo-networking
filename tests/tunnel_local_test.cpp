#include "obn/tunnel_local.hpp"
#include "obn/json_lite.hpp"

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

static void test_ft_wire_helpers()
{
    const std::string abi =
        obn::tunnel_local::build_media_ability_abi(3);
    CHECK(abi.find("\"cmdtype\":7") != std::string::npos);
    CHECK(abi.find("\"peer\":\"studio\"") != std::string::npos);
    CHECK(abi.find("\"api_version\":3") != std::string::npos);
    CHECK(abi.find("\"peer_t\":3") != std::string::npos);

    const std::string upload = obn::tunnel_local::build_file_upload_abi(
        4, "sdcard", "test.gcode.3mf", 12345, "ABCD");
    CHECK(upload.find("\"cmdtype\":5") != std::string::npos);
    CHECK(upload.find("test.gcode.3mf") != std::string::npos);

    const std::string init = obn::tunnel_local::build_file_upload_init_abi(
        5, "emmc", "test.gcode.3mf", 12345);
    CHECK(init.find("\"type\":\"model\"") != std::string::npos);
    CHECK(init.find("\"storage\":\"emmc\"") != std::string::npos);
    CHECK(init.find("\"total\":12345") != std::string::npos);

    const std::string chunk = obn::tunnel_local::build_file_upload_chunk_abi(
        5, 0, 0, 4096, "");
    CHECK(chunk.find("\"frag_id\":0") != std::string::npos);
    CHECK(chunk.find("file_md5") == std::string::npos);

    const std::string last = obn::tunnel_local::build_file_upload_chunk_abi(
        5, 3, 12288, 57, "deadbeef");
    CHECK(last.find("\"file_md5\":\"deadbeef\"") != std::string::npos);
    // frag_id must sit at the frame top level (sibling of cmdtype/req),
    // while file_md5 stays inside req (issue #48).
    {
        auto v = obn::json::parse(last);
        CHECK(v);
        CHECK(v->find("frag_id").is_number());
        CHECK(static_cast<int>(v->find("frag_id").as_number()) == 3);
        const auto req = v->find("req");
        CHECK(req.is_object());
        CHECK(!req.find("frag_id").is_number());
        CHECK(req.find("file_md5").as_string() == "deadbeef");
    }

    std::uint32_t kb = 0;
    std::uint64_t off = 999;
    int rc = -1;
    CHECK(obn::tunnel_local::parse_upload_init_reply(
        R"({"result":1,"reply":{"chunk_size":64,"offset":0}})", &kb, &off, &rc));
    CHECK(kb == 64u);
    CHECK(off == 0u);
    CHECK(rc == 1);

    const std::string reply =
        R"({"cmdtype":7,"result":0,"reply":{"storage":["emmc","usb"]}})";
    const std::string ft_json =
        obn::tunnel_local::parse_ability_reply_to_ft_json(reply);
    CHECK(ft_json == "[\"emmc\",\"usb\"]");

    int result = -1;
    const double pct_f = obn::tunnel_local::parse_upload_progress_value(
        R"({"result":1,"reply":{"progress":42.5}})", &result);
    CHECK(pct_f > 42.0 && pct_f < 43.0);
    CHECK(result == 1);
    CHECK(obn::tunnel_local::parse_upload_progress(
              R"({"result":1,"reply":{"progress":42.5}})", &result) == 43);

    CHECK(obn::tunnel_local::parse_wire_cmdtype(
              R"({"cmdtype":5,"sequence":3,"result":0})") == 5);
    CHECK(obn::tunnel_local::parse_wire_sequence(
              R"({"cmdtype":3,"sequence":6,"result":0})") == 6);

    std::string json;
    std::vector<std::uint8_t> bin;
    const std::string payload = R"({"x":1})" "\n\n" "bin";
    CHECK(obn::tunnel_local::split_json_prefix(
        reinterpret_cast<const std::uint8_t*>(payload.data()),
        payload.size(), &json, &bin));
    CHECK(json == R"({"x":1})");
    CHECK(bin.size() == 3u);
}

static void test_build_file_download_abi()
{
    const std::string abi = obn::tunnel_local::build_file_download_abi(
        9, "mem:/26", 0, "");
    CHECK(abi.find("\"cmdtype\":4") != std::string::npos);
    CHECK(abi.find("\"path\":\"mem:/26\"") != std::string::npos);
    CHECK(abi.find("is_mem_file") == std::string::npos);
}

static void test_build_sub_file_abi()
{
    const std::string abi = obn::tunnel_local::build_sub_file_abi(
        4, {"/cache/foo.gcode.3mf#thumbnail"}, "udisk");
    CHECK(abi.find("\"cmdtype\":2") != std::string::npos);
    CHECK(abi.find("\"sequence\":4") != std::string::npos);
    CHECK(abi.find("#thumbnail") != std::string::npos);
    CHECK(abi.find("\"peer\":\"studio\"") != std::string::npos);
    CHECK(abi.find("\"storage\":\"udisk\"") != std::string::npos);
}

static void test_build_list_info_abi()
{
    const std::string abi =
        obn::tunnel_local::build_list_info_abi(1, "model", "internal");
    CHECK(abi.find("\"cmdtype\":1") != std::string::npos);
    CHECK(abi.find("\"type\":\"model\"") != std::string::npos);
    CHECK(abi.find("\"api_version\":2") != std::string::npos);
    CHECK(abi.find("\"notify\":\"DETAIL\"") != std::string::npos);
    CHECK(abi.find("\"storage\":\"internal\"") != std::string::npos);
}

int main()
{
    test_frame_header();
    test_wrap_ctrl_abi();
    test_consume_frames();
    test_login_payload();
    test_ft_wire_helpers();
    test_build_file_download_abi();
    test_build_sub_file_abi();
    test_build_list_info_abi();
    if (fail_count) {
        std::fprintf(stderr, "%d test(s) failed\n", fail_count);
        return 1;
    }
    std::fprintf(stderr, "tunnel_local_test: ok\n");
    return 0;
}
