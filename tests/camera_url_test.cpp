#include "obn/camera_url.hpp"

#include <cassert>
#include <iostream>
#include <string>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << ": " #cond "\n"; \
        return 1; \
    } \
} while (0)

static int test_parse_packed_dev_key()
{
    // 4 components: serial|dev_ver|protocols|channel
    {
        const auto p = obn::camera::parse_packed_dev_key("01S00A123456789|01.07.03.00|tutk,agora|0");
        CHECK(p.serial == "01S00A123456789");
        CHECK(p.dev_version == "01.07.03.00");
        CHECK(p.protocols.size() == 2);
        CHECK(p.protocols[0] == "tutk");
        CHECK(p.protocols[1] == "agora");
    }

    // 3 components: serial|dev_ver|protocols
    {
        const auto p = obn::camera::parse_packed_dev_key("01S00A123456789|01.07.03.00|tutk");
        CHECK(p.serial == "01S00A123456789");
        CHECK(p.dev_version == "01.07.03.00");
        CHECK(p.protocols.size() == 1);
        CHECK(p.protocols[0] == "tutk");
    }

    // 2 components: serial|dev_ver
    {
        const auto p = obn::camera::parse_packed_dev_key("01S00A123456789|01.07.03.00");
        CHECK(p.serial == "01S00A123456789");
        CHECK(p.dev_version == "01.07.03.00");
        CHECK(p.protocols.size() == 2);
        CHECK(p.protocols[0] == "tutk");
        CHECK(p.protocols[1] == "agora");
    }

    // 1 component: serial only
    {
        const auto p = obn::camera::parse_packed_dev_key("01S00A123456789");
        CHECK(p.serial == "01S00A123456789");
        CHECK(p.dev_version.empty());
        CHECK(p.protocols.size() == 2);
        CHECK(p.protocols[0] == "tutk");
        CHECK(p.protocols[1] == "agora");
    }

    return 0;
}

static int test_build_ttcode_request_body()
{
    // With firmware version
    {
        const std::string body = obn::camera::build_ttcode_request_body(
            "01S00A123456789", "01.07.03.00", {"tutk", "agora"});
        CHECK(body == "{\"dev_id\":\"01S00A123456789\",\"dev_version\":\"01.07.03.00\",\"protocols\":[\"tutk\",\"agora\"]}");
    }

    // Without firmware version
    {
        const std::string body = obn::camera::build_ttcode_request_body(
            "01S00A123456789", "", {"tutk"});
        CHECK(body == "{\"dev_id\":\"01S00A123456789\",\"protocols\":[\"tutk\"]}");
    }

    return 0;
}

static int test_parse_ttcode_response()
{
    // Standard flat response
    {
        const std::string json = R"({
            "code": 0,
            "message": "success",
            "authkey": "c0c597fc",
            "passwd": "secret+pass/word",
            "region": "us",
            "ttcode": "VGC47JEVNKCHC9RZ111A",
            "type": "tutk"
        })";
        obn::camera::TtcodeResponse resp;
        CHECK(obn::camera::parse_ttcode_response(json, resp));
        CHECK(resp.uid == "VGC47JEVNKCHC9RZ111A");
        CHECK(resp.authkey == "c0c597fc");
        CHECK(resp.passwd == "secret+pass/word");
        CHECK(resp.region == "us");
        CHECK(resp.type == "tutk");
    }

    // Fallback to "uid" key
    {
        const std::string json = R"({"uid":"ABC123XYZ","authkey":"auth1","passwd":"pass1","region":"eu","type":"tutk"})";
        obn::camera::TtcodeResponse resp;
        CHECK(obn::camera::parse_ttcode_response(json, resp));
        CHECK(resp.uid == "ABC123XYZ");
        CHECK(resp.authkey == "auth1");
    }

    // Missing ttcode / uid
    {
        const std::string json = R"({"code":1,"message":"device offline"})";
        obn::camera::TtcodeResponse resp;
        CHECK(!obn::camera::parse_ttcode_response(json, resp));
    }

    return 0;
}

static int test_build_tutk_url()
{
    const std::string url = obn::camera::build_tutk_url(
        "VGC47JEVNKCHC9RZ111A", "c0c597fc", "p@ss+word#1", "us");
    // Verifies query construction and URL encoding of '@', '+', '#'
    CHECK(url == "bambu:///tutk?uid=VGC47JEVNKCHC9RZ111A&authkey=c0c597fc&passwd=p%40ss%2Bword%231&region=us");
    return 0;
}

int main()
{
    if (test_parse_packed_dev_key() != 0) return 1;
    if (test_build_ttcode_request_body() != 0) return 1;
    if (test_parse_ttcode_response() != 0) return 1;
    if (test_build_tutk_url() != 0) return 1;

    std::cout << "camera_url_test: ok\n";
    return 0;
}
