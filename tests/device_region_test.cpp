// Pins the device-region request body against the stock 02.08.04.60 MITM
// capture, and checks that block_cloud answers without opening a socket.

#include "obn/config.hpp"
#include "obn/device_region.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#if ABI_VERSION >= 0x020804
extern "C" int bambu_network_post_device_region(void* agent,
                                               BBL::DeviceRegionParams params,
                                               std::string* http_body);
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

#if ABI_VERSION >= 0x020804

// Studio's call: only ClientType is set, and it is "slicer". Stock also
// emits that same body when ClientType is left empty.
static void test_studio_default_body()
{
    BBL::DeviceRegionParams p;
    p.ClientType = "slicer";
    CHECK_EQ(obn::detail::build_device_region_body(p),
             R"({"ClientType":"slicer"})");

    BBL::DeviceRegionParams empty;
    CHECK_EQ(obn::detail::build_device_region_body(empty),
             R"({"ClientType":"slicer"})");
}

// Capture: ClientType "sli cer+A&b" went out raw inside the JSON string.
// DeviceId (a UUID), country "DE" and XClientCountry "FR" did not.
static void test_client_type_only()
{
    BBL::DeviceRegionParams p;
    p.DeviceId       = "11111111-2222-3333-4444-555555555555";
    p.ClientType     = "sli cer+A&b";
    p.country        = "DE";
    p.XClientCountry = "FR";
    CHECK_EQ(obn::detail::build_device_region_body(p),
             R"({"ClientType":"sli cer+A&b"})");
}

// Default block_cloud is on. Point the API hosts at a closed port so a
// missing gate would fail the call instead of reaching Bambu.
static void test_block_cloud_skips_network()
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "obn-device-region-test";
    fs::remove_all(dir);
    fs::create_directories(dir);
    {
        std::ofstream out(dir / obn::config::kConfigFileName);
        out << "block_cloud = 1\n"
            << "cloud_global_api_host = http://127.0.0.1:1\n"
            << "cloud_cn_api_host = http://127.0.0.1:1\n";
    }
    (void)obn::config::load_or_create(dir.string());
    CHECK(obn::config::current().block_cloud);

    BBL::DeviceRegionParams p;
    p.ClientType = "slicer";
    p.DeviceId   = "22E8BJ610801473";
    std::string body = "stale";
    const int rc = bambu_network_post_device_region(nullptr, p, &body);
    CHECK(rc == 0);
    CHECK(body.empty());
    fs::remove_all(dir);
}

#endif

int main()
{
#if ABI_VERSION >= 0x020804
    test_studio_default_body();
    test_client_type_only();
    test_block_cloud_skips_network();
#endif
    if (fail_count) {
        std::fprintf(stderr, "device_region_test: %d failure(s)\n", fail_count);
        return 1;
    }
    std::puts("device_region_test: all checks passed");
    return 0;
}
