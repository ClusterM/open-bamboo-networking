// Regression test for OssTutkCameraSource::parse_url_() — the genuine H2S
// tutk scheme (authkey=/passwd=) versus the prior key= substring bug.

#include "../src/camera/OssTutkCameraSource.hpp"

#include <cstdio>
#include <string>

using obn::camera::OssTutkCameraSource;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    printf("  FAIL: %s (line %d)\n", #cond, __LINE__); ++g_fail; } } while (0)

int main()
{
    // 1. Genuine H2S scheme: authkey and passwd are distinct; the old
    //    find("key=") bug returned the authkey value for passwd.
    {
        OssTutkCameraSource s(
            "bambu:///tutk?uid=aabbccddeeffgghhiijj&authkey=AAAAKEY&passwd=PPPP"
            "&region=us&device=SERIAL0000000000&net_ver=02.07.01.51");
        auto p = s.parse_for_test();
        CHECK(p.ok);
        CHECK(p.uid == "AABBCCDDEEFFGGHHIIJJ");   // uppercased
        CHECK(p.authkey == "AAAAKEY");
        CHECK(p.passwd  == "PPPP");                // NOT "AAAAKEY"
        CHECK(p.device  == "SERIAL0000000000");
        CHECK(p.area_code == 2);                    // us
    }

    // 2. authkey= must not be matched by a key= lookup (exact-key matching).
    {
        OssTutkCameraSource s(
            "bambu:///tutk?uid=ABCDEFGHIJKLMNOPQRST&authkey=ZZZ&passwd=secret");
        auto p = s.parse_for_test();
        CHECK(p.ok);
        CHECK(p.passwd == "secret");
        CHECK(p.authkey == "ZZZ");
    }

    // 3. Legacy form: key=<passwd>, no authkey/passwd.
    {
        OssTutkCameraSource s(
            "bambu:///tutk?uid=ABCDEFGHIJKLMNOPQRST&key=oldcode&region=eu");
        auto p = s.parse_for_test();
        CHECK(p.ok);
        CHECK(p.passwd == "oldcode");
        CHECK(p.authkey.empty());
        CHECK(p.area_code == 4);                    // eu
    }

    // 4. Missing passwd → parse fails.
    {
        OssTutkCameraSource s("bambu:///tutk?uid=ABCDEFGHIJKLMNOPQRST&region=us");
        auto p = s.parse_for_test();
        CHECK(!p.ok);
    }

    // 5. Region mapping + default channel = uid when absent.
    {
        OssTutkCameraSource s(
            "bambu:///tutk?uid=ABCDEFGHIJKLMNOPQRST&passwd=x&region=cn");
        auto p = s.parse_for_test();
        CHECK(p.ok);
        CHECK(p.area_code == 1);                    // cn
        CHECK(p.channel == "ABCDEFGHIJKLMNOPQRST");
    }

    printf("%s (%d failure%s)\n", g_fail ? "TUTK URL TEST FAILED" : "tutk_url_test OK",
           g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
