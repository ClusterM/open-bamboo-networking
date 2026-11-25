// Route lists of start_print / start_local_print_with_record per cloud_print
// mode and Studio's PrintParams::comments (obn/print_route.hpp).

#include "obn/print_route.hpp"

#include <cstdio>
#include <string>
#include <vector>

static int fail_count = 0;

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #cond);                                            \
            ++fail_count;                                                   \
        }                                                                   \
    } while (0)

namespace pr = obn::print_route;
using Mode   = obn::config::CloudPrintMode;
using R      = pr::Route;
using Routes = std::vector<R>;

static Routes start_print(Mode m, const std::string& comments)
{
    return pr::routes(m, pr::Entry::StartPrint, pr::lan_step_allowed(comments));
}

static Routes with_record(Mode m, const std::string& comments)
{
    return pr::routes(m, pr::Entry::WithRecord, pr::lan_step_allowed(comments));
}

static void test_comments()
{
    CHECK(pr::lan_step_allowed(""));
    for (const char* c : {"no_ip", "low_version", "no_sdcard", "no_password",
                          "upload_failed", "failed(-1)"})
        CHECK(!pr::lan_step_allowed(c));
}

// Studio 2.9.2: start_print is the first and only plugin call.
static void test_start_print_first_attempt()
{
    CHECK((start_print(Mode::CloudOnly, "") == Routes{R::LanRecord, R::Cloud}));
    CHECK((start_print(Mode::TryLanFirst, "") == Routes{R::Local, R::Cloud}));
    CHECK((start_print(Mode::LanOnly, "") == Routes{R::Local}));
    // Unresolved cloud_for_makerworld_only never uploads the model.
    CHECK((start_print(Mode::CloudForMakerWorldOnly, "") == Routes{R::Local}));
}

// Preconditions missing, or Studio <= 2.9.1 after a failed _with_record.
static void test_start_print_no_lan_step()
{
    for (const char* c : {"no_ip", "low_version", "no_sdcard", "no_password",
                          "upload_failed", "failed(-1)"}) {
        CHECK((start_print(Mode::CloudOnly, c) == Routes{R::Cloud}));
        CHECK((start_print(Mode::TryLanFirst, c) == Routes{R::Cloud}));
        CHECK(start_print(Mode::LanOnly, c).empty());
        CHECK(start_print(Mode::CloudForMakerWorldOnly, c).empty());
    }
}

// Studio <= 2.9.1 falls back to start_print itself, so _with_record makes
// exactly one LAN attempt, whatever the comment (lan_mode_only calls it
// with a non-empty one).
static void test_with_record()
{
    for (const char* c : {"", "no_sdcard", "low_version"}) {
        CHECK((with_record(Mode::CloudOnly, c) == Routes{R::LanRecord}));
        CHECK((with_record(Mode::TryLanFirst, c) == Routes{R::Local}));
        CHECK((with_record(Mode::LanOnly, c) == Routes{R::Local}));
        CHECK((with_record(Mode::CloudForMakerWorldOnly, c) == Routes{R::Local}));
    }
}

static void test_stops_fallback()
{
    for (int code : {BAMBU_NETWORK_ERR_CANCELED, BAMBU_NETWORK_SIGNED_ERROR,
                     BAMBU_NETWORK_ERR_PRINT_WR_FILE_NOT_EXIST,
                     BAMBU_NETWORK_ERR_PRINT_SP_FILE_NOT_EXIST,
                     BAMBU_NETWORK_ERR_PRINT_WR_FILE_OVER_SIZE,
                     BAMBU_NETWORK_ERR_PRINT_SP_FILE_OVER_SIZE,
                     BAMBU_NETWORK_ERR_PRINT_LP_FILE_OVER_SIZE})
        CHECK(pr::stops_fallback(code));
    for (int code : {BAMBU_NETWORK_ERR_INVALID_HANDLE,
                     BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED,
                     BAMBU_NETWORK_ERR_FILE_NOT_EXIST,
                     BAMBU_NETWORK_ERR_PRINT_WR_UPLOAD_FTP_FAILED})
        CHECK(!pr::stops_fallback(code));
}

static void test_error_update()
{
    CHECK(pr::is_error_update(BBL::PrintingStageERROR, 0));
    CHECK(pr::is_error_update(BBL::PrintingStageUpload, -1));
    CHECK(pr::is_error_update(BBL::PrintingStageUpload, 101));
    CHECK(!pr::is_error_update(BBL::PrintingStageUpload, 50));
    CHECK(!pr::is_error_update(BBL::PrintingStageFinished, 0));
}

int main()
{
    test_comments();
    test_start_print_first_attempt();
    test_start_print_no_lan_step();
    test_with_record();
    test_stops_fallback();
    test_error_update();
    if (fail_count) {
        std::fprintf(stderr, "print_route_test: %d failure(s)\n", fail_count);
        return 1;
    }
    std::puts("print_route_test: all checks passed");
    return 0;
}
