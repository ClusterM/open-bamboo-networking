// Unit tests for MQTT URL scheme helpers (brtc://, file://, ftp://).

#include "obn/bambu_networking.hpp"
#include "obn/print_job.hpp"

#include <cassert>
#include <iostream>
#include <string>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << ": " #cond "\n"; \
        return 1; \
    } \
} while (0)

int main()
{
    CHECK(obn::print_job::build_brtc_emmc_url("foo.gcode.3mf")
          == "brtc://emmc/foo.gcode.3mf");
    CHECK(obn::print_job::build_brtc_emmc_url("/foo.gcode.3mf")
          == "brtc://emmc/foo.gcode.3mf");

    CHECK(obn::print_job::build_file_url("/media/usb0/foo.gcode.3mf")
          == "file:///media/usb0/foo.gcode.3mf");
    CHECK(obn::print_job::build_file_url("media/usb0/foo.gcode.3mf")
          == "file:///media/usb0/foo.gcode.3mf");

    CHECK(obn::print_job::build_ftp_url("/foo.gcode.3mf")
          == "ftp://foo.gcode.3mf");
    CHECK(obn::print_job::build_ftp_url("foo.gcode.3mf")
          == "ftp://foo.gcode.3mf");

    BBL::PrintParams p{};
    p.try_emmc_print = true;
#if OBN_FT_TUNNEL_LOCAL
    CHECK(obn::print_job::use_brtc_cache_upload(p));
#else
    CHECK(!obn::print_job::use_brtc_cache_upload(p));
#endif
    p.try_emmc_print = false;
    CHECK(!obn::print_job::use_brtc_cache_upload(p));

    std::cout << "print_url_test: ok\n";
    return 0;
}
