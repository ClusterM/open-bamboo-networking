// Unit tests for the FTPS directory-listing parser in
// src/ftps_parse.hpp. Run hermetically (no network, no server) and
// catch regressions in "Mon DD HH:MM|YYYY name" parsing -- getting
// this wrong is the reason every file in Studio's storage tab
// previously showed up as 1970 (the plugin only spoke MLSD, which
// Bambu firmware does not implement; the LIST parser used to throw
// the date away on purpose).
//
// The tests use a fixed `now_utc` so the "recent file" year-inference
// branch is deterministic.

#include "../src/ftps_parse.hpp"

#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

using obn::ftps::Entry;
using obn::ftps::detail::parse_ls_line;

namespace {

struct Result {
    int failed = 0;
    int passed = 0;
};

#define EXPECT(r, cond)                                                   \
    do {                                                                  \
        if (cond) {                                                       \
            (r).passed++;                                                 \
        } else {                                                          \
            (r).failed++;                                                 \
            std::fprintf(stderr, "FAIL %s:%d: %s\n",                      \
                         __FILE__, __LINE__, #cond);                      \
        }                                                                 \
    } while (0)

// Reference point: 2026-04-21 10:00:00 UTC. All "recent" HH:MM times
// are resolved relative to this value.
constexpr std::time_t kNow = 1'776'823'200;

std::time_t utc(int y, int mo, int d, int h = 0, int mi = 0, int s = 0)
{
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon  = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min  = mi;
    tm.tm_sec  = s;
    return ::timegm(&tm);
}

void test_ls_with_year(Result& r)
{
    Entry e;
    parse_ls_line(
        "-rw-r--r--    1 root     root         2048 Oct 21  2020 foo.3mf",
        &e, kNow);
    EXPECT(r, !e.is_dir);
    EXPECT(r, e.size == 2048u);
    EXPECT(r, e.name == "foo.3mf");
    EXPECT(r, e.mtime == static_cast<std::uint64_t>(utc(2020, 10, 21)));
}

void test_ls_hhmm_recent_this_year(Result& r)
{
    // "Mar 15 14:25" -- before kNow in 2026; resolves to 2026-03-15.
    Entry e;
    parse_ls_line(
        "-rw-r--r--    1 root     root        12345 Mar 15 14:25 model.gcode",
        &e, kNow);
    EXPECT(r, !e.is_dir);
    EXPECT(r, e.size == 12345u);
    EXPECT(r, e.name == "model.gcode");
    EXPECT(r, e.mtime ==
              static_cast<std::uint64_t>(utc(2026, 3, 15, 14, 25)));
}

void test_ls_hhmm_recent_last_year(Result& r)
{
    // "Dec 12 08:00" -- from kNow (April 2026) this is >6 months in
    // the future if interpreted as 2026, so it must be 2025-12-12.
    Entry e;
    parse_ls_line(
        "-rw-rw-rw-    1 ftp      ftp         99999 Dec 12 08:00 old.3mf",
        &e, kNow);
    EXPECT(r, e.mtime ==
              static_cast<std::uint64_t>(utc(2025, 12, 12, 8, 0)));
}

void test_ls_directory(Result& r)
{
    Entry e;
    parse_ls_line(
        "drwxr-xr-x    2 root     root         4096 Apr 21 09:30 cache",
        &e, kNow);
    EXPECT(r, e.is_dir);
    EXPECT(r, e.name == "cache");
    EXPECT(r, e.size == 4096u);
    EXPECT(r, e.mtime ==
              static_cast<std::uint64_t>(utc(2026, 4, 21, 9, 30)));
}

void test_ls_name_with_spaces(Result& r)
{
    Entry e;
    parse_ls_line(
        "-rw-r--r--    1 root     root         1000 Apr 21 12:00 My model v2.3mf",
        &e, kNow);
    EXPECT(r, e.name == "My model v2.3mf");
}

void test_ls_symlink(Result& r)
{
    Entry e;
    parse_ls_line(
        "lrwxrwxrwx    1 root     root           12 Apr 21 12:00 current -> cache",
        &e, kNow);
    EXPECT(r, !e.is_dir);
    EXPECT(r, e.name == "current");
    EXPECT(r, e.mtime ==
              static_cast<std::uint64_t>(utc(2026, 4, 21, 12, 0)));
}

// Verbatim lines captured from Bambu O1S firmware (FTPS `LIST /`) on
// 2026-04-21. uid/gid are numeric (103/107) and the date format is
// "Mon DD HH:MM" for every recent file. MLSD is NOT listed in FEAT,
// so the plugin always falls through to this code path on O1S.
void test_ls_bambu_o1s_firmware(Result& r)
{
    {
        Entry e;
        parse_ls_line(
            "-rwxr-xr-x    1 103      107        921589 Apr 13 16:56 Cat_Treat_Toy_-_Rocking_Pear.gcode.3mf",
            &e, kNow);
        EXPECT(r, !e.is_dir);
        EXPECT(r, e.size == 921589u);
        EXPECT(r, e.name == "Cat_Treat_Toy_-_Rocking_Pear.gcode.3mf");
        EXPECT(r, e.mtime ==
                  static_cast<std::uint64_t>(utc(2026, 4, 13, 16, 56)));
    }
    {
        Entry e;
        parse_ls_line(
            "drwxr-xr-x    2 103      107         65536 Apr 20 19:11 cache",
            &e, kNow);
        EXPECT(r, e.is_dir);
        EXPECT(r, e.name == "cache");
        EXPECT(r, e.mtime ==
                  static_cast<std::uint64_t>(utc(2026, 4, 20, 19, 11)));
    }
    {
        // Single-byte "verify_job" file -- unusual, but present on
        // every O1S. Exercises the path where size < 16 bytes.
        Entry e;
        parse_ls_line(
            "-rwxr-xr-x    1 103      107            16 Apr 20 18:15 verify_job",
            &e, kNow);
        EXPECT(r, e.size == 16u);
        EXPECT(r, e.name == "verify_job");
        EXPECT(r, e.mtime ==
                  static_cast<std::uint64_t>(utc(2026, 4, 20, 18, 15)));
    }
}

void test_ls_junk(Result& r)
{
    // Total parser defence: truncated, empty, non-listing inputs must
    // not crash and must not fabricate a mtime.
    Entry e;
    parse_ls_line("", &e, kNow);
    EXPECT(r, e.mtime == 0u && e.name.empty());

    Entry e2;
    parse_ls_line("not a real listing line", &e2, kNow);
    EXPECT(r, e2.mtime == 0u);

    Entry e3;
    parse_ls_line("-rw- short output", &e3, kNow);
    EXPECT(r, e3.mtime == 0u);
}

void test_pasv(Result& r)
{
    using obn::ftps::detail::parse_pasv_reply;
    int h[4] = {};
    int port = 0;

    EXPECT(r, parse_pasv_reply("227 Entering Passive Mode (192,168,1,50,195,80).", h, &port));
    EXPECT(r, h[0] == 192 && h[1] == 168 && h[2] == 1 && h[3] == 50);
    EXPECT(r, port == 195 * 256 + 80);
    EXPECT(r, parse_pasv_reply("227 ( 10, 0, 0, 1, 0, 21 )", h, &port) && port == 21);
    EXPECT(r, parse_pasv_reply("227 (0,0,0,0,255,255)", h, &port) && port == 65535);

    // Out of range or overlong: previously sscanf("%d") territory.
    EXPECT(r, !parse_pasv_reply("227 (192,168,1,50,256,0)", h, &port));
    EXPECT(r, !parse_pasv_reply("227 (192,168,1,50,-1,80)", h, &port));
    EXPECT(r, !parse_pasv_reply("227 (192,168,1,50,99999999999999999999,80)", h, &port));
    EXPECT(r, !parse_pasv_reply("227 (192,168,1,50,0255,80)", h, &port));
    // Wrong shape.
    EXPECT(r, !parse_pasv_reply("227 (192,168,1,50,195)", h, &port));
    EXPECT(r, !parse_pasv_reply("227 (192,168,1,50,195,80,1)", h, &port));
    EXPECT(r, !parse_pasv_reply("227 (192,168,1,50,195,x)", h, &port));
    EXPECT(r, !parse_pasv_reply("227 (192,168,1,50,,80)", h, &port));
    EXPECT(r, !parse_pasv_reply("227 Entering Passive Mode 192,168,1,50,195,80", h, &port));
    EXPECT(r, !parse_pasv_reply("227 )192,168,1,50,195,80(", h, &port));
    EXPECT(r, !parse_pasv_reply("", h, &port));
    // Port 0 is not a usable data port.
    EXPECT(r, !parse_pasv_reply("227 (192,168,1,50,0,0)", h, &port));
}

} // namespace

int main()
{
    Result r;
    test_ls_with_year(r);
    test_ls_hhmm_recent_this_year(r);
    test_ls_hhmm_recent_last_year(r);
    test_ls_directory(r);
    test_ls_name_with_spaces(r);
    test_ls_symlink(r);
    test_ls_bambu_o1s_firmware(r);
    test_ls_junk(r);
    test_pasv(r);
    std::printf("ftps_parse_test: %d passed, %d failed\n",
                r.passed, r.failed);
    return r.failed == 0 ? 0 : 1;
}
