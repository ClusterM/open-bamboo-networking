// Internal parser for FTPS directory listings.
//
// Split out of ftps.cpp so the unit test (tests/ftps_parse_test.cpp)
// can exercise it directly without spinning up an FTPS server. This
// is free-standing, stateless and depends only on obn::ftps::Entry
// from the public header -- NOT on any connection state.
//
// Bambu printers' FTP daemons (across O1S / X1 / P1 / P2S / A1) do
// not implement MLSD -- FEAT simply does not list it, and the server
// replies with "500 Unknown command". The plugin therefore issues
// plain LIST exclusively and relies on `parse_ls_line` below to
// recover name / size / is_dir / mtime from the `ls -l` output.
//
// Keep this header private (not installed); it is #included by
// src/ftps.cpp and by the test. Everything lives in
// obn::ftps::detail to make that intent obvious.

#pragma once

#include "obn/ftps.hpp"
#include "obn/os_compat.hpp"

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

namespace obn {
namespace ftps {
namespace detail {

// 3-letter English month abbreviation -> 1-based month number (Jan..Dec).
// Returns 0 if the token does not look like a month name. ls(1) uses
// LC_TIME to pick abbreviations and may emit UTF-8 for non-English
// locales, but Bambu firmware runs ls under a C / POSIX locale so we
// only need to handle the canonical three-letter English set.
inline int ls_month_index(const std::string& tok)
{
    if (tok.size() != 3) return 0;
    static const char* kMonths[12] = {
        "jan","feb","mar","apr","may","jun",
        "jul","aug","sep","oct","nov","dec"
    };
    char lower[4] = {
        static_cast<char>(std::tolower(static_cast<unsigned char>(tok[0]))),
        static_cast<char>(std::tolower(static_cast<unsigned char>(tok[1]))),
        static_cast<char>(std::tolower(static_cast<unsigned char>(tok[2]))),
        '\0'
    };
    for (int i = 0; i < 12; ++i) {
        if (std::strcmp(lower, kMonths[i]) == 0) return i + 1;
    }
    return 0;
}

// Parser for `ls -l` style LIST output. Extracts name, size, is_dir
// and -- best effort -- the modification time.
//
// vsftpd / busybox ftpd / GNU ls emit two date forms, depending on
// whether the file is older or newer than ~6 months:
//   "Oct 21 12:34 name"  (recent: no year, time of day is shown)
//   "Oct 21  2020 name"  (old / future: year is shown, no time)
// We parse both. Note that ls shows the server's local time; we treat
// it as UTC because we have no way to learn the printer's timezone
// across the wire. The resulting mtime may be off by the server's UTC
// offset, but any value beats "1970" in the Studio file browser.
//
// `now_utc` is an injection point for tests (so "recent" year
// inference is deterministic). Production callers leave it at 0,
// which means "use std::time(nullptr)".
inline void parse_ls_line(const std::string& line, Entry* e,
                          std::time_t now_utc = 0)
{
    if (line.empty()) return;
    e->is_dir = (line[0] == 'd');

    // Split on runs of whitespace, remembering each token's starting
    // offset so we can keep everything after column 8 verbatim as the
    // filename (which may itself contain spaces).
    struct Tok { std::size_t start; std::size_t len; };
    std::vector<Tok> tokens;
    tokens.reserve(10);
    for (std::size_t i = 0; i < line.size(); ) {
        while (i < line.size() && line[i] == ' ') ++i;
        if (i >= line.size()) break;
        std::size_t s = i;
        while (i < line.size() && line[i] != ' ') ++i;
        tokens.push_back({s, i - s});
    }
    if (tokens.size() < 9) return;  // not a recognisable ls -l line

    auto token_str = [&](std::size_t idx) {
        return line.substr(tokens[idx].start, tokens[idx].len);
    };

    // Columns: 0=perms 1=links 2=owner 3=group 4=size 5=mon 6=day
    //          7=time|year 8+=name
    e->size = std::strtoull(token_str(4).c_str(), nullptr, 10);

    const int mo  = ls_month_index(token_str(5));
    const int day = std::atoi(token_str(6).c_str());
    const std::string ty = token_str(7);
    if (mo > 0 && day > 0 && !ty.empty()) {
        std::tm tm{};
        tm.tm_mon  = mo - 1;
        tm.tm_mday = day;
        auto colon = ty.find(':');
        if (colon != std::string::npos) {
            // "HH:MM" form: year is implicit. ls uses it for files
            // within roughly the past six months OR the next 6 months
            // (coreutils "recent_file_test"). Default to "this year";
            // if that produces a date more than six months in the
            // future we roll it back a year.
            tm.tm_hour = std::atoi(ty.substr(0, colon).c_str());
            tm.tm_min  = std::atoi(ty.substr(colon + 1).c_str());
            const std::time_t now_t =
                (now_utc != 0) ? now_utc : std::time(nullptr);
            std::tm now_tm{};
            obn::os::gmtime_safe(now_t, &now_tm);
            tm.tm_year = now_tm.tm_year;
            std::time_t candidate = obn::os::timegm_safe(&tm);
            constexpr std::time_t kSixMonths = 60LL * 60 * 24 * 183;
            if (candidate > now_t + kSixMonths) {
                tm.tm_year -= 1;
                candidate = obn::os::timegm_safe(&tm);
            }
            if (candidate > 0)
                e->mtime = static_cast<std::uint64_t>(candidate);
        } else {
            // "YYYY" form: explicit year, time defaults to 00:00 UTC.
            const int yr = std::atoi(ty.c_str());
            if (yr >= 1970) {
                tm.tm_year = yr - 1900;
                std::time_t candidate = obn::os::timegm_safe(&tm);
                if (candidate > 0)
                    e->mtime = static_cast<std::uint64_t>(candidate);
            }
        }
    }

    // Everything from token 8 onward is the name. Resist the urge to
    // join tokens[8..] with a single space -- the original run of
    // whitespace in the line may have been multiple spaces (e.g. in
    // an artist's "My  Song  (live).3mf"), so slice the raw line
    // starting at tokens[8].start instead.
    e->name = line.substr(tokens[8].start);
    auto arrow = e->name.find(" -> ");
    if (arrow != std::string::npos) e->name = e->name.substr(0, arrow);
}

} // namespace detail
} // namespace ftps
} // namespace obn
