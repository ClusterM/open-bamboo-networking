#pragma once

// Slicer <-> network-plugin version pairing for the cloud identity headers.
//
// A BambuStudio / OrcaSlicer release ships a specific network-plugin build:
// the slicer reports its own version in X-BBL-Client-Version and the plugin
// reports its build in X-BBL-Agent-Version (and the User-Agent). The two share
// MAJOR.MINOR.PATCH but differ in the 4th component (e.g. Studio 02.07.00.55
// ships plugin 02.07.00.50).
//
// The open plugin is configured with OBN_VERSION = <slicer MAJOR.MINOR.PATCH>.99
// (see ./configure), so at runtime it only knows the release line, not the real
// 4th components. This table recovers them so the headers match the stock build.
//
// Sources: BambuStudio version.inc (SLIC3R_VERSION) + its
// BAMBU_NETWORK_AGENT_VERSION define, and live MITM capture of the stock plugin.
// The table is compiled down to the single row matching the build's ABI_VERSION
// (see kSlicerPluginVersions below); an unmapped build uses the newest row.

#include <cctype>
#include <cstdlib>
#include <string>
#include <utility>

namespace obn::versions {

// When false (the default), the plugin ignores whatever versions the host slicer
// reports and presents the versions from the table below -- so a non-Bambu host
// (OrcaSlicer) is indistinguishable from the stock BambuStudio build. Set
// OBN_ALLOW_VERSION_OVERRIDES=1 (also true/yes/on) to instead obey the host
// slicer's own versions (preset-sync bundle version, and the client/agent version
// headers it supplies via set_extra_http_header).
inline bool allow_overrides()
{
    const char* v = std::getenv("OBN_ALLOW_VERSION_OVERRIDES");
    if (!v || !v[0]) return false;
    std::string s(v);
    for (char& c : s) c = static_cast<char>(std::tolower((unsigned char)c));
    return s == "1" || s == "true" || s == "yes" || s == "on";
}

struct SlicerPluginVersion {
    const char* line;    // "02.07.00" -- MAJOR.MINOR.PATCH (first 8 chars)
    const char* slicer;  // X-BBL-Client-Version
    const char* agent;   // X-BBL-Agent-Version + User-Agent (bambu_network_agent/<agent>)
    const char* sync;    // preset-sync bundle version: GET /slicer/setting?version=<sync>
                         // = the release's resources/profiles/BBL.json "version" with
                         //   leading zeros stripped (Semver::to_string), e.g. 2.7.0.2.
};

// Keep sorted ascending by `line`; newest() relies on the last-max entry.
//
// slicer  = real BambuStudio release tag (github.com/bambulab/BambuStudio/tags).
// agent   = real network-plugin build Bambu's cloud serves for that release
//           (GET api.bambulab.com/v1/iot-service/api/slicer/resource
//            ?slicer/plugins/cloud=<MAJOR.MINOR.PATCH>.00 -> resources[].version),
//           which is exactly how BambuStudio picks the plugin to download.
//
// The table is gated to the SINGLE row matching the build's ABI_VERSION, so the
// compiled binary only knows its own release -- the exact version it reports to
// Studio's 8-char gate and presents in the cloud identity headers. ABI_VERSION
// is 0xMMmmpp, derived from OBN_VERSION's MAJOR.MINOR.PATCH (see CMakeLists.txt),
// which is the same value resolve()/sync_version() look up at runtime
// (OBN_VERSION_STRING). One build == one version; there is nothing to fall back
// to across an ABI or version boundary.
//
// Add a release by inserting its `#elif ABI_VERSION == 0x0MMmmpp` line. The
// `#else` catches any newer/unmapped build, presenting the newest known row.
inline constexpr SlicerPluginVersion kSlicerPluginVersions[] = {
#if   ABI_VERSION == 0x020300
    {"02.03.00", "02.03.00.70", "02.03.00.62", "2.3.0.2"},
#elif ABI_VERSION == 0x020301
    {"02.03.01", "02.03.01.51", "02.03.01.52", "2.3.0.4"},
#elif ABI_VERSION == 0x020400
    {"02.04.00", "02.04.00.70", "02.04.00.79", "2.4.0.1"},
#elif ABI_VERSION == 0x020501
    {"02.05.01", "02.05.01.58", "02.05.01.52", "2.5.0.15"},
#elif ABI_VERSION == 0x020502
    {"02.05.02", "02.05.02.51", "02.05.02.58", "2.5.0.15"},
#elif ABI_VERSION == 0x020503
    {"02.05.03", "02.05.03.62", "02.05.03.63", "2.5.0.18"},
#elif ABI_VERSION == 0x020600
    {"02.06.00", "02.06.00.51", "02.06.00.50", "2.6.0.1"},
#elif ABI_VERSION == 0x020601
    {"02.06.01", "02.06.01.55", "02.06.01.50", "2.6.0.3"},
#elif ABI_VERSION == 0x020700
    {"02.07.00", "02.07.00.55", "02.07.00.50", "2.7.0.2"},
#elif ABI_VERSION == 0x020701
    {"02.07.01", "02.07.01.62", "02.07.01.51", "2.7.0.8"},
#elif ABI_VERSION == 0x020800
    {"02.08.00", "02.08.00.50", "02.08.00.51", "2.8.0.1"},
#elif ABI_VERSION == 0x020801
    // slicer/sync from BambuStudio tag v02.08.01.55 (version.inc, BBL.json);
    // agent from a live query against api.bambulab.com's own resource API
    // (slicer/plugins/cloud=02.08.01.00 -> resources[].version), 2026-07-22.
    {"02.08.01", "02.08.01.55", "02.08.01.53", "2.8.0.4"},
#else
    // Newer/unmapped release: use the newest known row.
    {"02.08.01", "02.08.01.55", "02.08.01.53", "2.8.0.4"},
#endif
};

// Newest known pair. Lines are zero-padded MAJOR.MINOR.PATCH, so lexicographic
// max == newest.
inline const SlicerPluginVersion& newest()
{
    const SlicerPluginVersion* best = &kSlicerPluginVersions[0];
    for (const auto& v : kSlicerPluginVersions)
        if (std::string(v.line) > best->line) best = &v;
    return *best;
}

// Returns {slicer_version, agent_version} for the release line of
// `plugin_version` (its MAJOR.MINOR.PATCH prefix). Always a REAL Bambu pair:
// if the line is not mapped, fall back to the newest known release rather than
// a synthetic OBN_VERSION build (which uses a .99 4th component no real build
// ships).
inline std::pair<std::string, std::string> resolve(const std::string& plugin_version)
{
    const std::string line = plugin_version.substr(0, 8);  // "MAJOR.MINOR.PATCH"
    for (const auto& v : kSlicerPluginVersions)
        if (line == v.line) return {v.slicer, v.agent};
    const auto& n = newest();
    return {n.slicer, n.agent};
}

// Preset-sync bundle version for the release line of `plugin_version` -- the
// value the stock slicer sends as GET /slicer/setting?version=<...>. Same
// real-or-newest fallback policy as resolve(). Host BambuStudio derives this
// from its bundled BBL.json; this table lets the open plugin reproduce it when
// the host does not supply one.
inline std::string sync_version(const std::string& plugin_version)
{
    const std::string line = plugin_version.substr(0, 8);
    for (const auto& v : kSlicerPluginVersions)
        if (line == v.line) return v.sync;
    return newest().sync;
}

}  // namespace obn::versions
