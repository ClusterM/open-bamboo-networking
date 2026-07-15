#pragma once

// The stock bambu_network_agent cloud identity headers, as a header map.
//
// api.bambulab.com sits behind Cloudflare, which fingerprints the request's
// header set + order (JA4H). http::perform() emits recognised headers in the
// stock wire order (see kBblHeaderOrder in http_client.cpp), so this only needs
// to populate the set; order is applied at the transport.
//
// Used both by Agent::cloud_api_http_headers() (which then overlays Studio's
// set_extra_http_header values) and directly by cloud calls that are plain
// functions without an Agent (e.g. get_app_cert).
//
// include_client_id / with_content_type select the per-call variation the stock
// agent uses. Real slicer/plugin versions come from slicer_plugin_versions.hpp.
// Values are env-overridable so a capture can be reproduced exactly.

#include "obn/slicer_plugin_versions.hpp"
#include "obn/config.hpp"

#include <openssl/evp.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <string>

#if defined(_WIN32)
#  include <windows.h>
#elif defined(__APPLE__)
#  include <unistd.h>        // gethostuuid
#else
#  include <sys/utsname.h>   // Linux/BSD kernel version
#endif

namespace obn::bbl {
namespace detail {

// Trim a raw version to exactly three dotted numeric components, stopping at the
// first non-numeric/non-dot char (e.g. Linux "5.15.0-185-generic" -> "5.15.0").
// Missing trailing components are padded with 0.
inline std::string three_component(const std::string& raw) {
    std::string out;
    int dots = 0;
    for (char c : raw) {
        if (c >= '0' && c <= '9') out.push_back(c);
        else if (c == '.' && dots < 2) { out.push_back('.'); ++dots; }
        else break;
    }
    if (out.empty()) out = "0";
    while (dots < 2) { out += ".0"; ++dots; }
    return out;
}

#if defined(_WIN32)
// Real Windows build as major.minor.build, e.g. "10.0.26200". GetVersionEx caps
// at 6.2 without an app manifest, so read RtlGetVersion from ntdll directly.
inline std::string detect_os_version() {
    typedef LONG(WINAPI * RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    if (HMODULE nt = ::GetModuleHandleW(L"ntdll.dll")) {
        if (auto p = reinterpret_cast<RtlGetVersionPtr>(
                ::GetProcAddress(nt, "RtlGetVersion"))) {
            RTL_OSVERSIONINFOW vi{};
            vi.dwOSVersionInfoSize = sizeof vi;
            if (p(&vi) == 0) {
                char buf[48];
                std::snprintf(buf, sizeof buf, "%lu.%lu.%lu",
                              vi.dwMajorVersion, vi.dwMinorVersion,
                              vi.dwBuildNumber);
                return buf;
            }
        }
    }
    return "10.0.26200";
}
inline const char* default_os_type() { return "windows"; }

#elif defined(__APPLE__)
// TODO: confirm the genuine macOS identity the stock agent sends -- needs a
// macOS BambuStudio capture. Best guess: X-BBL-OS-Type "macos" and the macOS
// *product* version (e.g. "14.5.0"), not the Darwin kernel version uname()
// reports. Reading the product version needs CoreFoundation/sysctl; until we
// capture the real format we return a plausible constant (env-overridable).
inline std::string detect_os_version() { return "14.5.0"; }  // TODO: real product version + format
inline const char* default_os_type() { return "mac"; }    // TODO: confirm ("mac"/"darwin"?)

#else
// Linux: three-digit kernel version (major.minor.patch) from uname, dropping the
// distro/build suffix (e.g. "5.15.0-185-generic" -> "5.15.0").
inline std::string detect_os_version() {
    struct utsname u{};
    if (::uname(&u) != 0) return "0.0.0";
    return three_component(u.release);
}
inline const char* default_os_type() { return "linux"; }
#endif

// User's UI language as a BCP-47 tag ("en-US", "de-DE", "zh-CN"), matching the
// X-BBL-Language the stock agent sends for the slicer's selected language.
#if defined(_WIN32)
inline std::string detect_language() {
    wchar_t w[LOCALE_NAME_MAX_LENGTH];
    if (::GetUserDefaultLocaleName(w, LOCALE_NAME_MAX_LENGTH) > 0) {
        char out[LOCALE_NAME_MAX_LENGTH * 2];
        if (::WideCharToMultiByte(CP_UTF8, 0, w, -1, out, sizeof out, nullptr,
                                  nullptr) > 0 && out[0])
            return out;   // already hyphenated BCP-47
    }
    return "en-US";
}
#else
// POSIX locale "en_US.UTF-8" / "zh_CN.UTF-8@pinyin" -> "en-US" / "zh-CN".
inline std::string detect_language() {
    const char* loc = nullptr;
    for (const char* k : {"LC_ALL", "LC_MESSAGES", "LANG"}) {
        const char* v = std::getenv(k);
        if (v && v[0]) { loc = v; break; }
    }
    if (!loc) return "en-US";
    std::string s(loc);
    if (s == "C" || s == "POSIX") return "en-US";
    if (auto cut = s.find_first_of(".@"); cut != std::string::npos) s.resize(cut);
    for (char& c : s) if (c == '_') c = '-';
    return s.empty() ? "en-US" : s;
}
#endif

// Stable per-machine identifier (raw bytes, may be text or binary). Studio's
// slicer_uuid is a random UUID saved to disk; we instead derive ours from the
// OS machine id so it is constant for this machine without needing to persist a
// file.
#if defined(_WIN32)
inline std::string read_machine_id() {
    // HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid -- per-install GUID.
    HKEY k;
    if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Cryptography", 0,
                        KEY_READ | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
        wchar_t w[128];
        DWORD sz = sizeof w;
        LONG r = ::RegQueryValueExW(k, L"MachineGuid", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(w), &sz);
        ::RegCloseKey(k);
        if (r == ERROR_SUCCESS) {
            char out[256];
            if (::WideCharToMultiByte(CP_UTF8, 0, w, -1, out, sizeof out,
                                      nullptr, nullptr) > 0)
                return out;
        }
    }
    return {};
}
#elif defined(__APPLE__)
inline std::string read_machine_id() {
    unsigned char id[16];
    struct timespec wait{0, 0};
    if (::gethostuuid(id, &wait) == 0)
        return std::string(reinterpret_cast<const char*>(id), sizeof id);
    return {};
}
#else
inline std::string read_machine_id() {
    // systemd machine-id: 32 hex chars, stable for the life of the install.
    for (const char* p : {"/etc/machine-id", "/var/lib/dbus/machine-id"}) {
        std::ifstream f(p);
        std::string s;
        if (f && std::getline(f, s)) {
            while (!s.empty() &&
                   (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
                s.pop_back();
            if (!s.empty()) return s;
        }
    }
    return {};
}
#endif

// Deterministic RFC-4122-style UUID (v5 layout) derived from the machine id, so
// X-BBL-Device-ID is constant for this machine yet never exposes the raw id.
// Falls back to a fixed name when the machine id is unavailable.
inline std::string machine_uuid() {
    std::string mid = read_machine_id();
    // Namespace salt keeps the derivation opaque and distinct from other uses.
    std::string name = "open-bamboo-networking:device:" +
                       (mid.empty() ? std::string("unknown") : mid);

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int  mdlen = 0;
    if (EVP_Digest(name.data(), name.size(), md, &mdlen, EVP_sha1(), nullptr) != 1
        || mdlen < 16)
        return "00000000-0000-5000-8000-000000000000";

    unsigned char b[16];
    std::memcpy(b, md, 16);
    b[6] = static_cast<unsigned char>((b[6] & 0x0F) | 0x50);  // version 5
    b[8] = static_cast<unsigned char>((b[8] & 0x3F) | 0x80);  // RFC 4122 variant

    char out[37];
    std::snprintf(out, sizeof out,
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
                  "%02x%02x%02x%02x%02x%02x",
                  b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                  b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return out;
}

}  // namespace detail

inline std::map<std::string, std::string>
identity_headers(const std::string& access_token, const std::string& user_id,
                 bool include_client_id, bool with_content_type)
{
    auto env_or = [](const char* k, const std::string& d) {
        const char* v = std::getenv(k);
        return (v && v[0]) ? std::string(v) : d;
    };
#ifdef OBN_VERSION_STRING
    const std::string release = OBN_VERSION_STRING;
#else
    const std::string release = "01.00.00.00";
#endif
    const auto vp = obn::versions::resolve(release);   // {slicer, agent}, always real
    // OS identity: Windows sends its real build (10.0.<build>), Linux the
    // three-digit kernel version, macOS a guessed product version (TODO). All
    // env-overridable to reproduce a specific capture.
    const std::string os_type = env_or("BBL_OS_TYPE",    detail::default_os_type());
    const std::string os_ver  = env_or("BBL_OS_VERSION", detail::detect_os_version());
    // Versions come from the table, never the environment. To present the host
    // slicer's real versions instead, set OBN_ALLOW_VERSION_OVERRIDES and let the
    // host supply them via set_extra_http_header (see Agent::cloud_api_http_headers).
    const std::string agent_ver  = vp.second;
    const std::string client_ver = vp.first;

    // Identity presented to the Bambu cloud. Defaults reproduce the stock
    // BambuStudio agent so a non-Bambu host (e.g. OrcaSlicer) is indistinguishable
    // by default; every field is env-overridable for tuning or to present a
    // different identity. This block also wins over any X-BBL-* the host slicer
    // sets via set_extra_http_header (see agent.cpp), so the masquerade holds
    // without the host cooperating.
    // Client-Name: BBL_CLIENT_NAME env wins, else the config knob
    // (config::client_name), else "BambuStudio" -- the value POST /my/task
    // requires to reach uploaded content.
    const std::string& cfg_name = obn::config::current().client_name;
    const std::string client_name =
        env_or("BBL_CLIENT_NAME", cfg_name.empty() ? "BambuStudio" : cfg_name);
    const std::string client_type = env_or("BBL_CLIENT_TYPE", "slicer");
    const std::string ua_product   = env_or("BBL_UA_PRODUCT", "bambu_network_agent");

    std::map<std::string, std::string> h;
    // Product token is a name (env-tunable); the version half always comes from
    // the table so the UA cannot leak a real host version via the environment.
    h["User-Agent"]            = ua_product + "/" + agent_ver;
    if (include_client_id && !user_id.empty()) {
        // slicer:<uid>:<4 hex>; the stock agent varies the suffix per request.
        static std::atomic<unsigned> ctr{0x1a2bu};
        char sfx[8];
        std::snprintf(sfx, sizeof sfx, "%04x", ctr.fetch_add(0x9e37u) & 0xffffu);
        h["X-BBL-Client-ID"]   = client_type + ":" + user_id + ":" + sfx;
    }
    h["X-BBL-Client-Name"]     = client_name;
    h["X-BBL-Client-Type"]     = client_type;
    h["X-BBL-Client-Version"]  = client_ver;
    h["X-BBL-Device-ID"]       = env_or("BBL_DEVICE_ID", detail::machine_uuid());
    h["X-BBL-Language"]        = env_or("BBL_LANGUAGE", detail::detect_language());
    h["X-BBL-OS-Type"]        = os_type;
    h["X-BBL-OS-Version"]     = os_ver;
    h["X-BBL-Agent-Version"]  = agent_ver;
    h["X-BBL-Executable-info"] = env_or("BBL_EXEC_INFO", "{}");
    h["X-BBL-Agent-OS-Type"]  = os_type;
    h["X-BBL-Executable-Env"] = "false";
    h["accept"]               = "application/json";
    if (!access_token.empty()) h["Authorization"] = "Bearer " + access_token;
    if (with_content_type) h["Content-Type"] = "application/json";
    return h;
}

}  // namespace obn::bbl
