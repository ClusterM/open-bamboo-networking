#include "source_log.hpp"

#include "obn/os_compat.hpp"

#include <cctype>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#endif

namespace obn::source {

void noop_logger(void*, int, obn_tchar const*) {}

namespace {

// Allocate a heap copy of `buf` in the platform-native character width
// for the Logger callback. The caller -- gstbambusrc on Linux,
// wxMediaCtrl2 on Windows -- frees it via Bambu_FreeLogMsg, which in
// turn calls free(). On POSIX we hand back UTF-8 unchanged; on Windows
// we transcode UTF-8 -> UTF-16 once, since Studio's wide-string
// callback would otherwise see mojibake for any multi-byte input.
obn_tchar* strdup_for_logger(const char* buf)
{
#if defined(_WIN32)
    int wlen = ::MultiByteToWideChar(CP_UTF8, 0, buf, -1, nullptr, 0);
    if (wlen <= 0) {
        // On a bogus UTF-8 sequence return an empty wide string rather
        // than nullptr -- the Studio side dereferences without checking.
        auto* empty = static_cast<wchar_t*>(std::malloc(sizeof(wchar_t)));
        if (empty) empty[0] = L'\0';
        return empty;
    }
    auto* w = static_cast<wchar_t*>(
        std::malloc(static_cast<std::size_t>(wlen) * sizeof(wchar_t)));
    if (!w) return nullptr;
    ::MultiByteToWideChar(CP_UTF8, 0, buf, -1, w, wlen);
    return w;
#else
    return ::strdup(buf);
#endif
}

} // namespace

namespace {

LogLevel parse_log_level(const char* s, LogLevel fallback)
{
    if (!s || !*s) return fallback;
    auto eq = [&](const char* a) {
        for (size_t i = 0;; ++i) {
            char x = s[i];
            char y = a[i];
            if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
            if (x != y) return false;
            if (!x) return true;
        }
    };
    if (eq("trace")) return LL_TRACE;
    if (eq("debug")) return LL_DEBUG;
    if (eq("info"))  return LL_INFO;
    if (eq("warn") || eq("warning")) return LL_WARN;
    if (eq("error") || eq("err"))    return LL_ERROR;
    if (eq("off") || eq("none") || eq("silent") || eq("0")) return LL_OFF;
    return fallback;
}

const char* level_tag(LogLevel lvl)
{
    switch (lvl) {
        case LL_TRACE: return "TRACE";
        case LL_DEBUG: return "DEBUG";
        case LL_INFO:  return "INFO";
        case LL_WARN:  return "WARN";
        case LL_ERROR: return "ERROR";
        case LL_OFF:   return "OFF";
    }
    return "?";
}

thread_local std::string g_last_error;

} // namespace

LogLevel current_log_level()
{
    static const LogLevel lvl = []() {
        return parse_log_level(std::getenv("OBN_BAMBUSOURCE_LOG_LEVEL"),
                               LL_INFO);
    }();
    return lvl;
}

#if defined(_WIN32)
namespace {
// Look up the absolute path of THIS DLL (the one that contains
// mirror_log_fp itself) using GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS.
// The plugin is installed to "<data_dir>\plugins\BambuSource.dll", so
// we strip the trailing two path components to recover <data_dir> at
// runtime — meaning the same DLL writes to %APPDATA%\BambuStudio\
// when Studio loads it and to %APPDATA%\OrcaSlicer\ when Orca does.
std::string this_dll_data_dir()
{
    HMODULE h = nullptr;
    if (!::GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&this_dll_data_dir),
            &h) || !h) {
        return {};
    }
    wchar_t wpath[MAX_PATH] = {0};
    DWORD n = ::GetModuleFileNameW(h, wpath, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    int u8 = ::WideCharToMultiByte(CP_UTF8, 0, wpath, -1,
                                   nullptr, 0, nullptr, nullptr);
    if (u8 <= 0) return {};
    std::string path(static_cast<std::size_t>(u8 - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, wpath, -1,
                          path.data(), u8, nullptr, nullptr);
    // Strip "\BambuSource.dll"
    auto slash = path.find_last_of("\\/");
    if (slash == std::string::npos) return {};
    std::string dir = path.substr(0, slash);
    // Strip "\plugins" if present (defensive: a developer running a
    // build tree directly might have the DLL in a different layout).
    auto slash2 = dir.find_last_of("\\/");
    if (slash2 != std::string::npos) {
        std::string leaf = dir.substr(slash2 + 1);
        for (auto& c : leaf) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (leaf == "plugins") dir = dir.substr(0, slash2);
    }
    return dir;
}
} // namespace
#endif

// Resolution order:
//   1. $OBN_BAMBUSOURCE_LOG_FILE (set to "off"/"none"/empty to disable
//      the file mirror entirely; "stderr" routes to stderr).
//   2. Windows: <this-dll's data dir>\obn-bambusource.log
//      POSIX:   $XDG_STATE_HOME/bambu-studio/obn-bambusource.log
//   3. POSIX:   $HOME/.local/state/bambu-studio/obn-bambusource.log
//      Windows: %APPDATA%\BambuStudio\obn-bambusource.log (legacy)
//   4. Last-resort fallback (TEMP / /tmp).
FILE* mirror_log_fp()
{
    static FILE* fp = []() -> FILE* {
        if (const char* env = std::getenv("OBN_BAMBUSOURCE_LOG_FILE")) {
            if (!*env || !std::strcmp(env, "off") ||
                !std::strcmp(env, "none") || !std::strcmp(env, "0"))
                return nullptr;
            if (!std::strcmp(env, "stderr") || !std::strcmp(env, "-"))
                return stderr;
            if (FILE* f = std::fopen(env, "a")) {
                // _IOLBF + nullptr buffer is invalid on MSVC CRT and triggers
                // __fastfail(FAST_FAIL_INVALID_ARG); use _IONBF (no buffering)
                // which is allowed with a NULL buffer on every supported CRT.
                std::setvbuf(f, nullptr, _IONBF, 0);
                std::fprintf(f, "--- obn libBambuSource opened ---\n");
                return f;
            }
            // Fall through to the default search if the user-supplied
            // path could not be opened — better than dropping logs.
        }

        static std::string p0, p1, p2, p3;
        const char* paths[4] = {nullptr, nullptr, nullptr, nullptr};
#if defined(_WIN32)
        // Preferred: alongside the host slicer's data dir, recovered
        // from this DLL's installed path. Works for both Studio and
        // Orca without any compile-time switch.
        std::string dd = this_dll_data_dir();
        if (!dd.empty()) {
            p0 = dd + "\\obn-bambusource.log";
            paths[0] = p0.c_str();
        }
        if (const char* appdata = std::getenv("APPDATA")) {
            p1 = std::string(appdata) + "\\BambuStudio\\obn-bambusource.log";
            paths[1] = p1.c_str();
        }
        if (const char* lappdata = std::getenv("LOCALAPPDATA")) {
            p2 = std::string(lappdata) + "\\BambuStudio\\obn-bambusource.log";
            paths[2] = p2.c_str();
        }
        if (const char* tmp = std::getenv("TEMP")) {
            p3 = std::string(tmp) + "\\obn-bambusource.log";
            paths[3] = p3.c_str();
        } else {
            paths[3] = "C:\\obn-bambusource.log";
        }
#else
        if (const char* xdg = std::getenv("XDG_STATE_HOME")) {
            p0 = std::string(xdg) + "/bambu-studio/obn-bambusource.log";
            paths[0] = p0.c_str();
        }
        if (const char* home = std::getenv("HOME")) {
            p1 = std::string(home) + "/.local/state/bambu-studio/obn-bambusource.log";
            paths[1] = p1.c_str();
        }
        paths[2] = "/tmp/obn-bambusource.log";
#endif
        for (const char* path : paths) {
            if (!path) continue;
            if (FILE* f = std::fopen(path, "a")) {
                // See note above: _IOLBF + nullptr buffer crashes the MSVC CRT.
                std::setvbuf(f, nullptr, _IONBF, 0);
                std::fprintf(f, "--- obn libBambuSource opened (path=%s) ---\n", path);
                return f;
            }
        }
        return nullptr;
    }();
    return fp;
}

void log_at(LogLevel lvl, Logger logger, void* ctx, const char* fmt, ...)
{
    if (lvl < current_log_level()) return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (FILE* fp = mirror_log_fp()) {
        auto now = std::chrono::system_clock::now();
        auto tt  = std::chrono::system_clock::to_time_t(now);
        std::tm lt{};
        obn::os::localtime_safe(tt, &lt);
        char ts[32];
        std::strftime(ts, sizeof(ts), "%F %T", &lt);
        std::fprintf(fp, "%s [%s] %s\n", ts, level_tag(lvl), buf);
    }

    if (logger) {
        // Studio expects a heap-allocated buffer that it will free via
        // Bambu_FreeLogMsg. POSIX -> strdup; Windows -> wide-char copy
        // via strdup_for_logger() (caller frees with free()).
        logger(ctx, /*level=*/static_cast<int>(lvl), strdup_for_logger(buf));
    }
}

void log_fmt(Logger logger, void* ctx, const char* fmt, ...)
{
    if (LL_INFO < current_log_level()) return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (FILE* fp = mirror_log_fp()) {
        auto now = std::chrono::system_clock::now();
        auto tt  = std::chrono::system_clock::to_time_t(now);
        std::tm lt{};
        obn::os::localtime_safe(tt, &lt);
        char ts[32];
        std::strftime(ts, sizeof(ts), "%F %T", &lt);
        std::fprintf(fp, "%s [INFO] %s\n", ts, buf);
    }

    if (logger) {
        logger(ctx, /*level=*/static_cast<int>(LL_INFO), strdup_for_logger(buf));
    }
}

void set_last_error(const char* msg)
{
    g_last_error.assign(msg ? msg : "");
}

const char* get_last_error()
{
    return g_last_error.c_str();
}

} // namespace obn::source
