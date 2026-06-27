#include "source_log.hpp"

#include "obn/lan_tls_env.hpp"
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
    if (const char* v = obn::lan_tls::env_var_get(obn::lan_tls::kEnvBsLogLevel))
        return parse_log_level(v, LL_INFO);
    return LL_INFO;
}

bool echo_stderr_enabled()
{
    const char* v = obn::lan_tls::env_var_get(obn::lan_tls::kEnvBsLogStderr);
    if (!v || !*v) return true;
    return v[0] == '1' || v[0] == 'y' || v[0] == 'Y' || v[0] == 't' || v[0] == 'T';
}

#if defined(_WIN32)
namespace {
// Look up the absolute path of THIS DLL (the one that contains
// mirror_log_fp itself) using GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS.
// The plugin is installed to "<data_dir>\plugins\BambuSource.dll", so
// we strip the trailing two path components to recover <data_dir> at
// runtime — meaning the same DLL writes to "%APPDATA%\BambuStudio\"
// when Studio loads it and to "%APPDATA%\OrcaSlicer\" when Orca does.
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
    std::string path(static_cast<std::size_t>(u8), '\0');
    if (::WideCharToMultiByte(CP_UTF8, 0, wpath, -1,
                              path.data(), u8, nullptr, nullptr) <= 0)
        return {};
    if (!path.empty() && path.back() == '\0') path.pop_back();
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

static FILE* open_log_file(const char* path)
{
    FILE* f = std::fopen(path, "a");
    if (!f) return nullptr;
    std::setvbuf(f, nullptr, _IONBF, 0);
    std::fprintf(f, "--- obn libBambuSource opened (path=%s) ---\n", path);
    return f;
}

// Resolve the default log file path when bambusource_log_to_file=1
// but no explicit bambusource_log_file is set.
static FILE* open_default_log_file()
{
#if defined(_WIN32)
    std::string dd = this_dll_data_dir();
    if (!dd.empty()) {
        if (FILE* f = open_log_file((dd + "\\obn-bambusource.log").c_str()))
            return f;
    }
#else
    if (const char* xdg = std::getenv("XDG_STATE_HOME")) {
        std::string p = std::string(xdg) + "/bambu-studio/obn-bambusource.log";
        if (FILE* f = open_log_file(p.c_str())) return f;
    }
    if (const char* home = std::getenv("HOME")) {
        std::string p = std::string(home) + "/.local/state/bambu-studio/obn-bambusource.log";
        if (FILE* f = open_log_file(p.c_str())) return f;
    }
    if (FILE* f = open_log_file("/tmp/obn-bambusource.log")) return f;
#endif
    return nullptr;
}

// Resolution (matches main plugin pattern):
//   1. bambusource_log_file (explicit path, "off"/"none" to disable, "stderr" for stderr)
//   2. bambusource_log_to_file=1 -> auto-detect path from DLL location / $HOME
//   3. Neither set -> no file (default, same as main plugin)
FILE* mirror_log_fp()
{
    static FILE* fp = []() -> FILE* {
        const char* explicit_path =
            obn::lan_tls::env_var_get(obn::lan_tls::kEnvBsLogFile);
        if (explicit_path && *explicit_path) {
            if (!std::strcmp(explicit_path, "off") ||
                !std::strcmp(explicit_path, "none") || !std::strcmp(explicit_path, "0"))
                return nullptr;
            if (!std::strcmp(explicit_path, "stderr") || !std::strcmp(explicit_path, "-"))
                return stderr;
            if (FILE* f = open_log_file(explicit_path))
                return f;
        }

        const char* to_file =
            obn::lan_tls::env_var_get(obn::lan_tls::kEnvBsLogToFile);
        if (to_file && (to_file[0] == '1' || to_file[0] == 'y' ||
                        to_file[0] == 'Y' || to_file[0] == 't' || to_file[0] == 'T'))
            return open_default_log_file();

        return nullptr;
    }();
    return fp;
}

static void emit_line(LogLevel lvl, const char* buf)
{
    auto now = std::chrono::system_clock::now();
    auto tt  = std::chrono::system_clock::to_time_t(now);
    std::tm lt{};
    obn::os::localtime_safe(tt, &lt);
    char ts[32];
    std::strftime(ts, sizeof(ts), "%F %T", &lt);

    if (FILE* fp = mirror_log_fp())
        std::fprintf(fp, "%s [%s] %s\n", ts, level_tag(lvl), buf);
    if (echo_stderr_enabled())
        std::fprintf(stderr, "[obn-bs] %s [%s] %s\n", ts, level_tag(lvl), buf);
}

void log_at(LogLevel lvl, Logger logger, void* ctx, const char* fmt, ...)
{
    if (lvl < current_log_level()) return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    emit_line(lvl, buf);

    if (logger)
        logger(ctx, /*level=*/static_cast<int>(lvl), strdup_for_logger(buf));
}

void log_fmt(Logger logger, void* ctx, const char* fmt, ...)
{
    if (LL_INFO < current_log_level()) return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    emit_line(LL_INFO, buf);

    if (logger)
        logger(ctx, /*level=*/static_cast<int>(LL_INFO), strdup_for_logger(buf));
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
