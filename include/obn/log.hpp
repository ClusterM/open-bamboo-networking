#pragma once

#include <cstdarg>
#include <cstdio>
#include <string>

namespace obn::config {
struct Settings;
} // namespace obn::config

// Minimal printf-style logger shared by all ABI implementations. Goals:
//   * zero runtime dependencies beyond libc;
//   * always-on (no macro stripping in release) so a deployed plugin can be
//     diagnosed in-field from the terminal or an opt-in log file;
//   * thread-safe - mosquitto calls us on a background thread, Studio calls
//     us on the main thread, and they often interleave.
//
// Configuration happens at first use through environment variables (highest
// priority), then obn.conf (see obn/config.hpp), then built-in defaults:
//   OBN_LOG_FILE      optional absolute path to a log file. If unset, no file
//                     sink is opened unless OBN_LOG_TO_FILE=1 or log_to_file
//                     in obn.conf (see below).
//   OBN_LOG_TO_FILE   set to 1 to also write to <log_dir>/obn.log (log_dir is
//                     passed from Studio to create_agent). Ignored if
//                     OBN_LOG_FILE is set (including empty: console-only).
//   OBN_LOG_LEVEL     trace | debug | info | warn | error | off (default: info).
//   OBN_LOG_STDERR    0|1 (default: 1) - copy every line to stderr, each
//                     line prefixed with "[obn] " so it is distinct from
//                     Bambu Studio's own stderr output.
//
// The logger intentionally leaks a static singleton: the plugin is unloaded
// together with the process, so there is no cleanup hazard.

namespace obn::log {

enum Level : int {
    LVL_TRACE = 0,
    LVL_DEBUG = 1,
    LVL_INFO  = 2,
    LVL_WARN  = 3,
    LVL_ERROR = 4,
    LVL_OFF   = 5,
};

// Called from bambu_network_create_agent once Studio gives us a log directory.
// Opens <log_dir>/obn.log when OBN_LOG_TO_FILE=1 or log_to_file in obn.conf.
// Safe to call multiple times; skipped if OBN_LOG_FILE was set explicitly via env.
void configure_from_log_dir(const std::string& log_dir);

// Apply obn.conf logging keys for any OBN_LOG_* env vars that are not set.
// Must run before the first OBN_* line (create_agent calls this after load_or_create).
void apply_config(const obn::config::Settings& cfg);

// Low-level emitter. Use the OBN_* macros below instead of calling directly.
// `__attribute__((format(printf,...)))` is GCC/Clang-only; MSVC accepts the
// equivalent _Printf_format_string_ SAL annotation through <sal.h> but for
// our purposes a static assertion at the call site (handled by the OBN_*
// macros' macro-stringification trick) is enough -- so we just drop the
// hint on MSVC.
#if defined(__GNUC__) || defined(__clang__)
void emit(Level lvl, const char* file, int line, const char* func, const char* fmt, ...)
    __attribute__((format(printf, 5, 6)));
#else
void emit(Level lvl, const char* file, int line, const char* func, const char* fmt, ...);
#endif

// Current threshold, used by macros to skip argument evaluation when muted.
Level threshold();

// Truncates/sanitises a potentially secret-bearing string for safe logging.
// Returns up to `max_chars` characters with any non-printable byte replaced
// by '.'. Caller-owned std::string, so it is safe to use inside %s.
std::string redact(const std::string& in, std::size_t max_chars = 40);

} // namespace obn::log

#define OBN_LOG_IMPL(lvl, ...)                                                  \
    do {                                                                        \
        if (::obn::log::threshold() <= (lvl))                                   \
            ::obn::log::emit((lvl), __FILE__, __LINE__, __func__, __VA_ARGS__); \
    } while (0)

#define OBN_TRACE(...) OBN_LOG_IMPL(::obn::log::LVL_TRACE, __VA_ARGS__)
#define OBN_DEBUG(...) OBN_LOG_IMPL(::obn::log::LVL_DEBUG, __VA_ARGS__)
#define OBN_INFO(...)  OBN_LOG_IMPL(::obn::log::LVL_INFO,  __VA_ARGS__)
#define OBN_WARN(...)  OBN_LOG_IMPL(::obn::log::LVL_WARN,  __VA_ARGS__)
#define OBN_ERROR(...) OBN_LOG_IMPL(::obn::log::LVL_ERROR, __VA_ARGS__)
