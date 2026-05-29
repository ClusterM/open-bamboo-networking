#include "obn/log.hpp"

#include "obn/build_identity.hpp"
#include "obn/config.hpp"
#include "obn/os_compat.hpp"

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>

namespace obn::log {

namespace {

struct State {
    std::mutex mu;
    FILE*      fp          = nullptr;
    bool       echo_stderr = true;
    bool       explicit_path = false; // OBN_LOG_FILE set by user
    bool       want_data_dir_file = false; // OBN_LOG_TO_FILE or log_to_file
    Level      level       = LVL_INFO;
    bool       initialized = false;
    bool       config_applied = false;
};

State& state()
{
    static State s;
    return s;
}

// Non-empty truthy value enables <log_dir>/obn.log unless explicitly false.
static bool env_wants_default_file(const char* v)
{
    if (!v || !*v) return false;
    if (v[0] == '0' && v[1] == '\0') return false;
    if (!obn::os::strcasecmp_portable(v, "false") ||
        !obn::os::strcasecmp_portable(v, "no")    ||
        !obn::os::strcasecmp_portable(v, "off"))
        return false;
    return true;
}

Level parse_level(const char* s)
{
    if (!s || !*s) return LVL_INFO;
    if (!obn::os::strcasecmp_portable(s, "trace")) return LVL_TRACE;
    if (!obn::os::strcasecmp_portable(s, "debug")) return LVL_DEBUG;
    if (!obn::os::strcasecmp_portable(s, "info"))  return LVL_INFO;
    if (!obn::os::strcasecmp_portable(s, "warn"))  return LVL_WARN;
    if (!obn::os::strcasecmp_portable(s, "warning")) return LVL_WARN;
    if (!obn::os::strcasecmp_portable(s, "error")) return LVL_ERROR;
    if (!obn::os::strcasecmp_portable(s, "off"))   return LVL_OFF;
    return LVL_INFO;
}

const char* level_name(Level l)
{
    switch (l) {
    case LVL_TRACE: return "TRC";
    case LVL_DEBUG: return "DBG";
    case LVL_INFO:  return "INF";
    case LVL_WARN:  return "WRN";
    case LVL_ERROR: return "ERR";
    default:        return "OFF";
    }
}

// Must be called with State::mu held.
void open_file_locked(State& s, const std::string& path)
{
    if (s.fp && s.fp != stderr) std::fclose(s.fp);
    s.fp = std::fopen(path.c_str(), "a");
    if (s.fp) {
        // _IOLBF combined with a NULL buffer is rejected by the MSVC CRT
        // (FAST_FAIL_INVALID_ARG); _IONBF is the portable way to get
        // immediate flushing without supplying our own buffer.
        std::setvbuf(s.fp, nullptr, _IONBF, 0);
    }
}

void ensure_initialized_locked(State& s)
{
    if (s.initialized) return;
    s.initialized = true;

    if (const char* lv = std::getenv("OBN_LOG_LEVEL"))
        s.level = parse_level(lv);

    if (const char* e = std::getenv("OBN_LOG_STDERR"))
        s.echo_stderr = !(e[0] == '0' && e[1] == '\0');

    if (const char* tf = std::getenv("OBN_LOG_TO_FILE"))
        s.want_data_dir_file = env_wants_default_file(tf);

    if (const char* p = std::getenv("OBN_LOG_FILE")) {
        s.explicit_path = true;
        if (*p) open_file_locked(s, p);
        // Empty OBN_LOG_FILE => explicit_path only: stderr-only unless user
        // enables OBN_LOG_TO_FILE from configure_from_log_dir (blocked below).
    }
    // No default file: logs go to stderr only unless OBN_LOG_FILE,
    // OBN_LOG_TO_FILE / log_to_file (see configure_from_log_dir), or tests
    // set a path.
}

// Must be called with State::mu held, and only outside the dynamic loader lock.
void write_load_banner_to_file_locked(State& s)
{
    static bool file_done = false;
    if (file_done || !s.fp || s.fp == stderr) return;
    std::fputs(OBN_PLUGIN_LOAD_BANNER_MSG, s.fp);
    std::fputc('\n', s.fp);
    std::fflush(s.fp);
    file_done = true;
}

long tid()
{
    return obn::os::thread_id();
}

void format_timestamp(char* buf, std::size_t n)
{
    using namespace std::chrono;
    auto        now  = system_clock::now();
    auto        tt   = system_clock::to_time_t(now);
    auto        us   = duration_cast<microseconds>(now.time_since_epoch()).count() % 1'000'000;
    std::tm     tm{};
    obn::os::localtime_safe(tt, &tm);
    std::snprintf(buf, n, "%04d-%02d-%02d %02d:%02d:%02d.%06lld",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec,
                  static_cast<long long>(us));
}

} // namespace

void apply_config(const obn::config::Settings& cfg)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mu);
    if (s.config_applied) return;
    s.config_applied = true;

    if (!std::getenv("OBN_LOG_LEVEL") && !cfg.log_level.empty())
        s.level = parse_level(cfg.log_level.c_str());

    if (!std::getenv("OBN_LOG_STDERR") && !cfg.log_stderr.empty())
        s.echo_stderr = env_wants_default_file(cfg.log_stderr.c_str());

    if (!std::getenv("OBN_LOG_TO_FILE") && !cfg.log_to_file.empty())
        s.want_data_dir_file = env_wants_default_file(cfg.log_to_file.c_str());

    if (!std::getenv("OBN_LOG_FILE") && !cfg.log_file.empty()) {
        s.explicit_path = true;
        open_file_locked(s, cfg.log_file);
    }
}

void configure_from_log_dir(const std::string& log_dir)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mu);
    ensure_initialized_locked(s);
    if (s.explicit_path || log_dir.empty()) return;
    if (!s.want_data_dir_file) return;
    std::string path = log_dir;
    // Tolerate either separator: log_dir comes from Studio (Windows uses
    // backslashes), and trailing-slash policy is left to the caller.
    char last = path.back();
    if (last != '/' && last != '\\') path += '/';
    path += "obn.log";
    open_file_locked(s, path);
    // Note: we do not log the switch here to avoid recursion.
    write_load_banner_to_file_locked(s);
}

Level threshold()
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mu);
    ensure_initialized_locked(s);
    return s.level;
}

void emit(Level lvl, const char* file, int line, const char* func, const char* fmt, ...)
{
    auto& s = state();
    char  ts[64];
    format_timestamp(ts, sizeof(ts));

    // Format the user message into a stack buffer; fall back to heap if it
    // doesn't fit (rare).
    char  small[1024];
    char* msg     = small;
    int   msg_len = 0;
    {
        va_list ap;
        va_start(ap, fmt);
        va_list ap2;
        va_copy(ap2, ap);
        msg_len = std::vsnprintf(small, sizeof(small), fmt, ap);
        va_end(ap);
        if (msg_len >= static_cast<int>(sizeof(small))) {
            msg = static_cast<char*>(std::malloc(msg_len + 1));
            if (msg) std::vsnprintf(msg, msg_len + 1, fmt, ap2);
            else     msg = small;
        }
        va_end(ap2);
    }

    // File location: trim to basename to keep lines short.
    const char* base = file;
    if (file) {
        for (const char* p = file; *p; ++p) if (*p == '/') base = p + 1;
    }

    std::lock_guard<std::mutex> lk(s.mu);
    ensure_initialized_locked(s);
    write_load_banner_to_file_locked(s);

    auto write_line = [&](FILE* f, bool obn_stderr_prefix) {
        if (!f) return;
        if (obn_stderr_prefix)
            std::fputs("[obn] ", f);
        std::fprintf(f, "%s [%3s] [%ld] %s:%d %s: %s\n",
                     ts, level_name(lvl), tid(), base, line, func, msg);
    };

    // File sink (normal case: obn.log or another path). No prefix — the
    // file is ours alone.
    if (s.fp && s.fp != stderr)
        write_line(s.fp, false);

    // Stderr: prefix every line with [obn] so it does not visually merge
    // with Bambu Studio's own logging on the same stream.
    const bool stderr_is_only_sink = (s.fp == stderr);
    if (stderr_is_only_sink) {
        write_line(stderr, true);
    } else if (s.echo_stderr) {
        write_line(stderr, true);
    }

    if (msg != small) std::free(msg);
}

std::string redact(const std::string& in, std::size_t max_chars)
{
    std::string out;
    out.reserve(std::min(in.size(), max_chars) + 3);
    for (std::size_t i = 0; i < in.size() && i < max_chars; ++i) {
        unsigned char c = static_cast<unsigned char>(in[i]);
        out.push_back((c >= 0x20 && c < 0x7f) ? static_cast<char>(c) : '.');
    }
    if (in.size() > max_chars) out += "...";
    return out;
}

} // namespace obn::log
