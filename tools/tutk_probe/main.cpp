// tutk_probe: open a bambu:/// camera URL through a libBambuSource.so and
// count the video samples it delivers. Pairs with
// `plugin_runner --action camera_url --camera-url-out FILE`, which mints the
// URL through a networking plugin (stock or ours) without Studio.
//
// The call sequence mirrors Studio's gstbambusrc: Create -> SetLogger ->
// Open -> StartStream(video) while would_block -> GetStreamCount/Info ->
// ReadSample loop. The URL carries TUTK credentials, so it is read from a
// file (never argv) and only printed with every query value masked.

#include <dlfcn.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

extern "C" {
typedef void* Bambu_Tunnel;

enum Bambu_Error { Bambu_success = 0, Bambu_stream_end, Bambu_would_block, Bambu_buffer_limit };

struct Bambu_StreamInfo {
    int type;
    int sub_type;
    union {
        struct { int width; int height; int frame_rate; } video;
        struct { int sample_rate; int channel_count; int sample_size; } audio;
    } format;
    int                  format_type;
    int                  format_size;
    int                  max_frame_size;
    unsigned char const* format_buffer;
};

struct Bambu_Sample {
    int                  itrack;
    int                  size;
    int                  flags;
    unsigned char const* buffer;
    unsigned long long   decode_time;
};

using Logger = void (*)(void* context, int level, char const* msg);
}

using fn_init             = int (*)();
using fn_create           = int (*)(Bambu_Tunnel*, char const*);
using fn_set_logger       = void (*)(Bambu_Tunnel, Logger, void*);
using fn_open             = int (*)(Bambu_Tunnel);
using fn_start_stream     = int (*)(Bambu_Tunnel, bool);
using fn_start_stream_ex  = int (*)(Bambu_Tunnel, int);
using fn_send_message     = int (*)(Bambu_Tunnel, int, char const*, int);
using fn_get_stream_count = int (*)(Bambu_Tunnel);
using fn_get_stream_info  = int (*)(Bambu_Tunnel, int, Bambu_StreamInfo*);
using fn_read_sample      = int (*)(Bambu_Tunnel, Bambu_Sample*);
using fn_close            = void (*)(Bambu_Tunnel);
using fn_destroy          = void (*)(Bambu_Tunnel);
using fn_last_error       = char const* (*)();
using fn_free_log_msg     = void (*)(char const*);

struct Api {
    fn_init             init             = nullptr;
    fn_create           create           = nullptr;
    fn_set_logger       set_logger       = nullptr;
    fn_open             open             = nullptr;
    fn_start_stream     start_stream     = nullptr;
    fn_start_stream_ex  start_stream_ex  = nullptr;
    fn_send_message     send_message     = nullptr;
    fn_get_stream_count get_stream_count = nullptr;
    fn_get_stream_info  get_stream_info  = nullptr;
    fn_read_sample      read_sample      = nullptr;
    fn_close            close            = nullptr;
    fn_destroy          destroy          = nullptr;
    fn_last_error       last_error       = nullptr;
    fn_free_log_msg     free_log_msg     = nullptr;
};

Api  g_api;
bool g_quiet_lib = false;
auto g_t0 = std::chrono::steady_clock::now();

long long ms_since_start()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - g_t0).count();
}

void lib_log(void* /*ctx*/, int level, char const* msg)
{
    if (!msg) return;
    if (!g_quiet_lib) std::fprintf(stderr, "[%6lld ms] lib[%d] %s\n", ms_since_start(), level, msg);
    if (g_api.free_log_msg) g_api.free_log_msg(msg);
}

std::string mask_url(const std::string& url)
{
    const auto q = url.find('?');
    if (q == std::string::npos) return url;
    std::string out = url.substr(0, q + 1);
    std::stringstream ss(url.substr(q + 1));
    std::string kv;
    bool first = true;
    while (std::getline(ss, kv, '&')) {
        if (!first) out += '&';
        first = false;
        const auto eq = kv.find('=');
        if (eq == std::string::npos) { out += kv; continue; }
        const std::string v = kv.substr(eq + 1);
        out += kv.substr(0, eq + 1);
        if (v.size() <= 3) out += v;
        else out += v.substr(0, 3) + "***(" + std::to_string(v.size()) + ")";
    }
    return out;
}

template <typename T>
T sym(void* h, const char* name, bool required)
{
    void* p = dlsym(h, name);
    if (!p && required) {
        std::fprintf(stderr, "tutk_probe: missing symbol %s\n", name);
        std::exit(2);
    }
    return reinterpret_cast<T>(p);
}

[[noreturn]] void usage(int rc)
{
    std::fputs(
R"(usage: tutk_probe --url-file PATH|- [--lib PATH] [--seconds N]
                  [--device SERIAL] [--dev-ver VER] [--net-ver VER]
                  [--cli-id ID] [--cli-ver VER] [--dump PATH]
                  [--no-init] [--quiet-lib] [--ctrl JSON]...

  --url-file  file with the bambu:/// URL on its first line ('-' = stdin)
  --lib       libBambuSource.so to load
              (default: ~/.config/BambuStudio/plugins/libBambuSource.so)
  --seconds   how long to read samples after the stream starts (default 10)
  --device/--dev-ver/--net-ver/--cli-id/--cli-ver
              appended as &device=...&net_ver=... the way MediaPlayCtrl does
              before handing the URL to the source
  --dump      write raw sample payloads to PATH (inspect with ffprobe)
  --no-init   do not call Bambu_Init even if exported
  --quiet-lib do not print the library's own log lines
  --ctrl      file-browser mode: open the CTRL channel the way Studio's
              PrinterFileSystem does (StartStreamEx 0x3001) and send JSON
              as one request {"cmdtype":..,"req":{..}}; "sequence" is added.
              Repeatable. Replies are printed until --seconds elapse.
)", stderr);
    std::exit(rc);
}

constexpr int kCtrlType = 0x3001;

// Prints the JSON head of a CTRL reply and the size of any binary tail
// (PrinterFileSystem splits them at the first "\n\n").
void print_ctrl_reply(const Bambu_Sample& s)
{
    const std::string all(reinterpret_cast<const char*>(s.buffer),
                          static_cast<std::size_t>(s.size));
    const auto sep = all.find("\n\n");
    const std::string head = all.substr(0, sep);
    const std::size_t tail = sep == std::string::npos ? 0 : all.size() - sep - 2;
    std::fprintf(stderr, "[%6lld ms] <<< %s%s\n", ms_since_start(),
                 head.substr(0, 2000).c_str(), head.size() > 2000 ? "..." : "");
    if (tail) std::fprintf(stderr, "             (+%zu binary bytes)\n", tail);
}

template <typename LastError>
int run_ctrl(Bambu_Tunnel tnl, const std::vector<std::string>& reqs, int seconds,
             LastError last_error)
{
    if (!g_api.start_stream_ex || !g_api.send_message) {
        std::fprintf(stderr, "tutk_probe: library lacks StartStreamEx/SendMessage\n");
        return 2;
    }
    int rc;
    const auto start_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    do {
        rc = g_api.start_stream_ex(tnl, kCtrlType);
        if (rc != Bambu_would_block) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } while (std::chrono::steady_clock::now() < start_deadline);
    std::fprintf(stderr, "[%6lld ms] Bambu_StartStreamEx(CTRL) rc=%d %s\n",
                 ms_since_start(), rc, last_error().c_str());
    if (rc != Bambu_success) {
        std::printf("{\"ok\":false,\"stage\":\"start_stream_ex\",\"rc\":%d}\n", rc);
        g_api.close(tnl);
        g_api.destroy(tnl);
        return 1;
    }

    int seq = 0;
    for (const auto& r : reqs) {
        std::string msg = r;
        const auto brace = msg.find('{');
        if (brace != std::string::npos && msg.find("\"sequence\"") == std::string::npos)
            msg.insert(brace + 1, "\"sequence\":" + std::to_string(seq) + ",");
        ++seq;
        std::fprintf(stderr, "[%6lld ms] >>> %s\n", ms_since_start(), msg.c_str());
        rc = g_api.send_message(tnl, kCtrlType, msg.data(), static_cast<int>(msg.size()));
        if (rc != Bambu_success)
            std::fprintf(stderr, "tutk_probe: SendMessage rc=%d %s\n", rc, last_error().c_str());
    }

    int replies = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    while (std::chrono::steady_clock::now() < deadline) {
        Bambu_Sample s{};
        rc = g_api.read_sample(tnl, &s);
        if (rc == Bambu_would_block) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            continue;
        }
        if (rc != Bambu_success) {
            std::fprintf(stderr, "[%6lld ms] ReadSample rc=%d %s\n", ms_since_start(), rc,
                         last_error().c_str());
            break;
        }
        ++replies;
        if (s.buffer && s.size > 0) print_ctrl_reply(s);
    }
    g_api.close(tnl);
    g_api.destroy(tnl);
    std::printf("{\"ok\":%s,\"replies\":%d,\"last_rc\":%d}\n", replies > 0 ? "true" : "false",
                replies, rc);
    return replies > 0 ? 0 : 1;
}

} // namespace

int main(int argc, char** argv)
{
    std::string lib;
    std::string url_file;
    std::string dump_path;
    std::string device, dev_ver, net_ver, cli_id, cli_ver;
    std::vector<std::string> ctrl_reqs;
    int  seconds = 10;
    bool do_init = true;

    for (int i = 1; i < argc; ++i) {
        const std::string f = argv[i];
        auto val = [&]() -> std::string {
            if (i + 1 >= argc) usage(64);
            return argv[++i];
        };
        if      (f == "--lib")        lib = val();
        else if (f == "--url-file")   url_file = val();
        else if (f == "--seconds")    seconds = std::atoi(val().c_str());
        else if (f == "--device")     device = val();
        else if (f == "--dev-ver")    dev_ver = val();
        else if (f == "--net-ver")    net_ver = val();
        else if (f == "--cli-id")     cli_id = val();
        else if (f == "--cli-ver")    cli_ver = val();
        else if (f == "--dump")       dump_path = val();
        else if (f == "--no-init")    do_init = false;
        else if (f == "--quiet-lib")  g_quiet_lib = true;
        else if (f == "--ctrl")       ctrl_reqs.push_back(val());
        else if (f == "-h" || f == "--help") usage(0);
        else {
            std::fprintf(stderr, "tutk_probe: unknown flag '%s'\n", f.c_str());
            usage(64);
        }
    }
    if (url_file.empty()) usage(64);
    if (lib.empty()) {
        const char* home = std::getenv("HOME");
        lib = std::string(home ? home : "") + "/.config/BambuStudio/plugins/libBambuSource.so";
    }

    std::string url;
    if (url_file == "-") {
        std::getline(std::cin, url);
    } else {
        std::ifstream in(url_file);
        if (!in) {
            std::fprintf(stderr, "tutk_probe: cannot read %s\n", url_file.c_str());
            return 2;
        }
        std::getline(in, url);
    }
    while (!url.empty() && (url.back() == '\r' || url.back() == '\n' || url.back() == ' '))
        url.pop_back();
    if (url.rfind("bambu:///", 0) != 0) {
        std::fprintf(stderr, "tutk_probe: URL does not start with bambu:/// (%s)\n",
                     mask_url(url).c_str());
        return 2;
    }
    if (!device.empty())  url += "&device=" + device;
    if (!net_ver.empty()) url += "&net_ver=" + net_ver;
    if (!dev_ver.empty()) url += "&dev_ver=" + dev_ver;
    if (!cli_id.empty())  url += "&cli_id=" + cli_id;
    if (!cli_ver.empty()) url += "&cli_ver=" + cli_ver;

    void* h = dlopen(lib.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        std::fprintf(stderr, "tutk_probe: dlopen %s: %s\n", lib.c_str(), dlerror());
        return 2;
    }
    g_api.init             = sym<fn_init>(h, "Bambu_Init", false);
    g_api.create           = sym<fn_create>(h, "Bambu_Create", true);
    g_api.set_logger       = sym<fn_set_logger>(h, "Bambu_SetLogger", true);
    g_api.open             = sym<fn_open>(h, "Bambu_Open", true);
    g_api.start_stream     = sym<fn_start_stream>(h, "Bambu_StartStream", true);
    g_api.start_stream_ex  = sym<fn_start_stream_ex>(h, "Bambu_StartStreamEx", false);
    g_api.send_message     = sym<fn_send_message>(h, "Bambu_SendMessage", false);
    g_api.get_stream_count = sym<fn_get_stream_count>(h, "Bambu_GetStreamCount", true);
    g_api.get_stream_info  = sym<fn_get_stream_info>(h, "Bambu_GetStreamInfo", true);
    g_api.read_sample      = sym<fn_read_sample>(h, "Bambu_ReadSample", true);
    g_api.close            = sym<fn_close>(h, "Bambu_Close", true);
    g_api.destroy          = sym<fn_destroy>(h, "Bambu_Destroy", true);
    g_api.last_error       = sym<fn_last_error>(h, "Bambu_GetLastErrorMsg", false);
    g_api.free_log_msg     = sym<fn_free_log_msg>(h, "Bambu_FreeLogMsg", false);

    auto last_error = [] {
        const char* e = g_api.last_error ? g_api.last_error() : nullptr;
        return std::string(e ? e : "");
    };

    std::fprintf(stderr, "tutk_probe: lib=%s\n", lib.c_str());
    std::fprintf(stderr, "tutk_probe: url=%s\n", mask_url(url).c_str());

    g_t0 = std::chrono::steady_clock::now();
    if (do_init && g_api.init) {
        int rc = g_api.init();
        std::fprintf(stderr, "[%6lld ms] Bambu_Init rc=%d\n", ms_since_start(), rc);
    }

    Bambu_Tunnel tnl = nullptr;
    int rc = g_api.create(&tnl, url.c_str());
    std::fprintf(stderr, "[%6lld ms] Bambu_Create rc=%d\n", ms_since_start(), rc);
    if (rc != Bambu_success || !tnl) {
        std::printf("{\"ok\":false,\"stage\":\"create\",\"rc\":%d}\n", rc);
        return 1;
    }
    g_api.set_logger(tnl, lib_log, nullptr);

    rc = g_api.open(tnl);
    const long long open_ms = ms_since_start();
    std::fprintf(stderr, "[%6lld ms] Bambu_Open rc=%d %s\n", open_ms, rc, last_error().c_str());
    if (rc != Bambu_success && rc != Bambu_would_block) {
        std::printf("{\"ok\":false,\"stage\":\"open\",\"rc\":%d,\"open_ms\":%lld}\n", rc, open_ms);
        g_api.destroy(tnl);
        return 1;
    }

    if (!ctrl_reqs.empty())
        return run_ctrl(tnl, ctrl_reqs, seconds, last_error);

    const auto start_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    do {
        rc = g_api.start_stream(tnl, true);
        if (rc != Bambu_would_block) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } while (std::chrono::steady_clock::now() < start_deadline);
    const long long stream_ms = ms_since_start();
    std::fprintf(stderr, "[%6lld ms] Bambu_StartStream rc=%d %s\n", stream_ms, rc,
                 last_error().c_str());
    if (rc != Bambu_success) {
        std::printf("{\"ok\":false,\"stage\":\"start_stream\",\"rc\":%d,\"open_ms\":%lld,"
                    "\"stream_ms\":%lld}\n", rc, open_ms, stream_ms);
        g_api.close(tnl);
        g_api.destroy(tnl);
        return 1;
    }

    const int nstreams = g_api.get_stream_count(tnl);
    int width = 0, height = 0, fps = 0, format_type = -1, sub_type = -1;
    for (int i = 0; i < nstreams; ++i) {
        Bambu_StreamInfo info{};
        if (g_api.get_stream_info(tnl, i, &info) != Bambu_success) continue;
        std::fprintf(stderr, "stream[%d] type=%d sub_type=%d %dx%d@%d format_type=%d "
                     "format_size=%d max_frame=%d\n", i, info.type, info.sub_type,
                     info.format.video.width, info.format.video.height,
                     info.format.video.frame_rate, info.format_type, info.format_size,
                     info.max_frame_size);
        if (info.type == 0 && width == 0) {
            width       = info.format.video.width;
            height      = info.format.video.height;
            fps         = info.format.video.frame_rate;
            format_type = info.format_type;
            sub_type    = info.sub_type;
        }
    }

    FILE* dump = nullptr;
    if (!dump_path.empty()) dump = std::fopen(dump_path.c_str(), "wb");

    long long samples = 0, bytes = 0, first_sample_ms = -1, keyframes = 0;
    int last_rc = Bambu_success;
    const auto read_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    while (std::chrono::steady_clock::now() < read_deadline) {
        Bambu_Sample s{};
        last_rc = g_api.read_sample(tnl, &s);
        if (last_rc == Bambu_would_block || last_rc == Bambu_buffer_limit) {
            std::this_thread::sleep_for(std::chrono::milliseconds(33));
            continue;
        }
        if (last_rc != Bambu_success) break;
        if (first_sample_ms < 0) first_sample_ms = ms_since_start();
        ++samples;
        bytes += s.size;
        if (s.flags & 1) ++keyframes;
        if (dump && s.buffer && s.size > 0) std::fwrite(s.buffer, 1, s.size, dump);
    }
    if (dump) std::fclose(dump);
    const long long end_ms = ms_since_start();

    g_api.close(tnl);
    g_api.destroy(tnl);

    const double secs = first_sample_ms >= 0 ? (end_ms - first_sample_ms) / 1000.0 : 0.0;
    std::printf("{\"ok\":%s,\"open_ms\":%lld,\"stream_ms\":%lld,\"first_sample_ms\":%lld,"
                "\"streams\":%d,\"width\":%d,\"height\":%d,\"fps_hint\":%d,"
                "\"format_type\":%d,\"sub_type\":%d,\"samples\":%lld,\"keyframes\":%lld,"
                "\"bytes\":%lld,\"measured_fps\":%.1f,\"last_rc\":%d}\n",
                samples > 0 ? "true" : "false", open_ms, stream_ms, first_sample_ms,
                nstreams, width, height, fps, format_type, sub_type, samples, keyframes,
                bytes, secs > 0 ? samples / secs : 0.0, last_rc);
    return samples > 0 ? 0 : 1;
}
