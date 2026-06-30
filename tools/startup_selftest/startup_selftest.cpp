// startup_selftest.cpp — headless reproduction of OrcaSlicer's network-plugin
// startup handshake, used to isolate the Windows agent-startup heap corruption
// (exception 0xc0000374) without needing the OrcaSlicer GUI/GL stack.
//
// WHY THIS EXISTS
//   The plugin loads + creates the agent fine, but Studio crashes with a heap
//   corruption around set_config_dir()/set_cert_file()/start(). The Bambu
//   plugin ABI passes std::string BY VALUE across the DLL boundary (the host
//   allocates the string, the plugin's CRT destroys it), so the failing call
//   MUST be reproduced with an MSVC-built exe that uses the EXACT same
//   std::string ABI as the DLL. A C-only LoadLibrary harness would not.
//
//   This file is therefore deliberately tiny and self-contained, and is built
//   in the SAME CMake/preset/toolchain as bambu_networking.dll (/MD, same
//   MSVC STL) so its std::string layout matches the DLL byte-for-byte.
//
// WHAT IT DOES
//   LoadLibraryW(argv[1]) the plugin DLL, GetProcAddress every startup symbol
//   exactly as src/slic3r/Utils/BBLNetworkPlugin.cpp does, then replay
//   OrcaSlicer's exact GUI_App startup sequence
//   (see GUI_App::on_init_network_done / load_networking_plugin):
//
//     get_version()
//     create_agent(log_dir)
//     set_config_dir(config_dir)
//     init_log(agent)
//     set_cert_file(cert_folder, "slicer_base64.cer")
//     set_country_code("US")
//     start(agent)
//     Sleep(4000)            // let any background startup threads run/crash
//     destroy_agent(agent)
//
//   A flushed printf is emitted BEFORE and AFTER every ABI call, so when the
//   process dies the last ">>" line printed names the call that corrupted the
//   heap (or the call after which the corruption was detected). Under Wine +
//   page-heap / Application Verifier this faults at the exact instruction.
//
// USAGE
//   startup_selftest.exe <path-to-bambu_networking.dll> <config_dir> [cert_folder]
//
//   The typedefs below are copied verbatim from the host header
//   src/slic3r/Utils/BBLNetworkPlugin.hpp so the std::string-by-value contract
//   is identical to what OrcaSlicer compiles against.

#include <windows.h>

#include <cstdio>
#include <string>

// ---------------------------------------------------------------------------
// Host ABI typedefs — copied verbatim from
// OrcaSlicer/src/slic3r/Utils/BBLNetworkPlugin.hpp (lines 24-31). std::string
// is passed BY VALUE on purpose: that is the boundary we are stress-testing.
// ---------------------------------------------------------------------------
typedef std::string (*func_get_version)(void);
typedef void* (*func_create_agent)(std::string log_dir);
typedef int   (*func_destroy_agent)(void* agent);
typedef int   (*func_init_log)(void* agent);
typedef int   (*func_set_config_dir)(void* agent, std::string config_dir);
typedef int   (*func_set_cert_file)(void* agent, std::string folder, std::string filename);
typedef int   (*func_set_country_code)(void* agent, std::string country_code);
typedef int   (*func_start)(void* agent);

namespace {

void log_line(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

// Resolve a symbol or abort loudly — a missing startup symbol is itself a
// fatal ABI problem worth reporting distinctly from a crash.
template <class T>
T resolve(HMODULE mod, const char* name)
{
    FARPROC p = ::GetProcAddress(mod, name);
    if (!p) {
        log_line("FATAL: GetProcAddress(%s) failed (err=%lu)", name, ::GetLastError());
        std::exit(2);
    }
    return reinterpret_cast<T>(p);
}

// Convert a narrow argv path to wide for LoadLibraryW. ASCII paths only
// (test harness; the CI passes simple build-dir paths).
std::wstring widen(const char* s)
{
    std::wstring w;
    for (const char* p = s; p && *p; ++p)
        w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*p)));
    return w;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::printf("usage: %s <bambu_networking.dll> <config_dir> [cert_folder]\n",
                    argc > 0 ? argv[0] : "startup_selftest");
        return 1;
    }

    const std::string dll_path    = argv[1];
    const std::string config_dir  = argv[2];
    const std::string cert_folder = (argc >= 4) ? argv[3] : std::string{};
    // OrcaSlicer hands create_agent() the data-dir; reuse config_dir as the
    // log dir here so we exercise the same long-path std::string traffic.
    const std::string log_dir     = config_dir;

    log_line(">> LoadLibraryW(%s)", dll_path.c_str());
    HMODULE mod = ::LoadLibraryW(widen(dll_path.c_str()).c_str());
    if (!mod) {
        log_line("FATAL: LoadLibraryW failed (err=%lu)", ::GetLastError());
        return 2;
    }
    log_line("<< LoadLibraryW ok");

    auto get_version      = resolve<func_get_version>     (mod, "bambu_network_get_version");
    auto create_agent     = resolve<func_create_agent>    (mod, "bambu_network_create_agent");
    auto set_config_dir   = resolve<func_set_config_dir>  (mod, "bambu_network_set_config_dir");
    auto init_log         = resolve<func_init_log>        (mod, "bambu_network_init_log");
    auto set_cert_file    = resolve<func_set_cert_file>   (mod, "bambu_network_set_cert_file");
    auto set_country_code = resolve<func_set_country_code>(mod, "bambu_network_set_country_code");
    auto start            = resolve<func_start>           (mod, "bambu_network_start");
    auto destroy_agent    = resolve<func_destroy_agent>   (mod, "bambu_network_destroy_agent");

    // get_version() returns std::string BY VALUE (plugin allocates, host frees).
    log_line(">> get_version()");
    {
        std::string ver = get_version();
        log_line("<< get_version() = \"%s\"", ver.c_str());
    }

    log_line(">> create_agent(\"%s\")", log_dir.c_str());
    void* agent = create_agent(log_dir);
    log_line("<< create_agent() = %p", agent);
    if (!agent) {
        log_line("FATAL: create_agent returned null");
        return 3;
    }

    log_line(">> set_config_dir(\"%s\")", config_dir.c_str());
    int rc = set_config_dir(agent, config_dir);
    log_line("<< set_config_dir() = %d", rc);

    log_line(">> init_log()");
    rc = init_log(agent);
    log_line("<< init_log() = %d", rc);

    log_line(">> set_cert_file(\"%s\", \"slicer_base64.cer\")", cert_folder.c_str());
    rc = set_cert_file(agent, cert_folder, std::string("slicer_base64.cer"));
    log_line("<< set_cert_file() = %d", rc);

    log_line(">> set_country_code(\"US\")");
    rc = set_country_code(agent, std::string("US"));
    log_line("<< set_country_code() = %d", rc);

    log_line(">> start()");
    rc = start(agent);
    log_line("<< start() = %d", rc);

    // Give any background startup threads (cloud MQTT, discovery) time to run
    // and trip a heap check, mirroring how the Studio crash surfaces shortly
    // after start() rather than synchronously inside it.
    log_line(">> Sleep(4000)");
    ::Sleep(4000);
    log_line("<< Sleep done");

    log_line(">> destroy_agent(%p)", agent);
    destroy_agent(agent);
    log_line("<< destroy_agent done");

    log_line(">> FreeLibrary");
    ::FreeLibrary(mod);

    log_line("DONE: startup self-test completed cleanly");
    return 0;
}
