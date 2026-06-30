// startup_selftest.cpp — headless reproduction of OrcaSlicer's network-plugin
// startup handshake, used to isolate the Windows agent-startup heap corruption
// (exception 0xc0000374) without needing the OrcaSlicer GUI/GL stack.
//
// WHY THIS EXISTS
//   The plugin loads + creates the agent fine, but Studio crashes with a heap
//   corruption around set_config_dir()/set_cert_file()/start(). The Bambu
//   plugin ABI passes std::string / std::function / std::vector BY VALUE across
//   the DLL boundary (the host allocates, the plugin's CRT destroys), so the
//   failing path MUST be reproduced with an MSVC-built exe that uses the EXACT
//   same STL ABI as the DLL. This file is therefore built in the SAME CMake
//   build as bambu_networking.dll (/MD, same MSVC STL).
//
// WHAT IT NOW DOES (mirrors GUI_App::on_init_network as closely as possible)
//   1. LoadLibraryW the DLL, GetProcAddress every export, as Studio does.
//   2. Bring up agent #1: create_agent -> set_config_dir -> init_log ->
//      set_cert_file -> register ALL 13 callbacks -> set_user_selected_machine
//      -> set_country_code -> start. The on_server_connected callback is
//      RE-ENTRANT: from the MQTT network thread it calls back into the agent
//      (set_user_selected_machine(get_user_selected_machine())), exactly like
//      GUI_App.cpp:55,60.
//   3. Bring up agent #2 the same way (mirrors GUI_App::on_init_network ~3476:
//      a SECOND plugin agent for the "bbl" cloud service, same config dir).
//      Both agents stay alive together — both touch the plugin's GLOBAL state
//      (lan_tls g_config_dir, config::current(), mosquitto / OpenSSL global
//      init), the prime suspect for the heap corruption.
//   4. Sleep(4000) so both cloud threads run and invoke callbacks, then
//      destroy both agents.
//
//   A flushed printf ">>"/"<<" wraps every ABI call; the last line printed
//   before the process dies names the corrupting call. Under Wine + page-heap
//   / Application Verifier this faults at the exact instruction.
//
// USAGE
//   startup_selftest.exe <path-to-bambu_networking.dll> <config_dir> [cert_folder]
//
//   All typedefs below are copied verbatim from the host headers
//   src/slic3r/Utils/BBLNetworkPlugin.hpp and bambu_networking.hpp so the
//   by-value ABI is identical to what OrcaSlicer compiles against.

#include <windows.h>

#include <cstdio>
#include <functional>
#include <map>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Host ABI typedefs — copied verbatim from
// OrcaSlicer/src/slic3r/Utils/BBLNetworkPlugin.hpp. std::string / std::vector
// are passed BY VALUE on purpose: that is the boundary we are stress-testing.
// ---------------------------------------------------------------------------
typedef std::string (*func_get_version)(void);
typedef void* (*func_create_agent)(std::string log_dir);
typedef int   (*func_destroy_agent)(void* agent);
typedef int   (*func_init_log)(void* agent);
typedef int   (*func_set_config_dir)(void* agent, std::string config_dir);
typedef int   (*func_set_cert_file)(void* agent, std::string folder, std::string filename);
typedef int   (*func_set_country_code)(void* agent, std::string country_code);
typedef int   (*func_start)(void* agent);

typedef std::string (*func_get_user_selected_machine)(void* agent);
typedef int (*func_set_user_selected_machine)(void* agent, std::string dev_id);
typedef int (*func_start_subscribe)(void* agent, std::string module);
typedef int (*func_add_subscribe)(void* agent, std::vector<std::string> dev_list);

// Telemetry hooks OrcaSlicer calls at startup (GUI_App::on_init_network BBL
// section + check_track_enable): track_enable(false) then track_remove_files().
// Signatures copied verbatim from BBLNetworkPlugin.hpp:109-110.
typedef int (*func_track_enable)(void* agent, bool enable);
typedef int (*func_track_remove_files)(void* agent);

// ---------------------------------------------------------------------------
// Callback std::function typedefs — copied verbatim from the host header
// OrcaSlicer/src/slic3r/Utils/bambu_networking.hpp so the std::function-by-value
// ABI matches exactly what OrcaSlicer hands the plugin. Also defined identically
// in the plugin's include/obn/bambu_networking.hpp.
namespace BBL {
typedef std::function<void(int online_login, bool login)>                    OnUserLoginFn;
typedef std::function<void(std::string topic_str)>                           OnPrinterConnectedFn;
typedef std::function<void(int status, std::string dev_id, std::string msg)> OnLocalConnectedFn;
typedef std::function<void(int return_code, int reason_code)>                OnServerConnectedFn;
typedef std::function<void(std::string dev_id, std::string msg)>             OnMessageFn;
typedef std::function<void(unsigned http_code, std::string http_body)>       OnHttpErrorFn;
typedef std::function<std::string()>                                         GetCountryCodeFn;
typedef std::function<void(std::string topic)>                               GetSubscribeFailureFn;
typedef std::function<void(std::string dev_info_json_str)>                    OnMsgArrivedFn;
typedef std::function<void(std::function<void()>)>                           QueueOnMainFn;
typedef std::function<void(std::string url, int status)>                     OnServerErrFn;
} // namespace BBL

// Callback-registration export typedefs (mirror the plugin's OBN_CB_EXPORT
// signatures in src/abi_callbacks.cpp: int(void* agent, BBL::<Fn> fn), the
// std::function passed BY VALUE).
typedef int (*func_set_on_ssdp_msg_fn)         (void*, BBL::OnMsgArrivedFn);
typedef int (*func_set_on_user_login_fn)       (void*, BBL::OnUserLoginFn);
typedef int (*func_set_on_printer_connected_fn)(void*, BBL::OnPrinterConnectedFn);
typedef int (*func_set_on_server_connected_fn) (void*, BBL::OnServerConnectedFn);
typedef int (*func_set_on_http_error_fn)       (void*, BBL::OnHttpErrorFn);
typedef int (*func_set_get_country_code_fn)    (void*, BBL::GetCountryCodeFn);
typedef int (*func_set_on_subscribe_failure_fn)(void*, BBL::GetSubscribeFailureFn);
typedef int (*func_set_on_message_fn)          (void*, BBL::OnMessageFn);
typedef int (*func_set_on_user_message_fn)     (void*, BBL::OnMessageFn);
typedef int (*func_set_on_local_connect_fn)    (void*, BBL::OnLocalConnectedFn);
typedef int (*func_set_on_local_message_fn)    (void*, BBL::OnMessageFn);
typedef int (*func_set_queue_on_main_fn)       (void*, BBL::QueueOnMainFn);
typedef int (*func_set_server_callback)        (void*, BBL::OnServerErrFn);

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

std::wstring widen(const char* s)
{
    std::wstring w;
    for (const char* p = s; p && *p; ++p)
        w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*p)));
    return w;
}

// All plugin exports we drive, resolved once.
struct PluginApi {
    func_get_version               get_version{};
    func_create_agent              create_agent{};
    func_destroy_agent             destroy_agent{};
    func_init_log                  init_log{};
    func_set_config_dir            set_config_dir{};
    func_set_cert_file             set_cert_file{};
    func_set_country_code          set_country_code{};
    func_start                     start{};

    func_get_user_selected_machine get_user_selected_machine{};
    func_set_user_selected_machine set_user_selected_machine{};
    func_start_subscribe           start_subscribe{};
    func_add_subscribe             add_subscribe{};
    func_track_enable              track_enable{};
    func_track_remove_files        track_remove_files{};

    func_set_server_callback         set_server_callback{};
    func_set_on_server_connected_fn  set_on_server_connected{};
    func_set_on_printer_connected_fn set_on_printer_connected{};
    func_set_get_country_code_fn     set_get_country_code{};
    func_set_on_subscribe_failure_fn set_on_subscribe_failure{};
    func_set_on_local_connect_fn     set_on_local_connect{};
    func_set_on_message_fn           set_on_message{};
    func_set_on_user_message_fn      set_on_user_message{};
    func_set_on_local_message_fn     set_on_local_message{};
    func_set_on_http_error_fn        set_on_http_error{};
    func_set_on_ssdp_msg_fn          set_on_ssdp_msg{};
    func_set_on_user_login_fn        set_on_user_login{};
    func_set_queue_on_main_fn        set_queue_on_main{};
};

PluginApi resolve_all(HMODULE mod)
{
    PluginApi a;
    a.get_version               = resolve<func_get_version>              (mod, "bambu_network_get_version");
    a.create_agent              = resolve<func_create_agent>             (mod, "bambu_network_create_agent");
    a.destroy_agent             = resolve<func_destroy_agent>            (mod, "bambu_network_destroy_agent");
    a.init_log                  = resolve<func_init_log>                 (mod, "bambu_network_init_log");
    a.set_config_dir            = resolve<func_set_config_dir>           (mod, "bambu_network_set_config_dir");
    a.set_cert_file             = resolve<func_set_cert_file>            (mod, "bambu_network_set_cert_file");
    a.set_country_code          = resolve<func_set_country_code>         (mod, "bambu_network_set_country_code");
    a.start                     = resolve<func_start>                    (mod, "bambu_network_start");

    a.get_user_selected_machine = resolve<func_get_user_selected_machine>(mod, "bambu_network_get_user_selected_machine");
    a.set_user_selected_machine = resolve<func_set_user_selected_machine>(mod, "bambu_network_set_user_selected_machine");
    a.start_subscribe           = resolve<func_start_subscribe>          (mod, "bambu_network_start_subscribe");
    a.add_subscribe             = resolve<func_add_subscribe>            (mod, "bambu_network_add_subscribe");
    a.track_enable              = resolve<func_track_enable>             (mod, "bambu_network_track_enable");
    a.track_remove_files        = resolve<func_track_remove_files>       (mod, "bambu_network_track_remove_files");

    a.set_server_callback       = resolve<func_set_server_callback>        (mod, "bambu_network_set_server_callback");
    a.set_on_server_connected   = resolve<func_set_on_server_connected_fn> (mod, "bambu_network_set_on_server_connected_fn");
    a.set_on_printer_connected  = resolve<func_set_on_printer_connected_fn>(mod, "bambu_network_set_on_printer_connected_fn");
    a.set_get_country_code      = resolve<func_set_get_country_code_fn>    (mod, "bambu_network_set_get_country_code_fn");
    a.set_on_subscribe_failure  = resolve<func_set_on_subscribe_failure_fn>(mod, "bambu_network_set_on_subscribe_failure_fn");
    a.set_on_local_connect      = resolve<func_set_on_local_connect_fn>    (mod, "bambu_network_set_on_local_connect_fn");
    a.set_on_message            = resolve<func_set_on_message_fn>          (mod, "bambu_network_set_on_message_fn");
    a.set_on_user_message       = resolve<func_set_on_user_message_fn>     (mod, "bambu_network_set_on_user_message_fn");
    a.set_on_local_message      = resolve<func_set_on_local_message_fn>    (mod, "bambu_network_set_on_local_message_fn");
    a.set_on_http_error         = resolve<func_set_on_http_error_fn>       (mod, "bambu_network_set_on_http_error_fn");
    a.set_on_ssdp_msg           = resolve<func_set_on_ssdp_msg_fn>         (mod, "bambu_network_set_on_ssdp_msg_fn");
    a.set_on_user_login         = resolve<func_set_on_user_login_fn>       (mod, "bambu_network_set_on_user_login_fn");
    a.set_queue_on_main         = resolve<func_set_queue_on_main_fn>       (mod, "bambu_network_set_queue_on_main_fn");
    return a;
}

// Bring one agent through OrcaSlicer's full configure+callbacks+start sequence.
// Returns the agent handle (already started), or nullptr on failure.
void* bring_up_agent(const PluginApi& api, const char* tag,
                     const std::string& log_dir, const std::string& config_dir,
                     const std::string& cert_folder, const std::string& dev_id)
{
    log_line(">> [%s] create_agent(\"%s\")", tag, log_dir.c_str());
    void* agent = api.create_agent(log_dir);
    log_line("<< [%s] create_agent() = %p", tag, agent);
    if (!agent) {
        log_line("FATAL: [%s] create_agent returned null", tag);
        return nullptr;
    }

    log_line(">> [%s] set_config_dir(\"%s\")", tag, config_dir.c_str());
    int rc = api.set_config_dir(agent, config_dir);
    log_line("<< [%s] set_config_dir() = %d", tag, rc);

    log_line(">> [%s] init_log()", tag);
    rc = api.init_log(agent);
    log_line("<< [%s] init_log() = %d", tag, rc);

    log_line(">> [%s] set_cert_file(\"%s\", \"slicer_base64.cer\")", tag, cert_folder.c_str());
    rc = api.set_cert_file(agent, cert_folder, std::string("slicer_base64.cer"));
    log_line("<< [%s] set_cert_file() = %d", tag, rc);

    // ------------------------------------------------------------------
    // init_networking_callbacks(): register EVERY callback with real
    // lambdas. on_server_connected is RE-ENTRANT — from the MQTT network
    // thread it calls back into the agent exactly like GUI_App.cpp:55,60.
    // ------------------------------------------------------------------
    log_line(">> [%s] set_server_callback", tag);
    rc = api.set_server_callback(agent, [tag](std::string url, int status) {
        log_line("   [%s cb] server_callback url=%s status=%d", tag, url.c_str(), status);
    });
    log_line("<< [%s] set_server_callback() = %d", tag, rc);

    log_line(">> [%s] set_on_server_connected_fn", tag);
    // Capture the agent + the get/set_user_selected_machine func ptrs so the
    // callback can re-enter the agent from the network thread (the exact
    // GUI_App pattern: set_user_selected_machine(get_user_selected_machine())).
    void* agent_for_cb              = agent;
    auto  get_sel                   = api.get_user_selected_machine;
    auto  set_sel                   = api.set_user_selected_machine;
    rc = api.set_on_server_connected(agent,
        [tag, agent_for_cb, get_sel, set_sel](int return_code, int reason_code) {
            log_line("   [%s cb] on_server_connected rc=%d reason=%d (re-entering agent)",
                     tag, return_code, reason_code);
            // get_user_selected_machine returns std::string BY VALUE (plugin
            // allocates, this callback's CRT frees); then hand it straight
            // back by value. Same cross-boundary ownership transfer Studio does.
            std::string sel = get_sel(agent_for_cb);
            log_line("   [%s cb] get_user_selected_machine = \"%s\"", tag, sel.c_str());
            set_sel(agent_for_cb, sel);
            log_line("   [%s cb] set_user_selected_machine done", tag);
        });
    log_line("<< [%s] set_on_server_connected_fn() = %d", tag, rc);

    log_line(">> [%s] set_on_printer_connected_fn", tag);
    rc = api.set_on_printer_connected(agent, [tag](std::string topic) {
        log_line("   [%s cb] on_printer_connected topic=%s", tag, topic.c_str());
    });
    log_line("<< [%s] set_on_printer_connected_fn() = %d", tag, rc);

    log_line(">> [%s] set_get_country_code_fn", tag);
    rc = api.set_get_country_code(agent, [tag]() -> std::string {
        log_line("   [%s cb] get_country_code -> US", tag);
        return std::string("US");
    });
    log_line("<< [%s] set_get_country_code_fn() = %d", tag, rc);

    log_line(">> [%s] set_on_subscribe_failure_fn", tag);
    rc = api.set_on_subscribe_failure(agent, [tag](std::string topic) {
        log_line("   [%s cb] on_subscribe_failure topic=%s", tag, topic.c_str());
    });
    log_line("<< [%s] set_on_subscribe_failure_fn() = %d", tag, rc);

    log_line(">> [%s] set_on_local_connect_fn", tag);
    rc = api.set_on_local_connect(agent, [tag](int status, std::string dev_id_, std::string msg) {
        log_line("   [%s cb] on_local_connect status=%d dev=%s msg=%s",
                 tag, status, dev_id_.c_str(), msg.c_str());
    });
    log_line("<< [%s] set_on_local_connect_fn() = %d", tag, rc);

    log_line(">> [%s] set_on_message_fn", tag);
    rc = api.set_on_message(agent, [tag](std::string dev_id_, std::string msg) {
        log_line("   [%s cb] on_message dev=%s len=%zu", tag, dev_id_.c_str(), msg.size());
    });
    log_line("<< [%s] set_on_message_fn() = %d", tag, rc);

    log_line(">> [%s] set_on_user_message_fn", tag);
    rc = api.set_on_user_message(agent, [tag](std::string dev_id_, std::string msg) {
        log_line("   [%s cb] on_user_message dev=%s len=%zu", tag, dev_id_.c_str(), msg.size());
    });
    log_line("<< [%s] set_on_user_message_fn() = %d", tag, rc);

    log_line(">> [%s] set_on_local_message_fn", tag);
    rc = api.set_on_local_message(agent, [tag](std::string dev_id_, std::string msg) {
        log_line("   [%s cb] on_local_message dev=%s len=%zu", tag, dev_id_.c_str(), msg.size());
    });
    log_line("<< [%s] set_on_local_message_fn() = %d", tag, rc);

    log_line(">> [%s] set_on_http_error_fn", tag);
    rc = api.set_on_http_error(agent, [tag](unsigned http_code, std::string body) {
        log_line("   [%s cb] on_http_error code=%u len=%zu", tag, http_code, body.size());
    });
    log_line("<< [%s] set_on_http_error_fn() = %d", tag, rc);

    log_line(">> [%s] set_on_ssdp_msg_fn", tag);
    rc = api.set_on_ssdp_msg(agent, [tag](std::string dev_info_json) {
        log_line("   [%s cb] on_ssdp_msg len=%zu", tag, dev_info_json.size());
    });
    log_line("<< [%s] set_on_ssdp_msg_fn() = %d", tag, rc);

    log_line(">> [%s] set_on_user_login_fn", tag);
    rc = api.set_on_user_login(agent, [tag](int online_login, bool login) {
        log_line("   [%s cb] on_user_login online=%d login=%d", tag, online_login, (int)login);
    });
    log_line("<< [%s] set_on_user_login_fn() = %d", tag, rc);

    log_line(">> [%s] set_queue_on_main_fn", tag);
    rc = api.set_queue_on_main(agent, [tag](std::function<void()> task) {
        log_line("   [%s cb] queue_on_main (running task inline)", tag);
        if (task) task();
    });
    log_line("<< [%s] set_queue_on_main_fn() = %d", tag, rc);

    // Device selection, mirroring Studio: set the selected machine before
    // start so connect_cloud has a device to subscribe to.
    log_line(">> [%s] set_user_selected_machine(\"%s\")", tag, dev_id.c_str());
    rc = api.set_user_selected_machine(agent, dev_id);
    log_line("<< [%s] set_user_selected_machine() = %d", tag, rc);

    log_line(">> [%s] set_country_code(\"US\")", tag);
    rc = api.set_country_code(agent, std::string("US"));
    log_line("<< [%s] set_country_code() = %d", tag, rc);

    // Telemetry hooks, in OrcaSlicer's on_init_network order (GUI_App.cpp
    // ~3491 BBL section + check_track_enable): track_enable(false) then
    // track_remove_files(), before start().
    log_line(">> [%s] track_enable(false)", tag);
    rc = api.track_enable(agent, false);
    log_line("<< [%s] track_enable() = %d", tag, rc);

    log_line(">> [%s] track_remove_files()", tag);
    rc = api.track_remove_files(agent);
    log_line("<< [%s] track_remove_files() = %d", tag, rc);

    log_line(">> [%s] start()", tag);
    rc = api.start(agent);
    log_line("<< [%s] start() = %d", tag, rc);

    // Mirror device subscription: start_subscribe(std::string) + add_subscribe
    // (std::vector<std::string> BY VALUE — another container ABI surface).
    log_line(">> [%s] start_subscribe(\"app\")", tag);
    rc = api.start_subscribe(agent, std::string("app"));
    log_line("<< [%s] start_subscribe() = %d", tag, rc);

    if (!dev_id.empty()) {
        std::vector<std::string> dev_list;
        dev_list.push_back(dev_id);
        log_line(">> [%s] add_subscribe([1 dev])", tag);
        rc = api.add_subscribe(agent, dev_list);
        log_line("<< [%s] add_subscribe() = %d", tag, rc);
    }

    return agent;
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
    // A plausible Bambu device id for set_user_selected_machine / add_subscribe.
    const std::string dev_id      = "00M00A1234567890";

    log_line(">> LoadLibraryW(%s)", dll_path.c_str());
    HMODULE mod = ::LoadLibraryW(widen(dll_path.c_str()).c_str());
    if (!mod) {
        log_line("FATAL: LoadLibraryW failed (err=%lu)", ::GetLastError());
        return 2;
    }
    log_line("<< LoadLibraryW ok");

    const PluginApi api = resolve_all(mod);

    // get_version() returns std::string BY VALUE (plugin allocates, host frees).
    log_line(">> get_version()");
    {
        std::string ver = api.get_version();
        log_line("<< get_version() = \"%s\"", ver.c_str());
    }

    // ---- Agent #1 (mirrors GUI_App m_agent / Orca cloud agent) ------------
    void* agent1 = bring_up_agent(api, "A1", log_dir, config_dir, cert_folder, dev_id);
    if (!agent1) { ::FreeLibrary(mod); return 3; }

    // ---- Agent #2 (mirrors GUI_App::on_init_network ~3476: a SECOND plugin
    //      agent created for the "bbl" cloud service, SAME config dir, kept
    //      alive concurrently). Both agents now share the plugin's GLOBAL
    //      state (lan_tls g_config_dir, config::current(), mosquitto/OpenSSL
    //      global init) — the prime suspect for the heap corruption.
    void* agent2 = bring_up_agent(api, "A2", log_dir, config_dir, cert_folder, dev_id);
    // Not fatal if the second agent fails to come up — keep going so we can
    // still observe / clean up agent1.

    // Both agents alive together: let both cloud threads run and invoke the
    // (re-entrant) callbacks, mirroring how Studio's crash surfaces shortly
    // after start() rather than synchronously inside it.
    log_line(">> Sleep(4000) with both agents alive");
    ::Sleep(4000);
    log_line("<< Sleep done");

    if (agent2) {
        log_line(">> [A2] destroy_agent(%p)", agent2);
        api.destroy_agent(agent2);
        log_line("<< [A2] destroy_agent done");
    }

    log_line(">> [A1] destroy_agent(%p)", agent1);
    api.destroy_agent(agent1);
    log_line("<< [A1] destroy_agent done");

    log_line(">> FreeLibrary");
    ::FreeLibrary(mod);

    log_line("DONE: startup self-test completed cleanly");
    return 0;
}
