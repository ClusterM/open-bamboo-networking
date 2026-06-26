#pragma once
#include <string>
#include <sys/types.h>

// Globals set by main(), used in daemon grandchild and setup_h2s_home.
// Defined in daemon.cpp.
extern std::string g_connect_redirect_so_path;
extern int g_fake_printer_port;
extern std::string g_plugin_path_for_home;

// Probe local plugin paths; returns path or empty.
std::string probe_plugin_path();

// Download plugin from Bambu CDN if not cached; returns path or empty.
std::string download_plugin_if_needed();

// Locate slicer cert and write it to a tmpdir; returns tmpdir path or empty.
// cert_override: explicit path (from --cert); empty = auto-search relative to plugin.
std::string write_cert_tmpdir(pid_t pid, const std::string& plugin_path,
                               const std::string& cert_override = {});

// Write daemon binary to a memfd; returns "/proc/self/fd/<n>" or empty.
std::string write_daemon_memfd();

// Set up the H2S home directory; returns home path or empty.
std::string setup_h2s_home(const std::string& dev_id);

// Launch the bridge daemon; returns PID or -1.
pid_t launch_daemon(const std::string& daemon_exe,
                    const std::string& h2s_home,
                    const std::string& plugin_path,
                    const std::string& dev_id,
                    const std::string& access_code,
                    const std::string& lan_ip,
                    const std::string& cert_dir,
                    const std::string& log_path);

// Wait until libbambu_networking.so is mapped; returns PID or 0.
pid_t wait_for_libbambu(pid_t daemon_pid,
                         const std::string& plugin_path,
                         int timeout_s);
