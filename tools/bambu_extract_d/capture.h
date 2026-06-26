#pragma once
#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>
#include <sys/types.h>
#include "logging.h"
#include "version.h"

// ===========================================================================
// Capture module: ptrace HW-BP capture of RSA CRT bytes.
// ===========================================================================

// Result of a capture run.
struct CaptureResult {
    bool ok = false;
    std::vector<uint8_t> stream;
    int total_traps = 0;
    int sign_cycles = 0;  // 256-byte chunks observed
};

// Memory map info for the plugin .so.
struct PluginMapInfo {
    uint64_t file_lo = 0;       // start of file-backed r-xp (lowest)
    uint64_t file_hi = 0;       // end   of file-backed r-xp
    uint64_t arena2_lo = 0;     // start of contiguous anonymous r-xp arena
    uint64_t arena2_hi = 0;     // end   of contiguous anonymous r-xp arena
};

// openat supervisor globals — defined in capture.cpp.
extern int g_openat_notif_fd;
extern int g_openat_notif_pipe_rd;
extern std::atomic<bool> g_notif_stop_flag;
extern std::thread g_notif_thread;
extern std::atomic<pid_t> g_libbambu_seen_pid;
extern std::string g_plugin_path_detect;

// openat supervisor thread — called from main.cpp to start the thread.
void openat_supervisor_thread(int notif_fd, std::atomic<bool>* stop_flag);

// Main entry point: attach to an existing process and capture d-bytes.
CaptureResult drive_capture_attach(pid_t target,
                                   const std::string& plugin_path,
                                   int timeout_s,
                                   bool require_bytes,
                                   const VersionProfile* ver = nullptr);
