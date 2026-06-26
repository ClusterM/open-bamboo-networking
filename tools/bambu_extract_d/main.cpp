// main.cpp — Self-contained RSA-d extractor for libbambu_networking
// Phase 0: if _SELF_PRELOADED not set, write watchdog shim to memfd and re-exec with LD_PRELOAD.

// ---- Embedded assets ----
#include "watchdog_defeat_embed.h"   // watchdog_defeat_embed_so[] + _len

// ---- Phase 0: self-re-exec bootstrap ----
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern char** environ;

static void bootstrap_if_needed(int argc, char** argv) {
    if (getenv("_SELF_PRELOADED")) return;

    int fd = memfd_create("bambu_wd", 0);
    if (fd < 0) { perror("memfd_create"); _exit(1); }

    size_t total = 0;
    while (total < watchdog_defeat_embed_so_len) {
        ssize_t n = write(fd,
            (const char*)watchdog_defeat_embed_so + total,
            watchdog_defeat_embed_so_len - total);
        if (n <= 0) { perror("write shim"); _exit(1); }
        total += (size_t)n;
    }

    char preload_path[64];
    snprintf(preload_path, sizeof(preload_path), "/proc/self/fd/%d", fd);
    setenv("LD_PRELOAD", preload_path, 1);
    setenv("_SELF_PRELOADED", "1", 1);

    execve("/proc/self/exe", argv, environ);
    perror("execve"); _exit(1);
}

#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <map>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "vendored/Sha256Portable.hpp"
#include "vendored/BigIntModExp.hpp"

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// Declaration headers (no definitions).
#include "logging.h"
#include "version.h"
#include "bigint.h"
#include "envelope.h"
#include "capture.h"
#include "reconstruct.h"
#include "output.h"
#include "fake_broker.h"
#include "daemon.h"

// ===========================================================================
// Logging globals (definitions; declared extern in logging.h)
// ===========================================================================
double g_t0 = 0;
bool g_verbose = false;

// ===========================================================================
// CLI parsing
// ===========================================================================
struct Args {
    std::string plugin_path;
    std::string cert_path;
    std::string envelopes_path;
    std::string modulus_n_hex;
    std::string dev_id;
    std::string access_code;
    std::string out_path      = "d_extracted.json";
    bool verbose              = false;
    int timeout_s             = 60;
    bool  no_envelopes        = false;
};

static void usage_simple(const char* prog) {
    std::fprintf(stderr,
        "usage: %s [options]\n"
        "\n"
        "Optional:\n"
        "  --plugin PATH       libbambu_networking.so path (probes defaults)\n"
        "  --out PATH          Output path: .json or .pem (PKCS#1 RSA PEM, default: d_extracted.json)\n"
        "  --timeout N         Seconds before giving up (default: 120)\n"
        "  --envelopes PATH    envelopes.json for validation (optional)\n"
        "  --verbose           Log every HW BP trap\n"
        "  --help              Show this message\n"
        "\n"
        "Example:\n"
        "  %s\n"
        "  %s --out slicer_key.pem\n",
        prog, prog, prog);
}

// Global daemon PID for signal handler cleanup.
static int g_cleanup_pipe[2] = {-1, -1};
static pid_t g_daemon_pid_atomic = 0;

static void cleanup_signal_handler(int /*sig*/) {
    pid_t dpid = g_daemon_pid_atomic;
    if (dpid > 0) {
        kill(dpid, SIGKILL);
        kill(-dpid, SIGKILL);
    }
    _exit(1);
}

int main(int argc, char** argv) {
    // Phase 0: re-exec with LD_PRELOAD shim if not already done.
    bootstrap_if_needed(argc, argv);

    // Phase 1 from here.
    g_t0 = now_s();

    // Install signal handler to clean up on SIGTERM/SIGINT.
    {
        struct sigaction sa{};
        sa.sa_handler = cleanup_signal_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESETHAND;
        sigaction(SIGTERM, &sa, nullptr);
        sigaction(SIGINT,  &sa, nullptr);
    }

    prctl(PR_SET_NAME, "bambustu_main", 0, 0, 0);

    {
        struct rlimit rl{0, 0};
        setrlimit(RLIMIT_CORE, &rl);
    }

    // ---- Parse simplified CLI ----
    Args args;
    args.no_envelopes = true;
    args.timeout_s    = 120;
    args.out_path     = "d_extracted.json";

    bool show_help = false;

    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](std::string& slot) -> bool {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", s.c_str());
                return false;
            }
            slot = argv[++i];
            return true;
        };
        if      (s == "--plugin")      { if (!need(args.plugin_path)) return 2; }
        else if (s == "--cert")        { if (!need(args.cert_path)) return 2; }
        else if (s == "--out")         { if (!need(args.out_path)) return 2; }
        else if (s == "--envelopes")   {
            if (!need(args.envelopes_path)) return 2;
            args.no_envelopes = false;
        }
        else if (s == "--timeout")     {
            std::string t; if (!need(t)) return 2;
            args.timeout_s = std::atoi(t.c_str());
        }
        else if (s == "--verbose")     { args.verbose = true; }
        else if (s == "--help" || s == "-h") { show_help = true; }
        else {
            std::fprintf(stderr, "unknown argument: %s\n", s.c_str());
            show_help = true;
        }
    }

    // Synthetic identifiers — no real printer required.
    args.dev_id      = "01S00A2B3C4D5E6";
    args.access_code = "offline";
    std::string lan_ip = "127.0.0.1";

    if (show_help) {
        usage_simple(argv[0]);
        return 2;
    }

    g_verbose = args.verbose;

    // Probe plugin path.
    if (args.plugin_path.empty()) {
        args.plugin_path = probe_plugin_path();
        if (args.plugin_path.empty()) {
            args.plugin_path = download_plugin_if_needed();
        }
        if (args.plugin_path.empty()) {
            LOG_E("--plugin: no local plugin found and auto-download failed. "
                  "Install BambuStudio or run with --plugin.");
            return 2;
        }
        LOG_I("plugin (auto): %s", args.plugin_path.c_str());
    }
    g_plugin_path_for_home = args.plugin_path;

    // ---- Identify plugin version from file size ----
    const VersionProfile* ver = identify_version(args.plugin_path);
    double warmup_s = 4.0;
    if (ver) {
        warmup_s = ver->warmup_s;
    }

    LOG_I("bambu_extract_d");
    LOG_I("mode      : no-printer (fake broker on 127.0.0.1:8883)");
    LOG_I("plugin    : %s", args.plugin_path.c_str());
    LOG_I("out       : %s", args.out_path.c_str());
    LOG_I("timeout   : %ds", args.timeout_s);
    if (ver) {
        LOG_I("version   : %s (size=%lu)", ver->tag, (unsigned long)ver->so_size);
    } else {
        struct stat vst{};
        stat(args.plugin_path.c_str(), &vst);
        LOG_W("version   : UNKNOWN (size=%lu) — using default profile", (unsigned long)(uint64_t)vst.st_size);
    }

    // ---- Locate slicer cert and copy to tmpdir ----
    std::string cert_dir = write_cert_tmpdir(getpid(), args.plugin_path, args.cert_path);
    if (cert_dir.empty()) {
        LOG_E("failed to locate slicer cert — see above for details");
        return 3;
    }
    LOG_I("cert dir  : %s", cert_dir.c_str());

    // ---- Parse modulus N ----
    bn::BigInt N;
    {
        std::string nhex = args.modulus_n_hex.empty()
            ? std::string(version_02_05_03_63::N_HEX_DEFAULT)
            : args.modulus_n_hex;
        N = bn::from_hex(nhex);
        if (N.is_zero() || N.bit_length() < 2000) {
            LOG_E("modulus N parse failed (bits=%d)", N.bit_length());
            return 3;
        }
        LOG_I("N bits=%d", N.bit_length());
    }

    // ---- Load envelopes if given ----
    std::vector<Envelope> envs;
    if (!args.no_envelopes) {
        std::string body = slurp(args.envelopes_path);
        if (body.empty()) {
            LOG_E("envelopes file empty/missing: %s", args.envelopes_path.c_str());
            return 3;
        }
        if (!mini_json::parse_envelopes(body, envs)) {
            LOG_E("could not parse envelopes JSON");
            return 3;
        }
        LOG_I("envelopes: %zu", envs.size());
    } else {
        LOG_I("envelopes: none (validation skipped)");
    }

    // ---- Start fake printer broker ----
    LOG_I("starting fake TLS MQTT broker on 127.0.0.1:8883");
    FakePrinterBroker fake_broker;
    if (!fake_broker.start(args.dev_id)) {
        LOG_E("failed to start fake printer broker on port 8883");
        return 4;
    }
    g_connect_redirect_so_path = fake_broker.connect_redirect_so_path;
    g_fake_printer_port = fake_broker.port;

    // ---- Write daemon binary to memfd ----
    std::string daemon_exe = write_daemon_memfd();
    if (daemon_exe.empty()) {
        LOG_E("failed to write daemon binary to memfd");
        return 4;
    }
    LOG_I("daemon exe: %s", daemon_exe.c_str());

    // ---- Set up H2S home directory ----
    std::string h2s_home = setup_h2s_home(args.dev_id);
    if (h2s_home.empty()) {
        LOG_E("failed to set up H2S home directory");
        return 4;
    }

    // ---- Launch daemon ----
    double daemon_start_ts = now_s();
    std::string daemon_log = cert_dir + "/daemon.log";
    pid_t daemon_pid = launch_daemon(daemon_exe, h2s_home, args.plugin_path,
                                     args.dev_id, args.access_code, lan_ip,
                                     cert_dir, daemon_log);
    if (daemon_pid < 0) {
        LOG_E("failed to launch daemon");
        return 4;
    }
    g_daemon_pid_atomic = daemon_pid;
    LOG_I("daemon launched: PID %d", (int)daemon_pid);
    LOG_I("daemon log: %s", daemon_log.c_str());

    // ---- Read seccomp notif_fd from daemon constructor ----
    if (g_openat_notif_pipe_rd >= 0) {
        struct pollfd pf = { g_openat_notif_pipe_rd, POLLIN, 0 };
#ifdef USE_SECCOMP_UNOTIFY
        int pr = poll(&pf, 1, 3000);
#else
        int pr = poll(&pf, 1, 0);
#endif
        if (pr > 0 && (pf.revents & POLLIN)) {
            int daemon_notif_fd = -1;
            ssize_t nr = read(g_openat_notif_pipe_rd, &daemon_notif_fd, sizeof(int));
            if (nr == sizeof(int) && daemon_notif_fd >= 0) {
                LOG_I("openat: daemon notif_fd=%d (in daemon pid=%d)", daemon_notif_fd, daemon_pid);
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
                long pidfd = syscall(SYS_pidfd_open, (pid_t)daemon_pid, 0);
                if (pidfd < 0) {
                    LOG_W("pidfd_open(daemon=%d) failed: %s — openat supervisor disabled",
                          daemon_pid, strerror(errno));
                } else {
                    long local_fd = syscall(SYS_pidfd_getfd, (int)pidfd, daemon_notif_fd, 0);
                    close((int)pidfd);
                    if (local_fd < 0) {
                        LOG_W("pidfd_getfd(notif_fd=%d) failed: %s — openat supervisor disabled",
                              daemon_notif_fd, strerror(errno));
                    } else {
                        g_openat_notif_fd = (int)local_fd;
                        LOG_I("openat notif_fd=%d stolen via pidfd_getfd (daemon fd was %d)",
                              (int)local_fd, daemon_notif_fd);
                    }
                }
            } else {
                LOG_W("notif pipe read failed nr=%zd daemon_notif_fd=%d", nr, daemon_notif_fd);
            }
        } else if (pr == 0) {
            LOG_W("notif pipe timeout — openat supervisor disabled");
        } else {
            LOG_W("notif pipe poll failed: %s — openat supervisor disabled", strerror(errno));
        }
        close(g_openat_notif_pipe_rd);
        g_openat_notif_pipe_rd = -1;
    }

    // ---- Start openat supervisor thread ----
    if (g_openat_notif_fd >= 0) {
        LOG_I("starting openat supervisor thread (notif_fd=%d)", g_openat_notif_fd);
        g_notif_stop_flag.store(false, std::memory_order_relaxed);
        int nfd = g_openat_notif_fd;
        g_notif_thread = std::thread([nfd]() {
            openat_supervisor_thread(nfd, &g_notif_stop_flag);
        });
    } else {
        LOG_I("openat supervisor not started (no notif_fd)");
    }

    // ---- Wait for plugin to be loaded ----
    LOG_I("waiting for libbambu_networking to map (max 90s)...");
    pid_t target_pid = wait_for_libbambu(daemon_pid, args.plugin_path, 90);
    if (target_pid == 0) {
        LOG_E("libbambu_networking never mapped in daemon — bailing");
        LOG_I("daemon log tail:");
        {
            FILE* f = fopen(daemon_log.c_str(), "r");
            if (f) {
                fseek(f, 0, SEEK_END);
                long sz = ftell(f);
                long off = std::max(0L, sz - 4096L);
                fseek(f, off, SEEK_SET);
                char buf[4097];
                size_t n = fread(buf, 1, 4096, f);
                buf[n] = 0;
                fclose(f);
                std::fprintf(stderr, "%s\n", buf);
            }
        }
        kill(daemon_pid, SIGKILL);
        waitpid(daemon_pid, nullptr, 0);
        return 5;
    }
    LOG_I("libbambu mapped in PID %d", (int)target_pid);

    // ---- VMP warm-up ----
    {
        const char* env_delay = std::getenv("BBL_SEIZE_DELAY");
        if (env_delay) {
            double extra_delay = std::atof(env_delay);
            if (extra_delay > 0) {
                LOG_I("BBL_SEIZE_DELAY=%.1fs: letting VMP run untraced (self-test window)...", extra_delay);
                double deadline = now_s() + extra_delay;
                while (now_s() < deadline) {
                    usleep(500 * 1000);
                    if (kill(daemon_pid, 0) != 0) {
                        LOG_E("daemon died during seize delay");
                        return 7;
                    }
                }
                LOG_I("BBL_SEIZE_DELAY elapsed — attaching now");
            }
        } else {
            double elapsed = now_s() - daemon_start_ts;
            if (elapsed < warmup_s) {
                double wait_s = warmup_s - elapsed;
                LOG_I("VMP warm-up: waiting %.1fs (until %.0fs from daemon start)", wait_s, warmup_s);
                while (wait_s > 0.0) {
                    double slice = std::min(wait_s, 2.0);
                    usleep((useconds_t)(slice * 1e6));
                    wait_s -= slice;
                    if (kill(daemon_pid, 0) != 0) {
                        LOG_E("daemon died during warm-up wait");
                        return 7;
                    }
                }
                LOG_I("VMP warm-up complete");
            }
        }
    }

    // ---- Arm DR0 and capture ----
    LOG_I("attaching to PID %d for d-capture (timeout=%ds)...",
          (int)target_pid, args.timeout_s);

    bool require_bytes = true;
    CaptureResult cap = drive_capture_attach(target_pid, args.plugin_path,
                                             args.timeout_s, require_bytes, ver);

    // Shut down daemon.
    LOG_I("shutting down daemon...");
    kill(daemon_pid, SIGTERM);
    {
        int st = 0;
        for (int i = 0; i < 20; ++i) {
            pid_t r = waitpid(daemon_pid, &st, WNOHANG);
            if (r == daemon_pid || r < 0) break;
            usleep(100 * 1000);
        }
        kill(daemon_pid, SIGKILL);
        waitpid(daemon_pid, nullptr, 0);
    }

    if (!cap.ok) {
        LOG_E("capture failed: only %zu bytes (need %d)",
              cap.stream.size(), version_02_05_03_63::TOTAL_BYTES);
        if (cap.total_traps > 0)
            LOG_W("trap count = %d (expected multiples of 256)", cap.total_traps);
        LOG_I("daemon log tail:");
        {
            FILE* f = fopen(daemon_log.c_str(), "r");
            if (f) {
                fseek(f, 0, SEEK_END);
                long sz = ftell(f);
                long off = std::max(0L, sz - 4096L);
                fseek(f, off, SEEK_SET);
                char buf[4097];
                size_t n = fread(buf, 1, 4096, f);
                buf[n] = 0;
                fclose(f);
                std::fprintf(stderr, "%s\n", buf);
            }
        }
        return 5;
    }
    LOG_I("byte stream complete (%zu bytes), traps=%d sign_cycles=%d",
          cap.stream.size(), cap.total_traps, cap.sign_cycles);

    // ---- Reconstruct ----
    int min_matches = args.no_envelopes ? 0 : 3;
    std::vector<Envelope> head_envs;
    if (!args.no_envelopes) {
        size_t head_n = std::min<size_t>(envs.size(), 10);
        head_envs.assign(envs.begin(), envs.begin() + head_n);
    }

    DRecon R = reconstruct(cap.stream, N, version_02_05_03_63::E_PUB,
                           version_02_05_03_63::MAX_K, head_envs, min_matches);
    if (!R.ok) {
        LOG_E("reconstruction failed (factor recovery produced no valid mode)");
        std::string hex;
        char buf[3];
        for (size_t i = 0; i < std::min<size_t>(64, cap.stream.size()); ++i) {
            snprintf(buf, 3, "%02x", cap.stream[i]);
            hex += buf;
        }
        LOG_W("stream[0..63]: %s", hex.c_str());
        return 6;
    }
    LOG_I("factor recovery: k=%d mode=%s", R.k_found, R.mode.c_str());

    // ---- Envelope validation ----
    int env_pass = 0;
    if (!args.no_envelopes) {
        env_pass = validate_envelopes(R.d, N, envs);
        LOG_I("envelope validation: %d/%zu", env_pass, envs.size());
        if (env_pass < min_matches) {
            LOG_E("only %d envelopes matched (need >= %d)", env_pass, min_matches);
            return 7;
        }
    } else {
        LOG_I("envelope validation: skipped");
    }

    // ---- Print d to stdout ----
    std::string d_hex = bn::to_hex_str(R.d, false);
    std::printf("d=%s\n", d_hex.c_str());
    std::fflush(stdout);

    // ---- Write output ----
    if (!write_output(args.out_path, R, N, env_pass, (int)envs.size())) {
        return 8;
    }
    LOG_I("%s written", args.out_path.c_str());
    LOG_I("wall time: %.2f s", now_s() - g_t0);

    // Cleanup.
    {
        char cert_path[300];
        snprintf(cert_path, sizeof(cert_path), "%s/slicer_base64.cer", cert_dir.c_str());
        unlink(cert_path);
        char dlog_path[300];
        snprintf(dlog_path, sizeof(dlog_path), "%s/daemon.log", cert_dir.c_str());
        unlink(dlog_path);
        rmdir(cert_dir.c_str());
    }

    (void)g_cleanup_pipe;  // suppress unused warning

    return 0;
}
