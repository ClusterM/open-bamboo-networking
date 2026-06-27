#include "daemon.h"
#include "daemon_embed.h"       // daemon_embed_bin[] + daemon_embed_bin_len
#include "capture.h"            // g_openat_notif_pipe_rd, g_connect_redirect_so_path etc.
#include "logging.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Globals defined here, declared extern in daemon.h.
std::string g_connect_redirect_so_path;
int g_fake_printer_port = 0;
std::string g_plugin_path_for_home;

static constexpr const char kDefaultPluginVersion[] = "02.07.01.51";

std::string probe_plugin_path() {
    const char* home = std::getenv("HOME");
    std::vector<std::string> candidates;
    if (home && home[0]) {
        // Version-specific cache location (preferred — survives plugin updates).
        candidates.push_back(std::string(home) + "/.cache/bambu_extract_d/plugins/"
                             + kDefaultPluginVersion + "/libbambu_networking.so");
        // BambuStudio install locations.
        candidates.push_back(std::string(home) + "/.config/BambuStudio/plugins/libbambu_networking.so");
        candidates.push_back(std::string(home) + "/.local/share/BambuStudio/plugins/libbambu_networking.so");
    }
    for (auto& p : candidates) {
        struct stat st{};
        if (stat(p.c_str(), &st) == 0) return p;
    }
    return {};
}

std::string download_plugin_if_needed() {
    const char* home = std::getenv("HOME");
    if (!home || !home[0]) {
        std::fprintf(stderr, "[plugin-dl] HOME not set, cannot cache plugin\n");
        return {};
    }
    std::string cache_dir = std::string(home) + "/.cache/bambu_extract_d/plugins/"
                           + kDefaultPluginVersion;
    std::string cache_so  = cache_dir + "/libbambu_networking.so";

    {
        struct stat st{};
        if (stat(cache_so.c_str(), &st) == 0 && st.st_size > 0) {
            std::fprintf(stderr, "[plugin-dl] using cached plugin: %s\n", cache_so.c_str());
            return cache_so;
        }
    }

    std::fprintf(stderr, "[plugin-dl] no local plugin found — fetching manifest from Bambu CDN...\n");

    char manifest_tmp[64];
    snprintf(manifest_tmp, sizeof(manifest_tmp), "/tmp/bambu_manifest_%d.json", (int)getpid());
    {
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
            "curl --silent --location --max-time 60 "
            "-H \"X-BBL-OS-Type: linux\" "
            "-o %s "
            "\"https://api.bambulab.com/v1/iot-service/api/slicer/resource?slicer/plugins/cloud=02.07.01.51\" "
            "2>&1",
            manifest_tmp);
        int rc = std::system(cmd);
        if (rc != 0) {
            std::fprintf(stderr, "[plugin-dl] manifest fetch failed (rc=%d)\n", rc);
            unlink(manifest_tmp);
            return {};
        }
    }

    std::string manifest_url;
    {
        FILE* f = fopen(manifest_tmp, "r");
        if (!f) {
            std::fprintf(stderr, "[plugin-dl] cannot read manifest tmp file\n");
            return {};
        }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        rewind(f);
        std::string body(sz > 0 ? sz : 0, '\0');
        if (sz > 0) fread(&body[0], 1, sz, f);
        fclose(f);
        unlink(manifest_tmp);

        const char* key = "\"url\":\"";
        size_t pos = body.find(key);
        if (pos == std::string::npos) {
            std::fprintf(stderr, "[plugin-dl] no url field in manifest\n");
            return {};
        }
        size_t start = pos + strlen(key);
        size_t end   = body.find('"', start);
        if (end == std::string::npos) {
            std::fprintf(stderr, "[plugin-dl] malformed url field in manifest\n");
            return {};
        }
        manifest_url = body.substr(start, end - start);
    }

    if (manifest_url.empty()) {
        std::fprintf(stderr, "[plugin-dl] empty url in manifest\n");
        return {};
    }
    std::fprintf(stderr, "[plugin-dl] downloading plugin ZIP from: %s\n", manifest_url.c_str());

    char zip_tmp[64];
    snprintf(zip_tmp, sizeof(zip_tmp), "/tmp/bambu_plugin_%d.zip", (int)getpid());
    {
        pid_t curl_pid = fork();
        if (curl_pid == 0) {
            execlp("curl", "curl", "--silent", "--location", "--max-time", "120",
                   "-o", zip_tmp,
                   manifest_url.c_str(), nullptr);
            _exit(127);
        }
        if (curl_pid < 0) {
            std::fprintf(stderr, "[plugin-dl] fork failed: %s\n", strerror(errno));
            return {};
        }
        int curl_st = 0;
        waitpid(curl_pid, &curl_st, 0);
        if (!WIFEXITED(curl_st) || WEXITSTATUS(curl_st) != 0) {
            std::fprintf(stderr, "[plugin-dl] ZIP download failed (curl exit=%d)\n",
                         WIFEXITED(curl_st) ? WEXITSTATUS(curl_st) : -1);
            unlink(zip_tmp);
            return {};
        }
    }

    {
        std::string parent1 = std::string(home) + "/.cache";
        std::string parent2 = std::string(home) + "/.cache/bambu_extract_d";
        mkdir(parent1.c_str(), 0700);
        mkdir(parent2.c_str(), 0700);
        if (mkdir(cache_dir.c_str(), 0700) != 0 && errno != EEXIST) {
            std::fprintf(stderr, "[plugin-dl] cannot create cache dir: %s\n", cache_dir.c_str());
            unlink(zip_tmp);
            return {};
        }
    }

    {
        pid_t unzip_pid = fork();
        if (unzip_pid == 0) {
            execlp("unzip", "unzip", "-j", "-o", zip_tmp, "*.so", "-d",
                   cache_dir.c_str(), nullptr);
            _exit(127);
        }
        unlink(zip_tmp);
        if (unzip_pid < 0) {
            std::fprintf(stderr, "[plugin-dl] fork failed: %s\n", strerror(errno));
            return {};
        }
        int unzip_st = 0;
        waitpid(unzip_pid, &unzip_st, 0);
        if (!WIFEXITED(unzip_st) || WEXITSTATUS(unzip_st) != 0) {
            std::fprintf(stderr, "[plugin-dl] unzip failed (rc=%d)\n",
                         WIFEXITED(unzip_st) ? WEXITSTATUS(unzip_st) : -1);
            return {};
        }
    }

    {
        struct stat st{};
        if (stat(cache_so.c_str(), &st) != 0 || st.st_size == 0) {
            std::fprintf(stderr, "[plugin-dl] extracted .so not found at %s\n", cache_so.c_str());
            return {};
        }
        chmod(cache_so.c_str(), 0600);
    }

    std::fprintf(stderr, "[plugin-dl] plugin cached: %s\n", cache_so.c_str());
    return cache_so;
}

static std::string find_slicer_cert(const std::string& plugin_path) {
    // The cert ships alongside the plugin inside BambuStudio:
    //   <install>/plugins/libbambu_networking.so
    //   <install>/resources/cert/slicer_base64.cer
    // Walk up from the plugin directory looking for resources/cert/.
    std::string dir = plugin_path;
    auto slash = dir.rfind('/');
    if (slash != std::string::npos) dir = dir.substr(0, slash);

    for (int up = 0; up < 4; ++up) {
        std::string candidate = dir + "/resources/cert/slicer_base64.cer";
        if (access(candidate.c_str(), R_OK) == 0)
            return candidate;
        auto p = dir.rfind('/');
        if (p == std::string::npos) break;
        dir = dir.substr(0, p);
    }

    const char* home = std::getenv("HOME");
    if (home) {
        std::string h(home);
        const char* extra[] = {
            "/.config/BambuStudio/slicer_base64.cer",
            "/BambuStudio/resources/cert/slicer_base64.cer",
            "/Applications/BambuStudio.app/Contents/Resources/cert/slicer_base64.cer",
        };
        for (const char* e : extra) {
            std::string fb = h + e;
            if (access(fb.c_str(), R_OK) == 0) return fb;
        }
    }

    const char* system_paths[] = {
        "/opt/BambuStudio/resources/cert/slicer_base64.cer",
        "/usr/local/share/BambuStudio/resources/cert/slicer_base64.cer",
    };
    for (const char* p : system_paths)
        if (access(p, R_OK) == 0) return p;

    return {};
}

static bool copy_file(const std::string& src, const std::string& dst) {
    int in  = open(src.c_str(), O_RDONLY);
    if (in < 0) return false;
    int out = open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out < 0) { close(in); return false; }
    char buf[65536];
    ssize_t n;
    bool ok = true;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(out, buf + written, (size_t)(n - written));
            if (w < 0) { ok = false; break; }
            written += w;
        }
        if (!ok) break;
    }
    close(in);
    close(out);
    return ok && n == 0;
}

std::string write_cert_tmpdir(pid_t pid, const std::string& plugin_path,
                               const std::string& cert_override) {
    char dir[128];
    snprintf(dir, sizeof(dir), "/tmp/bambu_extract_d_%d", (int)pid);
    if (mkdir(dir, 0700) < 0 && errno != EEXIST) {
        std::fprintf(stderr, "mkdir(%s): %s\n", dir, strerror(errno));
        return {};
    }

    std::string src = cert_override.empty() ? find_slicer_cert(plugin_path) : cert_override;
    if (src.empty()) {
        std::fprintf(stderr,
            "bambu_extract_d: cannot locate slicer_base64.cer\n"
            "  Searched relative to plugin path and standard BambuStudio locations.\n"
            "  Specify it explicitly with --cert /path/to/slicer_base64.cer\n"
            "  (found inside any BambuStudio installation at resources/cert/)\n");
        return {};
    }

    char cert_path[256];
    snprintf(cert_path, sizeof(cert_path), "%s/slicer_base64.cer", dir);
    if (!copy_file(src, cert_path)) {
        std::fprintf(stderr, "copy_file(%s -> %s) failed\n", src.c_str(), cert_path);
        return {};
    }
    return std::string(dir);
}

std::string write_daemon_memfd() {
    int fd = memfd_create("bambu_daemon", MFD_CLOEXEC);
    if (fd < 0) {
        LOG_E("memfd_create for daemon: %s", strerror(errno));
        return {};
    }
    size_t total = 0;
    while (total < daemon_embed_bin_len) {
        ssize_t n = write(fd,
            (const char*)daemon_embed_bin + total,
            daemon_embed_bin_len - total);
        if (n <= 0) { close(fd); return {}; }
        total += n;
    }
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    return std::string(path);
}

std::string setup_h2s_home(const std::string& dev_id) {
    const char* home_env = std::getenv("HOME");
    std::string bsl_config = (home_env && home_env[0])
        ? std::string(home_env) + "/.config/BambuStudio"
        : std::string("/root/.config/BambuStudio");
    const char* base_src = bsl_config.c_str();
    std::string h2s_home = "/tmp/bridge-mp/home-H2S";
    std::string cfg = h2s_home + "/.config/BambuStudio";

    struct stat st{};
    if (stat((cfg + "/BambuStudio.conf").c_str(), &st) == 0 &&
        stat((cfg + "/plugins").c_str(), &st) == 0) {
        LOG_I("H2S home already set up: %s", h2s_home.c_str());
        return h2s_home;
    }

    auto mkdirp = [](const std::string& path) {
        mkdir(path.c_str(), 0755);
        return true;
    };
    mkdirp(h2s_home);
    mkdirp(h2s_home + "/.config");
    mkdirp(cfg);
    mkdirp(cfg + "/log");
    mkdirp(cfg + "/cache");
    mkdirp(cfg + "/bridge");
    mkdirp(cfg + "/bridge/certs");

    auto copy_file = [](const std::string& src, const std::string& dst) -> bool {
        FILE* sf = fopen(src.c_str(), "rb");
        if (!sf) return false;
        FILE* df = fopen(dst.c_str(), "wb");
        if (!df) { fclose(sf); return false; }
        char buf[65536];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), sf)) > 0) fwrite(buf, 1, n, df);
        fclose(sf); fclose(df);
        return true;
    };

    bool bsl_conf_ok = copy_file(std::string(base_src) + "/BambuStudio.conf",
                                  cfg + "/BambuStudio.conf");
    if (!bsl_conf_ok) {
        std::string synth_conf = "{\"user_last_selected_machine\":\"" + dev_id + "\"}";
        FILE* sf = fopen((cfg + "/BambuStudio.conf").c_str(), "w");
        if (sf) {
            fputs(synth_conf.c_str(), sf);
            fclose(sf);
            bsl_conf_ok = true;
            LOG_I("BambuStudio.conf not found — wrote synthetic conf");
        } else {
            LOG_W("could not write synthetic BambuStudio.conf — daemon may crash");
        }
    }
    (void)bsl_conf_ok;
    if (!copy_file(std::string(base_src) + "/BambuNetworkEngine.conf",
                   cfg + "/BambuNetworkEngine.conf")) {
        LOG_W("could not copy BambuNetworkEngine.conf — cloud auth may fail");
    }

    {
        std::string conf_path = cfg + "/BambuStudio.conf";
        FILE* f = fopen(conf_path.c_str(), "r");
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            rewind(f);
            std::string content(sz, '\0');
            fread(&content[0], 1, sz, f);
            fclose(f);

            const char* key = "\"user_last_selected_machine\":";
            size_t pos = content.find(key);
            if (pos != std::string::npos) {
                size_t start = content.find('"', pos + strlen(key));
                if (start != std::string::npos) {
                    size_t end = content.find('"', start + 1);
                    if (end != std::string::npos) {
                        content.replace(start + 1, end - start - 1, dev_id);
                        FILE* wf = fopen(conf_path.c_str(), "w");
                        if (wf) {
                            fwrite(content.data(), 1, content.size(), wf);
                            fclose(wf);
                        }
                    }
                }
            }
        }
    }

    {
        std::string src_plugins = std::string(base_src) + "/plugins";
        struct stat pst{};
        if (stat(src_plugins.c_str(), &pst) == 0) {
            symlink(src_plugins.c_str(), (cfg + "/plugins").c_str());
        } else {
            mkdir((cfg + "/plugins").c_str(), 0755);
            if (!g_plugin_path_for_home.empty()) {
                const std::string& pp = g_plugin_path_for_home;
                size_t sl2 = pp.rfind('/');
                std::string bname = (sl2 != std::string::npos) ? pp.substr(sl2 + 1) : pp;
                symlink(pp.c_str(), (cfg + "/plugins/" + bname).c_str());
                LOG_I("synthetic plugins/ dir: symlinked %s", pp.c_str());
            } else {
                LOG_W("no plugin path available for synthetic plugins/ dir");
            }
        }
        std::string src_system = std::string(base_src) + "/system";
        if (stat(src_system.c_str(), &pst) == 0) {
            symlink(src_system.c_str(), (cfg + "/system").c_str());
        } else {
            mkdir((cfg + "/system").c_str(), 0755);
        }
    }

    auto copy_dir = [&](const char* dir_name) {
        std::string src_dir = std::string(base_src) + "/" + dir_name;
        std::string dst_dir = cfg + "/" + dir_name;
        mkdirp(dst_dir);
        DIR* d = opendir(src_dir.c_str());
        if (!d) return;
        struct dirent* ent;
        while ((ent = readdir(d)) != nullptr) {
            if (ent->d_name[0] == '.') continue;
            std::string src_f = src_dir + "/" + ent->d_name;
            std::string dst_f = dst_dir + "/" + ent->d_name;
            copy_file(src_f, dst_f);
        }
        closedir(d);
    };
    copy_dir("printers");
    mkdirp(cfg + "/user");

    if (const char* cert_src_dir = std::getenv("BBL_BRIDGE_CERT_DIR")) {
        std::string src_c = std::string(cert_src_dir) + "/" + dev_id + ".crt";
        std::string src_k = std::string(cert_src_dir) + "/" + dev_id + ".key";
        struct stat st2{};
        if (stat(src_c.c_str(), &st2) == 0) {
            copy_file(src_c, cfg + "/bridge/certs/" + dev_id + ".crt");
            copy_file(src_k, cfg + "/bridge/certs/" + dev_id + ".key");
            LOG_I("bridge certs copied for dev_id=%s", dev_id.c_str());
        } else {
            LOG_W("bridge certs not found for dev_id=%s (expected at %s)",
                  dev_id.c_str(), src_c.c_str());
        }
    }

    LOG_I("H2S home set up: %s", h2s_home.c_str());
    return h2s_home;
}

pid_t launch_daemon(const std::string& daemon_exe,
                    const std::string& h2s_home,
                    const std::string& plugin_path,
                    const std::string& dev_id,
                    const std::string& access_code,
                    const std::string& lan_ip,
                    const std::string& cert_dir,
                    const std::string& log_path) {
    std::string config_dir = h2s_home + "/.config/BambuStudio";

    int pipefds[2];
    if (pipe2(pipefds, O_CLOEXEC) < 0) {
        LOG_E("pipe2: %s", strerror(errno));
        return -1;
    }

    int notif_pipe[2] = {-1, -1};
    if (pipe2(notif_pipe, O_CLOEXEC) < 0) {
        LOG_E("pipe2 notif: %s", strerror(errno));
        close(pipefds[0]); close(pipefds[1]);
        return -1;
    }
    if (fcntl(notif_pipe[1], F_SETFD, 0) < 0) {
        LOG_E("fcntl notif_pipe[1] clear CLOEXEC: %s", strerror(errno));
    }

    pid_t intermediate = fork();
    if (intermediate < 0) {
        LOG_E("fork intermediate: %s", strerror(errno));
        close(pipefds[0]); close(pipefds[1]);
        close(notif_pipe[0]); close(notif_pipe[1]);
        return -1;
    }
    if (intermediate != 0) {
        close(pipefds[1]);
        close(notif_pipe[1]);
        waitpid(intermediate, nullptr, 0);
        pid_t daemon_pid = -1;
        read(pipefds[0], &daemon_pid, sizeof(daemon_pid));
        close(pipefds[0]);
        g_openat_notif_pipe_rd = notif_pipe[0];
        return daemon_pid;
    }

    close(pipefds[0]);
    close(notif_pipe[0]);
    pid_t daemon_pid = fork();
    if (daemon_pid != 0) {
        close(notif_pipe[1]);
        write(pipefds[1], &daemon_pid, sizeof(daemon_pid));
        close(pipefds[1]);
        _exit(0);
    }
    close(pipefds[1]);
    setsid();

    setenv("HOME", h2s_home.c_str(), 1);
    setenv("DISPLAY",    ":100", 1);
    setenv("XAUTHORITY", "/tmp/xvfb-bridge.auth", 1);
    setenv("LC_ALL",     "C", 1);

    {
        std::string plugin_dir = plugin_path;
        size_t sl = plugin_dir.rfind('/');
        if (sl != std::string::npos) plugin_dir = plugin_dir.substr(0, sl);
        else plugin_dir = ".";

        std::string daemon_dir = daemon_exe;
        sl = daemon_dir.rfind('/');
        if (sl != std::string::npos) daemon_dir = daemon_dir.substr(0, sl);
        else daemon_dir = ".";

        const char* existing = getenv("LD_LIBRARY_PATH");
        std::string ldp = plugin_dir + ":" + daemon_dir;
        if (existing && existing[0]) { ldp += ":"; ldp += existing; }
        setenv("LD_LIBRARY_PATH", ldp.c_str(), 1);
    }

    {
        const char* ap  = "/mnt/cephfs/ssd/extract-d/bin/allow_ptrace.so";
        const char* wd  = "/mnt/cephfs/ssd/extract-d/bin/watchdog_defeat_v2.so";
        struct stat st{};
        std::string preload;
        if (!g_connect_redirect_so_path.empty()) preload = g_connect_redirect_so_path;
        if (stat(ap, &st) == 0) { if (!preload.empty()) preload += ":"; preload += ap; }
        if (stat(wd, &st) == 0) { if (!preload.empty()) preload += ":"; preload += wd; }
        if (!preload.empty()) setenv("LD_PRELOAD", preload.c_str(), 1);
    }
    if (g_fake_printer_port > 0) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", g_fake_printer_port);
        setenv("FAKE_PRINTER_PORT", port_str, 1);
    }
    setenv("WD_V2_EAT_SIGABRT",   "1", 1);
    setenv("WD_V2_NO_EXIT",       "1", 1);
    setenv("WD_V2_FAKE_TRACEME",  "1", 1);
    setenv("WD_V2_PTRACE_TRACEME_SECCOMP", "1", 1);
#ifndef USE_SECCOMP_UNOTIFY
    setenv("WD_V2_OPENAT_SELFEXEMPT", "1", 1);
#endif
#ifdef USE_SECCOMP_UNOTIFY
    {
        char notif_pipe_str[32];
        snprintf(notif_pipe_str, sizeof(notif_pipe_str), "%d", notif_pipe[1]);
        setenv("WD_V2_OPENAT_NOTIF_PIPE", notif_pipe_str, 1);
    }
#endif
    {
        char logpath[256];
        snprintf(logpath, sizeof(logpath), "/tmp/wd_v2_daemon.log");
        setenv("WD_V2_LOG", logpath, 1);
    }

    setenv("BAMBU_BRIDGE_CLOUD_CERT_DIR",  cert_dir.c_str(),       1);
    setenv("BAMBU_BRIDGE_CLOUD_CERT_FILE", "slicer_base64.cer",    1);
    setenv("BAMBU_BRIDGE_RESIGN_MS", "3000", 1);
    setenv("BAMBU_BRIDGE_GCODE_CMD_MS", "2000", 1);
    setenv("BAMBU_BRIDGE_TARGET_DEV", dev_id.c_str(), 1);

    int null_fd = open("/dev/null", O_RDONLY);
    if (null_fd >= 0) { dup2(null_fd, STDIN_FILENO); close(null_fd); }
    if (!log_path.empty()) {
        int log_fd = open(log_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0640);
        if (log_fd >= 0) {
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }
    }

    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    prctl(PR_SET_PTRACER, (unsigned long)PR_SET_PTRACER_ANY, 0, 0, 0);

    const char* argv[] = {
        daemon_exe.c_str(),
        "--plugin",           plugin_path.c_str(),
        "--config-dir",       config_dir.c_str(),
        "--country-code",     "US",
        "--dev-id",           dev_id.c_str(),
        "--access-code",      access_code.c_str(),
        "--lan-ip",           lan_ip.c_str(),
        "--model",            "H2S",
        "--mqtt-port-base",   "8884",
        "--cloud-cert-dir",   cert_dir.c_str(),
        "--cloud-cert-file",  "slicer_base64.cer",
        "--no-ssdp",
        "--no-ftps",
        "--no-rtsp",
        "--inventory-poll-seconds", "5",
        nullptr
    };

    execv(daemon_exe.c_str(), const_cast<char* const*>(argv));
    std::fprintf(stderr, "[daemon-child] execv(%s): %s\n",
                 daemon_exe.c_str(), strerror(errno));
    _exit(2);
}

pid_t wait_for_libbambu(pid_t daemon_pid,
                         const std::string& plugin_path,
                         int timeout_s) {
    (void)plugin_path;
    const char* needle = "libbambu_networking";
    double deadline = now_s() + double(timeout_s);

    auto pid_has_libbambu = [&](pid_t pid) -> bool {
        char maps[64];
        snprintf(maps, sizeof(maps), "/proc/%d/maps", (int)pid);
        FILE* f = fopen(maps, "r");
        if (!f) return false;
        char line[512];
        bool found = false;
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, needle) != nullptr) { found = true; break; }
        }
        fclose(f);
        return found;
    };

    bool use_supervisor = (g_openat_notif_fd >= 0);

    while (now_s() < deadline) {
        pid_t seen = g_libbambu_seen_pid.load(std::memory_order_acquire);
        if (seen > 0) {
            LOG_I("openat supervisor saw libbambu opened by tgid=%d", (int)seen);
            return seen;
        }

        if (!use_supervisor) {
            if (pid_has_libbambu(daemon_pid)) return daemon_pid;

            DIR* d = opendir("/proc");
            if (d) {
                struct dirent* ent;
                while ((ent = readdir(d)) != nullptr) {
                    if (!isdigit(ent->d_name[0])) continue;
                    pid_t pid = (pid_t)atoi(ent->d_name);
                    if (pid == daemon_pid) continue;
                    char stat_path[64];
                    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", (int)pid);
                    FILE* sf = fopen(stat_path, "r");
                    if (!sf) continue;
                    int ppid_val = 0;
                    char name[256] = {};
                    fscanf(sf, "%*d (%255[^)]) %*c %d", name, &ppid_val);
                    fclose(sf);
                    if (ppid_val != (int)daemon_pid) continue;
                    if (pid_has_libbambu(pid)) { closedir(d); return pid; }
                }
                closedir(d);
            }
        }
        usleep(20 * 1000);
    }
    return 0;
}
