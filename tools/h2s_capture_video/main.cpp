#include "obn/json_lite.hpp"
#include "obn/os_compat.hpp"
#include "obn/tls_dial.hpp"
#include "obn/tunnel_local.hpp"

#include <openssl/evp.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#define LOG_INFO(fmt, ...)  do { fprintf(stdout, "[h2s-capture] " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while (0)
#define LOG_ERR(fmt, ...)   do { fprintf(stderr, "[h2s-capture] " fmt "\n", ##__VA_ARGS__); } while (0)

using Clock = std::chrono::steady_clock;
namespace tl = obn::tunnel_local;

struct FileEntry {
    std::string name;
    std::string path;
    long long   size  = 0;
    long long   mtime = 0;
};

// ---------------------------------------------------------------------------
// Tunnel helpers
// ---------------------------------------------------------------------------

static void tl_connect(const char* host, const tl::Config& cfg,
                        obn::os::socket_t& fd, SSL*& ssl, tl::Session& sess)
{
    if (obn::tls::dial_tls(host, 6000, 10000, &fd, &ssl) != 0)
        throw std::runtime_error(std::string("connect to ") + host + ":6000 failed");
    std::mutex mu;
    int r;
    while ((r = sess.handshake_step(ssl, cfg, &mu)) == 1) {}
    if (r < 0) {
        obn::tls::close_tls(&fd, &ssl);
        throw std::runtime_error("tunnel handshake failed");
    }
}

// Builds a file_download ABI request, using "path" for absolute/mem: paths
// and "file" for bare filenames (the printer expects different keys).
static std::string build_download_abi(std::uint32_t seq, const FileEntry& entry)
{
    bool use_path = !entry.path.empty() &&
                    (entry.path[0] == '/' || entry.path.rfind("mem:", 0) == 0);
    if (use_path)
        return tl::build_file_download_abi(seq, entry.path);
    char buf[1024];
    snprintf(buf, sizeof(buf),
             "{\"cmdtype\":4,\"sequence\":%u,\"req\":{\"file\":\"%s\",\"offset\":0}}",
             static_cast<unsigned>(seq), entry.name.c_str());
    return buf;
}

// ---------------------------------------------------------------------------
// List + download
// ---------------------------------------------------------------------------

static bool list_info(const char* host, const tl::Config& cfg,
                       const std::string& type, std::vector<FileEntry>& out)
{
    obn::os::socket_t fd{}; SSL* ssl = nullptr;
    tl::Session sess(0x12345678u);
    tl_connect(host, cfg, fd, ssl, sess);

    std::mutex mu;
    static std::uint32_t seq = 2;
    if (sess.send_abi_json(ssl, tl::build_list_info_abi(seq++, type), &mu) != 0) {
        obn::tls::close_tls(&fd, &ssl); return false;
    }

    bool done = false;
    while (!done) {
        std::vector<uint8_t> payload;
        if (sess.recv_payload(ssl, &payload, &mu) != 0) break;

        std::string jtext;
        std::vector<uint8_t> bin;
        tl::split_json_prefix(payload.data(), payload.size(), &jtext, &bin);

        auto root = obn::json::parse(jtext);
        if (!root) break;

        for (const auto& item : root->find("reply.file_lists").as_array()) {
            FileEntry fe;
            fe.name  = item.find("name").as_string();
            fe.path  = item.find("path").as_string();
            fe.size  = item.find("size").as_int(0);
            fe.mtime = item.find("time").as_int(0);
            if (!fe.name.empty()) out.push_back(fe);
        }

        int result = root->find("result").as_int(-999);
        if (result == 0)      done = true;
        else if (result != 1) break;
    }

    obn::tls::close_tls(&fd, &ssl);
    return done;
}

static long long download_to_fd(const char* host, const tl::Config& cfg,
                                  const FileEntry& entry, int out_fd)
{
    obn::os::socket_t fd{}; SSL* ssl = nullptr;
    tl::Session sess(0x12345678u);
    tl_connect(host, cfg, fd, ssl, sess);

    std::mutex mu;
    static std::uint32_t seq = 2;
    if (sess.send_abi_json(ssl, build_download_abi(seq++, entry), &mu) != 0) {
        obn::tls::close_tls(&fd, &ssl); return -1;
    }

    EVP_MD_CTX* md5ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md5ctx, EVP_md5(), nullptr);

    long long total_written = 0;
    bool      ok            = false;
    long long expect_total  = -1;
    std::string expect_md5;

    while (true) {
        std::vector<uint8_t> payload;
        if (sess.recv_payload(ssl, &payload, &mu) != 0) {
            LOG_ERR("download: timed out waiting for frame");
            break;
        }

        std::string jtext;
        std::vector<uint8_t> bin;
        tl::split_json_prefix(payload.data(), payload.size(), &jtext, &bin);

        auto root = obn::json::parse(jtext);
        if (!root) break;

        bool has_param_size = !root->find("reply.mem_dl_param_size").is_null();
        if (!bin.empty() && !has_param_size) {
            if (write(out_fd, bin.data(), bin.size()) != static_cast<ssize_t>(bin.size())) {
                LOG_ERR("download: write() failed: %s", strerror(errno));
                break;
            }
            EVP_DigestUpdate(md5ctx, bin.data(), bin.size());
            total_written += static_cast<long long>(bin.size());
        }

        int result = root->find("result").as_int(-999);
        if (result == 1) continue;
        if (result == 0) {
            long long tot = root->find("reply.total").as_int(-1);
            if (tot >= 0) expect_total = tot;
            expect_md5 = root->find("reply.file_md5").as_string();
            ok = true;
            break;
        }
        LOG_ERR("download: unexpected result=%d", result);
        break;
    }

    if (ok && expect_total >= 0 && total_written != expect_total) {
        LOG_ERR("download: size mismatch (got %lld, expected %lld)",
                total_written, expect_total);
        ok = false;
    }
    if (ok && !expect_md5.empty()) {
        unsigned char digest[16]; unsigned int dlen = 0;
        EVP_DigestFinal_ex(md5ctx, digest, &dlen);
        char got_md5[33]{};
        for (int i = 0; i < 16; ++i)
            snprintf(got_md5 + 2 * i, 3, "%02x", static_cast<unsigned>(digest[i]));
        std::string em = expect_md5;
        std::transform(em.begin(), em.end(), em.begin(), ::tolower);
        if (std::string(got_md5) != em) {
            LOG_ERR("download: MD5 mismatch (got %s, expected %s)", got_md5, em.c_str());
            ok = false;
        }
    }

    EVP_MD_CTX_free(md5ctx);
    obn::tls::close_tls(&fd, &ssl);
    return ok ? total_written : -1;
}

// ---------------------------------------------------------------------------
// ffmpeg helpers
// ---------------------------------------------------------------------------

static int run_cmd(const std::vector<std::string>& argv_)
{
    std::vector<const char*> argv;
    for (const auto& a : argv_) argv.push_back(a.c_str());
    argv.push_back(nullptr);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) { execvp(argv[0], const_cast<char* const*>(argv.data())); _exit(127); }
    int wstatus = 0;
    waitpid(pid, &wstatus, 0);
    return WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
}

static double probe_duration(const std::string& path)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1.0;
    pid_t pid = fork();
    if (pid < 0) { ::close(pipefd[0]); ::close(pipefd[1]); return -1.0; }
    if (pid == 0) {
        ::close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) dup2(devnull, STDERR_FILENO);
        execlp("ffprobe", "ffprobe", "-v", "quiet",
               "-show_entries", "format=duration",
               "-of", "default=noprint_wrappers=1:nokey=1",
               path.c_str(), nullptr);
        _exit(127);
    }
    ::close(pipefd[1]);
    char buf[128]{}; ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    ::close(pipefd[0]);
    int wstatus = 0; waitpid(pid, &wstatus, 0);
    if (n <= 0 || !WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) return -1.0;
    try { return std::stod(buf); } catch (...) { return -1.0; }
}

static bool trim_last_seconds(const std::string& src, const std::string& dst, double seconds)
{
    double duration = probe_duration(src);
    if (duration <= 0.0) return false;
    char seek_str[64], dur_str[64];
    snprintf(seek_str, sizeof(seek_str), "%.3f", std::max(0.0, duration - seconds));
    snprintf(dur_str,  sizeof(dur_str),  "%.3f", seconds);
    return run_cmd({"ffmpeg", "-y", "-i", src,
                    "-ss", seek_str, "-t", dur_str, "-c", "copy", dst}) == 0;
}

static void probe_video(const std::string& path)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) return;
    pid_t pid = fork();
    if (pid < 0) { ::close(pipefd[0]); ::close(pipefd[1]); return; }
    if (pid == 0) {
        ::close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) dup2(devnull, STDERR_FILENO);
        execlp("ffprobe", "ffprobe", "-v", "quiet", "-show_format", "-show_streams",
               path.c_str(), nullptr);
        _exit(127);
    }
    ::close(pipefd[1]);
    char buf[8192]{}; ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    ::close(pipefd[0]);
    waitpid(pid, nullptr, 0);
    if (n <= 0) return;
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.find("codec_name")   != std::string::npos ||
            line.find("width")        != std::string::npos ||
            line.find("height")       != std::string::npos ||
            line.find("duration=")    != std::string::npos ||
            line.find("bit_rate")     != std::string::npos ||
            line.find("nb_frames")    != std::string::npos ||
            line.find("r_frame_rate") != std::string::npos)
            printf("  %s\n", line.c_str());
    }
    fflush(stdout);
}

// ---------------------------------------------------------------------------
// Temporary file (RAII)
// ---------------------------------------------------------------------------

struct TempFile {
    std::string path;
    explicit TempFile(const std::string& suffix)
    {
        const char* tmpdir = getenv("TMPDIR");
        if (!tmpdir || !*tmpdir) tmpdir = "/tmp";
        path = std::string(tmpdir) + "/h2s_capture_XXXXXX" + suffix;
        int fd = mkstemps(const_cast<char*>(path.c_str()), static_cast<int>(suffix.size()));
        if (fd >= 0) ::close(fd); else path.clear();
    }
    ~TempFile() { if (!path.empty()) unlink(path.c_str()); }
    bool ok() const { return !path.empty(); }
};

// ---------------------------------------------------------------------------
// High-level fetch
// ---------------------------------------------------------------------------

static long long download_to_path(const char* host, const tl::Config& cfg,
                                   const FileEntry& entry, const std::string& out_path)
{
    int fd = open(out_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { LOG_ERR("cannot open %s: %s", out_path.c_str(), strerror(errno)); return -1; }
    long long bytes = download_to_fd(host, cfg, entry, fd);
    ::close(fd);
    if (bytes < 0) unlink(out_path.c_str());
    return bytes;
}

static int fetch_video(const char* host, const tl::Config& cfg,
                        const std::string& out_path, int index, double last_seconds)
{
    LOG_INFO("Connecting to %s:6000 (video) ...", host);
    std::vector<FileEntry> entries;
    if (!list_info(host, cfg, "video", entries))
        throw std::runtime_error("list_info(video) failed");
    if (entries.empty()) throw std::runtime_error("no ipcam-record files found on printer");

    std::sort(entries.begin(), entries.end(),
              [](const FileEntry& a, const FileEntry& b){ return a.mtime > b.mtime; });

    LOG_INFO("%zu ipcam-record file(s) available", entries.size());
    for (size_t i = 0; i < std::min(entries.size(), size_t(5)); ++i)
        LOG_INFO("  %s  %lld MB", entries[i].name.c_str(), entries[i].size / (1024 * 1024));

    if (index < 0 || static_cast<size_t>(index) >= entries.size())
        throw std::runtime_error("--index " + std::to_string(index) + " out of range");

    const FileEntry& target = entries[index];
    LOG_INFO("Downloading %s (%lld MB) ...", target.name.c_str(), target.size / (1024 * 1024));
    auto t0 = Clock::now();

    if (last_seconds > 0.0) {
        TempFile tmp(".mp4");
        if (!tmp.ok()) throw std::runtime_error("cannot create temp file");
        long long bytes = download_to_path(host, cfg, target, tmp.path);
        if (bytes < 0) throw std::runtime_error("download failed");

        auto elapsed = std::chrono::duration<double>(Clock::now() - t0).count();
        LOG_INFO("Downloaded %lld MB in %.1fs (%.0f KB/s)",
                 bytes / (1024*1024), elapsed, bytes / elapsed / 1024.0);
        LOG_INFO("Extracting last %.0fs ...", last_seconds);

        if (trim_last_seconds(tmp.path, out_path, last_seconds)) {
            LOG_INFO("Saved %.0fs clip -> %s", last_seconds, out_path.c_str());
        } else {
            LOG_INFO("ffmpeg trim failed; saving full file");
            if (rename(tmp.path.c_str(), out_path.c_str()) == 0) {
                tmp.path.clear();
            } else {
                int src_fd = open(tmp.path.c_str(), O_RDONLY);
                int dst_fd = open(out_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (src_fd >= 0 && dst_fd >= 0) {
                    char cbuf[65536]; ssize_t rn;
                    while ((rn = read(src_fd, cbuf, sizeof(cbuf))) > 0)
                        write(dst_fd, cbuf, static_cast<size_t>(rn));
                }
                if (src_fd >= 0) ::close(src_fd);
                if (dst_fd >= 0) ::close(dst_fd);
            }
            LOG_INFO("Saved %lld MB -> %s", bytes / 1024 / 1024, out_path.c_str());
        }
    } else {
        long long bytes = download_to_path(host, cfg, target, out_path);
        if (bytes < 0) throw std::runtime_error("download failed");
        auto elapsed = std::chrono::duration<double>(Clock::now() - t0).count();
        LOG_INFO("Saved %lld MB -> %s (%.0f KB/s)",
                 bytes / 1024 / 1024, out_path.c_str(), bytes / elapsed / 1024.0);
    }
    return 0;
}

static int fetch_timelapse(const char* host, const tl::Config& cfg,
                            const std::string& out_path, int index, double min_seconds)
{
    LOG_INFO("Connecting to %s:6000 (timelapse) ...", host);
    std::vector<FileEntry> entries;
    if (!list_info(host, cfg, "timelapse", entries))
        throw std::runtime_error("list_info(timelapse) failed");
    if (entries.empty()) throw std::runtime_error("no timelapse files found on printer");

    std::sort(entries.begin(), entries.end(),
              [](const FileEntry& a, const FileEntry& b){ return a.mtime > b.mtime; });

    LOG_INFO("%zu timelapse file(s) available", entries.size());

    const FileEntry* target = nullptr;
    if (index != 0) {
        if (static_cast<size_t>(index) >= entries.size())
            throw std::runtime_error("--index " + std::to_string(index) + " out of range");
        target = &entries[index];
        LOG_INFO("Fetching index %d: %s", index, target->name.c_str());
    } else {
        for (const auto& e : entries) {
            double est_seconds = static_cast<double>(e.size) / 750000.0;
            LOG_INFO("  %s  %lld KB  path=%s", e.name.c_str(), e.size / 1024, e.path.c_str());
            if (est_seconds < min_seconds) {
                LOG_INFO("    (skipping - estimated %.1fs < %.0fs)", est_seconds, min_seconds);
                continue;
            }
            target = &e;
            break;
        }
        if (!target) throw std::runtime_error("no timelapse file meets --min-seconds");
    }

    LOG_INFO("Downloading %s (%lld KB) ...", target->name.c_str(), target->size / 1024);
    auto t0 = Clock::now();
    long long bytes = download_to_path(host, cfg, *target, out_path);
    if (bytes < 0) throw std::runtime_error("download failed");

    auto elapsed = std::chrono::duration<double>(Clock::now() - t0).count();
    LOG_INFO("Downloaded %lld bytes in %.1fs (%.0f KB/s)", bytes, elapsed, bytes / elapsed / 1024.0);
    LOG_INFO("Saved %lld bytes -> %s", bytes, out_path.c_str());
    return 0;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

static void usage(const char* prog)
{
    fprintf(stderr,
        "Usage: %s <printer_ip> <access_code> [output.mp4]\n"
        "           [--type video|timelapse] [--last-seconds N]\n"
        "           [--index N] [--min-seconds N] [--username U]\n"
        "\n"
        "  --type          video (default) or timelapse\n"
        "  --last-seconds  (video) extract last N seconds; 0 = full file (default: 10)\n"
        "  --index         which file to fetch (0 = most recent, default: 0)\n"
        "  --min-seconds   (timelapse) skip files shorter than N seconds (default: 5)\n"
        "  --username      login username (default: bblp)\n",
        prog);
}

int main(int argc, char* argv[])
{
    const char* printer_ip  = nullptr;
    const char* access_code = nullptr;
    std::string output       = "h2s_capture.mp4";
    std::string type         = "video";
    std::string username     = "bblp";
    int         index        = 0;
    double      last_seconds = 10.0;
    double      min_seconds  = 5.0;

    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if      (!printer_ip  && a[0] != '-') { printer_ip  = a; }
        else if (!access_code && a[0] != '-') { access_code = a; }
        else if (strcmp(a, "--type")         == 0 && i + 1 < argc) { type         = argv[++i]; }
        else if (strcmp(a, "--username")     == 0 && i + 1 < argc) { username     = argv[++i]; }
        else if (strcmp(a, "--index")        == 0 && i + 1 < argc) { index        = atoi(argv[++i]); }
        else if (strcmp(a, "--last-seconds") == 0 && i + 1 < argc) { last_seconds = atof(argv[++i]); }
        else if (strcmp(a, "--min-seconds")  == 0 && i + 1 < argc) { min_seconds  = atof(argv[++i]); }
        else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) { usage(argv[0]); return 0; }
        else if (a[0] != '-') { output = a; }
        else { fprintf(stderr, "Unknown option: %s\n", a); usage(argv[0]); return 1; }
    }

    if (!printer_ip || !access_code) { usage(argv[0]); return 1; }
    if (type != "video" && type != "timelapse") {
        fprintf(stderr, "error: --type must be 'video' or 'timelapse'\n"); return 1;
    }

    tl::Config cfg;
    cfg.username    = username;
    cfg.access_code = access_code;

    try {
        int rc = (type == "video")
            ? fetch_video(printer_ip, cfg, output, index, last_seconds)
            : fetch_timelapse(printer_ip, cfg, output, index, min_seconds);
        if (rc == 0) probe_video(output);
        return rc;
    } catch (const std::exception& e) {
        LOG_ERR("Error: %s", e.what());
        return 1;
    }
}
