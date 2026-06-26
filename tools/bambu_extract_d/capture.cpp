#include "capture.h"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>
#include <vector>
#include <arpa/inet.h>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/procfs.h>

// ============================================================================
// openat supervisor globals — definitions (declared extern in capture.h)
// ============================================================================
int g_openat_notif_fd = -1;
int g_openat_notif_pipe_rd = -1;
std::atomic<bool> g_notif_stop_flag{false};
std::thread g_notif_thread;
std::atomic<pid_t> g_libbambu_seen_pid{0};
std::string g_plugin_path_detect;

// ============================================================================
// ptrace helpers
// ============================================================================
static const long DR_OFFSET = offsetof(struct user, u_debugreg[0]);
static bool g_suppress_dr_errors = false;

static bool poke_dr(pid_t pid, int idx, uint64_t val) {
    long off = DR_OFFSET + idx * (long)sizeof(uint64_t);
    if (ptrace(PTRACE_POKEUSER, pid, (void*)off, (void*)val) < 0) {
        if (!g_suppress_dr_errors) {
            LOG_E("PTRACE_POKEUSER dr%d: %s", idx, strerror(errno));
        }
        return false;
    }
    return true;
}

static long peek_dr(pid_t pid, int idx) {
    long off = DR_OFFSET + idx * (long)sizeof(uint64_t);
    errno = 0;
    long v = ptrace(PTRACE_PEEKUSER, pid, (void*)off, 0);
    if (errno != 0) return -1;
    return v;
}



static bool arm_dr_on_tid(pid_t tid, uint64_t acc_va) {
    if (!poke_dr(tid, 0, acc_va))     return false;
    if (!poke_dr(tid, 6, 0))          return false;
    if (!poke_dr(tid, 7, 0x00000401)) return false;
    return true;
}

static bool disarm_dr_on_tid(pid_t tid) {
    poke_dr(tid, 7, 0);
    poke_dr(tid, 6, 0);
    poke_dr(tid, 0, 0);
    poke_dr(tid, 1, 0);
    poke_dr(tid, 2, 0);
    poke_dr(tid, 3, 0);
    return true;
}

static bool cont_with_sig(pid_t tid, int sig) {
    if (ptrace(PTRACE_CONT, tid, 0, (void*)(long)sig) < 0) {
        LOG_W("PTRACE_CONT tid=%d sig=%d: %s", tid, sig, strerror(errno));
        return false;
    }
    return true;
}

static pid_t read_tracer_pid(pid_t pid) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    std::ifstream f(path);
    if (!f) return 0;
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            return (pid_t)std::atoi(line.c_str() + 10);
        }
    }
    return 0;
}

static std::vector<pid_t> enumerate_tids(pid_t pid) {
    std::vector<pid_t> out;
    char dirpath[64];
    std::snprintf(dirpath, sizeof(dirpath), "/proc/%d/task", (int)pid);
    DIR* d = opendir(dirpath);
    if (!d) return out;
    struct dirent* ent;
    while ((ent = readdir(d)) != nullptr) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        out.push_back((pid_t)std::atoi(ent->d_name));
    }
    closedir(d);
    return out;
}

PluginMapInfo read_plugin_map_info(pid_t pid, const std::string& plugin_path) {
    PluginMapInfo M;
    std::string bn;
    {
        size_t p = plugin_path.find_last_of('/');
        bn = (p == std::string::npos) ? plugin_path : plugin_path.substr(p + 1);
    }
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    std::ifstream f(path);
    if (!f) return M;
    std::string line;
    bool found_file = false;
    while (std::getline(f, line)) {
        size_t dash = line.find('-');
        size_t sp = line.find(' ');
        size_t sp2 = line.find(' ', sp + 1);
        if (dash == std::string::npos || sp == std::string::npos || sp2 == std::string::npos) continue;
        uint64_t lo = std::stoull(line.substr(0, dash), nullptr, 16);
        uint64_t hi = std::stoull(line.substr(dash + 1, sp - dash - 1), nullptr, 16);
        std::string perms = line.substr(sp + 1, sp2 - sp - 1);
        if (perms.size() < 4 || perms[2] != 'x') continue;
        bool has_bn = line.find(bn) != std::string::npos;
        bool is_anon = (line.find('/') == std::string::npos);
        if (has_bn) {
            if (!found_file || lo < M.file_lo) M.file_lo = lo;
            if (hi > M.file_hi) M.file_hi = hi;
            found_file = true;
        } else if (is_anon && found_file && lo >= M.file_hi && lo < M.file_hi + 0x100000) {
            if (M.arena2_lo == 0) M.arena2_lo = lo;
            M.arena2_hi = hi;
        }
    }
    return M;
}

static bool read_tracee_mem(pid_t pid, uint64_t va, void* dst, size_t n) {
    struct iovec local{ dst, n };
    struct iovec remote{ (void*)va, n };
    ssize_t got = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return got == (ssize_t)n;
}


// Scan memory for the byte_load+accumulator pair.
static uint64_t discover_accumulator_pc(pid_t child, uint64_t lo, uint64_t hi,
                                        uint64_t* discovered_wrap_va,
                                        uint64_t* discovered_byte_va,
                                        int* discovered_conv) {
    if (discovered_wrap_va) *discovered_wrap_va = 0;
    if (discovered_conv) *discovered_conv = 0;
    if (discovered_byte_va) *discovered_byte_va = 0;

    static const uint8_t K_BE[] = {
        0x42,0x8a,0x2f,0x98, 0x71,0x37,0x44,0x91,
        0xb5,0xc0,0xfb,0xcf, 0xe9,0xb5,0xdb,0xa5
    };
    static const uint8_t K_LE[] = {
        0x98,0x2f,0x8a,0x42, 0x91,0x44,0x37,0x71,
        0xcf,0xfb,0xc0,0xb5, 0xa5,0xdb,0xb5,0xe9
    };
    uint64_t k_table_va = 0;
    {
        std::vector<uint8_t> buf(4096 + 32);
        for (uint64_t cur = lo; cur < hi && !k_table_va; cur += 4096) {
            size_t want = std::min<uint64_t>(4096, hi - cur);
            if (!read_tracee_mem(child, cur, buf.data(), want)) continue;
            for (size_t i = 0; i + 16 <= want; ++i) {
                if (std::memcmp(buf.data() + i, K_BE, 16) == 0 ||
                    std::memcmp(buf.data() + i, K_LE, 16) == 0) {
                    k_table_va = cur + i;
                    LOG_I("[discover] SHA-256 K-table @0x%lx", (unsigned long)k_table_va);
                    break;
                }
            }
        }
    }
    if (!k_table_va) {
        LOG_W("[discover] SHA-256 K-table not found — sign path may not be decoded");
    }

    struct Conv {
        uint8_t bl_third;
        uint8_t bl_fourth;
        uint8_t ac_second;
        const char* name;
        bool has_fourth;
    };
    static const Conv CONVS[] = {
        {0x11, 0, 0x54, "edx<-[rcx]",  false},
        {0x10, 0, 0x54, "edx<-[rax]",  false},
        {0x12, 0, 0x54, "edx<-[rdx]",  false},
        {0x13, 0, 0x54, "edx<-[rbx]",  false},
        {0x16, 0, 0x54, "edx<-[rsi]",  false},
        {0x17, 0, 0x54, "edx<-[rdi]",  false},
        {0x55, 0x00, 0x54, "edx<-[rbp+0]", true},
        {0x01, 0, 0x44, "eax<-[rcx]",  false},
        {0x00, 0, 0x44, "eax<-[rax]",  false},
        {0x02, 0, 0x44, "eax<-[rdx]",  false},
        {0x03, 0, 0x44, "eax<-[rbx]",  false},
        {0x06, 0, 0x44, "eax<-[rsi]",  false},
        {0x07, 0, 0x44, "eax<-[rdi]",  false},
        {0x45, 0x00, 0x44, "eax<-[rbp+0]", true},
        {0x09, 0, 0x4c, "ecx<-[rcx]",  false},
        {0x08, 0, 0x4c, "ecx<-[rax]",  false},
        {0x0a, 0, 0x4c, "ecx<-[rdx]",  false},
        {0x0b, 0, 0x4c, "ecx<-[rbx]",  false},
        {0x0e, 0, 0x4c, "ecx<-[rsi]",  false},
        {0x0f, 0, 0x4c, "ecx<-[rdi]",  false},
        {0x4d, 0x00, 0x4c, "ecx<-[rbp+0]", true},
        {0x19, 0, 0x5c, "ebx<-[rcx]",  false},
        {0x18, 0, 0x5c, "ebx<-[rax]",  false},
        {0x1a, 0, 0x5c, "ebx<-[rdx]",  false},
        {0x1b, 0, 0x5c, "ebx<-[rbx]",  false},
        {0x1e, 0, 0x5c, "ebx<-[rsi]",  false},
        {0x1f, 0, 0x5c, "ebx<-[rdi]",  false},
        {0x5d, 0x00, 0x5c, "ebx<-[rbp+0]", true},
    };
    static const int N_CONVS = (int)(sizeof(CONVS)/sizeof(CONVS[0]));
    struct Cand { uint64_t va_bl, va_ac; int conv; int dist; };
    std::vector<Cand> cands;
    {
        const size_t PAGE = 4096;
        std::vector<uint8_t> buf(PAGE + 256);
        for (uint64_t cur = lo; cur < hi; cur += PAGE) {
            size_t want = std::min<uint64_t>(PAGE + 256, hi - cur);
            if (!read_tracee_mem(child, cur, buf.data(), want)) continue;
            for (size_t i = 0; i + 3 <= want; ++i) {
                if (buf[i] != 0x0f || buf[i+1] != 0xb6) continue;
                int cv = -1;
                for (int c = 0; c < N_CONVS; ++c) {
                    if (buf[i+2] == CONVS[c].bl_third) {
                        if (CONVS[c].has_fourth) {
                            if (i + 3 < want && buf[i+3] == CONVS[c].bl_fourth)
                                cv = c;
                        } else {
                            cv = c;
                        }
                        if (cv >= 0) break;
                    }
                }
                if (cv < 0) continue;
                size_t scan_lo = (i > 80) ? i - 80 : 0;
                size_t scan_hi = std::min(want, i + 80);
                for (size_t j = scan_lo; j + 4 <= scan_hi; ++j) {
                    if (buf[j] == 0x89 && buf[j+1] == CONVS[cv].ac_second &&
                        buf[j+2] == 0x24) {
                        cands.push_back({cur + i, cur + j, cv, int(j) - int(i)});
                    }
                }
            }
        }
    }
    LOG_I("[discover] %zu byte_load+accumulator candidates", cands.size());
    for (size_t i = 0; i < cands.size() && i < 500; ++i) {
        LOG_I("[discover]   #%zu conv=%s bl@0x%lx ac@0x%lx dist=%d",
              i, CONVS[cands[i].conv].name,
              (unsigned long)cands[i].va_bl, (unsigned long)cands[i].va_ac,
              cands[i].dist);
    }
    if (cands.empty()) return 0;

    Cand best{}; bool have = false;
    for (auto& c : cands) {
        if (c.conv == 0 && c.dist >= 40 && c.dist <= 60) {
            best = c; have = true; break;
        }
    }
    if (!have && k_table_va) {
        uint64_t best_d = UINT64_MAX;
        for (auto& c : cands) {
            uint64_t d = (c.va_ac > k_table_va) ? (c.va_ac - k_table_va) : (k_table_va - c.va_ac);
            if (d < best_d) { best_d = d; best = c; have = true; }
        }
    }
    const char* env_idx = std::getenv("BBL_CAND_IDX");
    if (!have && env_idx) {
        int idx = std::atoi(env_idx);
        if (idx >= 0 && (size_t)idx < cands.size()) {
            best = cands[idx];
            have = true;
            LOG_I("[discover] BBL_CAND_IDX=%d selected: conv=%s bl@0x%lx ac@0x%lx dist=%d",
                  idx, CONVS[best.conv].name,
                  (unsigned long)best.va_bl, (unsigned long)best.va_ac, best.dist);
        } else {
            LOG_W("[discover] BBL_CAND_IDX=%d out of range (have %zu cands)", idx, cands.size());
        }
    }
    if (!have) {
        LOG_W("[discover] no high-confidence candidate (K-table absent, no edx dist[40,60]) — "
              "returning 0 so caller may use VersionProfile offset");
        return 0;
    }
    LOG_I("[discover] CHOSEN: conv=%s bl@0x%lx ac@0x%lx dist=%d",
          CONVS[best.conv].name,
          (unsigned long)best.va_bl, (unsigned long)best.va_ac, best.dist);
    if (discovered_byte_va) *discovered_byte_va = best.va_bl;
    if (discovered_conv) *discovered_conv = best.conv;
    return best.va_ac;
}

// ============================================================================
// openat supervisor thread
// ============================================================================
static void openat_supervisor_thread_fn(int notif_fd, std::atomic<bool>* stop_flag)
{
    struct seccomp_notif_sizes nsizes = {};
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &nsizes) < 0) {
        fprintf(stderr, "[openat_sup] SECCOMP_GET_NOTIF_SIZES failed: %s\n",
                strerror(errno));
        return;
    }

    size_t req_sz  = std::max((size_t)nsizes.seccomp_notif,      sizeof(struct seccomp_notif));
    size_t resp_sz = std::max((size_t)nsizes.seccomp_notif_resp, sizeof(struct seccomp_notif_resp));

    auto* req  = (struct seccomp_notif*)     calloc(1, req_sz);
    auto* resp = (struct seccomp_notif_resp*)calloc(1, resp_sz);
    if (!req || !resp) {
        fprintf(stderr, "[openat_sup] alloc failed\n");
        free(req); free(resp);
        return;
    }

    fprintf(stderr, "[openat_sup] started, notif_fd=%d\n", notif_fd);

    while (!stop_flag->load(std::memory_order_relaxed)) {
        struct pollfd pf = { notif_fd, POLLIN, 0 };
        int pr = poll(&pf, 1, 200);
        if (pr < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[openat_sup] poll error errno=%d (%s)\n", errno, strerror(errno));
            break;
        }
        if (pr == 0) continue;
        if (!(pf.revents & POLLIN)) {
            if (pf.revents & POLLERR) {
                fprintf(stderr, "[openat_sup] poll POLLERR — fd invalid, stopping\n");
                break;
            }
            continue;
        }

        memset(req, 0, req_sz);
        if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOENT) continue;
            fprintf(stderr, "[openat_sup] NOTIF_RECV failed errno=%d (%s)\n",
                    errno, strerror(errno));
            break;
        }

        memset(resp, 0, resp_sz);
        resp->id = req->id;

        uintptr_t path_addr = (uintptr_t)req->data.args[1];
        char path_buf[PATH_MAX] = {};
        bool is_status = false;

        if (path_addr != 0) {
            char mem_path[64];
            snprintf(mem_path, sizeof(mem_path), "/proc/%u/mem", req->pid);
            int mem_fd = open(mem_path, O_RDONLY | O_CLOEXEC);
            if (mem_fd >= 0) {
                ssize_t n = pread(mem_fd, path_buf, sizeof(path_buf) - 1, (off_t)path_addr);
                close(mem_fd);
                if (n > 0) {
                    path_buf[n] = '\0';
                    if (strstr(path_buf, "/status") &&
                        strncmp(path_buf, "/proc/", 6) == 0) {
                        is_status = true;
                    }
                }
            }
        }

        if (is_status) {
            char real_status_path[64];
            snprintf(real_status_path, sizeof(real_status_path),
                     "/proc/%u/status", req->pid);
            int real_status_fd = open(real_status_path, O_RDONLY | O_CLOEXEC);
            char fake_content[8192] = {};
            ssize_t fake_len = 0;
            if (real_status_fd >= 0) {
                fake_len = read(real_status_fd, fake_content, sizeof(fake_content) - 1);
                close(real_status_fd);
            }
            if (fake_len <= 0) {
                fake_len = snprintf(fake_content, sizeof(fake_content),
                                    "Name:\tprocess\nState:\tS (sleeping)\n"
                                    "Pid:\t%u\nTracerPid:\t0\n", req->pid);
            }
            const char* tp_label = "TracerPid:";
            char* tp_ptr = (char*)memmem(fake_content, (size_t)fake_len,
                                          tp_label, strlen(tp_label));
            if (tp_ptr) {
                char* val = tp_ptr + strlen(tp_label);
                while (val < fake_content + fake_len && (*val == ' ' || *val == '\t')) ++val;
                char* d = val;
                while (d < fake_content + fake_len && *d >= '0' && *d <= '9') ++d;
                if (d > val) {
                    val[0] = '0';
                    for (char* p = val + 1; p < d; ++p) *p = ' ';
                }
            }

            int mfd = memfd_create("status_fake", MFD_CLOEXEC);
            bool injected = false;
            if (mfd >= 0) {
                if (write(mfd, fake_content, (size_t)fake_len) == fake_len) {
                    lseek(mfd, 0, SEEK_SET);
                    struct seccomp_notif_addfd addfd = {};
                    addfd.id = req->id;
                    addfd.flags = 0;
                    addfd.srcfd = (uint32_t)mfd;
                    addfd.newfd = 0;
                    addfd.newfd_flags = O_RDONLY;
                    long new_daemon_fd = ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
                    if (new_daemon_fd >= 0) {
                        resp->val   = new_daemon_fd;
                        resp->error = 0;
                        resp->flags = 0;
                        injected = true;
                        fprintf(stderr, "[openat_sup] FAKED pid=%u path=%s -> daemon_fd=%ld\n",
                                req->pid, path_buf, new_daemon_fd);
                    } else {
                        fprintf(stderr, "[openat_sup] ADDFD failed errno=%d (%s) for path=%s\n",
                                errno, strerror(errno), path_buf);
                    }
                }
                close(mfd);
            }
            if (!injected) {
                resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                resp->error = 0;
                resp->val   = 0;
                fprintf(stderr, "[openat_sup] ADDFD fallback CONTINUE for path=%s\n", path_buf);
            }
        } else {
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            resp->error = 0;
            resp->val   = 0;
            static int pass_count = 0;
            ++pass_count;
            struct timespec ts2 = {};
            clock_gettime(CLOCK_MONOTONIC, &ts2);
            double t_ms = ts2.tv_sec * 1000.0 + ts2.tv_nsec / 1e6;
            fprintf(stderr, "[openat_sup] PASS#%d @%.1fms pid=%u path=%s\n",
                    pass_count, t_ms, req->pid, path_buf[0] ? path_buf : "(empty)");
            if (strstr(path_buf, "libbambu_networking") != nullptr) {
                pid_t expected = 0;
                pid_t proc_pid = (pid_t)req->pid;
                char tpid_path[64];
                snprintf(tpid_path, sizeof(tpid_path), "/proc/%u/status", req->pid);
                FILE* tf = fopen(tpid_path, "r");
                if (tf) {
                    char line[128];
                    while (fgets(line, sizeof(line), tf)) {
                        if (strncmp(line, "Tgid:", 5) == 0) {
                            proc_pid = (pid_t)atoi(line + 5);
                            break;
                        }
                    }
                    fclose(tf);
                }
                g_libbambu_seen_pid.compare_exchange_strong(expected, proc_pid);
                fprintf(stderr, "[openat_sup] libbambu_networking opened by tgid=%d\n", (int)proc_pid);
            }
        }

        if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0) {
            if (errno == ENOENT) continue;
            fprintf(stderr, "[openat_sup] NOTIF_SEND failed: %s\n", strerror(errno));
        }
    }

    fprintf(stderr, "[openat_sup] stopped\n");
    free(req);
    free(resp);
}

// Public wrapper used by main.cpp to start the thread.
// (The thread function takes (nfd, &g_notif_stop_flag).)
// Exposed as a lambda-capture in main.cpp:
//   g_notif_thread = std::thread([nfd]() {
//       openat_supervisor_thread(nfd, &g_notif_stop_flag);
//   });
// But we need it accessible so capture.cpp can call it internally too.
// Export via a free function:
void openat_supervisor_thread(int notif_fd, std::atomic<bool>* stop_flag) {
    openat_supervisor_thread_fn(notif_fd, stop_flag);
}

// ============================================================================
// drive_capture_attach
// ============================================================================
static std::atomic<int> g_attach_interrupted{0};
static void attach_sigint_handler(int /*signo*/) {
    g_attach_interrupted.store(1, std::memory_order_relaxed);
}


CaptureResult drive_capture_attach(pid_t target,
                                   const std::string& plugin_path,
                                   int timeout_s,
                                   bool require_bytes,
                                   const VersionProfile* ver) {
    CaptureResult R;
    std::vector<pid_t> seized;

    auto cleanup_detach = [&]() {
        LOG_I("[attach] cleanup: detaching %zu tid(s)", seized.size());
        for (pid_t t : seized) {
            if (ptrace(PTRACE_INTERRUPT, t, 0, 0) < 0 && errno != ESRCH) {
                LOG_V("[attach] cleanup PTRACE_INTERRUPT(%d): %s", t, strerror(errno));
            }
            int st = 0;
            for (int i = 0; i < 100; ++i) {
                pid_t r = waitpid(t, &st, WNOHANG | __WALL);
                if (r == t && WIFSTOPPED(st)) break;
                if (r < 0) break;
                usleep(2 * 1000);
            }
            long off7 = DR_OFFSET + 7 * (long)sizeof(uint64_t);
            ptrace(PTRACE_POKEUSER, t, (void*)off7, 0);
            long off0 = DR_OFFSET + 0 * (long)sizeof(uint64_t);
            ptrace(PTRACE_POKEUSER, t, (void*)off0, 0);
            if (ptrace(PTRACE_DETACH, t, 0, 0) < 0 && errno != ESRCH) {
                LOG_V("[attach] PTRACE_DETACH tid=%d: %s", t, strerror(errno));
            }
        }
        pid_t tp = 0;
        for (int i = 0; i < 50; ++i) {
            tp = read_tracer_pid(target);
            if (tp == 0) break;
            usleep(10 * 1000);
        }
        if (tp == 0) {
            LOG_I("[attach] /proc/%d/status TracerPid=0 (clean)", target);
        } else {
            LOG_E("[attach] WARNING: /proc/%d/status TracerPid=%d (NOT clean!)",
                  target, tp);
        }
    };

    if (kill(target, 0) != 0) {
        LOG_E("[attach] pid %d not alive: %s", target, strerror(errno));
        return R;
    }

    struct sigaction sa{}, oldsa{};
    sa.sa_handler = attach_sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, &oldsa);
    auto restore_sigint = [&]() { sigaction(SIGINT, &oldsa, nullptr); };

    {
        pid_t watchdog = read_tracer_pid(target);
        if (watchdog > 0 && watchdog != getpid()) {
            LOG_I("[attach] VMP watchdog detected: TracerPid=%d — killing", watchdog);
            kill(watchdog, SIGKILL);
            for (int i = 0; i < 100; ++i) {
                if (read_tracer_pid(target) == 0) break;
                usleep(10 * 1000);
            }
            pid_t still = read_tracer_pid(target);
            if (still != 0) {
                LOG_W("[attach] watchdog still tracing (TracerPid=%d) after kill — SEIZE may fail", still);
            } else {
                LOG_I("[attach] watchdog killed, ptrace lock released");
            }
        } else if (watchdog == 0) {
            LOG_I("[attach] no watchdog (TracerPid=0)");
        }
    }

    long opts = PTRACE_O_TRACECLONE
              | PTRACE_O_TRACEFORK
              | PTRACE_O_TRACEVFORK
              | PTRACE_O_TRACEEXIT;

    LOG_I("[attach] PTRACE_SEIZE main pid %d", target);
    if (ptrace(PTRACE_SEIZE, target, 0, (void*)opts) < 0) {
        LOG_E("[attach] PTRACE_SEIZE pid=%d: %s", target, strerror(errno));
        if (errno == EPERM) {
            LOG_E("[attach] hint: check /proc/sys/kernel/yama/ptrace_scope and");
            LOG_E("[attach]       CAP_SYS_PTRACE; may need sudo or prctl(PR_SET_PTRACER).");
        }
        restore_sigint();
        return R;
    }
    seized.push_back(target);

    std::vector<pid_t> tids = enumerate_tids(target);
    LOG_I("[attach] enumerated %zu tid(s) under /proc/%d/task", tids.size(), target);
    for (pid_t t : tids) {
        if (t == target) continue;
        if (ptrace(PTRACE_SEIZE, t, 0, (void*)opts) < 0) {
            LOG_V("[attach] SEIZE tid=%d failed (%s) — skipping", t, strerror(errno));
            continue;
        }
        seized.push_back(t);
    }
    LOG_I("[attach] seized %zu tid(s) total", seized.size());

    if (g_openat_notif_fd >= 0 && g_notif_thread.joinable()) {
        LOG_I("[attach] openat supervisor running (notif_fd=%d)", g_openat_notif_fd);
    } else {
        LOG_I("[attach] openat supervisor not available");
    }

    auto stop_notif_thread = [&]() {
        g_notif_stop_flag.store(true, std::memory_order_relaxed);
        if (g_notif_thread.joinable()) {
            if (g_openat_notif_fd >= 0) {
                close(g_openat_notif_fd);
                g_openat_notif_fd = -1;
            }
            g_notif_thread.join();
        }
    };

    PluginMapInfo M = read_plugin_map_info(target, plugin_path);
    if (M.file_lo == 0) {
        LOG_E("[attach] %s not found in /proc/%d/maps r-xp",
              plugin_path.c_str(), target);
        stop_notif_thread();
        cleanup_detach();
        restore_sigint();
        return R;
    }
    LOG_I("[attach] libbambu r-xp file: 0x%lx-0x%lx (%.1f MB)",
          (unsigned long)M.file_lo, (unsigned long)M.file_hi,
          (M.file_hi - M.file_lo) / (1024.0 * 1024.0));
    if (M.arena2_lo) {
        LOG_I("[attach] libbambu r-xp anon arena2: 0x%lx-0x%lx (%.1f MB)",
              (unsigned long)M.arena2_lo, (unsigned long)M.arena2_hi,
              (M.arena2_hi - M.arena2_lo) / (1024.0 * 1024.0));
    }

    uint64_t acc_va = 0;
    int acc_conv = 0;
    if (const char* env_acc = std::getenv("BBL_ACC_VA")) {
        acc_va = std::stoull(env_acc, nullptr, 0);
        LOG_I("[attach] accumulator VA from env override: 0x%lx", (unsigned long)acc_va);
    } else if (M.arena2_lo && M.arena2_hi > M.arena2_lo) {
        uint64_t disc_bl = 0;
        acc_va = discover_accumulator_pc(target, M.arena2_lo, M.arena2_hi,
                                         nullptr, &disc_bl, &acc_conv);
        if (acc_va) {
            LOG_I("[attach] accumulator VA (discovered): 0x%lx (byte_load=0x%lx)",
                  (unsigned long)acc_va, (unsigned long)disc_bl);
        } else if (ver && ver->accumulator_offset) {
            acc_va = M.file_lo + ver->accumulator_offset;
            LOG_I("[attach] discovery failed; using VersionProfile offset: "
                  "file_lo(0x%lx) + 0x%lx = 0x%lx",
                  (unsigned long)M.file_lo,
                  (unsigned long)ver->accumulator_offset,
                  (unsigned long)acc_va);
        } else {
            acc_va = M.file_lo + version_02_05_03_63::ACCUMULATOR_OFFSET;
            LOG_W("[attach] discovery failed; fallback to baseline offset: 0x%lx",
                  (unsigned long)acc_va);
        }
    } else {
        if (ver && ver->accumulator_offset) {
            acc_va = M.file_lo + ver->accumulator_offset;
            LOG_I("[attach] no arena2; VersionProfile acc_va=0x%lx", (unsigned long)acc_va);
        } else {
            acc_va = M.file_lo + version_02_05_03_63::ACCUMULATOR_OFFSET;
            LOG_W("[attach] no arena2; baseline acc_va=0x%lx", (unsigned long)acc_va);
        }
    }

    const char* acc_reg_name = version_02_05_03_63::ACCUMULATOR_REG_NAME;
    if (acc_conv >= 7 && acc_conv <= 13) acc_reg_name = "rax";
    else if (acc_conv >= 14 && acc_conv <= 20) acc_reg_name = "rcx";
    else if (acc_conv >= 21 && acc_conv <= 27) acc_reg_name = "rbx";
    LOG_I("[attach] register: %s (low byte = captured dp/dq byte, conv=%d)",
          acc_reg_name, acc_conv);

    int n_armed = 0;
    for (pid_t t : seized) {
        if (ptrace(PTRACE_INTERRUPT, t, 0, 0) < 0) {
            LOG_V("[attach] PTRACE_INTERRUPT tid=%d: %s", t, strerror(errno));
            continue;
        }
        int st = 0;
        for (int i = 0; i < 50; ++i) {
            pid_t r = waitpid(t, &st, WNOHANG | __WALL);
            if (r == t && WIFSTOPPED(st)) break;
            if (r < 0) break;
            usleep(2 * 1000);
        }
        if (!WIFSTOPPED(st)) {
            LOG_W("[attach] tid=%d never stopped after INTERRUPT (status=0x%x)", t, st);
            continue;
        }
        if (arm_dr_on_tid(t, acc_va)) {
            ++n_armed;
        } else {
            LOG_W("[attach] arm_dr_on_tid(%d, 0x%lx) failed", t, (unsigned long)acc_va);
        }
        if (!cont_with_sig(t, 0)) {
            LOG_W("[attach] PTRACE_CONT(tid=%d) failed after arm", t);
        }
    }
    LOG_I("[attach] DR0 armed on %d/%zu tid(s)", n_armed, seized.size());
    if (n_armed == 0) {
        LOG_E("[attach] could not arm DR0 on any thread");
        stop_notif_thread();
        cleanup_detach();
        restore_sigint();
        return R;
    }

    LOG_I("[attach] entering capture loop; timeout=%ds; need %d bytes",
          timeout_s, version_02_05_03_63::TOTAL_BYTES);
    LOG_I("[attach] (Ctrl-C triggers clean detach.)");

    int bytes_needed = require_bytes ? version_02_05_03_63::TOTAL_BYTES : 0;
    double deadline = now_s() + double(timeout_s);
    int spurious_traps = 0;
    int sentinel_count = 0;
    std::vector<pid_t> parked_sentinels;

    while ((require_bytes ? (R.stream.size() < (size_t)bytes_needed) : true)
           && now_s() < deadline
           && !g_attach_interrupted.load(std::memory_order_relaxed)) {
        int st = 0;
        pid_t r = waitpid(-1, &st, WNOHANG | __WALL);
        if (r <= 0) { usleep(1 * 1000); continue; }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (r == target) {
                LOG_W("[attach] target main pid exited mid-capture (status=0x%x)", st);
                break;
            }
            for (auto it = seized.begin(); it != seized.end(); ++it) {
                if (*it == r) { seized.erase(it); break; }
            }
            continue;
        }
        if (!WIFSTOPPED(st)) continue;
        int sig = WSTOPSIG(st);
        int event = (st >> 16) & 0xffff;

        if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK ||
            event == PTRACE_EVENT_VFORK) {
            unsigned long new_tid_l = 0;
            ptrace(PTRACE_GETEVENTMSG, r, 0, &new_tid_l);
            pid_t new_tid = (pid_t)new_tid_l;
            if (new_tid > 0) {
                seized.push_back(new_tid);
                LOG_V("[attach] new clone tid=%d", new_tid);
            }
            cont_with_sig(r, 0);
            continue;
        }
        if (event == PTRACE_EVENT_EXIT) {
            cont_with_sig(r, 0);
            continue;
        }
        if (sig == SIGSTOP) {
            arm_dr_on_tid(r, acc_va);
            cont_with_sig(r, 0);
            continue;
        }
        if (sig == SIGTRAP) {
            struct user_regs_struct regs{};
            struct iovec iov{ &regs, sizeof(regs) };
            if (ptrace(PTRACE_GETREGSET, r, (void*)NT_PRSTATUS, &iov) < 0) {
                poke_dr(r, 6, 0);
                cont_with_sig(r, 0);
                continue;
            }
            if (regs.rip == acc_va) {
                uint64_t reg_val = regs.rdx;
                if (std::strcmp(acc_reg_name, "rax") == 0) reg_val = regs.rax;
                else if (std::strcmp(acc_reg_name, "rcx") == 0) reg_val = regs.rcx;
                else if (std::strcmp(acc_reg_name, "rbx") == 0) reg_val = regs.rbx;
                uint8_t lo = uint8_t(reg_val & 0xff);
                R.stream.push_back(lo);
                ++R.total_traps;
                if (g_verbose && (R.stream.size() % 32 == 0 || R.stream.size() <= 4)) {
                    LOG_V("[attach] trap #%d tid=%d %s=0x%lx byte=0x%02x stream=%zu/256",
                          R.total_traps, r, acc_reg_name, reg_val, lo,
                          R.stream.size());
                }
            } else {
                ++spurious_traps;
                LOG_I("[attach] spurious SIGTRAP tid=%d rip=0x%lx (acc_va=0x%lx) — forwarding",
                      r, (unsigned long)regs.rip, (unsigned long)acc_va);
                poke_dr(r, 6, 0);
                cont_with_sig(r, SIGTRAP);
                continue;
            }
            poke_dr(r, 6, 0);
            cont_with_sig(r, 0);
            continue;
        }
        if (sig == SIGSEGV || sig == SIGBUS) {
            struct user_regs_struct dregs{};
            struct iovec div{ &dregs, sizeof(dregs) };
            unsigned long rip = 0;
            if (ptrace(PTRACE_GETREGSET, r, (void*)NT_PRSTATUS, &div) == 0) {
                rip = (unsigned long)dregs.rip;
            }
            bool sentinel = (rip >= 0xdead0000 && rip < 0xdf000000);
            if (sentinel && r != target) {
                bool already = false;
                for (pid_t p : parked_sentinels) if (p == r) { already = true; break; }
                if (!already) {
                    parked_sentinels.push_back(r);
                    ++sentinel_count;
                    LOG_I("[attach] worker tid=%d hit VMP sentinel rip=0x%lx — parking",
                          r, rip);
                }
                disarm_dr_on_tid(r);
                continue;
            }
            LOG_V("[attach] worker SIGSEGV tid=%d rip=0x%lx — forwarding", r, rip);
            cont_with_sig(r, sig);
            continue;
        }
        if (sig != SIGSTOP && sig != SIGTRAP) {
            LOG_I("[attach] fwd sig=%d tid=%d", sig, r);
        }
        cont_with_sig(r, sig);
    }

    if (g_attach_interrupted.load()) {
        LOG_I("[attach] SIGINT received — detaching cleanly");
    } else if (now_s() >= deadline) {
        LOG_I("[attach] timeout reached; bytes=%zu traps=%d spurious=%d",
              R.stream.size(), R.total_traps, spurious_traps);
    } else {
        LOG_I("[attach] capture complete: bytes=%zu traps=%d", R.stream.size(), R.total_traps);
    }

    for (pid_t p : parked_sentinels) {
        if (ptrace(PTRACE_CONT, p, 0, (void*)SIGSEGV) < 0 && errno != ESRCH) {
            LOG_V("[attach] un-park PTRACE_CONT(%d): %s", p, strerror(errno));
        }
    }
    if (sentinel_count > 0) {
        LOG_I("[attach] un-parked %d sentinel thread(s)", sentinel_count);
    }

    stop_notif_thread();
    cleanup_detach();
    restore_sigint();

    R.ok = R.stream.size() >= (size_t)version_02_05_03_63::TOTAL_BYTES;
    if (R.ok) {
        R.stream.resize(version_02_05_03_63::TOTAL_BYTES);
        R.sign_cycles = R.total_traps / version_02_05_03_63::TOTAL_BYTES;
    }
    return R;
}
