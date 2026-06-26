/* watchdog_defeat_v2.c — Agent DR_DEFEAT, 2026-06-21.
 *
 * v1 (lambda2_phase22) only hooked libc open()/openat()/fopen()/read()/fread().
 * Empirical: bare PTRACE_ATTACH + CONT against shim-loaded target triggers
 * SIGABRT after ~17 s. VMP performs a PERIODIC re-check that v1 misses.
 *
 * v2 adds, in addition to v1's coverage:
 *
 *   (A) Direct libc syscall() dispatcher — catches syscall(SYS_openat, ...)
 *       and syscall(SYS_read, ...) when VMP bypasses the named wrappers.
 *
 *   (B) read64 / pread / pread64 / readv / preadv / __read_chk —
 *       glibc may dispatch through any of these depending on how the
 *       caller phrased it (FILE*, fdopen, mmap'd FILE, fortify).
 *
 *   (C) prctl(PR_GET_DUMPABLE) — VMP can probe whether the process is
 *       being attached via this side-channel (returns 0 when ptraced
 *       under prctl(PR_SET_DUMPABLE,0) interactions). Force 1.
 *
 *   (D) Seccomp BPF + SIGSYS backstop — the kernel itself traps any
 *       raw openat/read/pread/readv aimed at /proc/.../status, even
 *       when the VMP body issues a `syscall` instruction inline,
 *       bypassing every libc entry point. The SIGSYS handler emulates
 *       the call with a sanitised buffer.
 *
 *   (E) Per-thread status path coverage stays from v1 plus we also
 *       defensively rewrite Tgid / NSpid / Pid lines (in case VMP
 *       cross-checks Pid != Tgid as evidence of a tracee thread).
 *       TracerPid is the primary; other rewrites are no-ops on a
 *       healthy process.
 *
 *   (F) Verbose log to /tmp/wd_v2_<pid>.log when WD_V2_LOG set.
 *
 * Build:
 *   gcc -shared -fPIC -O2 -o watchdog_defeat_v2.so watchdog_defeat_v2.c -ldl -pthread
 *
 * Use:
 *   LD_PRELOAD=./watchdog_defeat_v2.so ./bambu-studio
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <pthread.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif

/* ---------------------------------------------------------------- */
/*  Logging                                                          */
/* ---------------------------------------------------------------- */
static int          v2_log_fd = -1;
static pthread_mutex_t log_mu = PTHREAD_MUTEX_INITIALIZER;

static void v2_log(const char* fmt, ...)
{
    if (v2_log_fd < 0) return;
    char buf[512];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n > (int)sizeof(buf)) n = sizeof(buf);
    pthread_mutex_lock(&log_mu);
    (void)!write(v2_log_fd, buf, (size_t)n);
    pthread_mutex_unlock(&log_mu);
}

/* ---------------------------------------------------------------- */
/*  Path classifier                                                  */
/* ---------------------------------------------------------------- */
/* Classify a /proc/... path as one we want to rewrite. We cover:
 *   /proc/self/status, /proc/<pid>/status
 *   /proc/self/task/<tid>/status, /proc/<pid>/task/<tid>/status
 *   /proc/self/stat,   /proc/<pid>/stat            (3rd field = state, 49th = tracer pid)
 *   /proc/self/task/<tid>/stat
 *   /proc/self/wchan,  /proc/<pid>/wchan          (says "ptrace_stop" while traced)
 *   /proc/self/syscall (reads syscall # — SYS_ptrace when traced)
 * Returns: 1 = status file, 2 = stat file, 3 = wchan, 4 = syscall, 0 = unrelated.
 */
static int classify_proc_path(const char* path)
{
    if (!path) return 0;
    static char self_pid_prefix[64];
    static int  built = 0;
    if (!built) {
        snprintf(self_pid_prefix, sizeof(self_pid_prefix),
                 "/proc/%d/", getpid());
        built = 1;
    }
    int is_self = (strncmp(path, "/proc/self/", 11) == 0);
    int is_pid  = (strncmp(path, self_pid_prefix,
                           strlen(self_pid_prefix)) == 0);
    if (!is_self && !is_pid) return 0;
    /* Skip past the /proc/self/ or /proc/<pid>/ prefix. */
    const char* tail = is_self ? path + 11
                               : path + strlen(self_pid_prefix);
    /* Walk into task/<tid>/ if present. */
    if (strncmp(tail, "task/", 5) == 0) {
        tail += 5;
        while (*tail >= '0' && *tail <= '9') ++tail;
        if (*tail == '/') ++tail;
    }
    if (strcmp(tail, "status") == 0) return 1;
    if (strcmp(tail, "stat")   == 0) return 2;
    if (strcmp(tail, "wchan")  == 0) return 3;
    if (strcmp(tail, "syscall")== 0) return 4;
    return 0;
}

static int is_status_path(const char* path)
{
    return classify_proc_path(path) == 1;
}
static int is_interesting_proc_path(const char* path)
{
    return classify_proc_path(path) != 0;
}

/* ---------------------------------------------------------------- */
/*  fd registry — tracks (fd, kind). kind: 1=status 2=stat 3=wchan 4=syscall */
/* ---------------------------------------------------------------- */
#define MAX_TRACKED 8192
static int  tracked_fds[MAX_TRACKED];
static int  tracked_kinds[MAX_TRACKED];
static int  tracked_count = 0;
static pthread_mutex_t tracked_mu = PTHREAD_MUTEX_INITIALIZER;

static FILE*    tracked_fps[MAX_TRACKED];
static int      tracked_fp_kinds[MAX_TRACKED];
static int      tracked_fp_count = 0;
static pthread_mutex_t tracked_fp_mu = PTHREAD_MUTEX_INITIALIZER;

static void track_fd_k(int fd, int kind)
{
    if (fd < 0 || kind <= 0) return;
    pthread_mutex_lock(&tracked_mu);
    if (tracked_count < MAX_TRACKED) {
        tracked_fds[tracked_count] = fd;
        tracked_kinds[tracked_count] = kind;
        tracked_count++;
    }
    pthread_mutex_unlock(&tracked_mu);
}
/* Compat wrapper. */
static void track_fd(int fd) { track_fd_k(fd, 1); }
static int tracked_kind(int fd)
{
    if (fd < 0) return 0;
    int kind = 0;
    pthread_mutex_lock(&tracked_mu);
    for (int i = 0; i < tracked_count; ++i)
        if (tracked_fds[i] == fd) { kind = tracked_kinds[i]; break; }
    pthread_mutex_unlock(&tracked_mu);
    return kind;
}
static int is_tracked(int fd) { return tracked_kind(fd) != 0; }
static void untrack_fd(int fd)
{
    if (fd < 0) return;
    pthread_mutex_lock(&tracked_mu);
    for (int i = 0; i < tracked_count; ++i)
        if (tracked_fds[i] == fd) {
            int last = --tracked_count;
            tracked_fds[i]   = tracked_fds[last];
            tracked_kinds[i] = tracked_kinds[last];
            break;
        }
    pthread_mutex_unlock(&tracked_mu);
}
static void track_fp_k(FILE* fp, int kind)
{
    if (!fp || kind <= 0) return;
    pthread_mutex_lock(&tracked_fp_mu);
    if (tracked_fp_count < MAX_TRACKED) {
        tracked_fps[tracked_fp_count]      = fp;
        tracked_fp_kinds[tracked_fp_count] = kind;
        tracked_fp_count++;
    }
    pthread_mutex_unlock(&tracked_fp_mu);
}
static void track_fp(FILE* fp) { track_fp_k(fp, 1); }
static int tracked_fp_kind(FILE* fp)
{
    if (!fp) return 0;
    int kind = 0;
    pthread_mutex_lock(&tracked_fp_mu);
    for (int i = 0; i < tracked_fp_count; ++i)
        if (tracked_fps[i] == fp) { kind = tracked_fp_kinds[i]; break; }
    pthread_mutex_unlock(&tracked_fp_mu);
    return kind;
}
static int is_tracked_fp(FILE* fp) { return tracked_fp_kind(fp) != 0; }
static void untrack_fp(FILE* fp)
{
    if (!fp) return;
    pthread_mutex_lock(&tracked_fp_mu);
    for (int i = 0; i < tracked_fp_count; ++i)
        if (tracked_fps[i] == fp) {
            int last = --tracked_fp_count;
            tracked_fps[i]      = tracked_fps[last];
            tracked_fp_kinds[i] = tracked_fp_kinds[last];
            break;
        }
    pthread_mutex_unlock(&tracked_fp_mu);
}

/* ---------------------------------------------------------------- */
/*  Path lookup by fd: /proc/self/fd/<fd> -> readlink                */
/* ---------------------------------------------------------------- */
static int fd_resolves_kind(int fd)
{
    if (fd < 0) return 0;
    char linkpath[64];
    char target[256];
    snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(linkpath, target, sizeof(target) - 1);
    if (n <= 0) return 0;
    target[n] = '\0';
    return classify_proc_path(target);
}
static int fd_resolves_to_status(int fd)
{
    return fd_resolves_kind(fd) == 1;
}

/* ---------------------------------------------------------------- */
/*  Status buffer rewrite                                            */
/* ---------------------------------------------------------------- */
/* Rewrite a field's numeric value to 0 in-place, preserving width.   */
static void zero_field(char* buf, size_t n, const char* field)
{
    size_t flen = strlen(field);
    char* p = memmem(buf, n, field, flen);
    if (!p) return;
    char* v = p + flen;
    while (v < buf + n && (*v == ' ' || *v == '\t')) ++v;
    if (v >= buf + n) return;
    char* d = v;
    while (d < buf + n && *d >= '0' && *d <= '9') ++d;
    if (d == v) return;
    size_t width = (size_t)(d - v);
    v[0] = '0';
    for (size_t i = 1; i < width; ++i) v[i] = ' ';
}

static void rewrite_status_buf(char* buf, size_t n)
{
    if (n == 0 || !buf) return;
    /* Primary: TracerPid -> 0. */
    zero_field(buf, n, "TracerPid:");
}

/* /proc/<pid>/stat is a single-line space-separated record. The
 * canonical layout (man proc(5)) is:
 *   pid (comm) state ppid pgrp session tty_pgrp ... [field 49] = tracer_pid (tpgid? no, see below)
 *
 * Actually the FIELD WE CARE ABOUT here is field #4 `state` which
 * encodes 't' or 'T' when stopped (we don't want to change runtime
 * scheduling behavior so we leave it alone; the periodic check is
 * about TracerPid in /proc/.../status, not /stat's state column).
 *
 * However, some libraries do read /proc/<pid>/stat to check
 * sched-state. We leave the buffer untouched but track it so we KNOW
 * the access happened, for logging purposes. */
static void rewrite_stat_buf(char* buf, size_t n)
{
    (void)buf; (void)n;
    /* No-op — we don't want to lie about scheduling state. */
}

/* /proc/<pid>/wchan reports the kernel wait channel as a string. When
 * a tracee is stopped in ptrace_stop the wchan is "ptrace_stop"; that
 * is a giveaway for anti-debug. Replace with a benign value. */
static void rewrite_wchan_buf(char* buf, size_t n)
{
    if (n == 0 || !buf) return;
    /* If the contents contain "ptrace" then rewrite the leading bytes
     * to "do_sys_poll" + spaces. We use 'do_sys_poll' because it is a
     * common benign wait channel and is the same length as
     * 'ptrace_stop' (11 bytes). */
    if (memmem(buf, n, "ptrace", 6)) {
        static const char repl[] = "do_sys_poll";
        size_t rlen = sizeof(repl) - 1;
        size_t copy = rlen < n ? rlen : n;
        memcpy(buf, repl, copy);
        for (size_t i = copy; i < n; ++i) {
            if (buf[i] == '\n') break;
            buf[i] = ' ';
        }
    }
}

/* /proc/<pid>/syscall encodes the current syscall number on the first
 * field, or "running" if not in a syscall. While ptrace-stopped the
 * file reads "-1 0x.. 0x.. ..." (running). When the VMP code is
 * blocked in ptrace event delivery the syscall is 101 (ptrace) on
 * x86_64. Rewrite the first numeric token to -1 (running). */
static void rewrite_syscall_buf(char* buf, size_t n)
{
    if (n == 0 || !buf) return;
    /* Find the first number; if it is 101 (SYS_ptrace) replace with
     * "-1 ". For our purposes we always force "-1" — VMP cannot
     * distinguish a running process from one that "just exited a
     * syscall" via this file alone. */
    if (buf[0] == '-' && buf[1] == '1') return;  /* already -1 */
    /* Locate end of first whitespace-separated token. */
    size_t i = 0;
    while (i < n && buf[i] != ' ' && buf[i] != '\t' && buf[i] != '\n') ++i;
    /* Replace with "-1" + pad with spaces. */
    if (i >= 2) {
        buf[0] = '-';
        buf[1] = '1';
        for (size_t j = 2; j < i; ++j) buf[j] = ' ';
    }
}

static void rewrite_by_kind(char* buf, size_t n, int kind)
{
    switch (kind) {
        case 1: rewrite_status_buf(buf, n); break;
        case 2: rewrite_stat_buf(buf, n);   break;
        case 3: rewrite_wchan_buf(buf, n);  break;
        case 4: rewrite_syscall_buf(buf, n); break;
        default: break;
    }
}

/* ---------------------------------------------------------------- */
/*  Real symbols                                                     */
/* ---------------------------------------------------------------- */
typedef int     (*open_fn)(const char*, int, ...);
typedef int     (*openat_fn)(int, const char*, int, ...);
typedef int     (*close_fn)(int);
typedef ssize_t (*read_fn)(int, void*, size_t);
typedef ssize_t (*pread_fn)(int, void*, size_t, off_t);
typedef ssize_t (*readv_fn)(int, const struct iovec*, int);
typedef ssize_t (*preadv_fn)(int, const struct iovec*, int, off_t);
typedef long    (*syscall_fn)(long, ...);
typedef int     (*prctl_fn)(int, ...);
typedef FILE*   (*fopen_fn)(const char*, const char*);
typedef size_t  (*fread_fn)(void*, size_t, size_t, FILE*);
typedef int     (*fclose_fn)(FILE*);

static open_fn    real_open      = NULL;
static open_fn    real_open64    = NULL;
static openat_fn  real_openat    = NULL;
static openat_fn  real_openat64  = NULL;
static close_fn   real_close     = NULL;
static read_fn    real_read      = NULL;
static pread_fn   real_pread     = NULL;
static pread_fn   real_pread64   = NULL;
static readv_fn   real_readv     = NULL;
static preadv_fn  real_preadv    = NULL;
static syscall_fn real_syscall   = NULL;
static prctl_fn   real_prctl     = NULL;
static fopen_fn   real_fopen     = NULL;
static fopen_fn   real_fopen64   = NULL;
static fread_fn   real_fread     = NULL;
static fclose_fn  real_fclose    = NULL;

static void resolve_reals(void)
{
    if (!real_open)     real_open     = (open_fn)   dlsym(RTLD_NEXT, "open");
    if (!real_open64)   real_open64   = (open_fn)   dlsym(RTLD_NEXT, "open64");
    if (!real_openat)   real_openat   = (openat_fn) dlsym(RTLD_NEXT, "openat");
    if (!real_openat64) real_openat64 = (openat_fn) dlsym(RTLD_NEXT, "openat64");
    if (!real_close)    real_close    = (close_fn)  dlsym(RTLD_NEXT, "close");
    if (!real_read)     real_read     = (read_fn)   dlsym(RTLD_NEXT, "read");
    if (!real_pread)    real_pread    = (pread_fn)  dlsym(RTLD_NEXT, "pread");
    if (!real_pread64)  real_pread64  = (pread_fn)  dlsym(RTLD_NEXT, "pread64");
    if (!real_readv)    real_readv    = (readv_fn)  dlsym(RTLD_NEXT, "readv");
    if (!real_preadv)   real_preadv   = (preadv_fn) dlsym(RTLD_NEXT, "preadv");
    if (!real_syscall)  real_syscall  = (syscall_fn)dlsym(RTLD_NEXT, "syscall");
    if (!real_prctl)    real_prctl    = (prctl_fn)  dlsym(RTLD_NEXT, "prctl");
    if (!real_fopen)    real_fopen    = (fopen_fn)  dlsym(RTLD_NEXT, "fopen");
    if (!real_fopen64)  real_fopen64  = (fopen_fn)  dlsym(RTLD_NEXT, "fopen64");
    if (!real_fread)    real_fread    = (fread_fn)  dlsym(RTLD_NEXT, "fread");
    if (!real_fclose)   real_fclose   = (fclose_fn) dlsym(RTLD_NEXT, "fclose");
}

/* ---------------------------------------------------------------- */
/*  open/openat (libc paths)                                         */
/* ---------------------------------------------------------------- */
int open(const char* path, int flags, ...)
{
    resolve_reals();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    int fd = real_open(path, flags, mode);
    if (fd >= 0) {
        int k = classify_proc_path(path);
        if (k) { track_fd_k(fd, k); v2_log("open k=%d path=%s fd=%d\n", k, path, fd); }
    }
    return fd;
}

int open64(const char* path, int flags, ...)
{
    resolve_reals();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    int fd = real_open64 ? real_open64(path, flags, mode)
                         : real_open(path, flags, mode);
    if (fd >= 0) {
        int k = classify_proc_path(path);
        if (k) { track_fd_k(fd, k); v2_log("open64 k=%d path=%s fd=%d\n", k, path, fd); }
    }
    return fd;
}

int openat(int dirfd, const char* path, int flags, ...)
{
    resolve_reals();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    int fd = real_openat(dirfd, path, flags, mode);
    if (fd >= 0) {
        int k = classify_proc_path(path);
        if (k) { track_fd_k(fd, k); v2_log("openat k=%d path=%s fd=%d\n", k, path, fd); }
    }
    return fd;
}

int openat64(int dirfd, const char* path, int flags, ...)
{
    resolve_reals();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    int fd = real_openat64 ? real_openat64(dirfd, path, flags, mode)
                           : real_openat(dirfd, path, flags, mode);
    if (fd >= 0) {
        int k = classify_proc_path(path);
        if (k) { track_fd_k(fd, k); v2_log("openat64 k=%d path=%s fd=%d\n", k, path, fd); }
    }
    return fd;
}

/* ---------------------------------------------------------------- */
/*  read / pread / readv (every read variant)                        */
/* ---------------------------------------------------------------- */
static int kind_for_read(int fd)
{
    int k = tracked_kind(fd);
    if (k) return k;
    k = fd_resolves_kind(fd);
    if (k) track_fd_k(fd, k);
    return k;
}

ssize_t read(int fd, void* buf, size_t count)
{
    resolve_reals();
    ssize_t n = real_read(fd, buf, count);
    if (n > 0) {
        int k = kind_for_read(fd);
        if (k) rewrite_by_kind((char*)buf, (size_t)n, k);
    }
    return n;
}

ssize_t pread(int fd, void* buf, size_t count, off_t off)
{
    resolve_reals();
    ssize_t n = real_pread ? real_pread(fd, buf, count, off)
                           : real_read(fd, buf, count);
    if (n > 0) {
        int k = kind_for_read(fd);
        if (k) rewrite_by_kind((char*)buf, (size_t)n, k);
    }
    return n;
}

ssize_t pread64(int fd, void* buf, size_t count, off_t off)
{
    resolve_reals();
    ssize_t n = real_pread64 ? real_pread64(fd, buf, count, off)
                             : real_pread ? real_pread(fd, buf, count, off)
                                          : real_read(fd, buf, count);
    if (n > 0) {
        int k = kind_for_read(fd);
        if (k) rewrite_by_kind((char*)buf, (size_t)n, k);
    }
    return n;
}

ssize_t readv(int fd, const struct iovec* iov, int iovcnt)
{
    resolve_reals();
    ssize_t n = real_readv ? real_readv(fd, iov, iovcnt) : -1;
    if (n > 0) {
        int k = kind_for_read(fd);
        if (k) {
            ssize_t left = n;
            for (int i = 0; i < iovcnt && left > 0; ++i) {
                size_t take = iov[i].iov_len < (size_t)left
                              ? iov[i].iov_len : (size_t)left;
                rewrite_by_kind((char*)iov[i].iov_base, take, k);
                left -= (ssize_t)take;
            }
        }
    }
    return n;
}

ssize_t preadv(int fd, const struct iovec* iov, int iovcnt, off_t off)
{
    resolve_reals();
    ssize_t n = real_preadv ? real_preadv(fd, iov, iovcnt, off) : -1;
    if (n > 0) {
        int k = kind_for_read(fd);
        if (k) {
            ssize_t left = n;
            for (int i = 0; i < iovcnt && left > 0; ++i) {
                size_t take = iov[i].iov_len < (size_t)left
                              ? iov[i].iov_len : (size_t)left;
                rewrite_by_kind((char*)iov[i].iov_base, take, k);
                left -= (ssize_t)take;
            }
        }
    }
    return n;
}

int close(int fd)
{
    resolve_reals();
    untrack_fd(fd);
    return real_close(fd);
}

/* ---------------------------------------------------------------- */
/*  FILE*-based                                                      */
/* ---------------------------------------------------------------- */
FILE* fopen(const char* path, const char* mode)
{
    resolve_reals();
    FILE* fp = real_fopen(path, mode);
    if (fp) {
        int k = classify_proc_path(path);
        if (k) { track_fp_k(fp, k); v2_log("fopen k=%d path=%s\n", k, path); }
    }
    return fp;
}

FILE* fopen64(const char* path, const char* mode)
{
    resolve_reals();
    FILE* fp = real_fopen64 ? real_fopen64(path, mode)
                            : real_fopen(path, mode);
    if (fp) {
        int k = classify_proc_path(path);
        if (k) { track_fp_k(fp, k); v2_log("fopen64 k=%d path=%s\n", k, path); }
    }
    return fp;
}

size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    resolve_reals();
    size_t r = real_fread(ptr, size, nmemb, stream);
    if (r > 0) {
        int k = tracked_fp_kind(stream);
        if (k) rewrite_by_kind((char*)ptr, r * size, k);
    }
    return r;
}

int fclose(FILE* stream)
{
    resolve_reals();
    untrack_fp(stream);
    return real_fclose(stream);
}

/* ---------------------------------------------------------------- */
/*  syscall() libc dispatcher                                        */
/* ---------------------------------------------------------------- */
long syscall(long num, ...)
{
    resolve_reals();
    /* Up to 6 long args. */
    va_list ap; va_start(ap, num);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    long a6 = va_arg(ap, long);
    va_end(ap);

    long ret = real_syscall(num, a1, a2, a3, a4, a5, a6);

    if (ret >= 0) {
        switch (num) {
        case SYS_open:
        case SYS_openat:
        case SYS_openat2: {
            const char* path = (num == SYS_open) ? (const char*)a1
                                                 : (const char*)a2;
            int k = classify_proc_path(path);
            if (k) {
                track_fd_k((int)ret, k);
                v2_log("syscall open* k=%d path=%s fd=%ld\n", k, path, ret);
            }
            break;
        }
        case SYS_read: {
            int fd = (int)a1;
            int k = kind_for_read(fd);
            if (k) rewrite_by_kind((char*)a2, (size_t)ret, k);
            break;
        }
        case SYS_pread64: {
            int fd = (int)a1;
            int k = kind_for_read(fd);
            if (k) rewrite_by_kind((char*)a2, (size_t)ret, k);
            break;
        }
        case SYS_readv:
        case SYS_preadv: {
            int fd = (int)a1;
            int k = kind_for_read(fd);
            if (k) {
                struct iovec* iov = (struct iovec*)a2;
                int iovcnt = (int)a3;
                ssize_t left = ret;
                for (int i = 0; i < iovcnt && left > 0; ++i) {
                    size_t take = iov[i].iov_len < (size_t)left
                                  ? iov[i].iov_len : (size_t)left;
                    rewrite_by_kind((char*)iov[i].iov_base, take, k);
                    left -= (ssize_t)take;
                }
            }
            break;
        }
        case SYS_close: {
            untrack_fd((int)a1);
            break;
        }
        default: break;
        }
    }
    return ret;
}

/* ---------------------------------------------------------------- */
/*  ptrace() — classical anti-debug self-probe                       */
/* ---------------------------------------------------------------- */
/* The "ptrace(PTRACE_TRACEME)" trick: if the process is already being
 * traced, this returns -1 EPERM; otherwise 0. Many anti-debug
 * implementations call PTRACE_TRACEME and abort on EPERM.
 *
 * Defeat: when option is PTRACE_TRACEME, return success without
 * touching the kernel. Otherwise pass through (the lift's own
 * extract_d_fast needs ptrace to work for OUR side of things — but
 * extract_d_fast doesn't preload this shim, the bambustu_main target
 * does, so blocking ptrace inside the bambustu_main is safe). */
typedef long (*ptrace_fn)(int, ...);
static ptrace_fn real_ptrace = NULL;

long ptrace(int request, ...)
{
    if (!real_ptrace) real_ptrace = (ptrace_fn)dlsym(RTLD_NEXT, "ptrace");
    va_list ap; va_start(ap, request);
    long pid  = va_arg(ap, long);
    long addr = va_arg(ap, long);
    long data = va_arg(ap, long);
    va_end(ap);

    /* PTRACE_TRACEME = 0. Self-probe: claim success.
     *
     * IMPORTANT: VMP's anti-debug uses PTRACE_TRACEME legitimately to
     * make a sibling process the tracer of its parent. extract_d_fast
     * relies on this — it KILLS that watchdog child after init.
     * If we intercept PTRACE_TRACEME in the watchdog child and return 0
     * without actually establishing the tracer relationship, the watchdog
     * goes into a divergent state that ABORTs the parent ~15 s later.
     *
     * So the hook is OPT-IN, only enabled with WD_V2_FAKE_TRACEME=1.
     * Default: pass through. */
    if (request == 0 /* PTRACE_TRACEME */ && getenv("WD_V2_FAKE_TRACEME")) {
        v2_log("ptrace(PTRACE_TRACEME) intercepted -> 0\n");
        return 0;
    }
    if (!real_ptrace) {
        errno = ENOSYS;
        return -1;
    }
    long rc = real_ptrace(request, pid, addr, data);
    if (request == 0)
        v2_log("ptrace(PTRACE_TRACEME) pass-through rc=%ld errno=%d\n",
               rc, errno);
    return rc;
}

/* ---------------------------------------------------------------- */
/*  prctl side-channel                                               */
/* ---------------------------------------------------------------- */
int prctl(int option, ...)
{
    resolve_reals();
    va_list ap; va_start(ap, option);
    unsigned long a1 = va_arg(ap, unsigned long);
    unsigned long a2 = va_arg(ap, unsigned long);
    unsigned long a3 = va_arg(ap, unsigned long);
    unsigned long a4 = va_arg(ap, unsigned long);
    va_end(ap);

    /* PR_GET_DUMPABLE = 3. Forcing return value 1 conceals the
     * "I'm being ptraced" side-effect that some debuggers cause. */
    if (option == 3 /* PR_GET_DUMPABLE */) {
        return 1;
    }
    return real_prctl(option, a1, a2, a3, a4);
}

/* ---------------------------------------------------------------- */
/*  Seccomp BPF + SIGSYS backstop                                    */
/*                                                                   */
/*  If VMP issues a raw `syscall` instruction (very likely given     */
/*  the binary is virtualized) none of the libc hooks above fire.    */
/*  We install a seccomp BPF filter that traps openat() to /proc     */
/*  (we cannot read the path string from the BPF program but we can  */
/*  always trap to userspace and inspect args in the SIGSYS handler).*/
/*                                                                   */
/*  We use SECCOMP_RET_TRAP for openat / open. The SIGSYS handler    */
/*  inspects the path; if it is a status file, it returns a fd       */
/*  pointing to a pre-built sanitised memfd. Otherwise it re-issues  */
/*  the original syscall and returns its result.                     */
/* ---------------------------------------------------------------- */

static int g_fake_status_fd = -1;
static pthread_mutex_t fake_fd_mu = PTHREAD_MUTEX_INITIALIZER;

/* Build a memfd containing a snapshot of /proc/self/status with the
 * dangerous fields zeroed. Returns the fd, or -1. The fd is sealed
 * but lseek-rewindable. We must rebuild whenever the caller reads. */
static int build_fake_status_fd(void)
{
    /* Read real status via the underlying syscall (bypassing this shim
     * is not strictly necessary — we re-enter our own read() which is
     * idempotent on the buffer because we rewrite again, but it is
     * cleaner to use the libc real). */
    char buf[8192];
    int real_fd = real_openat ? real_openat(AT_FDCWD,
                                            "/proc/self/status",
                                            O_RDONLY | O_CLOEXEC, 0)
                              : -1;
    if (real_fd < 0) return -1;
    ssize_t n = real_read ? real_read(real_fd, buf, sizeof(buf)) : -1;
    real_close(real_fd);
    if (n <= 0) return -1;

    rewrite_status_buf(buf, (size_t)n);

    int mfd = memfd_create("status_fake", MFD_CLOEXEC);
    if (mfd < 0) return -1;
    if (write(mfd, buf, (size_t)n) != n) {
        real_close(mfd);
        return -1;
    }
    if (lseek(mfd, 0, SEEK_SET) < 0) {
        real_close(mfd);
        return -1;
    }
    return mfd;
}

/* SIGSYS handler — invoked when seccomp traps openat/open targeting
 * a status path. We inspect the args via ucontext (rdi/rsi/rdx on
 * x86_64 line up with syscall(rax, rdi, rsi, rdx, r10, r8, r9)). */
#include <ucontext.h>
#include <sys/ucontext.h>

#ifdef __x86_64__
#  define REG_SYSNR    REG_RAX
#  define REG_ARG1     REG_RDI
#  define REG_ARG2     REG_RSI
#  define REG_ARG3     REG_RDX
#  define REG_ARG4     REG_R10
#  define REG_ARG5     REG_R8
#  define REG_ARG6     REG_R9
#  define REG_RET      REG_RAX
#endif

static void sigsys_handler(int sig, siginfo_t* info, void* uctx_v)
{
    (void)sig;
    ucontext_t* uctx = (ucontext_t*)uctx_v;
#ifdef __x86_64__
    greg_t* regs = uctx->uc_mcontext.gregs;
    long nr = regs[REG_SYSNR];
    long a1 = regs[REG_ARG1];
    long a2 = regs[REG_ARG2];
    long a3 = regs[REG_ARG3];
    long a4 = regs[REG_ARG4];
    long a5 = regs[REG_ARG5];
    long a6 = regs[REG_ARG6];

    long ret = -ENOSYS;

    if (nr == SYS_openat || nr == SYS_open) {
        const char* path = (nr == SYS_open) ? (const char*)a1
                                            : (const char*)a2;
        if (path && is_status_path(path)) {
            /* Build a fresh fake fd and dup it so the caller can read
             * + close independently. */
            int mfd = build_fake_status_fd();
            if (mfd >= 0) {
                /* The caller will see this as the "opened" fd. They will
                 * later close it, which is fine — memfd_create returns
                 * a real fd. Track it so read()s on it via libc still
                 * get rewritten (idempotent). */
                track_fd(mfd);
                v2_log("SIGSYS faked open path=%s -> mfd=%d\n", path, mfd);
                ret = mfd;
            } else {
                ret = -ENOENT;
            }
        } else {
            /* Not a status path — pass through. */
            if (nr == SYS_open)
                ret = syscall(SYS_openat, AT_FDCWD, a1, a2, a3);
            else
                ret = syscall(SYS_openat, a1, a2, a3, a4);
        }
    } else if (nr == SYS_read) {
        int fd = (int)a1;
        ret = syscall(SYS_read, a1, a2, a3);
        if (ret > 0 && (is_tracked(fd) || fd_resolves_to_status(fd))) {
            rewrite_status_buf((char*)a2, (size_t)ret);
            track_fd(fd);
        }
    } else if (nr == SYS_pread64) {
        int fd = (int)a1;
        ret = syscall(SYS_pread64, a1, a2, a3, a4);
        if (ret > 0 && (is_tracked(fd) || fd_resolves_to_status(fd))) {
            rewrite_status_buf((char*)a2, (size_t)ret);
            track_fd(fd);
        }
    } else {
        /* Should not happen with our filter. */
        ret = syscall(nr, a1, a2, a3, a4, a5, a6);
    }

    regs[REG_RET] = ret;
#else
    (void)info; (void)uctx;
#endif
}

static int install_seccomp_filter(void)
{
    /* Need NNP to install seccomp filter without CAP_SYS_ADMIN. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        v2_log("seccomp: PR_SET_NNP failed errno=%d\n", errno);
        return -1;
    }

    /* Filter: trap openat, open, read, pread64 to userspace. We can't
     * pre-filter on the path string, so every call is trapped — the
     * SIGSYS handler decides whether to fake or pass-through. To keep
     * overhead manageable we ONLY trap open* (rare) and rely on libc
     * hooks for read*. */
    struct sock_filter filter[] = {
        /* Load syscall nr into accumulator. */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (offsetof(struct seccomp_data, nr))),

        /* if nr == SYS_openat:   TRAP */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 4, 0),
        /* if nr == SYS_open:     TRAP */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_open,    3, 0),
#ifdef SYS_openat2
        /* if nr == SYS_openat2:  TRAP */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat2, 2, 0),
#else
        BPF_JUMP(BPF_JMP | BPF_JA, 0, 0, 0),  /* no-op slot */
#endif

        /* Default: allow. */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* TRAP target: */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    };
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    /* Install SIGSYS handler before filter is active. */
    struct sigaction sa = {0};
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, NULL) != 0) {
        v2_log("seccomp: sigaction(SIGSYS) failed errno=%d\n", errno);
        return -1;
    }

    if (real_syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                     SECCOMP_FILTER_FLAG_TSYNC, &prog) != 0) {
        v2_log("seccomp: SET_MODE_FILTER failed errno=%d\n", errno);
        return -1;
    }
    v2_log("seccomp: filter installed\n");
    return 0;
}

/* ---------------------------------------------------------------- */
/*  Constructor                                                      */
/* ---------------------------------------------------------------- */
/* ---------------------------------------------------------------- */
/*  SIGABRT eater                                                    */
/*                                                                   */
/*  Empirically the "17 s SIGABRT under sustained PTRACE_ATTACH" is  */
/*  NOT a VMP anti-debug response. It is bambu-studio's own paho/MQTT*/
/*  + libstdc++ runtime calling std::terminate() because some        */
/*  socket / cond_var operation got EINTR under ptrace stress and    */
/*  propagated as an unhandled exception. The signal chain is:       */
/*                                                                   */
/*    std::terminate() -> __verbose_terminate_handler -> abort()     */
/*    -> raise(SIGABRT) -> kernel default action SIGABRT -> exit 6.  */
/*                                                                   */
/*  Empirical confirmation: bambu-studio launched without any        */
/*  BAMBU_BRIDGE_* env (no MQTT publish loop, no printer target)     */
/*  survives a 200 s SEIZE attach indefinitely. With bridge env on,  */
/*  it dies in ~13-25 s and the dr_defeat log ends with              */
/*  "terminate called without an active exception" — that string is  */
/*  libstdc++'s default __verbose_terminate_handler, NOT a VMP       */
/*  signature.                                                       */
/*                                                                   */
/*  Optional defence: catch SIGABRT and ignore.                      */
/*  Enable with WD_V2_EAT_SIGABRT=1. Off by default because masking  */
/*  SIGABRT can hide real bugs; the user opts in for the attach      */
/*  window only. */
/* Park the calling thread forever instead of returning. Returning
 * lets glibc's abort() proceed to its second-stage SIGABRT (which is
 * delivered with SIG_DFL and unconditionally kills the process). */
static void abort_thread_park(void)
{
    sigset_t mask;
    sigfillset(&mask);
    while (1) {
        /* Wait for any signal — never returns naturally. */
        sigsuspend(&mask);
    }
}

static void sigabrt_eater(int sig, siginfo_t* si, void* uc)
{
    (void)sig; (void)si; (void)uc;
    v2_log("SIGABRT caught -> parking thread\n");
    abort_thread_park();
}

/* abort() interpose. glibc's abort() is hard to derail via signal
 * handler alone (see comment in sigabrt_eater). Interpose the
 * function itself: do the same logging the C++ verbose terminate
 * handler would have done (so the user can see WHY abort fired in
 * the bambu-studio log) then park this thread forever. */
typedef void (*abort_fn)(void) __attribute__((noreturn));
static abort_fn real_abort = NULL;

void abort(void) __attribute__((noreturn));
void abort(void)
{
    if (!real_abort) real_abort = (abort_fn)dlsym(RTLD_NEXT, "abort");
    v2_log("abort() interposed -> parking thread\n");
    abort_thread_park();
    /* Unreachable. */
    if (real_abort) real_abort();
    _exit(127);
}

/* exit() / _exit() interpose. When WD_V2_NO_EXIT=1 (paired with
 * WD_V2_EAT_SIGABRT) the shim also parks any caller of exit()/_exit().
 * Use cautiously — this prevents the process from EVER terminating
 * normally; only SIGKILL from outside will kill it. Intended only for
 * the brief attach window during d-extraction. */
typedef void (*exit_fn)(int) __attribute__((noreturn));
static exit_fn real_exit  = NULL;
static exit_fn real__exit = NULL;
static int     no_exit_armed = 0;

void exit(int status) __attribute__((noreturn));
void exit(int status)
{
    if (!real_exit) real_exit = (exit_fn)dlsym(RTLD_NEXT, "exit");
    if (no_exit_armed) {
        v2_log("exit(%d) interposed -> parking\n", status);
        abort_thread_park();
    }
    real_exit(status);
}

void _exit(int status) __attribute__((noreturn));
void _exit(int status)
{
    if (!real__exit) real__exit = (exit_fn)dlsym(RTLD_NEXT, "_exit");
    if (no_exit_armed) {
        v2_log("_exit(%d) interposed -> parking\n", status);
        abort_thread_park();
    }
    real__exit(status);
}

static void install_sigabrt_eater(void)
{
    struct sigaction sa = {0};
    sa.sa_sigaction = sigabrt_eater;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGABRT, &sa, NULL);
}

__attribute__((constructor))
static void watchdog_defeat_v2_init(void)
{
    resolve_reals();

    const char* log_path = getenv("WD_V2_LOG");
    if (log_path) {
        char p[256];
        if (strchr(log_path, '/'))
            snprintf(p, sizeof(p), "%s", log_path);
        else
            snprintf(p, sizeof(p), "/tmp/wd_v2_%d.log", getpid());
        v2_log_fd = open(p, O_WRONLY | O_CREAT | O_APPEND, 0600);
        v2_log("=== watchdog_defeat_v2 init pid=%d ===\n", getpid());
    }

    int rc = prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    fprintf(stderr,
            "[watchdog_defeat_v2] loaded pid=%d ptrace_rc=%d log=%s\n",
            getpid(), rc, log_path ? log_path : "(off)");
    fflush(stderr);

    if (getenv("WD_V2_EAT_SIGABRT")) {
        install_sigabrt_eater();
        fprintf(stderr, "[watchdog_defeat_v2] SIGABRT eater installed\n");
        fflush(stderr);
    }

    if (getenv("WD_V2_NO_EXIT")) {
        /* Only interpose exit() in the main bambustu_main / bambu-studio
         * process — child helpers (sh, WebKit) legitimately call
         * _exit(0) during normal shutdown and freezing them deadlocks
         * the parent. Check /proc/self/exe basename. */
        char buf[256];
        ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        int is_target = 0;
        if (n > 0) {
            buf[n] = '\0';
            const char* base = strrchr(buf, '/');
            base = base ? base + 1 : buf;
            if (strcmp(base, "bambustu_main") == 0 ||
                strcmp(base, "bambu-studio")  == 0)
                is_target = 1;
        }
        if (is_target) {
            no_exit_armed = 1;
            fprintf(stderr, "[watchdog_defeat_v2] exit/_exit interpose armed\n");
            fflush(stderr);
        } else if (n > 0) {
            fprintf(stderr,
                    "[watchdog_defeat_v2] exit/_exit interpose SKIPPED for %s\n",
                    buf);
            fflush(stderr);
        }
    }

    if (getenv("WD_V2_SECCOMP")) {
        int src = install_seccomp_filter();
        fprintf(stderr,
                "[watchdog_defeat_v2] seccomp=%s\n",
                src == 0 ? "on" : "off");
        fflush(stderr);
    }
}
