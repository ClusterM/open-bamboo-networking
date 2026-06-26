// bambu_extract_d.cpp — Self-contained RSA-d extractor for libbambu_networking v02.05.03.63
// Phase 0: if _SELF_PRELOADED not set, write watchdog shim to memfd and re-exec with LD_PRELOAD.
// Phase 1: fork child (dlopen+sign) + parent (ptrace+capture+reconstruct).
// Self-contained: embeds watchdog_defeat_v2.so + slicer_base64.cer as C arrays.

// ---- Embedded assets ----
#include "watchdog_defeat_embed.h"   // unsigned char watchdog_defeat_embed_so[] + _len
#include "slicer_cert_embed.h"       // unsigned char slicer_base64_cer[] + _len

// ---- Phase 0: self-re-exec bootstrap ----
// Must be included BEFORE any other code so bootstrap_if_needed() can be
// called as the very first thing in main().
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

    // Write shim to a memfd (no MFD_CLOEXEC — fd must survive execve).
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

// extract_d_fast.cpp — FASTPATH d-extractor for libbambu_networking 02.05.03.63
//
// Single C++17 binary. Forks a child that dlopens the proprietary plugin
// and drives a fake print.command=pushall through send_message_to_printer.
// Parent ptraces, arms a hardware breakpoint at the version-locked
// accumulator PC, harvests rdx-low-byte at every trap. After 256 bytes
// (= dp || dq big-endian) it factors N, computes d, validates against the
// envelope corpus, and writes d_extracted.json (mode 0600).
//
// No qemu. No trace files. No INT3 (HW BPs don't perturb the VMP CRC sweep).
// No Python.
//
// Target wall time: ~30 s on a workstation.
//
// Architecture lineage:
//   PATH_V + PATH_VV identified the version-locked accumulator PC
//     accumulator_offset = 0x1792ca, register rdx (low byte) for v02.05.03.63
//   This program is a thin runtime over that empirical finding.

#include <dirent.h>
#include <dlfcn.h>
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
#include "vendored/mqtt_mini_broker.hpp"

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// ===========================================================================
// Version-locked constants (PATH_V + PATH_VV discovery, linux_02.05.03.63)
// ===========================================================================
namespace version_02_05_03_63 {
    // Corrected 2026-06-20: PATH_V's notation `libbambu+0x178f5b` is shorthand
    // for the *absolute address* 0x7f017a178f5b, NOT an offset. The actual
    // offset from libbambu r-xp base 0x7f01799b8000 (at SCATTER capture time)
    // is 0x7c0f5b. Verified against path_y2_target.json::abs_at_SCATTER_libbambu_base
    // and against PATH_V findings.json: "libbambu+0x7c0f5b".
    static constexpr uint64_t WRAPPING_FN_OFFSET = 0x7c0f5b;  // optional sanity
    static constexpr uint64_t BYTE_LOAD_OFFSET   = 0x7c129c;  // movzx edx,[rcx]
    static constexpr uint64_t ACCUMULATOR_OFFSET = 0x7c12ca;  // mov [rsp+0x48],edx

    // Register holding the freshly loaded byte in its low 8 bits
    // at ACCUMULATOR_OFFSET (`mov [rsp+0x48], edx` — rdx low byte).
    static constexpr const char ACCUMULATOR_REG_NAME[] = "rdx";

    static constexpr int BYTES_PER_CRT_HALF = 128;
    static constexpr int CRT_HALVES         = 2;
    static constexpr int TOTAL_BYTES        = BYTES_PER_CRT_HALF * CRT_HALVES;

    static constexpr int E_PUB = 65537;
    static constexpr int MAX_K = 65537;  // bounds factor-recovery search

    // Public RSA modulus N for slicer key in this version, from
    // tests/regression_known_version/expected_d.json (sanity-check only;
    // the extractor accepts --modulus-n-hex to override).
    static constexpr const char N_HEX_DEFAULT[] =
        "0xe201171629c05d1b15a5db951e98b78c25a75489f7edbcb1759a0bbc15bf610a"
        "f498472b16ba182982d0475d5e1d162752582700282fd1bab3311d24108cb329"
        "32abb3d330e5d2950a8dcbee904169b209286604a01451ec80788e8f0256786f"
        "802fd6f4a5d6cff95c435c6c9836228cad8fe67452da64df84bfefa0f7f12ea7"
        "359de9b7621c630abbafc3e031f77e2a785a29ca3df9983e8f1cd519963951bd"
        "c3c9766dd1e80ca4b6ad65697b6269790f6cc6c35f997021aa55ab6a36f06340"
        "e3d1264717204853e592471462e9db937ab3bc1148f9148aca22a62932f154e0"
        "b672c223033c49c0efc921119b2d3687d5f4345da995d37c814ae24a09a287d1";
}

// ===========================================================================
// Per-version profiles for multi-version support
// ===========================================================================
struct VersionProfile {
    const char* tag;        // version label for logging
    uint64_t    so_size;    // file size in bytes (for .so identification)
    double      warmup_s;   // seconds to wait after ESTAB before attaching
    // accumulator_offset: if non-zero, override dynamic discovery fallback
    // (used when the version has a known stable offset)
    uint64_t    accumulator_offset; // 0 = rely on dynamic discover only
};

static const VersionProfile PROFILES[] = {
    // warmup_s: how long after daemon start to wait before SEIZE.
    // 4s gives the plugin time to dlopen+init while WD_V2_FAKE_TRACEME
    // suppresses the VMP sentinel so DR0 can be armed on all threads.
    // Dynamic discovery finds the accumulator after warmup (K-table absent
    // at 4s — VMP decodes lazily on first sign); VersionProfile offset used.
    {"02.04.00.84",  4474056,  4.0, 0},
    {"02.05.01.52",  4655128,  4.0, 0},
    {"02.05.03.63",  4589752,  4.0, version_02_05_03_63::ACCUMULATOR_OFFSET},  // baseline
    {"02.06.00.50",  4589320,  4.0, 0},
    {"02.06.01.50", 13864088,  4.0, 0},
    {"02.07.01.51", 14775608,  4.0, 0},
    {"02.05.03.63*", 15705656, 4.0, version_02_05_03_63::ACCUMULATOR_OFFSET},  // BambuStudio-installed full build
    {nullptr, 0, 4.0, 0},  // sentinel
};

// Identify plugin version from file size.
static const VersionProfile* identify_version(const std::string& plugin_path) {
    struct stat st{};
    if (stat(plugin_path.c_str(), &st) != 0) return nullptr;
    uint64_t sz = (uint64_t)st.st_size;
    for (const auto& p : PROFILES) {
        if (!p.tag) break;
        if (p.so_size == sz) return &p;
    }
    return nullptr;  // unknown
}

// ===========================================================================
// CLI parsing
// ===========================================================================
struct Args {
    std::string plugin_path;
    std::string envelopes_path;
    std::string modulus_n_hex;
    std::string dev_id;
    std::string mosquitto_host = "127.0.0.1:1883";
    std::string access_code   = "000000";
    std::string mtls_cert;
    std::string mtls_key;
    std::string out_path      = "d_extracted.json";
    bool verbose              = false;
    bool diagnostic           = false;  // arms DR0/DR1/DR2 simultaneously and
                                        // logs every trap exhaustively
    int timeout_s             = 60;

    // ATTACH_MODE additions (2026-06-21) ------------------------------------
    //   --attach-pid <pid>          attach to an existing process instead of
    //                               fork()+dlopen. Skips mock-broker / mock-
    //                               printer / cert-handshake. Used when the
    //                               target is a real BambuStudio in a logged-
    //                               in, sign-active state that we can't drive
    //                               from scratch (cloud-auth wall).
    //   --i-know-what-im-doing      required when --attach-pid targets a
    //                               process whose exe basename is one of the
    //                               "real bridge" binaries (bambustu_main /
    //                               bambu-studio). Default is to REFUSE so a
    //                               careless invocation can't disturb a live
    //                               sign session for a real printer.
    //   --no-envelopes              skip envelope validation. Used by the
    //                               smoke test to exercise the PTRACE_SEIZE +
    //                               arm + detach machinery against a benign
    //                               target without needing a sig corpus.
    pid_t attach_pid          = 0;
    bool  attach_override     = false;
    bool  no_envelopes        = false;
    bool  no_printer          = false;  // offline mode: start FakePrinterBroker
};

static void usage(const char* p) {
    std::fprintf(stderr,
        "usage: %s [options]\n"
        "  --plugin PATH           libbambu_networking.so to extract (REQUIRED)\n"
        "  --envelopes PATH        envelopes.json (REQUIRED unless --no-envelopes)\n"
        "  --modulus-n-hex HEX     N as 0x... (defaults to baked-in)\n"
        "  --dev-id ID             printer serial number (auto-detected from BambuStudio.conf\n"
        "                          if exactly one printer is paired)\n"
        "  --mosquitto-host HOST   broker (default 127.0.0.1:1883)\n"
        "  --access-code CODE      printer access code (default 000000)\n"
        "  --mtls-cert PATH        client cert (or env BBL_MTLS_CERT)\n"
        "  --mtls-key  PATH        client key  (or env BBL_MTLS_KEY)\n"
        "  --out PATH              output (default d_extracted.json)\n"
        "  --verbose               log every HW BP hit\n"
        "  --diagnostic            arm DR0/DR1/DR2 simultaneously at wrap+byte+acc\n"
        "                          PCs; log every trap with which DR fired and the\n"
        "                          full register state. Does NOT park sentinel\n"
        "                          threads. Does NOT attempt reconstruction.\n"
        "  --timeout SECONDS       fail if not 256 bytes (default 60)\n"
        "\n"
        "Attach mode (skip fork+dlopen+mock-broker, attach to a logged-in\n"
        "process whose sign-gate is already open):\n"
        "  --attach-pid PID        PTRACE_SEIZE this pid; discover acc PC by\n"
        "                          scanning its libbambu_networking r-xp +\n"
        "                          anon arena; capture 256 bytes from sign\n"
        "                          events. Skips ALL mock infra.\n"
        "  --i-know-what-im-doing  required to attach to bambustu_main /\n"
        "                          bambu-studio (real bridge / live UI). With-\n"
        "                          out this, attach to those binaries is REFUSED.\n"
        "  --no-envelopes          skip envelope load + validation. Use for the\n"
        "                          attach-mode smoke test against a benign target.\n",
        p);
}

static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](std::string& slot) -> bool {
            if (i + 1 >= argc) { std::fprintf(stderr, "missing value for %s\n", s.c_str()); return false; }
            slot = argv[++i]; return true;
        };
        if      (s == "--plugin")          { if (!need(a.plugin_path)) return false; }
        else if (s == "--envelopes")       { if (!need(a.envelopes_path)) return false; }
        else if (s == "--modulus-n-hex")   { if (!need(a.modulus_n_hex)) return false; }
        else if (s == "--dev-id")          { if (!need(a.dev_id)) return false; }
        else if (s == "--mosquitto-host")  { if (!need(a.mosquitto_host)) return false; }
        else if (s == "--access-code")     { if (!need(a.access_code)) return false; }
        else if (s == "--mtls-cert")       { if (!need(a.mtls_cert)) return false; }
        else if (s == "--mtls-key")        { if (!need(a.mtls_key)) return false; }
        else if (s == "--out")             { if (!need(a.out_path)) return false; }
        else if (s == "--verbose")         { a.verbose = true; }
        else if (s == "--diagnostic")      { a.diagnostic = true; a.verbose = true; }
        else if (s == "--timeout")         { std::string t; if (!need(t)) return false; a.timeout_s = std::atoi(t.c_str()); }
        else if (s == "--attach-pid")      { std::string t; if (!need(t)) return false; a.attach_pid = (pid_t)std::atoi(t.c_str()); }
        else if (s == "--i-know-what-im-doing") { a.attach_override = true; }
        else if (s == "--no-envelopes")    { a.no_envelopes = true; }
        else if (s == "--help" || s == "-h") { return false; }
        else { std::fprintf(stderr, "unknown arg: %s\n", s.c_str()); return false; }
    }
    if (a.plugin_path.empty()) {
        std::fprintf(stderr, "--plugin is required\n");
        return false;
    }
    if (a.envelopes_path.empty() && !a.no_envelopes) {
        std::fprintf(stderr, "--envelopes is required (or pass --no-envelopes for smoke-test mode)\n");
        return false;
    }
    if (a.mtls_cert.empty()) {
        if (const char* e = std::getenv("BBL_MTLS_CERT")) a.mtls_cert = e;
    }
    if (a.mtls_key.empty()) {
        if (const char* e = std::getenv("BBL_MTLS_KEY")) a.mtls_key = e;
    }
    return true;
}

// ===========================================================================
// Logging
// ===========================================================================
static double g_t0 = 0;
static double now_s() {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
#define LOGF(prefix, fmt, ...) do { \
    std::fprintf(stderr, "[%6.2fs] %s " fmt "\n", now_s() - g_t0, prefix, ##__VA_ARGS__); \
} while (0)
#define LOG_I(fmt, ...) LOGF("[ info]", fmt, ##__VA_ARGS__)
#define LOG_W(fmt, ...) LOGF("[ warn]", fmt, ##__VA_ARGS__)
#define LOG_E(fmt, ...) LOGF("[ err ]", fmt, ##__VA_ARGS__)
#define LOG_V(fmt, ...) do { if (g_verbose) LOGF("[trap ]", fmt, ##__VA_ARGS__); } while (0)
static bool g_verbose = false;

// ===========================================================================
// Bignum helpers built on top of vendored Montgomery modexp.
//
// We need:
//   - parse hex string -> 256-byte BE buffer (allowing shorter, left-pad)
//   - parse hex string -> arbitrary-precision big-int for factor recovery
//   - factor N from candidate dp/dq, compute d
//
// All bignum ops for factor recovery are done in a small home-grown
// big-int (`BigInt`) using base 2^32 limbs. We need:
//   add, sub, mul (small), divmod (small + by-self), shift, cmp, isqrt
// for the factor-recovery loop. 2048-bit ops are slow per-op but the
// factor-recovery loop runs at most max_k = E iterations.
// ===========================================================================
namespace bn {

struct BigInt {
    // Little-endian base 2^32 limbs. Empty = zero.
    std::vector<uint32_t> v;
    BigInt() = default;
    BigInt(uint32_t x) { if (x) v.push_back(x); }

    void trim() { while (!v.empty() && v.back() == 0) v.pop_back(); }
    bool is_zero() const { return v.empty(); }
    int bit_length() const {
        if (v.empty()) return 0;
        uint32_t top = v.back();
        int b = 32; while (top && !(top & 0x80000000u)) { top <<= 1; --b; }
        return (int(v.size()) - 1) * 32 + b;
    }
    static int cmp(const BigInt& a, const BigInt& b) {
        if (a.v.size() != b.v.size()) return a.v.size() < b.v.size() ? -1 : 1;
        for (size_t i = a.v.size(); i-- > 0;) {
            if (a.v[i] != b.v[i]) return a.v[i] < b.v[i] ? -1 : 1;
        }
        return 0;
    }
};

static BigInt from_bytes_be(const uint8_t* p, size_t n) {
    BigInt r;
    // big-endian -> little-endian limb array
    // group into 4-byte limbs from the right.
    if (n == 0) return r;
    size_t nl = (n + 3) / 4;
    r.v.assign(nl, 0);
    for (size_t i = 0; i < n; ++i) {
        size_t byte_from_lsb = n - 1 - i;
        size_t limb_ix = byte_from_lsb / 4;
        size_t in_limb = byte_from_lsb % 4;
        r.v[limb_ix] |= uint32_t(p[i]) << (in_limb * 8);
    }
    r.trim();
    return r;
}

static BigInt from_hex(const std::string& in) {
    std::string s = in;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s = s.substr(2);
    }
    // strip whitespace
    std::string clean;
    for (char c : s) if (c != ' ' && c != '\n' && c != '\r' && c != '\t') clean.push_back(c);
    if (clean.empty()) return BigInt(0);
    if (clean.size() & 1) clean = "0" + clean;
    std::vector<uint8_t> bytes(clean.size() / 2);
    auto hex_nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };
    for (size_t i = 0; i < bytes.size(); ++i) {
        int hi = hex_nib(clean[2*i]), lo = hex_nib(clean[2*i+1]);
        if (hi < 0 || lo < 0) return BigInt(0);
        bytes[i] = uint8_t((hi << 4) | lo);
    }
    return from_bytes_be(bytes.data(), bytes.size());
}

// Convert to fixed-size big-endian 256-byte buffer (RSA-2048 modulus or sig).
static void to_bytes_be_fixed(const BigInt& a, uint8_t* out, size_t n) {
    std::memset(out, 0, n);
    for (size_t i = 0; i < a.v.size(); ++i) {
        uint32_t w = a.v[i];
        for (int b = 0; b < 4; ++b) {
            size_t byte_from_lsb = i * 4 + b;
            if (byte_from_lsb >= n) break;
            size_t out_ix = n - 1 - byte_from_lsb;
            out[out_ix] = uint8_t(w >> (b * 8));
        }
    }
}

static std::string to_hex_str(const BigInt& a, bool with_0x = true) {
    if (a.v.empty()) return with_0x ? "0x0" : "0";
    std::string r;
    // emit MSB first.
    bool started = false;
    for (size_t i = a.v.size(); i-- > 0;) {
        uint32_t w = a.v[i];
        char buf[9];
        std::snprintf(buf, sizeof(buf), "%08x", w);
        if (!started) {
            int skip = 0;
            while (skip < 8 && buf[skip] == '0') ++skip;
            if (skip < 8) {
                r.append(buf + skip);
                started = true;
            }
        } else {
            r.append(buf);
        }
    }
    if (!started) r = "0";
    return with_0x ? "0x" + r : r;
}

// r = a + b
static BigInt add(const BigInt& a, const BigInt& b) {
    BigInt r;
    size_t n = std::max(a.v.size(), b.v.size());
    r.v.assign(n + 1, 0);
    uint64_t carry = 0;
    for (size_t i = 0; i < n; ++i) {
        uint64_t x = (i < a.v.size() ? a.v[i] : 0);
        uint64_t y = (i < b.v.size() ? b.v[i] : 0);
        uint64_t s = x + y + carry;
        r.v[i] = uint32_t(s);
        carry = s >> 32;
    }
    r.v[n] = uint32_t(carry);
    r.trim();
    return r;
}

// r = a - b assuming a >= b
static BigInt sub(const BigInt& a, const BigInt& b) {
    BigInt r;
    r.v.assign(a.v.size(), 0);
    int64_t borrow = 0;
    for (size_t i = 0; i < a.v.size(); ++i) {
        int64_t x = a.v[i];
        int64_t y = (i < b.v.size() ? b.v[i] : 0);
        int64_t s = x - y - borrow;
        if (s < 0) { s += (1LL << 32); borrow = 1; } else borrow = 0;
        r.v[i] = uint32_t(s);
    }
    r.trim();
    return r;
}

// r = a * small
static BigInt mul_small(const BigInt& a, uint32_t s) {
    BigInt r;
    if (a.is_zero() || s == 0) return r;
    r.v.assign(a.v.size() + 1, 0);
    uint64_t carry = 0;
    for (size_t i = 0; i < a.v.size(); ++i) {
        uint64_t p = uint64_t(a.v[i]) * s + carry;
        r.v[i] = uint32_t(p);
        carry = p >> 32;
    }
    r.v[a.v.size()] = uint32_t(carry);
    r.trim();
    return r;
}

// r = a / small ; rem = a % small. (small > 0)
static BigInt div_small(const BigInt& a, uint32_t s, uint32_t* rem_out = nullptr) {
    BigInt r;
    r.v.assign(a.v.size(), 0);
    uint64_t rem = 0;
    for (size_t i = a.v.size(); i-- > 0;) {
        uint64_t cur = (rem << 32) | a.v[i];
        r.v[i] = uint32_t(cur / s);
        rem = cur % s;
    }
    r.trim();
    if (rem_out) *rem_out = uint32_t(rem);
    return r;
}

// r = a * b (schoolbook)
static BigInt mul(const BigInt& a, const BigInt& b) {
    BigInt r;
    if (a.is_zero() || b.is_zero()) return r;
    r.v.assign(a.v.size() + b.v.size(), 0);
    for (size_t i = 0; i < a.v.size(); ++i) {
        uint64_t carry = 0;
        uint64_t ai = a.v[i];
        for (size_t j = 0; j < b.v.size(); ++j) {
            uint64_t s = uint64_t(r.v[i + j]) + ai * b.v[j] + carry;
            r.v[i + j] = uint32_t(s);
            carry = s >> 32;
        }
        r.v[i + b.v.size()] += uint32_t(carry);
    }
    r.trim();
    return r;
}

// r = a mod b   (binary long-division; b > 0).
// Used in two places only — N % p and a few setup divisions.
static BigInt mod(const BigInt& a, const BigInt& b) {
    if (BigInt::cmp(a, b) < 0) return a;
    if (b.v.size() == 1) {
        uint32_t rem = 0;
        div_small(a, b.v[0], &rem);
        return BigInt(rem);
    }
    // Bit-by-bit long division. 2048-bit "a" => 2048 iterations. Fine.
    BigInt r;
    int top = a.bit_length();
    for (int i = top - 1; i >= 0; --i) {
        // r = (r << 1) | bit_i_of_a
        // shift left by 1
        uint32_t carry = 0;
        for (size_t k = 0; k < r.v.size(); ++k) {
            uint64_t s = (uint64_t(r.v[k]) << 1) | carry;
            r.v[k] = uint32_t(s);
            carry = uint32_t(s >> 32);
        }
        if (carry) r.v.push_back(carry);
        // OR in bit i of a
        size_t limb = i / 32, bit = i % 32;
        if (limb < a.v.size() && ((a.v[limb] >> bit) & 1)) {
            if (r.v.empty()) r.v.push_back(1u); else r.v[0] |= 1u;
        }
        r.trim();
        if (BigInt::cmp(r, b) >= 0) r = sub(r, b);
    }
    return r;
}

// d = a / b (binary long division; companion to mod).
// Returns quotient AND modifies *rem_out to hold the remainder.
static BigInt div(const BigInt& a, const BigInt& b, BigInt* rem_out = nullptr) {
    if (BigInt::cmp(a, b) < 0) { if (rem_out) *rem_out = a; return BigInt(0); }
    BigInt q, r;
    int top = a.bit_length();
    q.v.assign((top + 31) / 32, 0);
    for (int i = top - 1; i >= 0; --i) {
        // r <<= 1
        uint32_t carry = 0;
        for (size_t k = 0; k < r.v.size(); ++k) {
            uint64_t s = (uint64_t(r.v[k]) << 1) | carry;
            r.v[k] = uint32_t(s);
            carry = uint32_t(s >> 32);
        }
        if (carry) r.v.push_back(carry);
        // r |= bit i of a
        size_t limb = i / 32, bit = i % 32;
        if (limb < a.v.size() && ((a.v[limb] >> bit) & 1)) {
            if (r.v.empty()) r.v.push_back(1u); else r.v[0] |= 1u;
        }
        r.trim();
        if (BigInt::cmp(r, b) >= 0) {
            r = sub(r, b);
            size_t qlimb = i / 32, qbit = i % 32;
            if (qlimb >= q.v.size()) q.v.resize(qlimb + 1, 0);
            q.v[qlimb] |= (1u << qbit);
        }
    }
    q.trim();
    if (rem_out) *rem_out = r;
    return q;
}

// Extended gcd in BigInt domain for modular inverse.
// Returns x with (a*x) mod n == 1, or BigInt(0) if no inverse.
// Sign handling: we keep separate signs since BigInt is unsigned.
struct SignedBI { BigInt val; bool neg = false; };

static int cmp_s(const SignedBI& a, const SignedBI& b) {
    if (a.neg != b.neg) {
        // both zero -> equal
        bool a_zero = a.val.is_zero(), b_zero = b.val.is_zero();
        if (a_zero && b_zero) return 0;
        return a.neg ? -1 : 1;
    }
    int c = BigInt::cmp(a.val, b.val);
    return a.neg ? -c : c;
}

static SignedBI add_s(const SignedBI& a, const SignedBI& b) {
    SignedBI r;
    if (a.neg == b.neg) { r.val = add(a.val, b.val); r.neg = a.neg && !r.val.is_zero(); return r; }
    int c = BigInt::cmp(a.val, b.val);
    if (c >= 0) { r.val = sub(a.val, b.val); r.neg = a.neg && !r.val.is_zero(); }
    else        { r.val = sub(b.val, a.val); r.neg = b.neg && !r.val.is_zero(); }
    return r;
}

static SignedBI sub_s(const SignedBI& a, const SignedBI& b) {
    SignedBI nb = b; if (!nb.val.is_zero()) nb.neg = !nb.neg;
    return add_s(a, nb);
}

static SignedBI mul_s(const SignedBI& a, const SignedBI& b) {
    SignedBI r; r.val = mul(a.val, b.val);
    r.neg = (a.neg != b.neg) && !r.val.is_zero();
    return r;
}

// (a*x) mod n == 1 → return x in [0, n); else BigInt(0) on failure.
static BigInt mod_inverse(const BigInt& a_in, const BigInt& n) {
    // Extended euclidean.
    SignedBI old_r{a_in, false}, r{n, false};
    SignedBI old_s{BigInt(1), false}, s{BigInt(0), false};
    while (!r.val.is_zero()) {
        BigInt rem;
        BigInt q = div(old_r.val, r.val, &rem);
        SignedBI sq; sq.val = q; sq.neg = (old_r.neg != r.neg);
        // (old_r, r) = (r, old_r - q*r)
        SignedBI mul_qr = mul_s(sq, r);
        SignedBI new_r  = sub_s(old_r, mul_qr);
        old_r = r; r = new_r;
        SignedBI mul_qs = mul_s(sq, s);
        SignedBI new_s  = sub_s(old_s, mul_qs);
        old_s = s; s = new_s;
    }
    // gcd is old_r.val; must be 1 for invertibility.
    if (BigInt::cmp(old_r.val, BigInt(1)) != 0) return BigInt(0);
    // result is old_s mod n
    SignedBI res = old_s;
    while (res.neg && !res.val.is_zero()) res = add_s(res, SignedBI{n, false});
    res.val = mod(res.val, n);
    return res.val;
}

// isqrt of a BigInt (Newton).
static BigInt isqrt(const BigInt& n) {
    if (n.is_zero()) return BigInt(0);
    int bits = n.bit_length();
    // Initial guess: x = 2^((bits+1)/2)
    BigInt x; x.v.assign(((bits + 1) / 2) / 32 + 1, 0);
    int b = (bits + 1) / 2;
    x.v[b / 32] = (1u << (b % 32));
    x.trim();
    while (true) {
        // y = (x + n/x) / 2
        BigInt q = div(n, x);
        BigInt s = add(x, q);
        // divide by 2
        uint32_t carry = 0;
        for (size_t k = s.v.size(); k-- > 0;) {
            uint32_t cur = s.v[k];
            uint32_t out = (carry << 31) | (cur >> 1);
            s.v[k] = out;
            carry = cur & 1;
        }
        s.trim();
        if (BigInt::cmp(s, x) >= 0) return x;
        x = s;
    }
}

}  // namespace bn

// ===========================================================================
// Maps parsing: find libbambu_networking.so r-xp base in child
// ===========================================================================
static uint64_t find_plugin_text_base(pid_t pid, const std::string& plugin_path) {
    // Resolve absolute basename so we match the entry in /proc/<pid>/maps.
    std::string bn;
    {
        size_t p = plugin_path.find_last_of('/');
        bn = (p == std::string::npos) ? plugin_path : plugin_path.substr(p + 1);
    }
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    std::ifstream f(path);
    if (!f) return 0;
    std::string line;
    while (std::getline(f, line)) {
        // 7f...000-7f...000 r-xp 00xxxx 00:00 inode  /path/to/lib
        if (line.find(bn) == std::string::npos) continue;
        // require r-xp permissions
        size_t sp = line.find(' ');
        if (sp == std::string::npos) continue;
        size_t sp2 = line.find(' ', sp + 1);
        if (sp2 == std::string::npos) continue;
        std::string perms = line.substr(sp + 1, sp2 - sp - 1);
        if (perms.size() < 4 || perms[2] != 'x') continue;
        // grab start
        size_t dash = line.find('-');
        if (dash == std::string::npos) continue;
        uint64_t lo = std::stoull(line.substr(0, dash), nullptr, 16);
        // Offset column (after inode is the path). Parse offset to ensure
        // r-xp segment is the one whose file-offset is 0 (or the lowest).
        // For .so r-xp it's usually 0 — keep first match.
        return lo;
    }
    return 0;
}

// ===========================================================================
// JSON envelope parsing — small + targeted.
//
// We only need: array of envelopes; per envelope we need ``to_sign`` (string)
// and ``sig_b64`` (string). Skip everything else.
// ===========================================================================
struct Envelope {
    std::string to_sign;
    std::string sig_b64;
    std::string cmd;  // optional, for error reporting
};

namespace mini_json {

// Skip whitespace.
static void skip_ws(const std::string& s, size_t& i) {
    while (i < s.size()) {
        char c = s[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++i;
        else break;
    }
}

// Parse a JSON string at s[i] (i pointing at the opening '"'). Returns
// the unescaped contents. Updates i to past the closing quote.
static bool parse_string(const std::string& s, size_t& i, std::string& out) {
    if (i >= s.size() || s[i] != '"') return false;
    ++i;
    out.clear();
    while (i < s.size()) {
        char c = s[i++];
        if (c == '"') return true;
        if (c == '\\') {
            if (i >= s.size()) return false;
            char e = s[i++];
            switch (e) {
                case '"':  out.push_back('"');  break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/');  break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'u': {
                    if (i + 4 > s.size()) return false;
                    int cp = 0;
                    for (int k = 0; k < 4; ++k) {
                        char h = s[i++]; int d = -1;
                        if (h >= '0' && h <= '9') d = h - '0';
                        else if (h >= 'a' && h <= 'f') d = 10 + h - 'a';
                        else if (h >= 'A' && h <= 'F') d = 10 + h - 'A';
                        else return false;
                        cp = (cp << 4) | d;
                    }
                    // Encode as UTF-8 (the envelopes' to_sign uses only
                    // ASCII in practice; but be safe).
                    if (cp < 0x80) out.push_back(char(cp));
                    else if (cp < 0x800) {
                        out.push_back(char(0xc0 | (cp >> 6)));
                        out.push_back(char(0x80 | (cp & 0x3f)));
                    } else {
                        out.push_back(char(0xe0 | (cp >> 12)));
                        out.push_back(char(0x80 | ((cp >> 6) & 0x3f)));
                        out.push_back(char(0x80 | (cp & 0x3f)));
                    }
                    break;
                }
                default: return false;
            }
        } else {
            out.push_back(c);
        }
    }
    return false;
}

// Skip an arbitrary JSON value at s[i]. Updates i past the value.
static bool skip_value(const std::string& s, size_t& i) {
    skip_ws(s, i);
    if (i >= s.size()) return false;
    char c = s[i];
    if (c == '"') { std::string t; return parse_string(s, i, t); }
    if (c == '{' || c == '[') {
        char open = c, close = (c == '{') ? '}' : ']';
        ++i;
        int depth = 1;
        bool in_str = false;
        bool esc = false;
        while (i < s.size() && depth > 0) {
            char ch = s[i++];
            if (in_str) {
                if (esc) { esc = false; continue; }
                if (ch == '\\') { esc = true; continue; }
                if (ch == '"') in_str = false;
                continue;
            }
            if (ch == '"') in_str = true;
            else if (ch == open) ++depth;
            else if (ch == close) --depth;
        }
        return depth == 0;
    }
    // primitive (number, true, false, null) — read until , } ]
    while (i < s.size()) {
        char ch = s[i];
        if (ch == ',' || ch == '}' || ch == ']' || ch == ' ' || ch == '\n' ||
            ch == '\r' || ch == '\t') break;
        ++i;
    }
    return true;
}

// Parse one envelope object {.. "to_sign": "...", "sig_b64": "...", ...}.
// On entry s[i] = '{'.
static bool parse_envelope(const std::string& s, size_t& i, Envelope& env) {
    if (i >= s.size() || s[i] != '{') return false;
    ++i;
    while (true) {
        skip_ws(s, i);
        if (i >= s.size()) return false;
        if (s[i] == '}') { ++i; return true; }
        if (s[i] == ',') { ++i; continue; }
        std::string key;
        if (!parse_string(s, i, key)) return false;
        skip_ws(s, i);
        if (i >= s.size() || s[i] != ':') return false;
        ++i;
        skip_ws(s, i);
        if (key == "to_sign") {
            if (!parse_string(s, i, env.to_sign)) return false;
        } else if (key == "sig_b64") {
            if (!parse_string(s, i, env.sig_b64)) return false;
        } else if (key == "cmd") {
            if (s[i] == '"') { parse_string(s, i, env.cmd); }
            else skip_value(s, i);
        } else {
            if (!skip_value(s, i)) return false;
        }
    }
}

static bool parse_envelopes(const std::string& s, std::vector<Envelope>& out) {
    size_t i = 0;
    skip_ws(s, i);
    if (i >= s.size() || s[i] != '{') return false;
    // Skim top-level dict for key "envelopes" -> array.
    ++i;
    bool found = false;
    while (i < s.size() && !found) {
        skip_ws(s, i);
        if (s[i] == '}') break;
        if (s[i] == ',') { ++i; continue; }
        std::string key;
        if (!parse_string(s, i, key)) return false;
        skip_ws(s, i);
        if (s[i] != ':') return false;
        ++i;
        skip_ws(s, i);
        if (key == "envelopes") {
            if (s[i] != '[') return false;
            ++i;
            while (true) {
                skip_ws(s, i);
                if (i >= s.size()) return false;
                if (s[i] == ']') { ++i; break; }
                if (s[i] == ',') { ++i; continue; }
                Envelope env;
                if (!parse_envelope(s, i, env)) return false;
                if (!env.to_sign.empty() && !env.sig_b64.empty()) {
                    out.push_back(std::move(env));
                }
            }
            found = true;
        } else {
            if (!skip_value(s, i)) return false;
        }
    }
    return found && !out.empty();
}

}  // namespace mini_json

// Base64 decode (RFC 4648). Output appended to `out`.
static bool base64_decode(const std::string& in, std::vector<uint8_t>& out) {
    static int8_t T[256];
    static bool init = false;
    if (!init) {
        for (int i = 0; i < 256; ++i) T[i] = -1;
        const char* A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; ++i) T[uint8_t(A[i])] = int8_t(i);
        T[uint8_t('=')] = -2;
        init = true;
    }
    uint32_t buf = 0; int bits = 0;
    for (char c : in) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        int v = T[uint8_t(c)];
        if (v == -2) break;
        if (v < 0) return false;
        buf = (buf << 6) | uint32_t(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(uint8_t(buf >> bits));
            buf &= (1u << bits) - 1;
        }
    }
    return true;
}

// ===========================================================================
// PKCS#1 v1.5 EMSA-PKCS1-v1_5 for SHA-256.
// ===========================================================================
static void pkcs1_v15_pad_sha256(const uint8_t hash[32], uint8_t out[256]) {
    // DigestInfo for SHA-256
    static const uint8_t DI[] = {
        0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,
        0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
    };
    const size_t k = 256;
    const size_t t_len = sizeof(DI) + 32;
    const size_t ps_len = k - 3 - t_len;
    size_t i = 0;
    out[i++] = 0x00;
    out[i++] = 0x01;
    for (size_t j = 0; j < ps_len; ++j) out[i++] = 0xff;
    out[i++] = 0x00;
    std::memcpy(out + i, DI, sizeof(DI)); i += sizeof(DI);
    std::memcpy(out + i, hash, 32); i += 32;
    // sanity: i == 256
}

// ===========================================================================
// Child: dlopen plugin, register callbacks, drive sign path.
// ===========================================================================

namespace child_side {

using OnUserLoginFn         = std::function<void(int, bool)>;
using OnPrinterConnectedFn  = std::function<void(std::string)>;
using OnLocalConnectedFn    = std::function<void(int, std::string, std::string)>;
using OnServerConnectedFn   = std::function<void(int, int)>;
using OnMessageFn           = std::function<void(std::string, std::string)>;
using OnHttpErrorFn         = std::function<void(unsigned, std::string)>;
using GetCountryCodeFn      = std::function<std::string()>;
using GetSubscribeFailureFn = std::function<void(std::string)>;
using OnMsgArrivedFn        = std::function<void(std::string)>;
using QueueOnMainFn         = std::function<void(std::function<void()>)>;
using ServerCallbackFn      = std::function<void(std::string, int)>;

using create_agent              = void* (*)(std::string);
using init_log                  = int   (*)(void*);
using start                     = int   (*)(void*);
using set_config_dir            = int   (*)(void*, std::string);
using set_cert_file             = int   (*)(void*, std::string, std::string);
using set_country_code          = int   (*)(void*, std::string);
using send_message_to_printer   = int   (*)(void*, std::string, std::string, int, int);
using connect_printer_fn_t      = int   (*)(void*, std::string, std::string,
                                             std::string, std::string, bool);
using install_device_cert_fn_t  = void  (*)(void*, std::string, bool);
using set_user_selected_fn_t    = int   (*)(void*, std::string);
using disconnect_printer_fn_t   = int   (*)(void*);

using set_on_ssdp_msg            = int (*)(void*, OnMsgArrivedFn);
using set_on_user_login          = int (*)(void*, OnUserLoginFn);
using set_on_printer_connected   = int (*)(void*, OnPrinterConnectedFn);
using set_on_server_connected    = int (*)(void*, OnServerConnectedFn);
using set_on_http_error          = int (*)(void*, OnHttpErrorFn);
using set_get_country_code       = int (*)(void*, GetCountryCodeFn);
using set_on_subscribe_failure   = int (*)(void*, GetSubscribeFailureFn);
using set_on_message             = int (*)(void*, OnMessageFn);
using set_on_user_message        = int (*)(void*, OnMessageFn);
using set_on_local_connect       = int (*)(void*, OnLocalConnectedFn);
using set_on_local_message       = int (*)(void*, OnMessageFn);
using set_queue_on_main          = int (*)(void*, QueueOnMainFn);
using set_server_cb_fn           = int (*)(void*, ServerCallbackFn);

// File descriptors for parent<->child rendezvous pipes:
//   g_ready_pipe[0]/[1]: child writes 1 byte AFTER plugin start() succeeds
//                        but BEFORE send_message — parent reads.
//   g_go_pipe[0]/[1]:    parent writes 1 byte after PTRACE_ATTACH is fully
//                        wired (DR0 armed on all threads) — child reads
//                        and then issues send_message_to_printer.
//
// These are defined at file scope below; the extern needs to escape
// the child_side namespace.
}  // close child_side temporarily
extern int g_ready_pipe[2];
extern int g_go_pipe[2];
extern int g_warmup_pipe[2];
extern int g_go2_pipe[2];
namespace child_side {

[[noreturn]] static void child_main(const Args& args) {
    // LATE-ATTACH protocol — no TRACEME at fork. The proprietary plugin
    // detects PTRACE_TRACEME during init (rip=0xdead9001 SIGSEGV within
    // 70ms). We let plugin init run unattended, then:
    //   1) Child writes 'R' to ready pipe.
    //   2) Parent identifies + kills the VMP watchdog process (which has
    //      ptrace-attached the main thread as anti-debug); then SEIZEs
    //      every thread, arms DR0/DR7, sends 'G'.
    //   3) Child reads 'G' and issues send_message_to_printer.

    // Ignore SIGPIPE — paho will write to closed sockets.
    signal(SIGPIPE, SIG_IGN);

    // Optional SIGSEGV diagnostic — print the faulting rip when set.
    if (std::getenv("BBL_CHILD_SEGV_DIAG")) {
        struct sigaction sa{};
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = [](int, siginfo_t* si, void* ctx) {
            ucontext_t* uc = (ucontext_t*)ctx;
            unsigned long rip = uc ? uc->uc_mcontext.gregs[REG_RIP] : 0;
            unsigned long rsp = uc ? uc->uc_mcontext.gregs[REG_RSP] : 0;
            std::fprintf(stderr,
                "[child-segv] rip=0x%lx rsp=0x%lx addr=0x%lx\n",
                rip, rsp, (unsigned long)si->si_addr);
            std::fflush(stderr);
            _exit(128 + SIGSEGV);
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, nullptr);
        sigaction(SIGBUS,  &sa, nullptr);
    }

    // Permit parent to ptrace us once we're ready.
    prctl(PR_SET_PTRACER, (unsigned long)getppid(), 0, 0, 0);
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);

    // Close ends we don't need.
    close(g_ready_pipe[0]);  // child only writes
    close(g_go_pipe[1]);     // child only reads
    close(g_warmup_pipe[0]); // child only writes
    close(g_go2_pipe[1]);    // child only reads

    void* h = dlopen(args.plugin_path.c_str(),
                     RTLD_NOW | RTLD_LOCAL | RTLD_NODELETE);
    if (!h) {
        std::fprintf(stderr, "[child] dlopen failed: %s\n", dlerror());
        _exit(2);
    }

    auto sym = [&](const char* n) {
        void* p = dlsym(h, n);
        if (!p) std::fprintf(stderr, "[child] dlsym %s: %s\n", n, dlerror());
        return p;
    };

    auto create_agent_fn        = (create_agent)               sym("bambu_network_create_agent");
    auto init_log_fn            = (init_log)                   sym("bambu_network_init_log");
    auto start_fn               = (start)                      sym("bambu_network_start");
    auto set_config_dir_fn      = (set_config_dir)             sym("bambu_network_set_config_dir");
    auto set_country_code_fn    = (set_country_code)           sym("bambu_network_set_country_code");
    auto send_msg_fn            = (send_message_to_printer)    sym("bambu_network_send_message_to_printer");
    auto connect_printer_fn     = (connect_printer_fn_t)       sym("bambu_network_connect_printer");
    auto install_dev_cert_fn    = (install_device_cert_fn_t)   sym("bambu_network_install_device_cert");
    auto set_user_machine_fn    = (set_user_selected_fn_t)     sym("bambu_network_set_user_selected_machine");
    auto disconnect_fn          = (disconnect_printer_fn_t)    sym("bambu_network_disconnect_printer");
    (void)disconnect_fn;

    auto set_ssdp_fn            = (set_on_ssdp_msg)            sym("bambu_network_set_on_ssdp_msg_fn");
    auto set_user_login_fn      = (set_on_user_login)          sym("bambu_network_set_on_user_login_fn");
    auto set_printer_conn_fn    = (set_on_printer_connected)   sym("bambu_network_set_on_printer_connected_fn");
    auto set_server_conn_fn     = (set_on_server_connected)    sym("bambu_network_set_on_server_connected_fn");
    auto set_http_err_fn        = (set_on_http_error)          sym("bambu_network_set_on_http_error_fn");
    auto set_cc_fn              = (set_get_country_code)       sym("bambu_network_set_get_country_code_fn");
    auto set_sub_fail_fn        = (set_on_subscribe_failure)   sym("bambu_network_set_on_subscribe_failure_fn");
    auto set_msg_fn             = (set_on_message)             sym("bambu_network_set_on_message_fn");
    auto set_user_msg_fn        = (set_on_user_message)        sym("bambu_network_set_on_user_message_fn");
    auto set_local_conn_fn      = (set_on_local_connect)       sym("bambu_network_set_on_local_connect_fn");
    auto set_local_msg_fn       = (set_on_local_message)       sym("bambu_network_set_on_local_message_fn");
    auto set_qom_fn             = (set_queue_on_main)          sym("bambu_network_set_queue_on_main_fn");
    auto set_server_cb_fn_p     = (set_server_cb_fn)           sym("bambu_network_set_server_callback");

    if (!create_agent_fn || !start_fn || !send_msg_fn) {
        std::fprintf(stderr, "[child] critical symbols missing\n");
        _exit(3);
    }

    // log dir under TMPDIR
    const char* tmpe = std::getenv("TMPDIR");
    std::string log_dir = (tmpe && *tmpe ? std::string(tmpe) : std::string("/tmp/")) +
                          "/fastpath_child_" + std::to_string(getpid());
    mkdir(log_dir.c_str(), 0700);

    void* agent = create_agent_fn(log_dir);
    if (!agent) { std::fprintf(stderr, "[child] create_agent null\n"); _exit(4); }

    if (set_qom_fn)        set_qom_fn(agent, [](std::function<void()> f){ if (f) f(); });
    if (set_ssdp_fn)       set_ssdp_fn(agent, [](std::string){});
    if (set_user_login_fn) set_user_login_fn(agent, [](int, bool){});
    if (set_printer_conn_fn) set_printer_conn_fn(agent, [](std::string){});
    if (set_server_conn_fn) set_server_conn_fn(agent, [](int, int){});
    if (set_http_err_fn)   set_http_err_fn(agent, [](unsigned, std::string){});
    if (set_cc_fn)         set_cc_fn(agent, []() -> std::string {
        const char* c = std::getenv("BBL_COUNTRY"); return c ? std::string(c) : "US";
    });
    if (set_sub_fail_fn)   set_sub_fail_fn(agent, [](std::string){});
    if (set_msg_fn)        set_msg_fn(agent, [](std::string, std::string){});
    if (set_user_msg_fn)   set_user_msg_fn(agent, [](std::string, std::string){});
    if (set_local_conn_fn) set_local_conn_fn(agent, [](int, std::string, std::string){});
    if (set_local_msg_fn)  set_local_msg_fn(agent, [](std::string, std::string){});
    if (set_server_cb_fn_p) set_server_cb_fn_p(agent, [](std::string, int){});

    if (set_config_dir_fn) set_config_dir_fn(agent, log_dir);
    if (init_log_fn) init_log_fn(agent);

    // GUI sets the slicer's verification cert via set_cert_file BEFORE
    // start(). Some plugin builds null-deref inside connect_printer when
    // this is unset (paho's SSLOptions reads from a null trustStore).
    // BBL_CERT_DIR + BBL_CERT_FILE override; default to the bridge's
    // shipped slicer_base64.cer if present.
    using set_cert_file_fn_t = int (*)(void*, std::string, std::string);
    auto set_cert_file_fn = (set_cert_file_fn_t)
        sym("bambu_network_set_cert_file");
    if (set_cert_file_fn) {
        std::string cert_dir = "/mnt/cephfs/ssd/BambuBridge/BambuStudio-bridge/resources/cert";
        std::string cert_file = "slicer_base64.cer";
        if (const char* e = std::getenv("BBL_CERT_DIR"))  cert_dir = e;
        if (const char* e = std::getenv("BBL_CERT_FILE")) cert_file = e;
        std::fprintf(stderr, "[child] set_cert_file(%s, %s)\n",
                     cert_dir.c_str(), cert_file.c_str());
        std::fflush(stderr);
        set_cert_file_fn(agent, cert_dir, cert_file);
    }

    if (set_country_code_fn) set_country_code_fn(agent, std::string("US"));
    if (start_fn) start_fn(agent);

    // Re-apply prctl settings — start() in some plugin variants resets
    // PR_SET_DUMPABLE to 0 as anti-debug. Re-enable AFTER it ran.
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    prctl(PR_SET_PTRACER, (unsigned long)getppid(), 0, 0, 0);

    (void)prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);

    // Pre-'R' handshake driver: connect_printer + install_device_cert run
    // here, BEFORE the watchdog is killed. Empirically the VMP plugin's
    // connect_printer SIGSEGVs when called after watchdog kill (some VMP
    // self-check depends on its ptracer still being attached). Doing the
    // network handshake first lets the plugin populate
    // device_pub_key_map[dev_id] from the printer-mock's cert_report
    // reply BEFORE we go intrusive.
    std::string mq_host = "127.0.0.1";
    int mq_port = 18900;
    bool use_ssl = false;
    if (const char* h = std::getenv("BBL_MOCK_HOST")) mq_host = h;
    if (const char* p = std::getenv("BBL_MOCK_PORT")) mq_port = std::atoi(p);
    if (std::getenv("BBL_MOCK_USE_SSL")) use_ssl = true;
    (void)mq_port;  // proprietary plugin's connect_printer uses ip; port implicit

    // connect_printer is OPT-IN via BBL_CALL_CONNECT_PRINTER. Empirically
    // the 02.06.x bridge plugin SIGSEGVs inside it when called from this
    // standalone process — likely missing GUI-side state (event loop +
    // MachineObjectStore + tutk session) the VMP wrapper checks. The
    // good news: the proprietary plugin's `install_device_cert` is a
    // pure MQTT publisher; it doesn't actually require connect_printer
    // to have succeeded (per the bridge's own usage at BridgeBootstrap.
    // cpp:471-484 — cloud-only path; LAN connect happens elsewhere).
    if (connect_printer_fn && std::getenv("BBL_DRIVE_HANDSHAKE") &&
        std::getenv("BBL_CALL_CONNECT_PRINTER")) {
        std::fprintf(stderr, "[child] connect_printer(%s, %s, ssl=%d) [pre-R]\n",
                     args.dev_id.c_str(), mq_host.c_str(), (int)use_ssl);
        std::fflush(stderr);
        int rc = connect_printer_fn(agent, args.dev_id,
                                     mq_host,
                                     std::string("bblp"),
                                     args.access_code,
                                     use_ssl);
        std::fprintf(stderr, "[child] connect_printer -> %d\n", rc);
        std::fflush(stderr);
        (void)rc;
        usleep(500 * 1000);
    }
    if (install_dev_cert_fn && std::getenv("BBL_DRIVE_HANDSHAKE")) {
        std::fprintf(stderr, "[child] install_device_cert(%s, lan_only=true) [pre-R]\n",
                     args.dev_id.c_str());
        std::fflush(stderr);
        (void)install_dev_cert_fn(agent, args.dev_id, /*lan_only=*/true);
        usleep(200 * 1000);
    }
    // Wait for cert_report round-trip to populate device_pub_key_map.
    int handshake_wait_ms = 3000;
    if (const char* w = std::getenv("BBL_HANDSHAKE_WAIT_MS")) {
        handshake_wait_ms = std::atoi(w);
    }
    if (std::getenv("BBL_DRIVE_HANDSHAKE")) {
        std::fprintf(stderr, "[child] waiting %d ms for cert_report cascade [pre-R]\n",
                     handshake_wait_ms);
        std::fflush(stderr);
        usleep(handshake_wait_ms * 1000);
    }

    // Plugin init complete (including watchdog spawn). Signal parent.
    char ready = 'R';
    if (write(g_ready_pipe[1], &ready, 1) != 1) {
        std::fprintf(stderr, "[child] write ready: %s\n", strerror(errno));
        _exit(5);
    }
    // Block waiting for parent's 'G'. While blocked, parent will kill the
    // VMP watchdog (which is ptrace-attached to us) and SEIZE every thread
    // itself.
    char go = 0;
    ssize_t gr = read(g_go_pipe[0], &go, 1);
    if (gr != 1) {
        std::fprintf(stderr, "[child] read go: %zd (%s)\n", gr, strerror(errno));
        _exit(6);
    }

    // PHASE A — warmup send_message (handshake already done pre-'R').
    std::string json = R"({"print":{"command":"pushall","sequence_id":"1"}})";
    {
        int rc = send_msg_fn(agent, args.dev_id, json, /*qos=*/0, /*flag=*/0);
        if (std::getenv("BBL_FASTPATH_VERBOSE_CHILD") ||
            std::getenv("BBL_DRIVE_HANDSHAKE")) {
            std::fprintf(stderr, "[child] warmup send_message -> %d\n", rc);
            std::fflush(stderr);
        }
        (void)rc;
        usleep(500 * 1000);
    }

    // PHASE B — tell parent warmup is done; parent will scan memory for
    // sign code patterns, identify accumulator PC, arm DR0, then 'G2'.
    char wb = 'W';
    if (write(g_warmup_pipe[1], &wb, 1) != 1) {
        std::fprintf(stderr, "[child] write warmup: %s\n", strerror(errno));
        _exit(7);
    }
    char go2 = 0;
    ssize_t gr2 = read(g_go2_pipe[0], &go2, 1);
    if (gr2 != 1) {
        std::fprintf(stderr, "[child] read go2: %zd (%s)\n", gr2, strerror(errno));
        _exit(8);
    }

    // PHASE C — drive the real sign path.
    for (int i = 0; i < 16; ++i) {
        int rc = send_msg_fn(agent, args.dev_id, json, /*qos=*/0, /*flag=*/0);
        if (std::getenv("BBL_FASTPATH_VERBOSE_CHILD")) {
            std::fprintf(stderr, "[child] send_message[%d] -> %d\n", i, rc);
        }
        (void)rc;
        usleep(200 * 1000);
    }
    // Stay alive briefly so parent can drain trap queue if any are pending.
    usleep(500 * 1000);

    _exit(0);
}

}  // namespace child_side

// ===========================================================================
// Parent: ptrace driver. Sets DR0=accumulator_pc, DR7=0x401 (local enable
// DR0, length-1, execute trap). Reads rdx low byte at every trap.
// ===========================================================================

// /sys/include/sys/user.h offers struct user with u_debugreg[8]. The kernel
// ABI for PTRACE_POKEUSER is by byte-offset into struct user; debugregs sit
// at offsetof(struct user, u_debugreg).
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

// Returns: true if at least 256 bytes captured.
struct CaptureResult {
    bool ok = false;
    std::vector<uint8_t> stream;
    int total_traps = 0;
    int sign_cycles = 0;  // 256-byte chunks observed
};

// Set DR0/DR7 on a specific TID. The kernel keeps debug-regs per-task, so
// each thread spawned by the plugin needs its own arm.
static bool arm_dr_on_tid(pid_t tid, uint64_t acc_va) {
    if (!poke_dr(tid, 0, acc_va))     return false;
    if (!poke_dr(tid, 6, 0))          return false;
    if (!poke_dr(tid, 7, 0x00000401)) return false;
    return true;
}

// Arm up to three HW BPs (DR0, DR1, DR2) on a tid for execute-trap. The
// kernel will deliver SIGTRAP with status' lowest 4 bits of DR6 indicating
// which BP fired. Used in --diagnostic to see which of {wrap, byte, acc}
// is hit by the actual sign-time code path.
static bool arm_dr012_on_tid(pid_t tid,
                             uint64_t va0, uint64_t va1, uint64_t va2) {
    if (!poke_dr(tid, 0, va0)) return false;
    if (!poke_dr(tid, 1, va1)) return false;
    if (!poke_dr(tid, 2, va2)) return false;
    if (!poke_dr(tid, 6, 0))   return false;
    // DR7: bits 0/2/4 = L0/L1/L2 (local enable); bits 16-19/20-23/24-27 =
    // R/W and len for DR0/DR1/DR2 (all execute-trap, len=1 → 0). So:
    //   L0=1, L1=1, L2=1, all other fields default = 0x00000015.
    if (!poke_dr(tid, 7, 0x00000015)) return false;
    return true;
}

// Disarm ALL DRs on a tid.
static bool disarm_dr_on_tid(pid_t tid) {
    poke_dr(tid, 7, 0);
    poke_dr(tid, 6, 0);
    poke_dr(tid, 0, 0);
    poke_dr(tid, 1, 0);
    poke_dr(tid, 2, 0);
    poke_dr(tid, 3, 0);
    return true;
}

// Resume a stopped tracee, forwarding the given signal (0 to swallow).
static bool cont_with_sig(pid_t tid, int sig) {
    if (ptrace(PTRACE_CONT, tid, 0, (void*)(long)sig) < 0) {
        LOG_W("PTRACE_CONT tid=%d sig=%d: %s", tid, sig, strerror(errno));
        return false;
    }
    return true;
}

// Read the TracerPid field from /proc/<pid>/status. Returns 0 if not
// traced or on error.
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

// Enumerate all TIDs of a process via /proc/<pid>/task/.
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

extern int g_ready_pipe[2];
extern int g_go_pipe[2];

// Read the file-backed library's name from its /proc/<pid>/maps entry,
// return the LOWEST and HIGHEST r-xp range that involves the basename
// AND additionally the largest anonymous r-xp arena that lies just past
// the file-backed mapping (this is segment 2 of the VMP-decoded region).
struct PluginMapInfo {
    uint64_t file_lo = 0;       // start of file-backed r-xp (lowest)
    uint64_t file_hi = 0;       // end   of file-backed r-xp
    uint64_t arena2_lo = 0;     // start of contiguous anonymous r-xp arena
    uint64_t arena2_hi = 0;     // end   of contiguous anonymous r-xp arena
};

static PluginMapInfo read_plugin_map_info(pid_t pid, const std::string& plugin_path) {
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
            // Anonymous r-xp arena right after the file-backed r-xp =
            // segment 2 of the VMP-decoded region.
            if (M.arena2_lo == 0) M.arena2_lo = lo;
            M.arena2_hi = hi;
        }
    }
    return M;
}

// Read up to `n` bytes from a tracee's VA via process_vm_readv.
static bool read_tracee_mem(pid_t pid, uint64_t va, void* dst, size_t n) {
    struct iovec local{ dst, n };
    struct iovec remote{ (void*)va, n };
    ssize_t got = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return got == (ssize_t)n;
}

// Scan a memory range in the tracee for the wrapping function prologue
// pattern (endbr64 + push r15..rbx + sub rsp,0x78). Returns up to `max_hits`
// runtime VAs. Useful when the version-locked offset doesn't fire — we can
// rediscover the function dynamically.
static std::vector<uint64_t>
scan_prologue(pid_t pid, uint64_t lo, uint64_t hi, size_t max_hits) {
    std::vector<uint64_t> hits;
    if (lo >= hi) return hits;
    // Prologue: f3 0f 1e fa  41 57  41 56  41 55  41 54  53  48 83 ec 78
    static const uint8_t PAT[] = {
        0xf3, 0x0f, 0x1e, 0xfa,
        0x41, 0x57,
        0x41, 0x56,
        0x41, 0x55,
        0x41, 0x54,
        0x53,
        0x48, 0x83, 0xec, 0x78
    };
    const size_t PLEN = sizeof(PAT);
    // Scan PAGE-BY-PAGE. process_vm_readv may fail across unreadable pages,
    // so reading 4KB at a time isolates failures. Use a 32-byte overlap to
    // catch matches that straddle page boundaries.
    const size_t PAGE = 4096;
    std::vector<uint8_t> buf(PAGE + PLEN);
    uint64_t prev_end = 0;
    std::vector<uint8_t> prev_tail(PLEN, 0);
    for (uint64_t cur = lo; cur < hi; cur += PAGE) {
        size_t want = std::min<uint64_t>(PAGE, hi - cur);
        if (!read_tracee_mem(pid, cur, buf.data(), want)) {
            prev_end = 0;
            continue;
        }
        // First try straddling tail of previous page + head of this one.
        if (prev_end == cur && PLEN > 1) {
            std::vector<uint8_t> combo(prev_tail.size() + PLEN);
            std::memcpy(combo.data(), prev_tail.data(), prev_tail.size());
            std::memcpy(combo.data() + prev_tail.size(), buf.data(), PLEN);
            for (size_t i = 0; i + PLEN <= combo.size(); ++i) {
                if (std::memcmp(combo.data() + i, PAT, PLEN) == 0) {
                    uint64_t va = (cur - prev_tail.size()) + i;
                    hits.push_back(va);
                    if (hits.size() >= max_hits) return hits;
                }
            }
        }
        // Then scan within this page (skipping the bytes already covered above).
        for (size_t i = 0; i + PLEN <= want; ++i) {
            if (std::memcmp(buf.data() + i, PAT, PLEN) == 0) {
                hits.push_back(cur + i);
                if (hits.size() >= max_hits) return hits;
            }
        }
        // Stash tail for next iteration.
        if (want >= PLEN) {
            std::memcpy(prev_tail.data(), buf.data() + want - PLEN, PLEN);
            prev_end = cur + want;
        } else {
            prev_end = 0;
        }
    }
    return hits;
}

// Find every runtime VA where the byte-load `movzx edx, byte ptr [rcx]`
// instruction (0f b6 11) appears. Pre-context: should be followed by
// some accumulator update; if the candidate has `89 54 24 48` (mov
// [rsp+0x48],edx) within ~80 bytes, it's a STRONG candidate for the
// PATH_V byte-load and accumulator pair.
struct PatternMatch {
    uint64_t va_byte_load = 0;
    uint64_t va_accumulator = 0;  // 0 if no nearby accumulator
};

static std::vector<PatternMatch>
scan_byte_load_accumulator(pid_t pid, uint64_t lo, uint64_t hi, size_t max_hits) {
    std::vector<PatternMatch> hits;
    if (lo >= hi) return hits;
    // Pattern A: movzx edx, byte ptr [rcx]  (0f b6 11)
    static const uint8_t BL[] = { 0x0f, 0xb6, 0x11 };
    // Pattern B: mov [rsp+0x48], edx       (89 54 24 48)
    static const uint8_t AC[] = { 0x89, 0x54, 0x24, 0x48 };
    const size_t BLN = sizeof(BL), ACN = sizeof(AC);
    const size_t PAGE = 4096;
    std::vector<uint8_t> buf(PAGE + 128);
    for (uint64_t cur = lo; cur < hi; cur += PAGE) {
        size_t want = std::min<uint64_t>(PAGE + 128, hi - cur);
        if (!read_tracee_mem(pid, cur, buf.data(), want)) continue;
        for (size_t i = 0; i + BLN <= want; ++i) {
            if (std::memcmp(buf.data() + i, BL, BLN) != 0) continue;
            uint64_t va = cur + i;
            // Search +/- 80 bytes for the accumulator pattern.
            uint64_t acc_va = 0;
            size_t scan_lo = (i > 80) ? i - 80 : 0;
            size_t scan_hi = std::min(want - ACN + 1, i + 80);
            for (size_t j = scan_lo; j < scan_hi; ++j) {
                if (std::memcmp(buf.data() + j, AC, ACN) == 0) {
                    acc_va = cur + j;
                    break;
                }
            }
            if (acc_va) {
                hits.push_back({va, acc_va});
                if (hits.size() >= max_hits) return hits;
            }
        }
    }
    return hits;
}

// Diagnostic capture: arm DR0/DR1/DR2 simultaneously, log every event
// extensively, do NOT park sentinel threads (disarm + continue instead),
// do NOT attempt reconstruction. Returns a summary count.
struct DiagSummary {
    int total_traps = 0;
    int traps_dr0 = 0;
    int traps_dr1 = 0;
    int traps_dr2 = 0;
    int sentinels = 0;
    int clones = 0;
    int spurious_sigtrap = 0;
    int sigsegv_non_sentinel = 0;
};

static void diagnostic_capture(pid_t child,
                               uint64_t wrap_va,
                               uint64_t byte_va,
                               uint64_t acc_va,
                               int timeout_s,
                               DiagSummary& S);

// Forward decl — defined below.
static int wait_byte(pid_t child, int fd, double deadline_extra_s,
                     char* out_byte, const char* tag);
// discovered_conv: 0=edx,1=eax,2=ebx,3=ecx (same index as CONVS[])
static uint64_t discover_accumulator_pc(pid_t child, uint64_t lo, uint64_t hi,
                                        uint64_t* discovered_wrap_va,
                                        uint64_t* discovered_byte_va,
                                        int* discovered_conv = nullptr);

// Discover the accumulator PC by scanning for byte_load+accumulator pair.
// Returns 0 if no candidate found. Tries multiple register conventions.
static uint64_t discover_accumulator_pc(pid_t child, uint64_t lo, uint64_t hi,
                                        uint64_t* discovered_wrap_va,
                                        uint64_t* discovered_byte_va,
                                        int* discovered_conv) {
    if (discovered_wrap_va) *discovered_wrap_va = 0;
    if (discovered_conv) *discovered_conv = 0; // default: edx
    if (discovered_byte_va) *discovered_byte_va = 0;
    // Look for the SHA-256 K-table. After warmup the K-table should be
    // present somewhere in the decoded segment.
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

    // Scan for byte_load + accumulator pair across multiple register
    // conventions:
    //   byte_load: movzx <reg32>, byte ptr [rcx]
    //     = 0x0f 0xb6 0x11 (edx,[rcx])
    //     = 0x0f 0xb6 0x01 (eax,[rcx])
    //     = 0x0f 0xb6 0x19 (ebx,[rcx])
    //     = 0x0f 0xb6 0x09 (ecx,[rcx])  unusual
    //     = 0x0f 0xb6 0x29 (ebp,[rcx])  unusual
    //   accumulator: mov [rsp + 8-bit disp], <reg32>
    //     = 0x89 <modrm> 0x24 <disp8> where modrm depends on register
    //     edx -> 0x89 0x54 0x24 <disp>
    //     eax -> 0x89 0x44 0x24 <disp>
    //     ecx -> 0x89 0x4c 0x24 <disp>
    //     ebx -> 0x89 0x5c 0x24 <disp>
    //
    // Strong candidate = byte_load and accumulator within 80 bytes,
    // SAME destination register written to accumulator.
    // bl_third  = third byte of movzx encoding (ModRM: Mod=00, base varies)
    // bl_fourth = fourth byte if needed (for rbp/disp8 variants), 0=no extra byte
    // ac_second = second byte of mov [rsp+disp8], <reg> (MovRM byte)
    // The accumulator writes the loaded byte to [rsp+disp8].
    struct Conv {
        uint8_t bl_third;   // ModRM for 0F B6 <ModRM> [<extra>]
        uint8_t bl_fourth;  // extra byte (for [rbp+0x00] = 0x55 0x00, set bl_third=0x55, bl_fourth=0x00)
        uint8_t ac_second;  // ModRM for 89 <ModRM> 24 <disp8>
        const char* name;
        bool has_fourth;    // true if bl_fourth is a required byte (e.g. for [rbp+0])
    };
    // We cover: movzx {eax,edx,ecx,ebx} [rcx|rax|rdx|rbx|rsi|rdi]  (Mod=00)
    // plus:    movzx {eax,edx,ecx,ebx} [rbp+0]  (Mod=01 + disp8=0x00)
    // ModRM for movzx edx,[rxx]: 0x11(rcx) 0x10(rax) 0x12(rdx) 0x13(rbx) 0x16(rsi) 0x17(rdi)
    //          movzx eax,[rxx]: 0x01 0x00 0x02 0x03 0x06 0x07
    //          movzx ecx,[rxx]: 0x09 0x08 0x0a 0x0b 0x0e 0x0f
    //          movzx ebx,[rxx]: 0x19 0x18 0x1a 0x1b 0x1e 0x1f
    // acc:     mov [rsp+?],edx = 89 54 24; mov [rsp+?],eax = 89 44 24
    //          mov [rsp+?],ecx = 89 4c 24; mov [rsp+?],ebx = 89 5c 24
    static const Conv CONVS[] = {
        // --- edx as destination ---
        {0x11, 0, 0x54, "edx<-[rcx]",  false},
        {0x10, 0, 0x54, "edx<-[rax]",  false},
        {0x12, 0, 0x54, "edx<-[rdx]",  false},
        {0x13, 0, 0x54, "edx<-[rbx]",  false},
        {0x16, 0, 0x54, "edx<-[rsi]",  false},
        {0x17, 0, 0x54, "edx<-[rdi]",  false},
        {0x55, 0x00, 0x54, "edx<-[rbp+0]", true},
        // --- eax as destination ---
        {0x01, 0, 0x44, "eax<-[rcx]",  false},
        {0x00, 0, 0x44, "eax<-[rax]",  false},
        {0x02, 0, 0x44, "eax<-[rdx]",  false},
        {0x03, 0, 0x44, "eax<-[rbx]",  false},
        {0x06, 0, 0x44, "eax<-[rsi]",  false},
        {0x07, 0, 0x44, "eax<-[rdi]",  false},
        {0x45, 0x00, 0x44, "eax<-[rbp+0]", true},
        // --- ecx as destination ---
        {0x09, 0, 0x4c, "ecx<-[rcx]",  false},
        {0x08, 0, 0x4c, "ecx<-[rax]",  false},
        {0x0a, 0, 0x4c, "ecx<-[rdx]",  false},
        {0x0b, 0, 0x4c, "ecx<-[rbx]",  false},
        {0x0e, 0, 0x4c, "ecx<-[rsi]",  false},
        {0x0f, 0, 0x4c, "ecx<-[rdi]",  false},
        {0x4d, 0x00, 0x4c, "ecx<-[rbp+0]", true},
        // --- ebx as destination ---
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
                // Search +/- 80 bytes for matching accumulator pattern.
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
    // Top N by display (all of them, up to 500)
    for (size_t i = 0; i < cands.size() && i < 500; ++i) {
        LOG_I("[discover]   #%zu conv=%s bl@0x%lx ac@0x%lx dist=%d",
              i, CONVS[cands[i].conv].name,
              (unsigned long)cands[i].va_bl, (unsigned long)cands[i].va_ac,
              cands[i].dist);
    }
    if (cands.empty()) return 0;
    // Picker priority (PATH_V signature observation):
    //   1. Prefer conv = edx-from-rcx with dist in [40, 60] (the PATH_V
    //      pattern: byte_load at +0x0, accumulator at +0x2e = 46 bytes).
    //   2. Otherwise prefer closest to SHA-256 K-table (only if K-table found).
    //   3. Return 0 if neither applies: sign path not yet decoded, caller
    //      should use VersionProfile known offset instead.
    //
    // IMPORTANT: we deliberately do NOT fall through to "first edx-conv
    // candidate" when the K-table is absent.  That third-tier pick reliably
    // chooses the WRONG VA (a different byte-load in another library) and
    // causes 0 DR0 traps.  Returning 0 lets drive_capture_attach() use the
    // VersionProfile-baked offset, which is always correct.
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
    // BBL_CAND_IDX=N forces selection of candidate N from the full list.
    // Use this to brute-force candidates when no high-confidence match is found.
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

// seccomp user-notification fd (openat supervisor).
// Set in launch_daemon() after reading from the notif pipe.
// Consumed by drive_capture_attach() to start the openat supervisor thread.
static int g_openat_notif_fd = -1;
// read-end of the pipe that the daemon writes its notif_fd to.
static int g_openat_notif_pipe_rd = -1;
// Global supervisor thread and stop flag — started early (before wait_for_libbambu)
// so dlopen calls during plugin load are not blocked.
static std::atomic<bool> g_notif_stop_flag{false};
static std::thread g_notif_thread;

// Set by the supervisor thread when it sees an openat for libbambu_networking.so.
// The wait_for_libbambu loop reads this PID immediately instead of polling.
static std::atomic<pid_t> g_libbambu_seen_pid{0};
// The plugin path suffix to detect (set before supervisor starts).
static std::string g_plugin_path_detect;

// ===========================================================================
// openat supervisor — runs in a background thread; handles seccomp USER_NOTIF
// events from the daemon's openat seccomp filter.
//
// For each notification:
//   - Read the path string from the daemon's address space via /proc/<pid>/mem
//   - If path contains "/status" (likely /proc/self/status or /proc/<pid>/status):
//       respond with error=ENOENT (VMP falls back, no TracerPid check)
//   - Otherwise: respond with SECCOMP_USER_NOTIF_FLAG_CONTINUE (pass through)
//
// The thread stops when g_openat_notif_fd is closed or when *stop_flag is set.
// ===========================================================================
static void openat_supervisor_thread(int notif_fd, std::atomic<bool>* stop_flag)
{
    // Query kernel struct sizes.
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
        int pr = poll(&pf, 1, 200);  // 200ms timeout to check stop_flag
        if (pr < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[openat_sup] poll error errno=%d (%s)\n", errno, strerror(errno));
            break;  // fd closed or error
        }
        if (pr == 0) continue;  // timeout, check stop_flag
        if (!(pf.revents & POLLIN)) {
            // POLLHUP on seccomp notif fd means "no pending notifications right now"
            // (the notification list is empty), NOT "filter is dead." Continue
            // polling — new notifications will arrive as the daemon makes more
            // openat calls (e.g. from dlopen, plugin init, etc.).
            // Only stop on POLLERR (which means the fd is truly invalid).
            if (pf.revents & POLLERR) {
                fprintf(stderr, "[openat_sup] poll POLLERR — fd invalid, stopping\n");
                break;
            }
            // POLLHUP or other: just continue.
            continue;
        }

        // Receive one notification.
        memset(req, 0, req_sz);
        if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOENT) continue;  // notification already gone
            fprintf(stderr, "[openat_sup] NOTIF_RECV failed errno=%d (%s)\n",
                    errno, strerror(errno));
            break;
        }

        // Prepare response.
        memset(resp, 0, resp_sz);
        resp->id = req->id;

        // Read the path from the daemon's address space.
        // args[1] = const char* path (for SYS_openat, args[0]=dirfd, args[1]=pathname).
        uintptr_t path_addr = (uintptr_t)req->data.args[1];
        char path_buf[PATH_MAX] = {};
        bool is_status = false;

        if (path_addr != 0) {
            // Read via /proc/<pid>/mem.
            char mem_path[64];
            snprintf(mem_path, sizeof(mem_path), "/proc/%u/mem", req->pid);
            int mem_fd = open(mem_path, O_RDONLY | O_CLOEXEC);
            if (mem_fd >= 0) {
                // Read up to 256 bytes to get the path string.
                ssize_t n = pread(mem_fd, path_buf, sizeof(path_buf) - 1, (off_t)path_addr);
                close(mem_fd);
                if (n > 0) {
                    path_buf[n] = '\0';
                    // Null-terminate at first null byte.
                    for (int i = 0; i < n; ++i) {
                        if (path_buf[i] == '\0') break;
                    }
                    // Check if this is a /proc/self/status or /proc/<pid>/status path.
                    if (strstr(path_buf, "/status") &&
                        strncmp(path_buf, "/proc/", 6) == 0) {
                        is_status = true;
                    }
                }
            }
        }

        if (is_status) {
            // Inject a fake /proc/self/status fd with TracerPid: 0.
            // Strategy: create a memfd with sanitised content and inject it
            // into the daemon via SECCOMP_IOCTL_NOTIF_ADDFD, then respond
            // with the daemon-side fd number as the return value.
            //
            // Build fake status content: read the REAL status from /proc/<pid>/status
            // (in our process, using the daemon's pid) then zero TracerPid.
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
                // Fallback: minimal status with TracerPid: 0.
                fake_len = snprintf(fake_content, sizeof(fake_content),
                                    "Name:\tprocess\nState:\tS (sleeping)\n"
                                    "Pid:\t%u\nTracerPid:\t0\n", req->pid);
            }
            // Zero out TracerPid field in the buffer.
            const char* tp_label = "TracerPid:";
            char* tp_ptr = (char*)memmem(fake_content, (size_t)fake_len,
                                          tp_label, strlen(tp_label));
            if (tp_ptr) {
                char* val = tp_ptr + strlen(tp_label);
                while (val < fake_content + fake_len && (*val == ' ' || *val == '\t')) ++val;
                // Replace digits with '0' + spaces.
                char* d = val;
                while (d < fake_content + fake_len && *d >= '0' && *d <= '9') ++d;
                if (d > val) {
                    val[0] = '0';
                    for (char* p = val + 1; p < d; ++p) *p = ' ';
                }
            }

            // Create memfd and write fake content.
            int mfd = memfd_create("status_fake", MFD_CLOEXEC);
            bool injected = false;
            if (mfd >= 0) {
                if (write(mfd, fake_content, (size_t)fake_len) == fake_len) {
                    lseek(mfd, 0, SEEK_SET);
                    // Inject into daemon via SECCOMP_IOCTL_NOTIF_ADDFD.
                    struct seccomp_notif_addfd addfd = {};
                    addfd.id = req->id;
                    addfd.flags = 0;       // let kernel pick the fd number
                    addfd.srcfd = (uint32_t)mfd;
                    addfd.newfd = 0;
                    addfd.newfd_flags = O_RDONLY;
                    long new_daemon_fd = ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
                    if (new_daemon_fd >= 0) {
                        // Respond with the new fd as the return value.
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
                // Fallback: pass through (VMP will see real TracerPid but at
                // least won't crash from ENOENT).
                resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                resp->error = 0;
                resp->val   = 0;
                fprintf(stderr, "[openat_sup] ADDFD fallback CONTINUE for path=%s\n", path_buf);
            }
        } else {
            // Pass through all other openat calls.
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            resp->error = 0;
            resp->val   = 0;
            // Log all non-status paths for debugging.
            static int pass_count = 0;
            ++pass_count;
            struct timespec ts2 = {};
            clock_gettime(CLOCK_MONOTONIC, &ts2);
            double t_ms = ts2.tv_sec * 1000.0 + ts2.tv_nsec / 1e6;
            fprintf(stderr, "[openat_sup] PASS#%d @%.1fms pid=%u path=%s\n",
                    pass_count, t_ms, req->pid, path_buf[0] ? path_buf : "(empty)");
            // Detect libbambu_networking.so being opened — notify wait_for_libbambu.
            if (strstr(path_buf, "libbambu_networking") != nullptr) {
                pid_t expected = 0;
                // Use req->pid (the thread TID) — convert to process PID by reading /proc/<tid>/status
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
            if (errno == ENOENT) {
                // Notification expired (process died or syscall cancelled) — safe to ignore.
                continue;
            }
            fprintf(stderr, "[openat_sup] NOTIF_SEND failed: %s\n", strerror(errno));
        }
    }

    fprintf(stderr, "[openat_sup] stopped\n");
    free(req);
    free(resp);
}

// ===========================================================================
// ATTACH_MODE (2026-06-21) — drive_capture_attach
// ===========================================================================
//
// Skips fork+dlopen+mock-broker+warmup. Attaches to an existing process which
// is presumed to already be in a sign-active state (i.e. its libbambu_networking
// has decoded the VMP'd sign path because the gate is open by virtue of a real
// logged-in user session and a real printer pairing).
//
// Flow:
//   1) read /proc/<pid>/exe -> safety check (refuse bambustu_main / bambu-studio
//      unless caller passed --i-know-what-im-doing)
//   2) PTRACE_SEIZE main pid with PTRACE_O_TRACECLONE
//   3) enumerate /proc/<pid>/task; SEIZE each non-main TID
//   4) read /proc/<pid>/maps; find libbambu_networking r-xp + anon arena2
//   5) dynamic-discovery — find accumulator PC (already-decoded VMP region)
//   6) arm DR0 on every TID
//   7) capture loop until 256 events or timeout
//   8) clean detach (disarm + DETACH every TID, including any parked sentinel
//      threads which we must un-park first)
//   9) verify /proc/<pid>/status TracerPid == 0
//
// Defensive guarantees:
//   - SIGINT installs a global trigger that the loop polls; on Ctrl-C we exit
//     the loop early and proceed to clean detach.
//   - On any error, we ALWAYS clean-detach every seized TID before returning.
//   - We do NOT send SIGSTOP / SIGKILL to the target. We do NOT modify its
//     memory. The only state we touch is the debug-regs of each thread (DR0,
//     DR6, DR7) which we restore to 0 on detach.
//
// Return: CaptureResult; .ok = (bytes >= 256).

// Global SIGINT trigger for attach-mode clean shutdown.
static std::atomic<int> g_attach_interrupted{0};
static void attach_sigint_handler(int /*signo*/) {
    g_attach_interrupted.store(1, std::memory_order_relaxed);
    // No async-signal-safe stderr write; we just flag and let the loop pick up.
}

// Read the exe symlink for a pid (basename only).
static std::string read_exe_basename(pid_t pid) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/exe", (int)pid);
    char buf[PATH_MAX];
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = 0;
    const char* sl = std::strrchr(buf, '/');
    return sl ? std::string(sl + 1) : std::string(buf);
}

// True if exe-basename is in the "real bridge" allowlist that we refuse to
// touch without the override flag.
static bool is_protected_target(const std::string& exe) {
    if (exe == "bambustu_main") return true;
    if (exe == "bambu-studio")  return true;
    if (exe == "bambu_studio")  return true;
    return false;
}

static CaptureResult drive_capture_attach(pid_t target,
                                          const std::string& plugin_path,
                                          int timeout_s,
                                          bool require_bytes,
                                          const VersionProfile* ver = nullptr) {
    CaptureResult R;
    std::vector<pid_t> seized;  // every tid we PTRACE_SEIZE'd; release on exit

    auto cleanup_detach = [&]() {
        // PTRACE_DETACH requires the tracee to be in ptrace-stop. With
        // PTRACE_SEIZE the tracee is NOT auto-stopped; if we never INTERRUPT'd
        // it, DETACH succeeds at the syscall level but the kernel leaves the
        // tracee bound to us until the next stop-signal. So we PTRACE_INTERRUPT
        // first, wait for the group-stop, disarm DRs, and only then DETACH.
        LOG_I("[attach] cleanup: detaching %zu tid(s)", seized.size());
        for (pid_t t : seized) {
            // Interrupt the tracee (no-op if already in ptrace-stop).
            if (ptrace(PTRACE_INTERRUPT, t, 0, 0) < 0 && errno != ESRCH) {
                LOG_V("[attach] cleanup PTRACE_INTERRUPT(%d): %s", t, strerror(errno));
            }
            // Wait briefly for the group-stop. The tracee may already be in
            // ptrace-stop (e.g. parked sentinel we just un-parked) in which
            // case waitpid returns immediately.
            int st = 0;
            for (int i = 0; i < 100; ++i) {
                pid_t r = waitpid(t, &st, WNOHANG | __WALL);
                if (r == t && WIFSTOPPED(st)) break;
                if (r < 0) break;  // ESRCH = thread gone
                usleep(2 * 1000);
            }
            // Best-effort disarm. If the thread is gone (ESRCH), that's fine.
            long off7 = DR_OFFSET + 7 * (long)sizeof(uint64_t);
            ptrace(PTRACE_POKEUSER, t, (void*)off7, 0);
            long off0 = DR_OFFSET + 0 * (long)sizeof(uint64_t);
            ptrace(PTRACE_POKEUSER, t, (void*)off0, 0);
            // Final detach.
            if (ptrace(PTRACE_DETACH, t, 0, 0) < 0 && errno != ESRCH) {
                LOG_V("[attach] PTRACE_DETACH tid=%d: %s", t, strerror(errno));
            }
        }
        // Confirm tracer is gone. TracerPid is updated lazily by the kernel
        // after the last DETACH; poll briefly (up to ~500ms).
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

    // ---- Safety: refuse if target is gone ----
    if (kill(target, 0) != 0) {
        LOG_E("[attach] pid %d not alive: %s", target, strerror(errno));
        return R;
    }

    // ---- Install SIGINT handler ----
    struct sigaction sa{}, oldsa{};
    sa.sa_handler = attach_sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, &oldsa);

    auto restore_sigint = [&]() { sigaction(SIGINT, &oldsa, nullptr); };

    // ---- Kill VMP watchdog (TracerPid anti-debug) before SEIZE ----
    // libbambu_networking's VMP self-protection forks a child that calls
    // PTRACE_ATTACH on the daemon's main process.  This sets TracerPid in
    // /proc/<pid>/status and causes our PTRACE_SEIZE to fail with EPERM
    // (a process may have only one tracer at a time).
    //
    // Fix: read TracerPid, kill the watchdog child, wait for TracerPid to
    // clear, then proceed with SEIZE.  The daemon continues running
    // normally after the watchdog is gone; the VMP sign path is already
    // decoded (we waited for ESTAB+warmup) and doesn't need the watchdog.
    {
        pid_t watchdog = read_tracer_pid(target);
        if (watchdog > 0 && watchdog != getpid()) {
            LOG_I("[attach] VMP watchdog detected: TracerPid=%d — killing", watchdog);
            kill(watchdog, SIGKILL);
            // Wait for TracerPid to clear (kernel updates it lazily).
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

    // ---- PTRACE_SEIZE main + enumerated threads ----
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
            // Thread may have exited between enumerate and seize — log + skip.
            LOG_V("[attach] SEIZE tid=%d failed (%s) — skipping", t, strerror(errno));
            continue;
        }
        seized.push_back(t);
    }
    LOG_I("[attach] seized %zu tid(s) total", seized.size());

    // ---- openat supervisor thread status ----
    // The supervisor thread was started earlier (before wait_for_libbambu) to
    // handle dlopen openat calls. Report its status here for logging.
    if (g_openat_notif_fd >= 0 && g_notif_thread.joinable()) {
        LOG_I("[attach] openat supervisor running (notif_fd=%d)", g_openat_notif_fd);
    } else {
        LOG_I("[attach] openat supervisor not available");
    }

    // stop_notif_thread: signal the global supervisor thread to stop and join it.
    // Called on all exit paths so we don't leave a dangling thread.
    auto stop_notif_thread = [&]() {
        g_notif_stop_flag.store(true, std::memory_order_relaxed);
        if (g_notif_thread.joinable()) {
            // Close the notif_fd to unblock any poll() in the supervisor.
            if (g_openat_notif_fd >= 0) {
                close(g_openat_notif_fd);
                g_openat_notif_fd = -1;
            }
            g_notif_thread.join();
        }
    };

    // ---- Find plugin r-xp base + arena2 ----
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

    // ---- Accumulator PC: dynamic discovery on the VMP-decoded anon arena ----
    // Scan arena2 (the VMP-decoded overlay) for the edx byte_load+accumulator
    // pattern pair (edx, dist ~46). This is the same scan extract_d_fast uses
    // in --attach-pid mode and is correct even under ASLR.
    //
    // Key address formula (verified 2026-06-25):
    //   acc_va = file_lo + ACCUMULATOR_OFFSET
    // file_lo is the r-xp file-backed base of the plugin .so.  The arena2
    // (anon VMP overlay) starts at file_hi (= file_lo + 3.9 MB for baseline).
    // ACCUMULATOR_OFFSET = 0x7c12ca places the accumulator ~0x400000 bytes
    // past the file region, squarely inside arena2.  The old formula
    // arena2_lo + (OFFSET - 0x1000) was wrong — it gave an address ~7.6 MB
    // into arena2, past arena2_hi.
    //
    // Dynamic discovery is preferred when the sign path is decoded (SHA-256
    // K-table present in arena2).  If K-table is absent we fall back to the
    // VersionProfile known offset, which is correct regardless of decode state.

    uint64_t acc_va = 0;
    // 0=edx,1=eax,2=ebx,3=ecx; default edx matches PATH_VV / VersionProfile
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
            // Discovery failed (K-table not yet decoded).  Use the known
            // per-version offset from the file r-xp base.
            acc_va = M.file_lo + ver->accumulator_offset;
            LOG_I("[attach] discovery failed; using VersionProfile offset: "
                  "file_lo(0x%lx) + 0x%lx = 0x%lx",
                  (unsigned long)M.file_lo,
                  (unsigned long)ver->accumulator_offset,
                  (unsigned long)acc_va);
        } else {
            // No known offset; last resort: baseline constant.
            acc_va = M.file_lo + version_02_05_03_63::ACCUMULATOR_OFFSET;
            LOG_W("[attach] discovery failed; fallback to baseline offset: 0x%lx",
                  (unsigned long)acc_va);
        }
    } else {
        // No arena2; use per-version or baseline offset from file_lo.
        if (ver && ver->accumulator_offset) {
            acc_va = M.file_lo + ver->accumulator_offset;
            LOG_I("[attach] no arena2; VersionProfile acc_va=0x%lx", (unsigned long)acc_va);
        } else {
            acc_va = M.file_lo + version_02_05_03_63::ACCUMULATOR_OFFSET;
            LOG_W("[attach] no arena2; baseline acc_va=0x%lx", (unsigned long)acc_va);
        }
    }
    // Determine register name from acc_conv (index into CONVS table).
    // Groups: conv 0-6=edx, 7-13=eax, 14-20=ecx, 21-27=ebx
    const char* acc_reg_name = version_02_05_03_63::ACCUMULATOR_REG_NAME; // default: rdx
    if (acc_conv >= 7 && acc_conv <= 13) acc_reg_name = "rax";
    else if (acc_conv >= 14 && acc_conv <= 20) acc_reg_name = "rcx";
    else if (acc_conv >= 21 && acc_conv <= 27) acc_reg_name = "rbx";
    LOG_I("[attach] register: %s (low byte = captured dp/dq byte, conv=%d)",
          acc_reg_name, acc_conv);

    // ---- Arm DR0 on every seized tid ----
    // The signing thread is a worker thread (not the main tid), so we must
    // arm ALL seized threads. BBL_ARM_ALL_TIDS env var is ignored here.
    int n_armed = 0;
    for (pid_t t : seized) {
        // The seized thread is NOT stopped under PTRACE_SEIZE semantics —
        // PTRACE_INTERRUPT it first so PTRACE_POKEUSER is legal, then CONT.
        if (ptrace(PTRACE_INTERRUPT, t, 0, 0) < 0) {
            LOG_V("[attach] PTRACE_INTERRUPT tid=%d: %s", t, strerror(errno));
            continue;
        }
        // Wait for the stop. Use WNOHANG with a short retry loop; if a thread
        // is already wedged (e.g. a prior debugger), don't block forever.
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
        // Resume the thread.
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

    // ---- Capture loop ----
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
        // Smoke-test mode (require_bytes=false): just spin to the timeout to
        // exercise the wait/continue paths, then exit cleanly.
        int st = 0;
        pid_t r = waitpid(-1, &st, WNOHANG | __WALL);
        if (r <= 0) { usleep(1 * 1000); continue; }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (r == target) {
                LOG_W("[attach] target main pid exited mid-capture (status=0x%x)", st);
                break;
            }
            // A worker tid exited; drop it from our seized list so cleanup
            // doesn't try to detach a corpse.
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
                // The new thread auto-attaches via TRACECLONE and will deliver
                // SIGSTOP momentarily; we arm it then.
                LOG_V("[attach] new clone tid=%d", new_tid);
            }
            cont_with_sig(r, 0);
            continue;
        }
        if (event == PTRACE_EVENT_EXIT) {
            // Thread is about to die; just resume.
            cont_with_sig(r, 0);
            continue;
        }
        if (sig == SIGSTOP) {
            // Initial SIGSTOP for a freshly-cloned thread.
            // Always arm DR0 on new threads — the signing thread may be
            // spawned after our initial seize (e.g. LAN uplink thread created
            // during printer connection). arm_only_main applies to the initial
            // seize only; post-seize clones must always get DR0.
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
                // Read the low byte from the appropriate register.
                // acc_reg_name is set from the discovered conv.
                uint64_t reg_val = regs.rdx;  // default: edx
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
                // VMP uses INT3 for its threaded-dispatch mechanism. If we
                // swallow SIGTRAP instead of forwarding it, VMP's handler
                // never runs and the signing path stalls. Forward SIGTRAP
                // so VMP can continue execution.
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
                // PARK (do NOT PTRACE_CONT). We'll continue it just before detach.
                continue;
            }
            // Forward SIGSEGV/SIGBUS to the process regardless of which thread.
            // VMP uses SIGSEGV for on-demand page decryption (mprotect+re-map);
            // swallowing it prevents VMP's own handler from running and locks
            // the thread in an infinite SIGSEGV loop without ever executing the
            // sign path. Only the 0xdead* sentinel (handled above) is suppressed.
            LOG_V("[attach] worker SIGSEGV tid=%d rip=0x%lx — forwarding", r, rip);
            cont_with_sig(r, sig);
            continue;
        }
        // Log non-trivial signals
        if (sig != SIGSTOP && sig != SIGTRAP) {
            LOG_I("[attach] fwd sig=%d tid=%d", sig, r);
        }
        // Other signal — forward unchanged.
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

    // ---- UN-PARK sentinel threads so PTRACE_DETACH can release them ----
    // PARKED threads have not received PTRACE_CONT; we MUST continue them now
    // (with the SIGSEGV signal so VMP can handle / kill normally) so the
    // kernel doesn't leave them stuck stopped after we detach.
    for (pid_t p : parked_sentinels) {
        // Best-effort: continue parked thread with SIGSEGV so VMP's anti-debug
        // path can do its usual thing. If the thread already vanished, ESRCH
        // is fine.
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

static CaptureResult drive_capture(pid_t child, uint64_t acc_pc, int timeout_s) {
    CaptureResult R;
    // LATE-ATTACH + WATCHDOG-KILL + WARMUP-SCAN flow:
    //   1) Child ran plugin init unattended. The plugin spawned a watchdog
    //      process that ptrace-ATTACHed the main thread as anti-debug.
    //   2) Child writes 'R' to ready pipe; blocks on read('G').
    //   3) Parent reads 'R', kills VMP watchdog. Writes 'G'.
    //   4) Child does ONE WARMUP send_message — forces VMP to lazily
    //      decode the sign path code into segment 2.
    //   5) Child writes 'W'; blocks on read('G2').
    //   6) Parent SEIZEs every TID, scans segment 2 for byte_load +
    //      accumulator pair near the SHA-256 K-table. Arms DR0 at the
    //      discovered accumulator PC. Writes 'G2'.
    //   7) Child does 16 more send_messages.
    //   8) Parent harvests 256 bytes via SIGTRAP.
    close(g_ready_pipe[1]);  // parent only reads
    close(g_go_pipe[0]);     // parent only writes
    close(g_warmup_pipe[1]); // parent only reads
    close(g_go2_pipe[0]);    // parent only writes

    long opts = PTRACE_O_TRACECLONE
              | PTRACE_O_TRACEFORK
              | PTRACE_O_TRACEVFORK;
    LOG_I("waiting for child ready signal (plugin init)...");
    char ready_byte = 0;
    if (wait_byte(child, g_ready_pipe[0], 30.0, &ready_byte, "ready") < 0) return R;
    if (ready_byte != 'R') {
        LOG_E("child ready handshake failed (byte=0x%x)", (int)ready_byte);
        return R;
    }
    LOG_I("child ready — plugin init complete");

    // Kill VMP watchdog (ptrace anti-debug parent).
    pid_t watchdog = read_tracer_pid(child);
    if (watchdog > 0 && watchdog != getpid()) {
        LOG_I("VMP watchdog detected: PID %d — killing", watchdog);
        kill(watchdog, SIGKILL);
        for (int i = 0; i < 50; ++i) {
            if (read_tracer_pid(child) == 0) break;
            usleep(10 * 1000);
        }
        pid_t still = read_tracer_pid(child);
        if (still != 0) LOG_W("watchdog still tracing (TracerPid=%d)", still);
        else            LOG_I("watchdog killed, ptrace lock released");
    } else if (watchdog == 0) {
        LOG_I("no watchdog detected (TracerPid=0)");
    }

    // Let child run warmup send_message UNTRACED.
    char go1 = 'G';
    if (write(g_go_pipe[1], &go1, 1) != 1) { LOG_E("write go: %s", strerror(errno)); return R; }
    LOG_I("warmup go sent");
    char wb = 0;
    // 60s = handshake_wait + connect_printer + warmup; bump from 15 to
    // accommodate BBL_DRIVE_HANDSHAKE path (cert_report cascade takes
    // 10-15s for the plugin to lazily subscribe).
    if (wait_byte(child, g_warmup_pipe[0], 60.0, &wb, "warmup") < 0) return R;
    if (wb != 'W') { LOG_E("warmup byte=0x%x", (int)wb); return R; }
    LOG_I("warmup complete — segment 2 should be decoded");

    // Find plugin r-xp base + arena2.
    extern Args g_args_for_child;
    PluginMapInfo M = read_plugin_map_info(child, g_args_for_child.plugin_path);
    uint64_t plugin_base = M.file_lo;
    if (!plugin_base) {
        LOG_E("plugin r-xp base not in /proc/%d/maps", child);
        return R;
    }
    LOG_I("libbambu base: 0x%lx  arena2: 0x%lx-0x%lx",
          (unsigned long)plugin_base,
          (unsigned long)M.arena2_lo, (unsigned long)M.arena2_hi);

    // Resolve accumulator VA. Strategy:
    //   1. If --accumulator-va is set via env BBL_ACC_VA, use it as override.
    //   2. Otherwise dynamically discover via byte_load+accumulator scan.
    //   3. Last resort: fall back to the PATH_V offset (only works if the
    //      plugin matches the bridge build).
    uint64_t acc_va = 0;
    uint64_t discovered_bl = 0, discovered_wrap = 0;
    const char* env_acc = std::getenv("BBL_ACC_VA");
    if (env_acc) {
        acc_va = std::stoull(env_acc, nullptr, 0);
        LOG_I("accumulator VA from env: 0x%lx", (unsigned long)acc_va);
    } else if (M.arena2_lo && M.arena2_hi) {
        acc_va = discover_accumulator_pc(child, M.arena2_lo, M.arena2_hi,
                                         &discovered_wrap, &discovered_bl);
    }
    if (!acc_va) {
        // Fall back to the version-locked offset.
        acc_va = plugin_base + acc_pc;
        LOG_W("dynamic discovery failed; falling back to baked offset 0x%lx",
              (unsigned long)acc_va);
    }
    LOG_I("accumulator PC: 0x%lx", (unsigned long)acc_va);

    // Enumerate every TID and SEIZE+arm each.
    std::vector<pid_t> tids = enumerate_tids(child);
    if (tids.empty()) tids.push_back(child);
    LOG_I("enumerated %zu thread(s); seizing...", tids.size());

    // Move main to front of list.
    for (auto it = tids.begin(); it != tids.end(); ++it) {
        if (*it == child) {
            tids.erase(it);
            tids.insert(tids.begin(), child);
            break;
        }
    }
    if (tids.empty() || tids.front() != child) {
        tids.insert(tids.begin(), child);
    }

    // ARM ONLY MAIN by default — VMP anti-debug sweeps on worker threads
    // trip a sentinel SIGSEGV at 0xdead9001 when DR0..3 are non-zero,
    // Sign runs on a worker thread (not main), so arm ALL threads.
    std::vector<pid_t> known_tids;
    int n_armed = 0;
    for (pid_t t : tids) {
        if (ptrace(PTRACE_SEIZE, t, 0, (void*)opts) < 0) {
            LOG_W("PTRACE_SEIZE tid=%d: %s", t, strerror(errno));
            if (t == child) {
                LOG_E("cannot proceed without main thread");
                for (pid_t at : known_tids) ptrace(PTRACE_DETACH, at, 0, 0);
                kill(child, SIGKILL);
                return R;
            }
            continue;
        }
        if (ptrace(PTRACE_INTERRUPT, t, 0, 0) < 0) {
            LOG_W("PTRACE_INTERRUPT tid=%d: %s", t, strerror(errno));
            ptrace(PTRACE_DETACH, t, 0, 0);
            continue;
        }
        int st = 0;
        if (waitpid(t, &st, __WALL) < 0 || !WIFSTOPPED(st)) {
            LOG_W("tid=%d waitpid after INTERRUPT (status=0x%x): %s",
                  t, st, strerror(errno));
            ptrace(PTRACE_DETACH, t, 0, 0);
            continue;
        }
        if (!arm_dr_on_tid(t, acc_va)) {
            LOG_W("arm DR on tid=%d failed", t);
        } else {
            ++n_armed;
        }
        known_tids.push_back(t);
    }
    if (known_tids.empty()) {
        LOG_E("could not seize any tid");
        return R;
    }
    LOG_I("HW BP armed on %d tid(s); observed-only on %d; DR0=0x%lx",
          n_armed, (int)(known_tids.size() - n_armed), (unsigned long)acc_va);

    // Resume every attached tid.
    for (pid_t t : known_tids) cont_with_sig(t, 0);

    // Tell child to drive real sign cycles.
    char go = 'G';
    if (write(g_go2_pipe[1], &go, 1) != 1) {
        LOG_E("write go2: %s", strerror(errno));
        return R;
    }
    LOG_I("go2 signal sent to child");

    // ============================================================ //
    // PHASE C — harvest. Read rdx low byte at every SIGTRAP whose
    // rip == acc_va. Reset DR6 after each trap; some kernels need it.
    // ============================================================ //
    double deadline = now_s() + double(timeout_s);
    int bytes_needed = version_02_05_03_63::TOTAL_BYTES;
    int spurious_traps = 0;
    while (R.stream.size() < (size_t)bytes_needed && now_s() < deadline) {
        int st = 0;
        pid_t r = waitpid(-1, &st, WNOHANG | __WALL);
        if (r <= 0) {
            usleep(1 * 1000);
            continue;
        }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (r == child) {
                LOG_W("main thread exited mid-capture (status=0x%x bytes=%zu)",
                      st, R.stream.size());
                break;
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
                // Newly-cloned thread INHERITS the parent's user-space
                // debug-regs in current Linux kernels — but to be safe,
                // explicitly arm. It will receive its own SIGSTOP first
                // (handled below via SIGSTOP branch).
                known_tids.push_back(new_tid);
            }
            cont_with_sig(r, 0);
            continue;
        }
        if (sig == SIGSTOP) {
            // Initial-attach SIGSTOP for a freshly-cloned thread; arm + go.
            arm_dr_on_tid(r, acc_va);
            cont_with_sig(r, 0);
            continue;
        }
        if (sig == SIGTRAP) {
            // Verify rip == acc_va (HW BPs report rip == BP address before
            // the instruction executes — same as INT3 but with no byte
            // patch). Read GPRs.
            struct user_regs_struct regs{};
            struct iovec iov{ &regs, sizeof(regs) };
            if (ptrace(PTRACE_GETREGSET, r, (void*)NT_PRSTATUS, &iov) < 0) {
                LOG_W("PTRACE_GETREGSET tid=%d: %s", r, strerror(errno));
                poke_dr(r, 6, 0);
                cont_with_sig(r, 0);
                continue;
            }
            if (regs.rip == acc_va) {
                uint8_t lo = uint8_t(regs.rdx & 0xff);
                R.stream.push_back(lo);
                ++R.total_traps;
                if (g_verbose && (R.stream.size() % 32 == 0 || R.stream.size() <= 4)) {
                    LOG_V("trap #%d tid=%d rdx=0x%lx byte=0x%02x stream=%zu/256",
                          R.total_traps, r, (unsigned long)regs.rdx, lo,
                          R.stream.size());
                }
            } else {
                ++spurious_traps;
                if (g_verbose && spurious_traps < 4) {
                    LOG_V("spurious SIGTRAP tid=%d rip=0x%lx (expected 0x%lx)",
                          r, (unsigned long)regs.rip, (unsigned long)acc_va);
                }
            }
            poke_dr(r, 6, 0);
            cont_with_sig(r, 0);
            continue;
        }
        // Other signals.
        if (sig == SIGSEGV || sig == SIGBUS) {
            // Diagnostic: where did it die?
            struct user_regs_struct dregs{};
            struct iovec div{ &dregs, sizeof(dregs) };
            unsigned long rip = 0;
            if (ptrace(PTRACE_GETREGSET, r, (void*)NT_PRSTATUS, &div) == 0) {
                rip = (unsigned long)dregs.rip;
            }
            // VMP anti-debug jumps to 0xdead9001 when it sees DR0..3 non-zero.
            // PARK the thread (disarm DR, no PTRACE_CONT). Forwarding
            // SIGSEGV killed the whole thread group in v2 testing because
            // VMP does not install a SIGSEGV handler — it relies on the
            // BB-sweep thread spinning in its own loop. Parking is the
            // only non-fatal option.
            bool sentinel = (rip >= 0xdead0000 && rip < 0xdf000000);
            if (sentinel && r != child) {
                static std::vector<pid_t> parked;
                bool already = false;
                for (pid_t p : parked) if (p == r) { already = true; break; }
                if (!already) {
                    parked.push_back(r);
                    LOG_I("worker tid=%d hit sentinel rip=0x%lx — parking",
                          r, rip);
                }
                disarm_dr_on_tid(r);
                continue;
            }
            if (r == child) {
                LOG_W("main thread SIGSEGV rip=0x%lx — forwarding", rip);
                cont_with_sig(r, sig);
            } else {
                LOG_V("SIGSEGV on worker tid=%d rip=0x%lx swallowed", r, rip);
                cont_with_sig(r, 0);
            }
            continue;
        }
        // Default: forward.
        cont_with_sig(r, sig);
    }

    // Cleanly detach every known tid then SIGKILL the group.
    LOG_I("capture loop done: bytes=%zu traps=%d spurious=%d",
          R.stream.size(), R.total_traps, spurious_traps);
    for (pid_t t : known_tids) {
        // Disarm DR first. Suppress logs since many TIDs may have died
        // already by the time we get here.
        long off7 = DR_OFFSET + 7 * (long)sizeof(uint64_t);
        ptrace(PTRACE_POKEUSER, t, (void*)off7, 0);
        ptrace(PTRACE_DETACH, t, 0, 0);
    }
    kill(child, SIGKILL);
    // Drain.
    for (int i = 0; i < 50; ++i) {
        int s = 0; pid_t r = waitpid(child, &s, WNOHANG | __WALL);
        if (r == child || r == -1) break;
        usleep(20 * 1000);
    }

    R.ok = R.stream.size() >= (size_t)bytes_needed;
    if (R.ok) {
        R.stream.resize(bytes_needed);  // clip to 256
        R.sign_cycles = R.total_traps / bytes_needed;
    }
    return R;
}

// Storage for shared Args (used by find_plugin_text_base via extern).
Args g_args_for_child;

// Globals set in main, used in launch_daemon grandchild and setup_h2s_home.
static std::string g_connect_redirect_so_path;
static int g_fake_printer_port = 0;
static std::string g_plugin_path_for_home;

// Rendezvous pipes: parent and child synchronize on plugin init / attach.
int g_ready_pipe[2] = {-1, -1};  // child -> parent: "init complete"
int g_go_pipe[2]    = {-1, -1};  // parent -> child: "attached, drive sign"
int g_warmup_pipe[2] = {-1, -1}; // child -> parent: "warmup send_message done"
int g_go2_pipe[2]    = {-1, -1}; // parent -> child: "arm done, drive real signs"

// ===========================================================================
// Diagnostic capture (v2 addition)
// ===========================================================================
//
// Arms DR0/DR1/DR2 simultaneously at:
//   DR0 = wrap_va (function entry: endbr64 + push r15..rbx + sub rsp,0x78)
//   DR1 = byte_va (movzx edx, byte ptr [rcx])
//   DR2 = acc_va  (mov [rsp+0x48], edx)
//
// Logs every trap with:
//   - tid
//   - rip, rdx, rcx, rsi, rdi
//   - DR6 (which BP fired — bit0=DR0, bit1=DR1, bit2=DR2)
//
// Does NOT park sentinel threads — disarms DR on them and forwards
// SIGSEGV (letting VMP's handler swallow it). Also handles newly-cloned
// threads by arming all three BPs.
//
// Used to ground-truth WHICH PCs actually fire during the real sign
// path. Returns a summary in DiagSummary.

// Wait up to `deadline_extra_s` seconds for a single byte on `fd`. Returns
// 0 on success, -1 on timeout / failure. Handles child early-exit by
// returning -1 and logging.
static int wait_byte(pid_t child, int fd, double deadline_extra_s,
                     char* out_byte, const char* tag) {
    double deadline = now_s() + deadline_extra_s;
    while (now_s() < deadline) {
        struct pollfd pfd{ fd, POLLIN, 0 };
        int rv = poll(&pfd, 1, 200);
        if (rv > 0 && (pfd.revents & POLLIN)) {
            if (read(fd, out_byte, 1) == 1) return 0;
        }
        int st = 0;
        pid_t r = waitpid(child, &st, WNOHANG);
        if (r == child && (WIFEXITED(st) || WIFSIGNALED(st))) {
            LOG_E("[%s] child exited before signal (status=0x%x)", tag, st);
            return -1;
        }
    }
    LOG_E("[%s] timeout waiting for signal", tag);
    return -1;
}

static void diagnostic_capture(pid_t child,
                               uint64_t wrap_va,
                               uint64_t byte_va,
                               uint64_t acc_va,
                               int timeout_s,
                               DiagSummary& S) {
    // Read the LATE_ATTACH handshake from drive_capture's setup.
    close(g_ready_pipe[1]);
    close(g_go_pipe[0]);
    close(g_warmup_pipe[1]);
    close(g_go2_pipe[0]);

    long opts = PTRACE_O_TRACECLONE
              | PTRACE_O_TRACEFORK
              | PTRACE_O_TRACEVFORK;
    LOG_I("[diag] waiting for child ready signal...");
    char ready = 0;
    if (wait_byte(child, g_ready_pipe[0], 30.0, &ready, "diag-ready") < 0) return;
    if (ready != 'R') {
        LOG_E("[diag] child ready handshake failed (byte=0x%x)", (int)ready);
        return;
    }
    LOG_I("[diag] child ready — plugin init complete");

    pid_t watchdog = read_tracer_pid(child);
    if (watchdog > 0 && watchdog != getpid()) {
        LOG_I("[diag] VMP watchdog PID %d — killing", watchdog);
        kill(watchdog, SIGKILL);
        for (int i = 0; i < 50; ++i) {
            if (read_tracer_pid(child) == 0) break;
            usleep(10 * 1000);
        }
    }

    // PHASE A — let child run warmup send_message UNTRACED so VMP lazily
    // decodes the sign path. Just write 'G' and wait for 'W'.
    char go1 = 'G';
    if (write(g_go_pipe[1], &go1, 1) != 1) {
        LOG_E("[diag] write go: %s", strerror(errno));
        return;
    }
    LOG_I("[diag] go (warmup) sent");

    char wb = 0;
    if (wait_byte(child, g_warmup_pipe[0], 30.0, &wb, "diag-warmup") < 0) return;
    if (wb != 'W') {
        LOG_E("[diag] warmup byte = 0x%x", (int)wb); return;
    }
    LOG_I("[diag] warmup complete — sign path should be decoded now");

    // Read maps and dump rich context for offset triage.
    extern Args g_args_for_child;
    PluginMapInfo M = read_plugin_map_info(child, g_args_for_child.plugin_path);
    LOG_I("[diag] file-backed r-xp : 0x%lx-0x%lx (%.1f MB)",
          (unsigned long)M.file_lo, (unsigned long)M.file_hi,
          (M.file_hi - M.file_lo) / (1024.0 * 1024.0));
    LOG_I("[diag] anon r-xp arena2 : 0x%lx-0x%lx (%.1f MB)",
          (unsigned long)M.arena2_lo, (unsigned long)M.arena2_hi,
          (M.arena2_hi - M.arena2_lo) / (1024.0 * 1024.0));
    // Dump ALL r-xp regions so we can see if there's a third VMP segment.
    {
        char path[64]; std::snprintf(path, sizeof(path), "/proc/%d/maps", (int)child);
        std::ifstream f(path);
        std::string ln;
        int n_rxp = 0;
        while (std::getline(f, ln)) {
            size_t sp = ln.find(' ');
            size_t sp2 = ln.find(' ', sp + 1);
            if (sp == std::string::npos || sp2 == std::string::npos) continue;
            std::string perms = ln.substr(sp + 1, sp2 - sp - 1);
            if (perms.size() < 4 || perms[2] != 'x') continue;
            ++n_rxp;
            LOG_I("[diag] r-xp #%d: %s", n_rxp, ln.c_str());
        }
    }
    LOG_I("[diag] DR0=wrap=0x%lx", (unsigned long)wrap_va);
    LOG_I("[diag] DR1=byte=0x%lx", (unsigned long)byte_va);
    LOG_I("[diag] DR2=acc =0x%lx", (unsigned long)acc_va);

    // Dump bytes at each target so we can confirm runtime decode is
    // present.
    auto dump_at = [&](const char* label, uint64_t va) {
        uint8_t buf[32];
        if (read_tracee_mem(child, va, buf, sizeof(buf))) {
            std::string hex;
            char tmp[4];
            for (auto b : buf) { std::snprintf(tmp, sizeof(tmp), "%02x", b); hex += tmp; }
            LOG_I("[diag] mem@%s = %s", label, hex.c_str());
        } else {
            LOG_W("[diag] mem@%s = <unreadable>", label);
        }
    };
    dump_at("wrap", wrap_va);
    dump_at("byte", byte_va);
    dump_at("acc",  acc_va);

    // Optional: prologue scan to find runtime address of the wrapping fn
    // if the offset-based VA doesn't match what's at runtime.
    auto count_readable = [&](uint64_t lo, uint64_t hi) -> std::pair<size_t, size_t> {
        size_t readable = 0, total = 0;
        uint8_t buf[4096];
        for (uint64_t cur = lo; cur < hi; cur += 4096) {
            ++total;
            if (read_tracee_mem(child, cur, buf, std::min<uint64_t>(4096, hi - cur))) ++readable;
        }
        return {readable, total};
    };
    auto count_pattern = [&](uint64_t lo, uint64_t hi, const uint8_t* PAT, size_t PLEN) -> size_t {
        size_t hits = 0;
        std::vector<uint8_t> buf(4096 + PLEN);
        for (uint64_t cur = lo; cur < hi; cur += 4096) {
            size_t want = std::min<uint64_t>(4096, hi - cur);
            if (!read_tracee_mem(child, cur, buf.data(), want)) continue;
            for (size_t i = 0; i + PLEN <= want; ++i) {
                if (std::memcmp(buf.data() + i, PAT, PLEN) == 0) ++hits;
            }
        }
        return hits;
    };
    if (M.arena2_lo && M.arena2_hi) {
        auto rd = count_readable(M.arena2_lo, M.arena2_hi);
        LOG_I("[diag] arena2 readable pages: %zu/%zu", rd.first, rd.second);
        static const uint8_t E[] = {0xf3, 0x0f, 0x1e, 0xfa};
        static const uint8_t BL[] = {0x0f, 0xb6, 0x11};
        static const uint8_t AC[] = {0x89, 0x54, 0x24, 0x48};
        size_t n_endbr = count_pattern(M.arena2_lo, M.arena2_hi, E, sizeof(E));
        size_t n_bl    = count_pattern(M.arena2_lo, M.arena2_hi, BL, sizeof(BL));
        size_t n_ac    = count_pattern(M.arena2_lo, M.arena2_hi, AC, sizeof(AC));
        LOG_I("[diag] arena2 patterns: endbr64=%zu movzx[rcx]=%zu mov[rsp+0x48],edx=%zu",
              n_endbr, n_bl, n_ac);
        // Show a few endbr64 sites with the 13 bytes that follow, so we
        // can see what prologues the plugin actually emits.
        {
            int dumped = 0;
            std::vector<uint8_t> buf(4096);
            for (uint64_t cur = M.arena2_lo; cur < M.arena2_hi && dumped < 6; cur += 4096) {
                size_t want = std::min<uint64_t>(4096, M.arena2_hi - cur);
                if (!read_tracee_mem(child, cur, buf.data(), want)) continue;
                for (size_t i = 0; i + 17 <= want; ++i) {
                    if (buf[i]==0xf3 && buf[i+1]==0x0f && buf[i+2]==0x1e && buf[i+3]==0xfa) {
                        std::string hex; char tmp[4];
                        for (int j=0;j<17;++j){std::snprintf(tmp,sizeof(tmp),"%02x",buf[i+j]); hex+=tmp;}
                        LOG_I("[diag]   endbr64@0x%lx (arena2+0x%lx) : %s",
                              (unsigned long)(cur + i),
                              (unsigned long)(cur + i - M.arena2_lo),
                              hex.c_str());
                        if (++dumped >= 6) break;
                    }
                }
            }
        }

        auto hits = scan_prologue(child, M.arena2_lo, M.arena2_hi, 16);
        LOG_I("[diag] prologue scan in arena2: %zu hit(s)", hits.size());
        for (size_t i = 0; i < hits.size() && i < 16; ++i) {
            LOG_I("[diag]   prologue@0x%lx (offset arena2+0x%lx)",
                  (unsigned long)hits[i],
                  (unsigned long)(hits[i] - M.arena2_lo));
        }
        // Dump a few mov[rsp+0x48],edx sites — they should let us see the
        // accumulator context regardless of byte-load proximity.
        {
            int dumped = 0;
            std::vector<uint8_t> buf(4096);
            for (uint64_t cur = M.arena2_lo; cur < M.arena2_hi && dumped < 8; cur += 4096) {
                size_t want = std::min<uint64_t>(4096, M.arena2_hi - cur);
                if (!read_tracee_mem(child, cur, buf.data(), want)) continue;
                for (size_t i = 0; i + 4 <= want; ++i) {
                    if (buf[i]==0x89 && buf[i+1]==0x54 && buf[i+2]==0x24 && buf[i+3]==0x48) {
                        // Show 8 bytes before + 8 bytes after.
                        size_t bk = (i >= 8 ? 8 : i);
                        size_t fw = std::min<size_t>(want - i, 16);
                        std::string hex; char tmp[4];
                        for (size_t j = i - bk; j < i + fw; ++j) {
                            std::snprintf(tmp,sizeof(tmp),"%02x",buf[j]); hex += tmp;
                        }
                        LOG_I("[diag]   acc-cand@0x%lx (arena2+0x%lx) ctx[-%zu..+%zu]: %s",
                              (unsigned long)(cur + i),
                              (unsigned long)(cur + i - M.arena2_lo),
                              bk, fw, hex.c_str());
                        if (++dumped >= 8) break;
                    }
                }
            }
        }
        auto bah = scan_byte_load_accumulator(child, M.arena2_lo, M.arena2_hi, 32);
        LOG_I("[diag] byte_load+accumulator pairs in arena2: %zu", bah.size());
        for (size_t i = 0; i < bah.size() && i < 32; ++i) {
            LOG_I("[diag]   bl@0x%lx (arena2+0x%lx)  ac@0x%lx (arena2+0x%lx)  diff=%ld",
                  (unsigned long)bah[i].va_byte_load,
                  (unsigned long)(bah[i].va_byte_load - M.arena2_lo),
                  (unsigned long)bah[i].va_accumulator,
                  (unsigned long)(bah[i].va_accumulator - M.arena2_lo),
                  (long)(bah[i].va_accumulator - bah[i].va_byte_load));
        }
    }
    if (M.file_lo && M.file_hi) {
        auto rd = count_readable(M.file_lo, M.file_hi);
        LOG_I("[diag] file-rxp readable pages: %zu/%zu", rd.first, rd.second);
        static const uint8_t E[] = {0xf3, 0x0f, 0x1e, 0xfa};
        size_t n_endbr = count_pattern(M.file_lo, M.file_hi, E, sizeof(E));
        LOG_I("[diag] file-rxp patterns: endbr64=%zu", n_endbr);
    }
    // Locate SHA-256 K-table (first 8 dwords) in EVERY readable region.
    // The sign helper that calls modexp is in the same compilation unit as
    // SHA-256, so the K-table anchors that code.
    {
        static const uint8_t K_BE[] = {
            0x42,0x8a,0x2f,0x98, 0x71,0x37,0x44,0x91,
            0xb5,0xc0,0xfb,0xcf, 0xe9,0xb5,0xdb,0xa5,
            0x39,0x56,0xc2,0x5b, 0x59,0xf1,0x11,0xf1
        };
        static const uint8_t K_LE[] = {
            0x98,0x2f,0x8a,0x42, 0x91,0x44,0x37,0x71,
            0xcf,0xfb,0xc0,0xb5, 0xa5,0xdb,0xb5,0xe9,
            0x5b,0xc2,0x56,0x39, 0xf1,0x11,0xf1,0x59
        };
        char path[64]; std::snprintf(path, sizeof(path), "/proc/%d/maps", (int)child);
        std::ifstream f(path);
        std::string ln;
        int found = 0;
        while (std::getline(f, ln)) {
            size_t sp = ln.find(' ');
            size_t sp2 = ln.find(' ', sp + 1);
            if (sp == std::string::npos || sp2 == std::string::npos) continue;
            std::string perms = ln.substr(sp + 1, sp2 - sp - 1);
            if (perms.size() < 4 || perms[0] != 'r') continue;
            // Skip massive RW heaps and stacks to save time.
            if (ln.find("[heap]") != std::string::npos) continue;
            if (ln.find("[stack]") != std::string::npos) continue;
            if (ln.find("[vvar]") != std::string::npos) continue;
            if (ln.find("[vsyscall]") != std::string::npos) continue;
            size_t dash = ln.find('-');
            uint64_t lo = std::stoull(ln.substr(0, dash), nullptr, 16);
            uint64_t hi = std::stoull(ln.substr(dash + 1, sp - dash - 1), nullptr, 16);
            // Cap to first 8 MB per region for sanity.
            uint64_t end = std::min<uint64_t>(hi, lo + 8 * 1024 * 1024);
            std::vector<uint8_t> buf(4096 + 32);
            for (uint64_t cur = lo; cur < end; cur += 4096) {
                size_t want = std::min<uint64_t>(4096, end - cur);
                if (!read_tracee_mem(child, cur, buf.data(), want)) continue;
                for (size_t i = 0; i + 32 <= want; ++i) {
                    if (std::memcmp(buf.data() + i, K_BE, 32) == 0) {
                        LOG_I("[diag] SHA-256 K-table (BE) @0x%lx perms=%s",
                              (unsigned long)(cur + i), perms.c_str());
                        ++found;
                    } else if (std::memcmp(buf.data() + i, K_LE, 32) == 0) {
                        LOG_I("[diag] SHA-256 K-table (LE) @0x%lx perms=%s",
                              (unsigned long)(cur + i), perms.c_str());
                        ++found;
                    }
                }
            }
        }
        if (found == 0) LOG_W("[diag] no SHA-256 K-table found in any region");
    }
    // Run dynamic accumulator discovery.
    if (M.arena2_lo && M.arena2_hi) {
        uint64_t bl_va = 0, wrap_dummy = 0;
        uint64_t disc_acc = discover_accumulator_pc(child, M.arena2_lo, M.arena2_hi,
                                                    &wrap_dummy, &bl_va);
        LOG_I("[diag] discover_accumulator_pc -> acc_va=0x%lx bl=0x%lx",
              (unsigned long)disc_acc, (unsigned long)bl_va);
        if (disc_acc) {
            // Update DR0 = disc_acc, DR1 = bl_va, DR2 = wrap_va.
            // Will be applied below.
            LOG_I("[diag] OVERRIDING DR0/DR1 with discovered VAs");
            acc_va = disc_acc;
            byte_va = bl_va;
        }
    }

    // Enumerate + SEIZE every TID. Arm DR ONLY on main thread by default.
    // Workers running VMP anti-debug sweeps trip a sentinel SIGSEGV at
    // 0xdead9001 when DR is non-zero. Send_message runs on main thread
    // (single-threaded), so main is the right target.
    bool arm_only_main = (std::getenv("BBL_ARM_ALL_TIDS") == nullptr);
    std::vector<pid_t> tids = enumerate_tids(child);
    if (tids.empty()) tids.push_back(child);
    for (auto it = tids.begin(); it != tids.end(); ++it) {
        if (*it == child) { tids.erase(it); tids.insert(tids.begin(), child); break; }
    }
    if (tids.empty() || tids.front() != child) tids.insert(tids.begin(), child);

    std::vector<pid_t> known;
    int armed = 0, observed = 0;
    for (pid_t t : tids) {
        if (ptrace(PTRACE_SEIZE, t, 0, (void*)opts) < 0) {
            LOG_W("[diag] SEIZE tid=%d: %s", t, strerror(errno));
            if (t == child) { kill(child, SIGKILL); return; }
            continue;
        }
        if (ptrace(PTRACE_INTERRUPT, t, 0, 0) < 0) {
            ptrace(PTRACE_DETACH, t, 0, 0); continue;
        }
        int st = 0;
        if (waitpid(t, &st, __WALL) < 0 || !WIFSTOPPED(st)) {
            ptrace(PTRACE_DETACH, t, 0, 0); continue;
        }
        if (!arm_only_main || t == child) {
            arm_dr012_on_tid(t, wrap_va, byte_va, acc_va);
            ++armed;
        } else {
            // Observed-only — we'll arm later if traffic shows the sign
            // happens on this tid.
            ++observed;
        }
        known.push_back(t);
    }
    LOG_I("[diag] HW BP armed on %d tid(s); observed-only on %d tid(s)", armed, observed);
    for (pid_t t : known) cont_with_sig(t, 0);

    // Go2: tell child to do real sign cycles now.
    char go2 = 'G';
    if (write(g_go2_pipe[1], &go2, 1) != 1) {
        LOG_E("[diag] write go2: %s", strerror(errno));
        return;
    }
    LOG_I("[diag] go2 signal sent (real signs)");

    double deadline = now_s() + double(timeout_s);
    while (now_s() < deadline) {
        int st = 0;
        pid_t r = waitpid(-1, &st, WNOHANG | __WALL);
        if (r <= 0) { usleep(1 * 1000); continue; }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (r == child) {
                LOG_W("[diag] main thread exited mid-capture (status=0x%x)", st);
                break;
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
            ++S.clones;
            LOG_I("[diag] tid=%d cloned new_tid=%d", r, new_tid);
            cont_with_sig(r, 0);
            continue;
        }
        if (sig == SIGSTOP) {
            arm_dr012_on_tid(r, wrap_va, byte_va, acc_va);
            cont_with_sig(r, 0);
            continue;
        }
        if (sig == SIGTRAP) {
            struct user_regs_struct regs{};
            struct iovec iov{ &regs, sizeof(regs) };
            if (ptrace(PTRACE_GETREGSET, r, (void*)NT_PRSTATUS, &iov) < 0) {
                poke_dr(r, 6, 0); cont_with_sig(r, 0); continue;
            }
            errno = 0;
            long dr6 = peek_dr(r, 6);
            (void)dr6;
            // DR6 low 4 bits indicate which DR fired.
            int which = -1;
            if (dr6 & 0x1) which = 0;
            else if (dr6 & 0x2) which = 1;
            else if (dr6 & 0x4) which = 2;
            ++S.total_traps;
            if (which == 0) ++S.traps_dr0;
            else if (which == 1) ++S.traps_dr1;
            else if (which == 2) ++S.traps_dr2;
            else ++S.spurious_sigtrap;
            // Throttle log to first 20 + every 64th.
            if (S.total_traps <= 20 || (S.total_traps % 64) == 0) {
                LOG_I("[diag] trap #%d tid=%d which=DR%d dr6=0x%lx "
                      "rip=0x%lx rdx=0x%lx rcx=0x%lx rsi=0x%lx rdi=0x%lx",
                      S.total_traps, r, which, (unsigned long)dr6,
                      (unsigned long)regs.rip,
                      (unsigned long)regs.rdx, (unsigned long)regs.rcx,
                      (unsigned long)regs.rsi, (unsigned long)regs.rdi);
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
            if (sentinel) {
                ++S.sentinels;
                // PARK the thread — disarm DR but DO NOT PTRACE_CONT.
                // The kernel keeps the thread in tracee-stop, the rest of
                // the process continues on other threads. Forwarding
                // SIGSEGV killed the whole group in v1 testing.
                LOG_I("[diag] sentinel tid=%d rip=0x%lx — parking", r, rip);
                disarm_dr_on_tid(r);
                continue;
            }
            ++S.sigsegv_non_sentinel;
            if (r == child) {
                LOG_W("[diag] main SIGSEGV rip=0x%lx — forwarding", rip);
                cont_with_sig(r, sig);
            } else {
                cont_with_sig(r, 0);
            }
            continue;
        }
        cont_with_sig(r, sig);
    }
    LOG_I("[diag] capture window closed");
    LOG_I("[diag] total_traps=%d  DR0_wrap=%d  DR1_byte=%d  DR2_acc=%d",
          S.total_traps, S.traps_dr0, S.traps_dr1, S.traps_dr2);
    LOG_I("[diag] sentinels=%d clones=%d spurious_SIGTRAP=%d non_sentinel_SEGV=%d",
          S.sentinels, S.clones, S.spurious_sigtrap, S.sigsegv_non_sentinel);

    g_suppress_dr_errors = true;
    for (pid_t t : known) {
        disarm_dr_on_tid(t);
        ptrace(PTRACE_DETACH, t, 0, 0);
    }
    g_suppress_dr_errors = false;
    kill(child, SIGKILL);
    for (int i = 0; i < 50; ++i) {
        int s = 0; pid_t r = waitpid(child, &s, WNOHANG | __WALL);
        if (r == child || r == -1) break;
        usleep(20 * 1000);
    }
}

// ===========================================================================
// Factor recovery + d reconstruction
// ===========================================================================

struct DRecon {
    bool ok = false;
    bn::BigInt p, q, dp, dq, d;
    int k_found = 0;
    std::string mode;  // C_crt_be (dp=first half, dq=second half) or D_crt_be_swap
};

// Try a single (dp_candidate, N, E) pair via E*dp - 1 = k*(p-1).
// Returns success + (p, q, k).
static bool factor_one(const bn::BigInt& dp_cand,
                       int E,
                       const bn::BigInt& N,
                       int max_k,
                       bn::BigInt& p_out,
                       bn::BigInt& q_out,
                       int& k_out) {
    if (dp_cand.is_zero()) return false;
    // num = E * dp - 1
    bn::BigInt num = bn::mul_small(dp_cand, uint32_t(E));
    if (num.is_zero()) return false;
    num = bn::sub(num, bn::BigInt(1));
    for (int k = 1; k < max_k; ++k) {
        uint32_t rem = 0;
        bn::BigInt q = bn::div_small(num, uint32_t(k), &rem);
        if (rem != 0) continue;
        bn::BigInt p = bn::add(q, bn::BigInt(1));
        if (bn::BigInt::cmp(p, bn::BigInt(1)) <= 0) continue;
        if (bn::BigInt::cmp(p, N) >= 0) continue;
        // Test p | N
        bn::BigInt N_rem = bn::mod(N, p);
        if (!N_rem.is_zero()) continue;
        bn::BigInt other = bn::div(N, p);
        // Verify other * p == N
        bn::BigInt prod = bn::mul(other, p);
        if (bn::BigInt::cmp(prod, N) != 0) continue;
        if (bn::BigInt::cmp(other, bn::BigInt(1)) <= 0) continue;
        p_out = p; q_out = other; k_out = k;
        return true;
    }
    return false;
}

// Given p, q, E, compute d = E^{-1} mod lcm(p-1, q-1).
// We use phi = (p-1)*(q-1); d = E^{-1} mod phi. Same answer mod lcm for the
// signing purpose because E*d ≡ 1 (mod (p-1)(q-1)) implies E*d ≡ 1 mod
// lcm too.
static bool compute_d(const bn::BigInt& p, const bn::BigInt& q, int E, bn::BigInt& d) {
    bn::BigInt p_minus_1 = bn::sub(p, bn::BigInt(1));
    bn::BigInt q_minus_1 = bn::sub(q, bn::BigInt(1));
    bn::BigInt phi = bn::mul(p_minus_1, q_minus_1);
    d = bn::mod_inverse(bn::BigInt(uint32_t(E)), phi);
    return !d.is_zero();
}

// Given full d and full N, validate against envelopes.
static int validate_envelopes(const bn::BigInt& d, const bn::BigInt& N,
                              const std::vector<Envelope>& envs,
                              int* first_fail_ix = nullptr) {
    // Pre-compute N_be (256 bytes) and d_be (variable length).
    uint8_t N_be[256], d_be[256];
    bn::to_bytes_be_fixed(N, N_be, 256);
    bn::to_bytes_be_fixed(d, d_be, 256);
    // Find first non-zero byte in d for short exp_len.
    size_t d_first = 0;
    while (d_first < 256 && d_be[d_first] == 0) ++d_first;
    size_t exp_len = 256 - d_first;
    const uint8_t* exp_ptr = d_be + d_first;

    int passed = 0;
    for (size_t ix = 0; ix < envs.size(); ++ix) {
        const auto& env = envs[ix];
        // SHA-256 to_sign
        auto h = bambu_signing::Sha256Portable::hash(env.to_sign);
        uint8_t EM[256];
        pkcs1_v15_pad_sha256(h.data(), EM);
        uint8_t sig[256];
        bambu_signing::big_modexp_rsa2048(EM, exp_ptr, exp_len, N_be, sig);
        // expected
        std::vector<uint8_t> exp_bytes;
        if (!base64_decode(env.sig_b64, exp_bytes)) {
            if (first_fail_ix && *first_fail_ix < 0) *first_fail_ix = int(ix);
            continue;
        }
        if (exp_bytes.size() != 256) {
            if (first_fail_ix && *first_fail_ix < 0) *first_fail_ix = int(ix);
            continue;
        }
        if (std::memcmp(sig, exp_bytes.data(), 256) == 0) {
            ++passed;
        } else if (first_fail_ix && *first_fail_ix < 0) {
            *first_fail_ix = int(ix);
        }
    }
    return passed;
}

static DRecon reconstruct(const std::vector<uint8_t>& stream,
                          const bn::BigInt& N,
                          int E,
                          int max_k,
                          const std::vector<Envelope>& head_envs,
                          int min_matches) {
    DRecon R;
    if (stream.size() != 256) return R;

    const int H = 128;
    // Mode C: dp = first 128 BE, dq = second 128 BE
    // Mode D: dp = second 128 BE, dq = first 128 BE  (swap)
    struct Try { std::string mode; const uint8_t* a; const uint8_t* b; };
    std::vector<Try> tries = {
        {"C_crt_be",      stream.data(),       stream.data() + H},
        {"D_crt_be_swap", stream.data() + H,   stream.data()},
    };
    for (const auto& t : tries) {
        bn::BigInt dp = bn::from_bytes_be(t.a, H);
        bn::BigInt dq = bn::from_bytes_be(t.b, H);

        bn::BigInt p, q; int k = 0;
        bool got = factor_one(dp, E, N, max_k, p, q, k);
        if (!got) {
            // Try with dq instead; if it succeeds we still set p=that-factor,
            // q=other. We want the convention "p such that dp = d mod (p-1)".
            bn::BigInt p2, q2; int k2 = 0;
            if (factor_one(dq, E, N, max_k, p2, q2, k2)) {
                p = q2; q = p2; k = k2;  // dq corresponds to q-factor
                got = true;
            }
        }
        if (!got) continue;

        bn::BigInt d;
        if (!compute_d(p, q, E, d)) continue;

        // Validate against head envelopes for cheap pre-filter.
        int head_pass = validate_envelopes(d, N, head_envs);
        if (head_pass < min_matches) continue;

        R.ok = true;
        R.mode = t.mode;
        R.p = p; R.q = q; R.dp = dp; R.dq = dq;
        R.d = d;
        R.k_found = k;
        return R;
    }
    return R;
}

// ===========================================================================
// I/O helpers
// ===========================================================================
static std::string slurp(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::stringstream ss; ss << f.rdbuf(); return ss.str();
}

// Write a PKCS#1 RSA private key PEM file (mode 0600).
// Compatible with: openssl rsa -in slicer_key.pem -text -noout
// and with open-bamboo-networking's signing.cpp PEM loader.
static bool write_pem_output(const std::string& path,
                              const DRecon& R, const bn::BigInt& N) {
    auto bn_from_bigint = [](const bn::BigInt& x) -> BIGNUM* {
        BIGNUM* b = nullptr;
        std::string h = bn::to_hex_str(x, false);
        BN_hex2bn(&b, h.c_str());
        return b;
    };

    RSA* rsa = RSA_new();
    if (!rsa) { LOG_E("RSA_new failed"); return false; }

    BIGNUM* n  = bn_from_bigint(N);
    BIGNUM* e  = BN_new(); BN_set_word(e, 65537);
    BIGNUM* d  = bn_from_bigint(R.d);
    BIGNUM* p  = bn_from_bigint(R.p);
    BIGNUM* q  = bn_from_bigint(R.q);
    BIGNUM* dp = bn_from_bigint(R.dp);
    BIGNUM* dq = bn_from_bigint(R.dq);

    // qInv = q^{-1} mod p
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* qi  = BN_new();
    BN_mod_inverse(qi, q, p, ctx);
    BN_CTX_free(ctx);

    RSA_set0_key(rsa, n, e, d);
    RSA_set0_factors(rsa, p, q);
    RSA_set0_crt_params(rsa, dp, dq, qi);

    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        LOG_E("open(%s): %s", path.c_str(), strerror(errno));
        RSA_free(rsa);
        return false;
    }
    FILE* f = fdopen(fd, "w");
    if (!f) { close(fd); RSA_free(rsa); return false; }

    int ok = PEM_write_RSAPrivateKey(f, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    RSA_free(rsa);
    if (!ok) { LOG_E("PEM_write_RSAPrivateKey failed"); return false; }
    return true;
}

static bool write_output(const std::string& path,
                         const DRecon& R, const bn::BigInt& N,
                         int env_pass, int env_total) {
    // PEM output when path ends in .pem
    if (path.size() >= 4 && path.compare(path.size() - 4, 4, ".pem") == 0)
        return write_pem_output(path, R, N);

    // Mode 0600.
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        LOG_E("open(%s): %s", path.c_str(), strerror(errno));
        return false;
    }
    std::string body;
    body += "{\n";
    body += "  \"p_hex\":  \"" + bn::to_hex_str(R.p)  + "\",\n";
    body += "  \"q_hex\":  \"" + bn::to_hex_str(R.q)  + "\",\n";
    body += "  \"dp_hex\": \"" + bn::to_hex_str(R.dp) + "\",\n";
    body += "  \"dq_hex\": \"" + bn::to_hex_str(R.dq) + "\",\n";
    body += "  \"d_hex\":  \"" + bn::to_hex_str(R.d)  + "\",\n";
    body += "  \"N_hex\":  \"" + bn::to_hex_str(N)    + "\",\n";
    body += "  \"E\": 65537,\n";
    body += "  \"mode\": \"" + R.mode + "\",\n";
    body += "  \"k_factor\": " + std::to_string(R.k_found) + ",\n";
    body += "  \"envelope_pass_count\": " + std::to_string(env_pass) + ",\n";
    body += "  \"envelope_total\": " + std::to_string(env_total) + ",\n";
    body += "  \"_security\": \"SECRET: slicer RSA-2048 d. Mode 0600.\"\n";
    body += "}\n";
    ssize_t w = write(fd, body.data(), body.size());
    close(fd);
    if (w != (ssize_t)body.size()) {
        LOG_E("short write to %s", path.c_str());
        return false;
    }
    return true;
}

// ===========================================================================
// Main
// ===========================================================================
// ============================================================================
// New main() for bambu_extract_d — replaces extract_d_fast's main().
// Simplified CLI: --dev-id, --access-code, --lan-ip, --plugin, --out,
// --timeout, --verbose, --envelopes (optional), --help.
//
// Architecture: embeds bambu-bridge-daemon binary + watchdog shim.
// Phase 0: re-exec with watchdog_defeat_v2.so via memfd LD_PRELOAD.
// Phase 1: write daemon binary to memfd, set up H2S home, launch daemon,
//          wait for sign code to be decoded (SHA-256 K-table present in
//          arena2), then call drive_capture_attach() which finds the
//          accumulator PC via dynamic discovery and captures 256 d-bytes.
// ============================================================================

#include <sys/wait.h>
#include <dirent.h>
#include <sys/mman.h>

// Embed the bambu-bridge-daemon binary so bambu_extract_d is self-contained.
#include "daemon_embed.h"  // daemon_embed_bin[] + daemon_embed_bin_len

static void usage_simple(const char* prog) {
    std::fprintf(stderr,
        "usage: %s --access-code CODE [--dev-id ID] [--lan-ip IP] [options]\n"
        "   or: %s --no-printer [--dev-id ID]   (offline — no printer needed)\n"
        "\n"
        "Required (unless --no-printer):\n"
        "  --access-code CODE  Printer access code (from BambuStudio Settings)\n"
        "\n"
        "Auto-discovered (SSDP / BambuStudio.conf — omit when only one printer on LAN):\n"
        "  --dev-id ID         Printer device ID (e.g. 0938BC582502312)\n"
        "  --lan-ip IP         Printer LAN IP address\n"
        "\n"
        "Optional:\n"
        "  --no-printer        Offline mode: start a fake TLS MQTT broker instead of\n"
        "                      connecting to a real printer. dev-id from BambuStudio.conf\n"
        "                      (or SSDP), access-code and lan-ip not needed.\n"
        "  --plugin PATH       libbambu_networking.so path (probes defaults)\n"
        "  --out PATH          Output path: .json or .pem (PKCS#1 RSA PEM, default: d_extracted.json)\n"
        "  --timeout N         Seconds before giving up (default: 120)\n"
        "  --envelopes PATH    envelopes.json for validation (optional)\n"
        "  --verbose           Log every HW BP trap\n"
        "  --help              Show this message\n"
        "\n"
        "Example (with printer — access code auto-discovered from SSDP + BambuStudio.conf):\n"
        "  %s --access-code 64e81956\n"
        "\n"
        "Example (offline — no printer required, dev-id from BambuStudio.conf):\n"
        "  %s --no-printer\n"
        "\n"
        "Example (offline, explicit dev-id):\n"
        "  %s --no-printer --dev-id 0938BC582502312\n",
        prog, prog, prog, prog, prog);
}

// Probe for the plugin .so. Prefers the bridge home copy, then the user's
// BambuStudio install, then falls back to known versioned paths.
static std::string probe_plugin_path() {
    const char* home = std::getenv("HOME");
    std::vector<std::string> candidates = {
        "/tmp/bridge-mp/home-H2S/.config/BambuStudio/plugins/libbambu_networking.so",
    };
    if (home && home[0]) {
        candidates.push_back(std::string(home) + "/.config/BambuStudio/plugins/libbambu_networking.so");
        candidates.push_back(std::string(home) + "/.local/share/BambuStudio/plugins/libbambu_networking.so");
    }
    // Fallback versioned paths (dev/test only).
    candidates.push_back("/mnt/cephfs/Source/lost_library/plugins/linux_02.05.03.63/libbambu_networking.so");
    for (auto& p : candidates) {
        struct stat st{};
        if (stat(p.c_str(), &st) == 0) return p;
    }
    return {};
}

// Download the libbambu_networking.so plugin from Bambu's CDN if not cached.
// Cache location: ~/.cache/bambu_extract_d/plugins/libbambu_networking.so
// Returns the cached path on success, empty string on failure.
static std::string download_plugin_if_needed() {
    const char* home = std::getenv("HOME");
    if (!home || !home[0]) {
        std::fprintf(stderr, "[plugin-dl] HOME not set, cannot cache plugin\n");
        return {};
    }
    std::string cache_dir = std::string(home) + "/.cache/bambu_extract_d/plugins";
    std::string cache_so  = cache_dir + "/libbambu_networking.so";

    // 1. Return cached copy if present.
    {
        struct stat st{};
        if (stat(cache_so.c_str(), &st) == 0 && st.st_size > 0) {
            std::fprintf(stderr, "[plugin-dl] using cached plugin: %s\n", cache_so.c_str());
            return cache_so;
        }
    }

    std::fprintf(stderr, "[plugin-dl] no local plugin found — fetching manifest from Bambu CDN...\n");

    // 2. Fetch manifest JSON.
    char manifest_tmp[64];
    snprintf(manifest_tmp, sizeof(manifest_tmp), "/tmp/bambu_manifest_%d.json", (int)getpid());
    {
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
            "curl --silent --location --max-time 60 "
            "-H \"X-BBL-OS-Type: linux\" "
            "-o %s "
            "\"https://api.bambulab.com/v1/iot-service/api/slicer/resource?slicer/plugins/cloud=02.05.03.00\" "
            "2>&1",
            manifest_tmp);
        int rc = std::system(cmd);
        if (rc != 0) {
            std::fprintf(stderr, "[plugin-dl] manifest fetch failed (rc=%d)\n", rc);
            unlink(manifest_tmp);
            return {};
        }
    }

    // 3. Parse "url":"..." from manifest JSON.
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

        // Look for "url":"..." (first occurrence).
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

    // 4. Download ZIP.
    char zip_tmp[64];
    snprintf(zip_tmp, sizeof(zip_tmp), "/tmp/bambu_plugin_%d.zip", (int)getpid());
    {
        char cmd[2048];
        snprintf(cmd, sizeof(cmd),
            "curl --silent --location --max-time 120 -o %s \"%s\" 2>&1",
            zip_tmp, manifest_url.c_str());
        int rc = std::system(cmd);
        if (rc != 0) {
            std::fprintf(stderr, "[plugin-dl] ZIP download failed (rc=%d)\n", rc);
            unlink(zip_tmp);
            return {};
        }
    }

    // 5. Create cache dir (mode 0700).
    {
        // Create parent dirs.
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

    // 6. Extract .so from ZIP into cache dir.
    {
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
            "unzip -j -o %s \"*.so\" -d %s 2>&1",
            zip_tmp, cache_dir.c_str());
        int rc = std::system(cmd);
        unlink(zip_tmp);
        if (rc != 0) {
            std::fprintf(stderr, "[plugin-dl] unzip failed (rc=%d)\n", rc);
            return {};
        }
    }

    // 7. Check that the expected .so exists; chmod 0600.
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

// Parse "multi_devices" from BambuStudio.conf and return the list of dev_ids.
// multi_devices is a JSON object like {"0":"dev_id1","1":"dev_id2",...}.
// Returns empty vector on failure or if the key is absent.
static std::vector<std::string> probe_dev_ids_from_bsl_conf() {
    const char* home_env = std::getenv("HOME");
    if (!home_env || !home_env[0]) return {};
    std::string conf_path = std::string(home_env) + "/.config/BambuStudio/BambuStudio.conf";
    FILE* f = std::fopen(conf_path.c_str(), "r");
    if (!f) return {};
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::rewind(f);
    if (sz <= 0 || sz > 8 * 1024 * 1024) { std::fclose(f); return {}; }
    std::string body(sz, '\0');
    (void)std::fread(&body[0], 1, sz, f);
    std::fclose(f);

    // Find "multi_devices":{...}
    const char* key = "\"multi_devices\"";
    size_t pos = body.find(key);
    if (pos == std::string::npos) return {};
    pos = body.find('{', pos + std::strlen(key));
    if (pos == std::string::npos) return {};
    size_t end = body.find('}', pos);
    if (end == std::string::npos) return {};
    std::string obj = body.substr(pos + 1, end - pos - 1);

    // Pull out all quoted string values (the dev_ids are values, not keys).
    std::vector<std::string> ids;
    bool is_val = false;  // alternate key/value
    size_t i = 0;
    while (i < obj.size()) {
        if (obj[i] == '"') {
            size_t start = i + 1;
            size_t close = obj.find('"', start);
            if (close == std::string::npos) break;
            std::string tok = obj.substr(start, close - start);
            if (is_val && !tok.empty()) ids.push_back(tok);
            is_val = !is_val;
            i = close + 1;
        } else if (obj[i] == ':') {
            i++;
        } else {
            i++;
        }
    }
    return ids;
}

// ---------------------------------------------------------------------------
// FakePrinterBroker — offline mode TLS MQTT broker that mimics a Bambu printer.
//
// The proprietary plugin gates RSA signing on device_pub_key_map[dev_id] being
// populated.  That map is filled when the plugin receives a `cert_report` MQTT
// message from the printer on `device/<dev_id>/security`.  This broker:
//   1. Generates an ephemeral RSA-2048 key + self-signed X.509 cert.
//   2. Accepts one TLS connection on 127.0.0.1:8883 (or next free port).
//   3. Speaks MQTT 3.1.1: CONNECT→CONNACK, SUBSCRIBE→SUBACK, PINGREQ→PINGRESP.
//   4. Watches for PUBLISH to device/<dev_id>/security (app_cert_install).
//   5. Immediately replies with a cert_report carrying the generated PEM.
// ---------------------------------------------------------------------------

struct FakePrinterBroker {
    std::string dev_id;
    int         port         = 8883;   // the port we actually bound
    bool        ready        = false;
    bool        cert_sent    = false;
    bool        used_iptables = false;
    bool        used_connect_redirect = false;
    std::string connect_redirect_so_path;
    std::string connect_redirect_c_path;
    std::mutex  mu;
    std::condition_variable cv;
    std::thread  thr;
    SSL_CTX*     ctx     = nullptr;
    int          srv_fd  = -1;
    std::string  printer_cert_pem;  // returned so caller can embed in cert_report

    // Start listening.  Returns false on failure.
    // Strategy: try port 8883; if busy, pick a random free port and install an
    // iptables OUTPUT REDIRECT rule so the plugin's connect(127.0.0.1:8883) lands
    // on our port.  Rule is removed in stop().
    bool start(const std::string& target_dev_id) {
        dev_id = target_dev_id;
        if (!gen_ctx()) return false;
        // Try to bind on 8883 first.
        if (!try_bind(8883)) {
            // Find a free ephemeral port.
            int free_port = find_free_port();
            if (free_port <= 0) return false;
            if (!try_bind(free_port)) return false;
            // Port 8883 busy — compile a tiny connect() interceptor .so that
            // redirects 127.0.0.1:8883 to our port, then LD_PRELOAD it into
            // the daemon subprocess.  No iptables / no root needed.
            if (!build_connect_redirect_so(free_port)) {
                std::fprintf(stderr,
                    "[fake-printer] port 8883 busy and connect() redirect compile failed.\n"
                    "  Stop the bridge daemon first, or run as root for iptables.\n");
                close(srv_fd); srv_fd = -1;
                return false;
            }
            used_connect_redirect = true;
            std::fprintf(stderr,
                "[fake-printer] port 8883 busy — using LD_PRELOAD connect() redirect to %d\n",
                free_port);
        }
        if (listen(srv_fd, 4) < 0) {
            close(srv_fd); srv_fd = -1; return false;
        }
        thr = std::thread([this]{ accept_loop(); });
        {
            std::unique_lock<std::mutex> lk(mu);
            cv.wait_for(lk, std::chrono::seconds(1), [this]{ return ready; });
        }
        return ready;
    }

    void stop() {
        if (srv_fd >= 0) { shutdown(srv_fd, SHUT_RDWR); close(srv_fd); srv_fd = -1; }
        if (thr.joinable()) thr.join();
        if (ctx) { SSL_CTX_free(ctx); ctx = nullptr; }
        if (used_iptables) {
            char cmd[256];
            std::snprintf(cmd, sizeof(cmd),
                "iptables -t nat -D OUTPUT -d 127.0.0.1 -p tcp "
                "--dport 8883 -j REDIRECT --to-ports %d 2>/dev/null", port);
            std::system(cmd);
            used_iptables = false;
            std::fprintf(stderr, "[fake-printer] iptables REDIRECT removed\n");
        }
        if (used_connect_redirect) {
            if (!connect_redirect_so_path.empty()) unlink(connect_redirect_so_path.c_str());
            if (!connect_redirect_c_path.empty())  unlink(connect_redirect_c_path.c_str());
            used_connect_redirect = false;
            std::fprintf(stderr, "[fake-printer] connect() redirect .so removed\n");
        }
    }

    ~FakePrinterBroker() { stop(); }

private:
    static int find_free_port() {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr("127.0.0.1");
        sa.sin_port = 0;
        if (bind(fd, (sockaddr*)&sa, sizeof(sa)) < 0) { close(fd); return -1; }
        socklen_t len = sizeof(sa);
        getsockname(fd, (sockaddr*)&sa, &len);
        int p = ntohs(sa.sin_port);
        close(fd);
        return p;
    }
    bool try_bind(int p) {
        if (srv_fd >= 0) { close(srv_fd); srv_fd = -1; }
        srv_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (srv_fd < 0) return false;
        int yes = 1;
        setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr("127.0.0.1");
        sa.sin_port = htons((uint16_t)p);
        if (bind(srv_fd, (sockaddr*)&sa, sizeof(sa)) < 0) {
            close(srv_fd); srv_fd = -1; return false;
        }
        port = p;
        return true;
    }

    bool build_connect_redirect_so(int target_port) {
        // Write interceptor C source to a temp file.
        char src_tmp[128];
        snprintf(src_tmp, sizeof(src_tmp), "/tmp/bambu_cr_%d_%d.c", (int)getpid(), target_port);
        char so_tmp[128];
        snprintf(so_tmp, sizeof(so_tmp), "/tmp/bambu_cr_%d_%d.so", (int)getpid(), target_port);

        const char* src =
            "#define _GNU_SOURCE\n"
            "#include <sys/socket.h>\n"
            "#include <netinet/in.h>\n"
            "#include <dlfcn.h>\n"
            "#include <string.h>\n"
            "#include <stdlib.h>\n"
            "#include <arpa/inet.h>\n"
            "/* Redirect connect() to 127.0.0.1:8883 → FAKE_PRINTER_PORT */\n"
            "static int (*real_connect)(int, const struct sockaddr*, socklen_t) = NULL;\n"
            "int connect(int fd, const struct sockaddr* addr, socklen_t len) {\n"
            "    if (!real_connect)\n"
            "        real_connect = (int(*)(int,const struct sockaddr*,socklen_t))dlsym(RTLD_NEXT, \"connect\");\n"
            "    if (addr && addr->sa_family == AF_INET) {\n"
            "        const struct sockaddr_in* sin = (const struct sockaddr_in*)addr;\n"
            "        if (ntohl(sin->sin_addr.s_addr) == 0x7f000001 && ntohs(sin->sin_port) == 8883) {\n"
            "            const char* redir = getenv(\"FAKE_PRINTER_PORT\");\n"
            "            if (redir && redir[0]) {\n"
            "                struct sockaddr_in sa2;\n"
            "                memcpy(&sa2, sin, sizeof(sa2));\n"
            "                sa2.sin_port = htons((unsigned short)atoi(redir));\n"
            "                return real_connect(fd, (const struct sockaddr*)&sa2, len);\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "    return real_connect(fd, addr, len);\n"
            "}\n"
            "/* Disable TLS peer cert verification so our self-signed broker cert\n"
            "   is accepted. The real Bambu printer cert is signed by Bambu's CA;\n"
            "   the plugin would otherwise reject our ephemeral self-signed cert. */\n"
            "#include <openssl/ssl.h>\n"
            "void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb cb) {\n"
            "    typedef void (*fn_t)(SSL_CTX*, int, SSL_verify_cb);\n"
            "    fn_t real = (fn_t)dlsym(RTLD_NEXT, \"SSL_CTX_set_verify\");\n"
            "    if (real) real(ctx, SSL_VERIFY_NONE, NULL);\n"
            "}\n"
            "void SSL_set_verify(SSL *ssl, int mode, SSL_verify_cb cb) {\n"
            "    typedef void (*fn_t)(SSL*, int, SSL_verify_cb);\n"
            "    fn_t real = (fn_t)dlsym(RTLD_NEXT, \"SSL_set_verify\");\n"
            "    if (real) real(ssl, SSL_VERIFY_NONE, NULL);\n"
            "}\n";

        FILE* f = fopen(src_tmp, "w");
        if (!f) return false;
        fputs(src, f);
        fclose(f);

        // Clear LD_PRELOAD so the shell spawned by popen() doesn't load our
        // watchdog shim (which prints a noisy init message to stderr).
        const char* saved_preload = getenv("LD_PRELOAD");
        std::string saved_preload_str = saved_preload ? saved_preload : "";
        if (!saved_preload_str.empty()) unsetenv("LD_PRELOAD");

        char cmd[512];
        snprintf(cmd, sizeof(cmd),
            "gcc -shared -fPIC -O2 -nostartfiles -o %s %s -ldl -lssl 2>&1",
            so_tmp, src_tmp);
        FILE* p2 = popen(cmd, "r");
        if (!saved_preload_str.empty()) setenv("LD_PRELOAD", saved_preload_str.c_str(), 1);
        if (!p2) { unlink(src_tmp); return false; }
        char line[256];
        bool any_output = false;
        while (fgets(line, sizeof(line), p2)) {
            std::fprintf(stderr, "[fake-printer] gcc: %s", line);
            any_output = true;
        }
        int rc = pclose(p2);
        if (rc != 0) {
            unlink(src_tmp);
            return false;
        }

        connect_redirect_so_path = so_tmp;
        connect_redirect_c_path  = src_tmp;
        (void)any_output;
        return true;
    }

private:
    // Generate ephemeral RSA-2048 key + self-signed cert; store PEM.
    bool gen_ctx() {
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) return false;

        // Generate RSA-2048 key.
        EVP_PKEY* pkey = EVP_RSA_gen(2048);
        if (!pkey) return false;

        // Build a minimal self-signed X.509 cert.
        X509* cert = X509_new();
        if (!cert) { EVP_PKEY_free(pkey); return false; }
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 3600);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char*)"bambu-fake-printer", -1, -1, 0);
        X509_set_issuer_name(cert, name);
        X509_sign(cert, pkey, EVP_sha256());

        // Export printer_cert_pem (what we'll send in cert_report).
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(bio, cert);
        char* data = nullptr;
        long data_len = BIO_get_mem_data(bio, &data);
        printer_cert_pem = std::string(data, (size_t)data_len);
        BIO_free(bio);

        // Load into SSL_CTX.
        if (SSL_CTX_use_certificate(ctx, cert) != 1 ||
            SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
            X509_free(cert); EVP_PKEY_free(pkey); return false;
        }
        // Disable server cert verification (we're the server, no client cert needed).
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return true;
    }

    // MQTT fixed header: first byte = (type<<4)|flags, then remaining_length.
    static std::vector<uint8_t> encode_remaining(uint32_t n) {
        std::vector<uint8_t> out;
        do {
            uint8_t b = n & 0x7f; n >>= 7;
            out.push_back(n ? (b | 0x80) : b);
        } while (n);
        return out;
    }
    static bool ssl_write_all(SSL* ssl, const void* buf, size_t n) {
        size_t off = 0;
        while (off < n) {
            int w = SSL_write(ssl, (const char*)buf + off, (int)(n - off));
            if (w <= 0) return false;
            off += (size_t)w;
        }
        return true;
    }
    static bool ssl_read_exact(SSL* ssl, void* buf, size_t n) {
        size_t off = 0;
        while (off < n) {
            int r = SSL_read(ssl, (char*)buf + off, (int)(n - off));
            if (r <= 0) return false;
            off += (size_t)r;
        }
        return true;
    }
    // Read one MQTT packet; returns type byte (high nibble) and body, or 0 on error.
    static uint8_t read_packet(SSL* ssl, std::vector<uint8_t>& body) {
        uint8_t hdr;
        if (!ssl_read_exact(ssl, &hdr, 1)) return 0;
        uint32_t rem = 0; int shift = 0;
        for (int i = 0; i < 4; i++) {
            uint8_t b;
            if (!ssl_read_exact(ssl, &b, 1)) return 0;
            rem |= (uint32_t)(b & 0x7f) << shift;
            shift += 7;
            if (!(b & 0x80)) break;
        }
        body.resize(rem);
        if (rem > 0 && !ssl_read_exact(ssl, body.data(), rem)) return 0;
        return hdr;
    }
    // Build PUBLISH packet and send.
    bool mqtt_publish(SSL* ssl, const std::string& topic, const std::string& payload) {
        uint16_t tlen = (uint16_t)topic.size();
        uint32_t rem = 2 + tlen + payload.size();  // QoS 0 — no packet id
        std::vector<uint8_t> pkt;
        pkt.push_back(0x30);  // PUBLISH, QoS 0
        for (uint8_t b : encode_remaining(rem)) pkt.push_back(b);
        pkt.push_back((uint8_t)(tlen >> 8));
        pkt.push_back((uint8_t)(tlen & 0xff));
        for (char c : topic) pkt.push_back((uint8_t)c);
        for (char c : payload) pkt.push_back((uint8_t)c);
        return ssl_write_all(ssl, pkt.data(), pkt.size());
    }

    void handle_client(SSL* ssl) {
        std::string security_topic = "device/" + dev_id + "/security";
        bool conn_sent = false;
        while (true) {
            std::vector<uint8_t> body;
            uint8_t hdr = read_packet(ssl, body);
            if (!hdr) break;
            uint8_t type = hdr >> 4;
            if (type == 1) {  // CONNECT
                uint8_t connack[4] = {0x20, 0x02, 0x00, 0x00};
                ssl_write_all(ssl, connack, 4);
                conn_sent = true;
                std::fprintf(stderr, "[fake-printer] MQTT CONNECT accepted\n");
                std::fflush(stderr);
            } else if (type == 8 && conn_sent) {  // SUBSCRIBE
                if (body.size() >= 2) {
                    uint16_t pid = ((uint16_t)body[0] << 8) | body[1];
                    uint8_t suback[5] = {0x90, 0x03,
                        (uint8_t)(pid >> 8), (uint8_t)(pid & 0xff), 0x00};
                    ssl_write_all(ssl, suback, 5);
                }
            } else if (type == 3 && conn_sent) {  // PUBLISH from daemon
                // Parse topic from body.
                if (body.size() < 2) continue;
                uint16_t tlen = ((uint16_t)body[0] << 8) | body[1];
                if (2 + tlen > body.size()) continue;
                std::string topic(body.begin() + 2, body.begin() + 2 + tlen);
                if (topic == security_topic && !cert_sent) {
                    // Daemon sent app_cert_install — reply with cert_report.
                    std::string pem_escaped = printer_cert_pem;
                    // Replace newlines with \n for JSON embedding.
                    std::string pem_json;
                    pem_json.reserve(pem_escaped.size() + 64);
                    for (char c : pem_escaped) {
                        if (c == '\n') { pem_json += "\\n"; }
                        else if (c == '"') { pem_json += "\\\""; }
                        else { pem_json += c; }
                    }
                    std::string cr_payload =
                        "{\"cert_report\":{\"command\":\"cert_report\","
                        "\"dev_id\":\"" + dev_id + "\","
                        "\"printer_cert\":\"" + pem_json + "\"}}";
                    if (mqtt_publish(ssl, security_topic, cr_payload)) {
                        std::fprintf(stderr,
                            "[fake-printer] cert_report injected (%zu bytes)\n",
                            cr_payload.size());
                        std::fflush(stderr);
                        cert_sent = true;
                        std::lock_guard<std::mutex> lk(mu);
                        cv.notify_all();
                    }
                }
                // PUBACK for QoS 1 publishes.
                if ((hdr & 0x06) == 0x02 && body.size() >= (size_t)(2 + tlen + 2)) {
                    uint16_t pid = ((uint16_t)body[2+tlen] << 8) | body[3+tlen];
                    uint8_t puback[4] = {0x40, 0x02,
                        (uint8_t)(pid >> 8), (uint8_t)(pid & 0xff)};
                    ssl_write_all(ssl, puback, 4);
                }
            } else if (type == 12) {  // PINGREQ
                uint8_t pingresp[2] = {0xd0, 0x00};
                ssl_write_all(ssl, pingresp, 2);
            } else if (type == 14) {  // DISCONNECT
                break;
            }
        }
    }

    void accept_loop() {
        {
            std::lock_guard<std::mutex> lk(mu);
            ready = true;
        }
        cv.notify_all();
        while (srv_fd >= 0) {
            struct sockaddr_in peer{};
            socklen_t plen = sizeof(peer);
            int fd = accept(srv_fd, (sockaddr*)&peer, &plen);
            if (fd < 0) break;
            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, fd);
            if (SSL_accept(ssl) == 1) {
                std::fprintf(stderr, "[fake-printer] TLS accepted from %s\n",
                             inet_ntoa(peer.sin_addr));
                std::fflush(stderr);
                handle_client(ssl);
            } else {
                unsigned long e = ERR_get_error();
                char ebuf[256];
                ERR_error_string_n(e, ebuf, sizeof(ebuf));
                std::fprintf(stderr, "[fake-printer] TLS handshake failed: %s\n", ebuf);
                std::fflush(stderr);
            }
            SSL_free(ssl);
            close(fd);
        }
    }
};

// Wait up to timeout_ms for the fake broker to inject cert_report.
static bool fake_broker_wait_cert(FakePrinterBroker& b, int timeout_ms) {
    std::unique_lock<std::mutex> lk(b.mu);
    return b.cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                         [&b]{ return b.cert_sent; });
}

struct SsdpPrinter { std::string dev_id, lan_ip; };

// Listen on UDP 2021 for Bambu SSDP NOTIFY broadcasts (printers send these
// every ~30s). Returns all printers heard within timeout_ms milliseconds.
// Filters out bridge-virtual entries (USN starts with "FFFF" or has
// Bambu-Mqtt-Port header indicating a non-standard port).
static std::vector<SsdpPrinter> probe_printers_via_ssdp(int timeout_ms = 2500) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return {};
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
    struct sockaddr_in bind_addr{};
    bind_addr.sin_family      = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port        = htons(2021);
    if (bind(sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0) {
        close(sock);
        return {};
    }

    std::map<std::string, SsdpPrinter> seen;  // dev_id -> entry, dedup
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) break;
        int ms_left = (int)std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        struct timeval tv{ ms_left / 1000, (ms_left % 1000) * 1000 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        char buf[4096];
        struct sockaddr_in src{};
        socklen_t slen = sizeof(src);
        ssize_t n = recvfrom(sock, buf, sizeof(buf) - 1, 0,
                             reinterpret_cast<sockaddr*>(&src), &slen);
        if (n <= 0) break;
        buf[n] = '\0';

        // Only process Bambu SSDP NOTIFY packets.
        if (!std::strstr(buf, "bambulab-com:device")) continue;
        if (!std::strstr(buf, "NOTIFY")) continue;

        // Extract USN (dev_id).
        const char* usn_p = std::strstr(buf, "\nUSN:");
        if (!usn_p) usn_p = std::strstr(buf, "\nUsn:");
        if (!usn_p) continue;
        usn_p += 5;
        while (*usn_p == ' ' || *usn_p == '\t') usn_p++;
        const char* usn_end = usn_p;
        while (*usn_end && *usn_end != '\r' && *usn_end != '\n') usn_end++;
        std::string dev_id(usn_p, usn_end - usn_p);
        if (dev_id.empty()) continue;

        // Skip bridge-virtual entries: real Bambu serials never start with FFFF.
        if (dev_id.size() >= 4 && dev_id.substr(0, 4) == "FFFF") continue;
        // Skip if Bambu-Mqtt-Port is present (bridge proxies use custom ports).
        if (std::strstr(buf, "Bambu-Mqtt-Port:")) continue;

        // Source IP is the printer's LAN address.
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src.sin_addr, ip_str, sizeof(ip_str));

        if (seen.find(dev_id) == seen.end())
            seen[dev_id] = {dev_id, ip_str};
    }
    close(sock);

    std::vector<SsdpPrinter> result;
    for (auto& kv : seen) result.push_back(kv.second);
    return result;
}

// Write embedded cert to tmpdir so the daemon can find it.
static std::string write_cert_tmpdir(pid_t pid) {
    char dir[128];
    snprintf(dir, sizeof(dir), "/tmp/bambu_extract_d_%d", (int)pid);
    if (mkdir(dir, 0700) < 0 && errno != EEXIST) {
        std::fprintf(stderr, "mkdir(%s): %s\n", dir, strerror(errno));
        return {};
    }
    char cert_path[256];
    snprintf(cert_path, sizeof(cert_path), "%s/slicer_base64.cer", dir);
    int fd = open(cert_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        std::fprintf(stderr, "open(%s): %s\n", cert_path, strerror(errno));
        return {};
    }
    size_t total = 0;
    while (total < slicer_base64_cer_len) {
        ssize_t n = write(fd,
            (const char*)slicer_base64_cer + total,
            slicer_base64_cer_len - total);
        if (n <= 0) { close(fd); return {}; }
        total += (size_t)n;
    }
    close(fd);
    return std::string(dir);
}

// Write daemon binary to a memfd so we can execve it without hitting the
// noexec filesystem. Returns the fd path "/proc/self/fd/<n>".
static std::string write_daemon_memfd() {
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
    // Do NOT close fd — we keep it open so the path remains valid.
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    return std::string(path);
}

// Set up the H2S home directory structure that bambu-bridge-daemon needs.
// Mirrors what gate_min_gcodecmd.sh does:
//   - Copy BambuStudio.conf + BambuNetworkEngine.conf from the base config
//   - Symlink plugins/ and system/ to the base config dirs
//   - Copy user/ printers/ ota/ directories
// Returns "" on failure.
static std::string setup_h2s_home(const std::string& dev_id) {
    const char* home_env = std::getenv("HOME");
    std::string bsl_config = (home_env && home_env[0])
        ? std::string(home_env) + "/.config/BambuStudio"
        : std::string("/root/.config/BambuStudio");
    const char* base_src = bsl_config.c_str();
    // Try the known H2S home first (may already be set up).
    std::string h2s_home = "/tmp/bridge-mp/home-H2S";
    std::string cfg = h2s_home + "/.config/BambuStudio";

    // Check if already valid.
    struct stat st{};
    if (stat((cfg + "/BambuStudio.conf").c_str(), &st) == 0 &&
        stat((cfg + "/plugins").c_str(), &st) == 0) {
        LOG_I("H2S home already set up: %s", h2s_home.c_str());
        return h2s_home;
    }

    // Create dirs.
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

    // Copy config files.
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
        // BambuStudio not installed — write a minimal synthetic conf.
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

    // Patch user_last_selected_machine to our dev_id.
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

            // Find and replace user_last_selected_machine value.
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

    // Symlink plugins and system — fall back to synthetic plugin dir if BSL not installed.
    {
        std::string src_plugins = std::string(base_src) + "/plugins";
        struct stat pst{};
        if (stat(src_plugins.c_str(), &pst) == 0) {
            symlink(src_plugins.c_str(), (cfg + "/plugins").c_str());
        } else {
            // BambuStudio not installed: create a plugins/ dir and symlink just
            // the plugin .so into it so the daemon can dlopen it.
            mkdir((cfg + "/plugins").c_str(), 0755);
            if (!g_plugin_path_for_home.empty()) {
                // Symlink the .so by its basename into plugins/.
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

    // Copy user/printers/ota dirs if present.
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
    // user/ has subdirs — just touch the top level for now.
    mkdirp(cfg + "/user");

    // Copy bridge certs if available.
    {
        std::string src_c = "/tmp/ee-bridge-home/.config/BambuStudio/bridge/certs/" + dev_id + ".crt";
        std::string src_k = "/tmp/ee-bridge-home/.config/BambuStudio/bridge/certs/" + dev_id + ".key";
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

// Find all bambu-studio / bambustu_main processes that have an established
// connection to printer_ip:8883 and kill them. Also touch the stop-marker
// so the supervisor doesn't immediately restart them.
// Returns the list of PIDs killed, for later restart notification.
// The supervisor is told to restart via restore_h2s_supervisor() at the end.
static std::vector<pid_t> stop_h2s_bridge(const std::string& dev_id,
                                          const std::string& printer_ip) {
    std::vector<pid_t> killed;

    // Touch stop marker so supervisor won't respawn.
    std::string stop_marker = "/tmp/bridge-mp/stop-markers/H2S";
    // Create the dir if it doesn't exist.
    mkdir("/tmp/bridge-mp/stop-markers", 0755);
    // Touch the marker.
    int f = open(stop_marker.c_str(), O_CREAT | O_WRONLY, 0644);
    if (f >= 0) close(f);
    LOG_I("stop marker set: %s", stop_marker.c_str());

    // Kill by local port 8884 (the H2S bridge's local MQTT broker).
    // This is the primary kill path — matches the gate script's approach
    // (kills the broker process which is the same process that holds the
    // printer's LAN MQTT session). Use SIGTERM first, then SIGKILL.
    {
        const char* port_cmd = "ss -tlnp 2>/dev/null | grep ':8884 ' | "
                               "grep -oP 'pid=\\K[0-9]+' | sort -u";
        FILE* p = popen(port_cmd, "r");
        if (p) {
            int pid_val;
            while (fscanf(p, "%d", &pid_val) == 1) {
                pid_t victim = (pid_t)pid_val;
                bool already = false;
                for (pid_t k : killed) if (k == victim) { already = true; break; }
                if (!already) {
                    LOG_I("killing bridge PID %d (holds port 8884)", (int)victim);
                    // Kill whole process group like the gate script.
                    int pgid = getpgid(victim);
                    if (pgid > 0 && pgid != getpgrp()) {
                        kill(-pgid, SIGTERM);
                    }
                    kill(victim, SIGTERM);
                    killed.push_back(victim);
                }
            }
            pclose(p);
        }
    }

    // Find PIDs connected to printer_ip:8883 (ESTABLISHED).
    // Secondary kill path: catches any process with a LAN MQTT session.
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd),
                 "ss -tnp 2>/dev/null | grep ESTAB | grep '%s:8883' | "
                 "grep -oP 'pid=\\K[0-9]+' | sort -u", printer_ip.c_str());
        FILE* p = popen(cmd, "r");
        if (p) {
            int pid_val;
            while (fscanf(p, "%d", &pid_val) == 1) {
                pid_t victim = (pid_t)pid_val;
                bool already = false;
                for (pid_t k : killed) if (k == victim) { already = true; break; }
                if (!already) {
                    LOG_I("killing bridge PID %d (has ESTAB to %s:8883)",
                          (int)victim, printer_ip.c_str());
                    kill(victim, SIGTERM);
                    killed.push_back(victim);
                }
            }
            pclose(p);
        }
    }

    // Also find bambu-studio / bambustu_main that target our dev_id (via env).
    {
    DIR* proc_dir = opendir("/proc");
    if (proc_dir) {
    struct dirent* ent;
    while ((ent = readdir(proc_dir)) != nullptr) {
        if (!isdigit(ent->d_name[0])) continue;
        pid_t pid = (pid_t)atoi(ent->d_name);
        // Check if it targets our dev_id.
        char env_path[64];
        snprintf(env_path, sizeof(env_path), "/proc/%d/environ", pid);
        FILE* ef = fopen(env_path, "r");
        if (!ef) continue;
        char env_buf[4096];
        size_t env_sz = fread(env_buf, 1, sizeof(env_buf) - 1, ef);
        fclose(ef);
        env_buf[env_sz] = '\0';
        // Check for BAMBU_BRIDGE_TARGET_DEV=dev_id.
        bool targets_dev = false;
        std::string needle = "BAMBU_BRIDGE_TARGET_DEV=" + dev_id;
        // Find null-separated env.
        const char* p = env_buf;
        while (p < env_buf + env_sz) {
            if (needle == std::string(p)) { targets_dev = true; break; }
            p += strlen(p) + 1;
        }
        if (!targets_dev) continue;
        // Kill if not already killed.
        bool already = false;
        for (pid_t k : killed) if (k == pid) { already = true; break; }
        if (!already) {
            LOG_I("killing bridge PID %d (BAMBU_BRIDGE_TARGET_DEV=%s)",
                  (int)pid, dev_id.c_str());
            kill(pid, SIGTERM);
            killed.push_back(pid);
        }
    }
    closedir(proc_dir);
    } // if proc_dir
    } // block

    // Kill any orphaned bambu-bridge-daemon processes (from prior failed runs).
    // These are identified by having "memfd:bambu_daemon" or "bambu-bridge-daemon"
    // in their /proc/pid/exe or cmdline, AND targeting dev_id (from env or cmdline).
    {
        DIR* proc_dir = opendir("/proc");
        if (proc_dir) {
            struct dirent* ent;
            while ((ent = readdir(proc_dir)) != nullptr) {
                if (!isdigit(ent->d_name[0])) continue;
                pid_t pid = (pid_t)atoi(ent->d_name);
                if (pid == getpid()) continue;  // skip ourselves
                // Check cmdline for our dev_id + access_code.
                char cmdline_path[64];
                snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
                FILE* cf = fopen(cmdline_path, "r");
                if (!cf) continue;
                char cbuf[2048];
                size_t csz = fread(cbuf, 1, sizeof(cbuf) - 1, cf);
                fclose(cf);
                cbuf[csz] = '\0';
                for (size_t i = 0; i < csz; i++) if (cbuf[i] == '\0') cbuf[i] = ' ';
                // Look for our dev_id in cmdline (daemon was launched with --dev-id <devid>).
                if (strstr(cbuf, dev_id.c_str()) == nullptr) continue;
                // Also look for access_code to distinguish from legitimate H2S bridge.
                // Actually, check if it has bambu_daemon or bridge-daemon indicators.
                bool is_daemon = false;
                char exe_path[64], link_buf[256];
                snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
                ssize_t ln = readlink(exe_path, link_buf, sizeof(link_buf) - 1);
                if (ln > 0) {
                    link_buf[ln] = '\0';
                    if (strstr(link_buf, "memfd:bambu_daemon") ||
                        strstr(link_buf, "bambu-bridge-daemon")) {
                        is_daemon = true;
                    }
                }
                if (!is_daemon) continue;
                bool already = false;
                for (pid_t k : killed) if (k == pid) { already = true; break; }
                if (!already) {
                    LOG_I("killing orphaned daemon PID %d (dev_id=%s)", (int)pid, dev_id.c_str());
                    kill(pid, SIGKILL);
                    killed.push_back(pid);
                }
            }
            closedir(proc_dir);
        }
    }

    // Also kill H2S supervisor bash scripts (they keep spawning new children).
    // Supervisors have "stop-markers/H2S" in their cmdline or "H2S" in argv.
    {
        DIR* proc_dir = opendir("/proc");
        if (proc_dir) {
            struct dirent* ent;
            while ((ent = readdir(proc_dir)) != nullptr) {
                if (!isdigit(ent->d_name[0])) continue;
                pid_t pid = (pid_t)atoi(ent->d_name);
                char cmdline_path[64];
                snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
                FILE* cf = fopen(cmdline_path, "r");
                if (!cf) continue;
                char cbuf[2048];
                size_t csz = fread(cbuf, 1, sizeof(cbuf) - 1, cf);
                fclose(cf);
                cbuf[csz] = '\0';
                // Replace NUL with space for grep.
                for (size_t i = 0; i < csz; i++) if (cbuf[i] == '\0') cbuf[i] = ' ';
                // Look for "stop-markers/H2S" or "H2S" supervisor markers.
                if (strstr(cbuf, "stop-markers/H2S") != nullptr ||
                    (strstr(cbuf, "H2S") != nullptr && strstr(cbuf, "supervisor") != nullptr)) {
                    bool already = false;
                    for (pid_t k : killed) if (k == pid) { already = true; break; }
                    if (!already) {
                        LOG_I("killing H2S supervisor PID %d", (int)pid);
                        kill(pid, SIGTERM);
                        killed.push_back(pid);
                    }
                }
            }
            closedir(proc_dir);
        }
    }

    // Wait for known killed PIDs to exit (up to 10s).
    {
        double deadline = now_s() + 10.0;
        while (now_s() < deadline) {
            bool all_gone = true;
            for (pid_t k : killed) {
                if (kill(k, 0) == 0) { all_gone = false; break; }
            }
            if (all_gone) break;
            usleep(200 * 1000);
        }
        // Force-kill any still alive.
        for (pid_t k : killed) {
            if (kill(k, 0) == 0) {
                LOG_W("force-killing PID %d", (int)k);
                kill(k, SIGKILL);
            }
        }
    }

    // Aggressively clear ALL remaining processes with ESTAB to printer OR
    // holding port 8884. Loop until both are clear, OR 60s timeout.
    // This handles supervisor respawns, orphaned daemons, driver_child procs.
    {
        double clear_deadline = now_s() + 60.0;
        int clear_iter = 0;
        while (now_s() < clear_deadline) {
            bool any_found = false;

            // Kill any holder of port 8884.
            {
                const char* cmd = "ss -tlnp 2>/dev/null | grep ':8884 ' | "
                                  "grep -oP 'pid=\\K[0-9]+' | sort -u";
                FILE* p = popen(cmd, "r");
                if (p) {
                    int pid_val;
                    while (fscanf(p, "%d", &pid_val) == 1) {
                        pid_t victim = (pid_t)pid_val;
                        bool already = false;
                        for (pid_t k : killed) if (k == victim) { already = true; break; }
                        if (!already) {
                            LOG_I("clearing port-8884 holder PID %d (iter %d)",
                                  (int)victim, clear_iter);
                            kill(victim, SIGKILL);
                            killed.push_back(victim);
                        }
                        any_found = true;
                    }
                    pclose(p);
                }
            }

            // Kill any ESTAB to printer_ip:8883.
            {
                char cmd[256];
                snprintf(cmd, sizeof(cmd),
                         "ss -tnp 2>/dev/null | grep ESTAB | grep '%s:8883' | "
                         "grep -oP 'pid=\\K[0-9]+' | sort -u", printer_ip.c_str());
                FILE* p = popen(cmd, "r");
                if (p) {
                    int pid_val;
                    while (fscanf(p, "%d", &pid_val) == 1) {
                        pid_t victim = (pid_t)pid_val;
                        bool already = false;
                        for (pid_t k : killed) if (k == victim) { already = true; break; }
                        if (!already) {
                            LOG_I("clearing residual PID %d (ESTAB to %s:8883, iter %d)",
                                  (int)victim, printer_ip.c_str(), clear_iter);
                            kill(victim, SIGKILL);
                            killed.push_back(victim);
                        }
                        any_found = true;
                    }
                    pclose(p);
                }
            }

            if (!any_found) break;
            clear_iter++;
            usleep(2 * 1000 * 1000);
        }
        if (clear_iter > 0)
            LOG_I("cleared residual H2S processes in %d iterations", clear_iter);
    }

    // Wait for port 8884 to stop being listened on.
    // This is critical: if a killed daemon still has the port in TIME_WAIT,
    // our new daemon will fail to bind 8884 and fall back to cloud routing.
    // Gate script waits up to 60s for port 8884 to free.
    {
        double port_deadline = now_s() + 30.0;
        while (now_s() < port_deadline) {
            FILE* p = popen("ss -tlnp 2>/dev/null | grep ':8884 '", "r");
            bool port_busy = false;
            if (p) {
                char buf[256];
                if (fgets(buf, sizeof(buf), p)) port_busy = true;
                pclose(p);
            }
            if (!port_busy) {
                LOG_I("port 8884 is free");
                break;
            }
            LOG_I("waiting for port 8884 to free...");
            usleep(2 * 1000 * 1000);
        }
    }
    // Brief additional wait for TCP sessions to drain (TIME_WAIT/FIN_WAIT).
    usleep(2 * 1000 * 1000);
    LOG_I("H2S bridge stopped (%zu processes)", killed.size());
    return killed;
}

static void restore_h2s_supervisor() {
    // Remove stop marker so supervisor will restart on next bridge-multiproc.sh start.
    unlink("/tmp/bridge-mp/stop-markers/H2S");
    LOG_I("H2S stop marker removed — supervisor can restart bridge");
    // Optionally restart the supervisor.
    const char* supervisor = "/mnt/cephfs/ssd/BambuBridge/bridge-multiproc.sh";
    struct stat st{};
    if (stat(supervisor, &st) == 0) {
        // Fork and exec the supervisor start command.
        pid_t p = fork();
        if (p == 0) {
            // Redirect to /dev/null.
            int fd = open("/dev/null", O_WRONLY);
            if (fd >= 0) { dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO); close(fd); }
            execlp("bash", "bash", supervisor, "start", nullptr);
            _exit(1);
        }
        if (p > 0) {
            // Don't wait — let it run in background.
            LOG_I("H2S bridge supervisor restart initiated (pid=%d)", (int)p);
        }
    }
}

// Launch bambu-bridge-daemon and return its PID.
// The daemon will:
//   - dlopen the plugin from the H2S home's plugins/ symlink
//   - connect to the real printer via TLS (mTLS cert from env)
//   - drive signing every BAMBU_BRIDGE_RESIGN_MS ms
// Returns child PID or -1 on failure.
static pid_t launch_daemon(const std::string& daemon_exe,
                           const std::string& h2s_home,
                           const std::string& plugin_path,
                           const std::string& dev_id,
                           const std::string& access_code,
                           const std::string& lan_ip,
                           const std::string& cert_dir,
                           const std::string& mtls_cert,
                           const std::string& mtls_key,
                           const std::string& log_path) {
    std::string config_dir = h2s_home + "/.config/BambuStudio";

    // Double-fork: the daemon is a GRANDCHILD re-parented to init/systemd.
    // This makes the binary a NON-PARENT ptracer (identical to the gate's
    // extract_d_fast --attach-pid mode). Parent-ptrace vs non-parent-ptrace
    // differ in how ptrace stop events interact with SIGCHLD; non-parent
    // is the proven code path and mirrors extract_d_fast --attach-pid exactly.
    int pipefds[2];
    if (pipe2(pipefds, O_CLOEXEC) < 0) {
        LOG_E("pipe2: %s", strerror(errno));
        return -1;
    }

    // notif_pipe: daemon constructor (LD_PRELOAD) writes seccomp notif_fd
    // back to us after install_openat_usernotif_seccomp() completes.
    // Write end (notif_pipe[1]) must NOT have O_CLOEXEC so it survives execve.
    int notif_pipe[2] = {-1, -1};
    if (pipe2(notif_pipe, O_CLOEXEC) < 0) {
        LOG_E("pipe2 notif: %s", strerror(errno));
        close(pipefds[0]); close(pipefds[1]);
        return -1;
    }
    // Clear O_CLOEXEC on write end so it survives execve in daemon grandchild.
    if (fcntl(notif_pipe[1], F_SETFD, 0) < 0) {
        LOG_E("fcntl notif_pipe[1] clear CLOEXEC: %s", strerror(errno));
        // Non-fatal — just won't have openat supervisor.
    }

    pid_t intermediate = fork();
    if (intermediate < 0) {
        LOG_E("fork intermediate: %s", strerror(errno));
        close(pipefds[0]); close(pipefds[1]);
        close(notif_pipe[0]); close(notif_pipe[1]);
        return -1;
    }
    if (intermediate != 0) {
        // Grandparent (binary): wait for intermediate to exit, read daemon pid.
        close(pipefds[1]);
        // Close write end of notif pipe in grandparent (only daemon writes to it).
        close(notif_pipe[1]);
        waitpid(intermediate, nullptr, 0);
        pid_t daemon_pid = -1;
        read(pipefds[0], &daemon_pid, sizeof(daemon_pid));
        close(pipefds[0]);
        // Save the read end for the notif_fd read in the call site.
        g_openat_notif_pipe_rd = notif_pipe[0];
        return daemon_pid;
    }

    // Intermediate: fork the real daemon and exit immediately so the daemon
    // is orphaned (re-parented to init/systemd, NOT to the binary).
    close(pipefds[0]);
    // Close read end of notif pipe in intermediate (only grandchild uses write).
    close(notif_pipe[0]);
    pid_t daemon_pid = fork();
    if (daemon_pid != 0) {
        // Intermediate exits: writes daemon pid and exits.
        // Also close notif_pipe[1] in intermediate (daemon grandchild keeps it).
        close(notif_pipe[1]);
        write(pipefds[1], &daemon_pid, sizeof(daemon_pid));
        close(pipefds[1]);
        _exit(0);
    }
    close(pipefds[1]);
    // Daemon grandchild: new session so it doesn't inherit the binary's
    // controlling terminal and signal mask.
    setsid();

    // Grandchild: set up environment and exec the daemon.
    // Mirror the gate script (fitness_daemon_gcodecmd.sh) environment exactly.

    // HOME must be the H2S config home (contains BambuStudio.conf, user/, etc.)
    setenv("HOME", h2s_home.c_str(), 1);

    // Display env — some Qt/xcb internals in the plugin reference DISPLAY even
    // without drawing; setting the same value the gate uses avoids crash paths.
    setenv("DISPLAY",    ":100", 1);
    setenv("XAUTHORITY", "/tmp/xvfb-bridge.auth", 1);
    setenv("LC_ALL",     "C", 1);

    // LD_LIBRARY_PATH: plugin dir first, then daemon exe dir, then inherited.
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

    // LD_PRELOAD: connect_redirect.so (if port 8883 busy) + allow_ptrace.so + watchdog_defeat_v2.so.
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
    // WD_V2_FAKE_TRACEME=1: intercepts libc ptrace(PTRACE_TRACEME) wrapper
    // and returns 0 (fake success) so VMP concludes it is NOT being traced.
    // This handles the case where VMP calls ptrace() via the libc wrapper.
    setenv("WD_V2_FAKE_TRACEME",  "1", 1);
    // WD_V2_PTRACE_TRACEME_SECCOMP=1: installs a targeted BPF seccomp filter
    // that ONLY intercepts raw syscall(SYS_ptrace, PTRACE_TRACEME, ...) and
    // returns 0 via SIGSYS handler.  This handles the case where VMP calls
    // ptrace(PTRACE_TRACEME) via a raw `syscall` instruction (bypassing libc),
    // which would otherwise be invisible to the libc wrapper interception above.
    // Unlike WD_V2_SECCOMP (which traps openat and breaks dlopen), this filter
    // ONLY traps ptrace/PTRACE_TRACEME and allows all other syscalls through.
    setenv("WD_V2_PTRACE_TRACEME_SECCOMP", "1", 1);
    // WD_V2_OPENAT_SELFEXEMPT=1: arms a SIGUSR2 handler in the daemon.
    // When the extractor sends SIGUSR2 (after libbambu is loaded and just
    // before PTRACE_SEIZE), the daemon installs an openat SIGSYS filter
    // that is IP-exempt for calls from within the shim itself.  This:
    //   - Traps raw openat from VMP bytecode (libbambu region) → SIGSYS
    //   - Allows openat from within our shim's own handler (no recursion)
    //   - Allows all openat from ld.so/glibc during dlopen (installed late)
    // The filter is installed POST-dlopen so it never affects dynamic linking.
    // NOT set when USE_SECCOMP_UNOTIFY: the USER_NOTIF supervisor already
    // intercepts all openat calls; stacking a SIGSYS filter on top would
    // override USER_NOTIF (TRAP > USER_NOTIF in seccomp priority) and hand
    // the plugin the real /proc/self/status with TracerPid ≠ 0.
#ifndef USE_SECCOMP_UNOTIFY
    setenv("WD_V2_OPENAT_SELFEXEMPT", "1", 1);
#endif
#ifdef USE_SECCOMP_UNOTIFY
    // Pass the write end of notif_pipe to the daemon shim so it can install
    // the USER_NOTIF openat filter and send us back the notif_fd.
    {
        char notif_pipe_str[32];
        snprintf(notif_pipe_str, sizeof(notif_pipe_str), "%d", notif_pipe[1]);
        setenv("WD_V2_OPENAT_NOTIF_PIPE", notif_pipe_str, 1);
    }
#endif
    // WD_V2_LOG: enable verbose logging to capture all ptrace/seccomp events
    {
        char logpath[256];
        snprintf(logpath, sizeof(logpath), "/tmp/wd_v2_daemon.log");
        setenv("WD_V2_LOG", logpath, 1);  // explicit path for easy reading
    }

    // mTLS certs for the real printer TLS connection.
    if (!mtls_cert.empty()) setenv("BBL_MTLS_CERT", mtls_cert.c_str(), 1);
    if (!mtls_key.empty())  setenv("BBL_MTLS_KEY",  mtls_key.c_str(),  1);

    // Cloud cert dir (also passed as --cloud-cert-dir CLI arg below).
    setenv("BAMBU_BRIDGE_CLOUD_CERT_DIR",  cert_dir.c_str(),       1);
    setenv("BAMBU_BRIDGE_CLOUD_CERT_FILE", "slicer_base64.cer",    1);

    // RESIGN_MS pulse: repeatedly calls set_user_selected_machine + install_device_cert.
    setenv("BAMBU_BRIDGE_RESIGN_MS", "3000", 1);
    // GCODE_CMD_MS pulse: publishes print.command=gcode_file via send_message_to_printer.
    // THIS is the signed path that fires the RSA modexp that DR0 captures.
    // Requires device_pub_key_map populated (cert_report received from printer via LAN).
    setenv("BAMBU_BRIDGE_GCODE_CMD_MS", "2000", 1);
    setenv("BAMBU_BRIDGE_TARGET_DEV", dev_id.c_str(), 1);

    // Redirect stdout+stderr to log file.
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

    // Allow ptrace from any process (matches allow_ptrace.so's prctl call,
    // which fires after exec via LD_PRELOAD, but we also set it here so it
    // applies even before the .so initializers run).
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    prctl(PR_SET_PTRACER, (unsigned long)PR_SET_PTRACER_ANY, 0, 0, 0);

    // Build argv. Use mqtt-port-base 8884 (same as gate) — 28900 was unused.
    const char* argv[] = {
        daemon_exe.c_str(),
        "--plugin",           plugin_path.c_str(),
        "--config-dir",       config_dir.c_str(),
        "--country-code",     "US",
        "--dev-id",           dev_id.c_str(),
        "--access-code",      access_code.c_str(),
        "--lan-ip",           lan_ip.c_str(),
        "--model",            "H2S",
        "--mqtt-port-base",   "8884",    // same as gate script
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

// Poll /proc/<pid>/maps until libbambu_networking.so appears. Returns
// the PID that has it loaded, or 0 on timeout.
// The daemon may fork internally; we watch daemon_pid and any child/grandchild.
// If the openat supervisor is running, it sets g_libbambu_seen_pid when it sees
// libbambu_networking.so being opened — we can return that PID immediately
// (even if the .so disappears from maps before our next poll).
static pid_t wait_for_libbambu(pid_t daemon_pid,
                                const std::string& plugin_path,
                                int timeout_s) {
    (void)plugin_path;  // use needle below
    const char* needle = "libbambu_networking";
    double deadline = now_s() + double(timeout_s);

    // Helper: check if a given pid has libbambu in maps.
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
        // Fast path: supervisor already saw libbambu_networking being opened.
        pid_t seen = g_libbambu_seen_pid.load(std::memory_order_acquire);
        if (seen > 0) {
            // Even if the .so was briefly mapped and unmapped (due to dlopen
            // exception), we return the PID so ptrace can attach.  The PID is
            // still valid (process parked by abort eater).
            LOG_I("openat supervisor saw libbambu opened by tgid=%d", (int)seen);
            return seen;
        }

        if (!use_supervisor) {
            // Slow path: scan /proc for any process in the daemon's process group
            // that has libbambu in maps.  Used only when the openat supervisor is
            // not running (e.g. older build without USER_NOTIF).

            // Check daemon_pid itself.
            if (pid_has_libbambu(daemon_pid)) return daemon_pid;

            // Check direct children of daemon_pid.
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
        usleep(20 * 1000);  // 20ms fast-poll (was 500ms)
    }
    return 0;
}

// Poll /proc/<pid>/net/tcp* for ESTABLISHED connection to printer IP.
// Returns true when at least one ESTAB is found.
static bool wait_for_estab(pid_t pid, const std::string& printer_ip, int timeout_s) {
    // Convert IP to hex (network byte order).
    struct in_addr addr{};
    if (inet_pton(AF_INET, printer_ip.c_str(), &addr) != 1) return false;
    // /proc/net/tcp uses little-endian hex for IPv4.
    char hex_ip[16];
    snprintf(hex_ip, sizeof(hex_ip), "%08X", ntohl(addr.s_addr));
    // In /proc/net/tcp, remote address is "IP:PORT" in host byte order hex,
    // but actually it's: "hex_ip_LE:port". For 192.168.1.209 = 0xD101A8C0.
    // Let's use ss instead.
    double deadline = now_s() + double(timeout_s);
    while (now_s() < deadline) {
        // Check /proc/<pid>/net/tcp6 for ESTABLISHED connection to printer IP:8883.
        // This is PID-specific unlike ss -tn which is system-wide.
        char tcp6_path[64];
        snprintf(tcp6_path, sizeof(tcp6_path), "/proc/%d/net/tcp6", (int)pid);
        FILE* f = fopen(tcp6_path, "r");
        if (!f) {
            // Fallback: ss filtered by PID
            char cmd[256];
            snprintf(cmd, sizeof(cmd),
                     "ss -tnp 2>/dev/null | grep ESTAB | grep 'pid=%d' | grep -c '%s'",
                     (int)pid, printer_ip.c_str());
            FILE* p = popen(cmd, "r");
            if (p) {
                int cnt = 0;
                fscanf(p, "%d", &cnt);
                pclose(p);
                if (cnt > 0) return true;
            }
        } else {
            // Parse /proc/pid/net/tcp6: fields are local, remote (IPv4-mapped hex).
            // IPv4 ::ffff:192.168.1.209 = 00000000000000000000FFFFD101A8C0 (BE hex)
            // Port 8883 = 22B3 (BE hex)
            char line[256];
            bool found = false;
            while (fgets(line, sizeof(line), f) && !found) {
                // Remote address in field 3 (0-indexed).
                // Format: "  sl  local_address rem_address st tx_queue rx_queue ..."
                char local[64], remote[64], state_str[8];
                if (sscanf(line, "%*d: %63s %63s %7s", local, remote, state_str) == 3) {
                    // state 01 = ESTABLISHED
                    if (strcmp(state_str, "01") == 0) {
                        // Check remote port = 22B3 (8883 hex).
                        const char* colon = strrchr(remote, ':');
                        if (colon && strncmp(colon + 1, "22B3", 4) == 0) {
                            found = true;
                        }
                    }
                }
            }
            fclose(f);
            if (found) return true;
        }
        usleep(2 * 1000 * 1000);  // 2s
    }
    return false;
}

// Poll arena2 in /proc/<pid>/mem for SHA-256 K-table. Returns true when found.
// This signals that VMP has decoded the sign code path (fired by first sign).
static bool wait_for_sign_decoded(pid_t pid, int timeout_s) {
    static const uint8_t K_BE[] = {0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
                                    0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5, 0xdb, 0xa5};
    double deadline = now_s() + double(timeout_s);
    while (now_s() < deadline) {
        // Read maps to find large anon r-xp regions.
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
        FILE* mf = fopen(maps_path, "r");
        if (!mf) { usleep(1000000); continue; }
        std::vector<std::pair<uint64_t,uint64_t>> anon_rxp;
        char line[512];
        while (fgets(line, sizeof(line), mf)) {
            if (strstr(line, "r-xp 00000000 00:00") == nullptr) continue;
            if (strstr(line, "vdso") != nullptr) continue;
            uint64_t lo = 0, hi = 0;
            sscanf(line, "%lx-%lx", &lo, &hi);
            if (hi - lo > 2 * 1024 * 1024) anon_rxp.push_back({lo, hi});
        }
        fclose(mf);

        if (anon_rxp.empty()) { usleep(1000000); continue; }

        // Scan for K-table.
        char mem_path[64];
        snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
        int memfd = open(mem_path, O_RDONLY);
        if (memfd < 0) { usleep(1000000); continue; }
        bool found = false;
        for (auto& [lo, hi] : anon_rxp) {
            uint8_t buf[4096];
            for (uint64_t cs = lo; cs < hi && !found; cs += 4096) {
                size_t rsz = std::min<uint64_t>(4096, hi - cs);
                if (pread(memfd, buf, rsz, (off_t)cs) != (ssize_t)rsz) continue;
                for (size_t i = 0; i + 16 <= rsz && !found; ++i) {
                    if (memcmp(buf + i, K_BE, 16) == 0) found = true;
                }
            }
            if (found) break;
        }
        close(memfd);
        if (found) return true;
        usleep(2 * 1000 * 1000);  // 2s
    }
    return false;
}

// Global daemon PID for signal handler cleanup.
// Use a pipe to store the PID atomically (signal-handler safe).
static int g_cleanup_pipe[2] = {-1, -1};
static pid_t g_daemon_pid_atomic = 0;  // written before signal can fire on main path

static void cleanup_signal_handler(int /*sig*/) {
    // Kill all processes in the daemon's process group.
    // Read saved PID from the pipe-trick or the global.
    pid_t dpid = g_daemon_pid_atomic;
    if (dpid > 0) {
        // Kill the daemon and its entire process group.
        kill(dpid, SIGKILL);
        kill(-dpid, SIGKILL);  // kill process group if dpid is also PGID
    }
    // Remove stop marker so supervisor can restart.
    unlink("/tmp/bridge-mp/stop-markers/H2S");
    // Also try pkilling by name pattern just in case.
    system("pkill -KILL -f 'memfd:bambu_daemon' 2>/dev/null");
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

    // Discourage core dumps.
    {
        struct rlimit rl{0, 0};
        setrlimit(RLIMIT_CORE, &rl);
    }

    // ---- Parse simplified CLI ----
    Args args;
    args.no_envelopes = true;   // default: no envelopes required
    args.timeout_s    = 120;
    args.out_path     = "d_extracted.json";

    std::string lan_ip;
    bool show_help = (argc < 2);

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
        if      (s == "--dev-id")      { if (!need(args.dev_id)) return 2; }
        else if (s == "--access-code") { if (!need(args.access_code)) return 2; }
        else if (s == "--lan-ip")      { if (!need(lan_ip)) return 2; }
        else if (s == "--plugin")      { if (!need(args.plugin_path)) return 2; }
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
        else if (s == "--no-printer")  { args.no_printer = true; }
        else if (s == "--help" || s == "-h") { show_help = true; }
        else {
            std::fprintf(stderr, "unknown argument: %s\n", s.c_str());
            show_help = true;
        }
    }

    // In --no-printer mode, pre-fill lan_ip and dev_id so SSDP scan is skipped
    // when both are already known (no wasted 2.5s scan).
    if (args.no_printer) {
        if (lan_ip.empty()) lan_ip = "127.0.0.1";
        if (args.dev_id.empty()) {
            args.dev_id = "01S00A2B3C4D5E6";
            std::fprintf(stderr, "[info] --no-printer: using synthetic dev-id %s\n",
                         args.dev_id.c_str());
        }
    }

    // Auto-discover dev_id and/or LAN IP via SSDP (UDP 2021, 2.5s listen).
    // Printers broadcast NOTIFY every ~30s; we parse USN (=dev_id) + source IP.
    // Virtual bridge entries (USN starts "FFFF" or has Bambu-Mqtt-Port) are filtered.
    if ((!args.dev_id.empty() || !show_help) && (args.dev_id.empty() || lan_ip.empty())) {
        std::vector<SsdpPrinter> found;
        if (!show_help) {
            std::fprintf(stderr, "[info] scanning LAN for Bambu printers via SSDP (2.5s)...\n");
            found = probe_printers_via_ssdp(2500);
        }

        if (!found.empty()) {
            SsdpPrinter* match = nullptr;
            if (!args.dev_id.empty()) {
                // User specified dev_id — find matching SSDP entry for its IP.
                for (auto& p : found) {
                    if (p.dev_id == args.dev_id) { match = &p; break; }
                }
            } else if (found.size() == 1) {
                // Exactly one printer on LAN — use it.
                match = &found[0];
            } else {
                // Multiple printers: try to narrow via BambuStudio.conf dev_ids.
                auto conf_ids = probe_dev_ids_from_bsl_conf();
                for (auto& p : found) {
                    for (auto& cid : conf_ids) {
                        if (p.dev_id == cid) { match = &p; break; }
                    }
                    if (match) break;
                }
                if (!match) {
                    std::fprintf(stderr, "ERROR: %zu printers found — use --dev-id to specify one:\n",
                                 found.size());
                    for (auto& p : found)
                        std::fprintf(stderr, "  %s  (%s)\n", p.dev_id.c_str(), p.lan_ip.c_str());
                    return 2;
                }
            }

            if (match) {
                if (args.dev_id.empty()) {
                    args.dev_id = match->dev_id;
                    std::fprintf(stderr, "[info] dev-id auto-discovered via SSDP: %s\n",
                                 args.dev_id.c_str());
                }
                if (lan_ip.empty()) {
                    lan_ip = match->lan_ip;
                    std::fprintf(stderr, "[info] lan-ip auto-discovered via SSDP: %s\n",
                                 lan_ip.c_str());
                }
            }
        } else if (!show_help) {
            // SSDP got nothing — fall back to BambuStudio.conf for dev_id.
            if (args.dev_id.empty()) {
                auto ids = probe_dev_ids_from_bsl_conf();
                if (ids.size() == 1) {
                    args.dev_id = ids[0];
                    std::fprintf(stderr, "[info] dev-id from BambuStudio.conf: %s\n",
                                 args.dev_id.c_str());
                } else if (ids.size() > 1) {
                    std::fprintf(stderr, "ERROR: %zu printers in BambuStudio.conf — use --dev-id:\n",
                                 ids.size());
                    for (auto& id : ids) std::fprintf(stderr, "  %s\n", id.c_str());
                    return 2;
                }
            }
        }
    }

    // In --no-printer mode, access-code is not needed.
    if (args.no_printer) {
        if (args.access_code.empty() || args.access_code == "000000")
            args.access_code = "no-printer-offline";
    }

    if (show_help || args.dev_id.empty() ||
        (!args.no_printer && (args.access_code.empty() || lan_ip.empty()))) {
        usage_simple(argv[0]);
        if (!show_help) {
            std::fprintf(stderr, "\nERROR:");
            if (args.dev_id.empty()) std::fprintf(stderr, " --dev-id (SSDP found no printer; try --no-printer)");
            if (!args.no_printer) {
                std::fprintf(stderr, " --access-code");
                if (lan_ip.empty()) std::fprintf(stderr, " --lan-ip (SSDP found no printer)");
            }
            std::fprintf(stderr, " required\n");
        }
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
    g_args_for_child = args;
    g_plugin_path_for_home = args.plugin_path;

    // ---- Identify plugin version from file size ----
    const VersionProfile* ver = identify_version(args.plugin_path);
    double warmup_s = 4.0;  // default
    if (ver) {
        warmup_s = ver->warmup_s;
    }

    LOG_I("bambu_extract_d");
    LOG_I("dev-id    : %s", args.dev_id.c_str());
    LOG_I("lan-ip    : %s", lan_ip.c_str());
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

    // ---- Write embedded slicer cert to tmpdir ----
    std::string cert_dir = write_cert_tmpdir(getpid());
    if (cert_dir.empty()) {
        LOG_E("failed to write embedded cert");
        return 3;
    }
    LOG_I("cert dir  : %s", cert_dir.c_str());

    // ---- Parse modulus N (needed for reconstruction) ----
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

    // ---- Start fake printer broker (--no-printer offline mode) ----
    // Must start BEFORE the daemon so it's listening on 127.0.0.1:8883 when
    // the daemon's connect_printer fires.
    FakePrinterBroker fake_broker;
    if (args.no_printer) {
        LOG_I("--no-printer: starting fake TLS MQTT broker on 127.0.0.1:8883");
        if (!fake_broker.start(args.dev_id)) {
            LOG_E("failed to start fake printer broker on port 8883 "
                  "(is port 8883 already in use?)");
            return 4;
        }
        LOG_I("fake broker ready — will inject cert_report when daemon sends app_cert_install");
        lan_ip = "127.0.0.1";
        g_connect_redirect_so_path = fake_broker.connect_redirect_so_path;
        g_fake_printer_port = fake_broker.port;
    } else {
        // ---- Verify printer reachability ----
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, lan_ip.c_str(), &sa.sin_addr);
        sa.sin_port = htons(8883);
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            struct timeval tv{2, 0};
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            int ok = connect(sock, (sockaddr*)&sa, sizeof(sa));
            close(sock);
            if (ok == 0) LOG_I("printer %s:8883 reachable", lan_ip.c_str());
            else LOG_W("printer %s:8883 not immediately reachable", lan_ip.c_str());
        }
    }

    // ---- Write daemon binary to memfd ----
    std::string daemon_exe = write_daemon_memfd();
    if (daemon_exe.empty()) {
        LOG_E("failed to write daemon binary to memfd");
        return 4;
    }
    LOG_I("daemon exe: %s (%zu bytes)", daemon_exe.c_str(), (size_t)daemon_embed_bin_len);

    // ---- Set up H2S home directory ----
    std::string h2s_home = setup_h2s_home(args.dev_id);
    if (h2s_home.empty()) {
        LOG_E("failed to set up H2S home directory");
        return 4;
    }

    // ---- Find mTLS cert/key ----
    std::string mtls_cert, mtls_key;
    {
        const char* home_env2 = std::getenv("HOME");
        std::string home2 = (home_env2 && home_env2[0]) ? home_env2 : "";
        // Search order: env-specified bridge path first, then extract_mtls output,
        // then standard BambuStudio cert cache locations.
        std::vector<std::string> cert_candidates = {
            "/tmp/bbl_capture/mtls.fresh/paired/H2S_" + args.dev_id + "_chain.pem",
            "/tmp/bbl_capture/mtls.fresh/paired/" + args.dev_id + "_chain.pem",
            "/tmp/bbl_capture/mtls/" + args.dev_id + "_chain.pem",
            "/tmp/bbl_capture/mtls/" + args.dev_id + ".crt",
        };
        std::vector<std::string> key_candidates = {
            "/tmp/bbl_capture/mtls.fresh/paired/H2S_" + args.dev_id + "_key.pem",
            "/tmp/bbl_capture/mtls.fresh/paired/" + args.dev_id + "_key.pem",
            "/tmp/bbl_capture/mtls/" + args.dev_id + "_key.pem",
            "/tmp/bbl_capture/mtls/" + args.dev_id + ".key",
        };
        if (!home2.empty()) {
            // BambuStudio stores per-device certs under user/<uid>/device/<dev_id>/
            // Try common locations.
            cert_candidates.push_back(home2 + "/.config/BambuStudio/user/0/device/" + args.dev_id + "/certificate.pem");
            cert_candidates.push_back(home2 + "/.config/BambuStudio/certificate/" + args.dev_id + "_chain.pem");
            key_candidates.push_back(home2 + "/.config/BambuStudio/user/0/device/" + args.dev_id + "/private_key.pem");
            key_candidates.push_back(home2 + "/.config/BambuStudio/certificate/" + args.dev_id + "_key.pem");
        }
        struct stat st{};
        for (auto& c : cert_candidates) {
            if (stat(c.c_str(), &st) == 0) { mtls_cert = c; break; }
        }
        for (auto& k : key_candidates) {
            if (stat(k.c_str(), &st) == 0) { mtls_key = k; break; }
        }
        if (!mtls_cert.empty()) LOG_I("mTLS cert: %s", mtls_cert.c_str());
        else LOG_W("mTLS cert not found — SSL auth may fail");
        if (!mtls_key.empty())  LOG_I("mTLS key : %s", mtls_key.c_str());
    }

    // ---- Also set BBL_MTLS_CERT/KEY env so any inner process sees them ----
    if (!mtls_cert.empty()) setenv("BBL_MTLS_CERT", mtls_cert.c_str(), 1);
    if (!mtls_key.empty())  setenv("BBL_MTLS_KEY",  mtls_key.c_str(),  1);

    // ---- Stop running H2S bridge processes ----
    // The printer only accepts cert_report for ONE active MQTT session per device.
    // Existing H2S bridges hold the printer's session — our daemon can't get
    // cert_report until they release it. Stop them first, capture d, then restore.
    std::vector<pid_t> killed_bridges = stop_h2s_bridge(args.dev_id, lan_ip);

    // ---- Launch daemon ----
    double daemon_start_ts = now_s();
    std::string daemon_log = cert_dir + "/daemon.log";
    pid_t daemon_pid = launch_daemon(daemon_exe, h2s_home, args.plugin_path,
                                     args.dev_id, args.access_code, lan_ip,
                                     cert_dir, mtls_cert, mtls_key, daemon_log);
    if (daemon_pid < 0) {
        restore_h2s_supervisor();
        LOG_E("failed to launch daemon");
        return 4;
    }
    g_daemon_pid_atomic = daemon_pid;  // signal handler can kill it on SIGTERM
    LOG_I("daemon launched: PID %d", (int)daemon_pid);
    LOG_I("daemon log: %s", daemon_log.c_str());

    // ---- Read seccomp notif_fd from daemon constructor ----
    // The daemon constructor (watchdog_defeat_v2.so) calls
    // install_openat_usernotif_seccomp() which writes the notif fd back to us.
    // We read it with a timeout so we don't block indefinitely if the feature
    // is not available (e.g. old .so, kernel too old).
    if (g_openat_notif_pipe_rd >= 0) {
        struct pollfd pf = { g_openat_notif_pipe_rd, POLLIN, 0 };
#ifdef USE_SECCOMP_UNOTIFY
        int pr = poll(&pf, 1, 3000);  // wait up to 3s for shim to install filter + send notif_fd
#else
        int pr = poll(&pf, 1, 0);     // no wait — shim doesn't implement seccomp USER_NOTIF
#endif
        if (pr > 0 && (pf.revents & POLLIN)) {
            int daemon_notif_fd = -1;  // fd number *in the daemon process*
            ssize_t nr = read(g_openat_notif_pipe_rd, &daemon_notif_fd, sizeof(int));
            if (nr == sizeof(int) && daemon_notif_fd >= 0) {
                LOG_I("openat: daemon notif_fd=%d (in daemon pid=%d)", daemon_notif_fd, daemon_pid);
                // Use pidfd_getfd to steal the fd from the daemon into our process.
                // pidfd_open: create a pidfd for the daemon.
                // pidfd_getfd: duplicate the daemon's notif_fd into our fd table.
                // Requires CAP_SYS_PTRACE or /proc/sys/kernel/yama/ptrace_scope<=1.
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

    // ---- Start openat supervisor thread NOW (before wait_for_libbambu) ----
    // CRITICAL: the supervisor must be running BEFORE dlopen of the plugin.
    // The seccomp USER_NOTIF filter intercepts ALL openat calls in the daemon,
    // including dlopen's internal openat calls to load .so files. If the
    // supervisor is not running to respond to those notifications, dlopen will
    // deadlock (blocked waiting for supervisor response that never arrives).
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
        restore_h2s_supervisor();
        return 5;
    }
    LOG_I("libbambu mapped in PID %d", (int)target_pid);

    // ---- Trigger late openat seccomp filter installation via SIGUSR2 ----
    // The WD_V2_OPENAT_SELFEXEMPT handler installs a SIGSYS filter for
    // raw openat, exempt for calls from within the shim's own IP range.
    // This is done AFTER libbambu is fully loaded so dlopen is unaffected.
    // ---- Wait for ESTAB TCP connection to printer before attaching ----
    // The signing thread (LAN uplink) is spawned during printer connection,
    // not at plugin init time. If we attach too early (e.g. at t=5s), the
    // signing thread doesn't exist yet — DR0 is armed on the wrong threads.
    // PTRACE_O_TRACECLONE catches threads spawned AFTER we attach, but the
    // window between SEIZE and CLONE event delivery introduces a race.
    //
    // The safe approach: wait until the daemon has an ESTABLISHED TCP
    // connection to the printer (:8883 ESTAB). At that point, the LAN uplink
    // thread already exists and is in the thread list, so the initial SEIZE
    // arms DR0 on it directly. No clone-race needed.
    //
    // We detect ESTAB via /proc/<daemon_pid>/net/tcp6 (IPv4-mapped IPv6) or
    // /proc/<daemon_pid>/net/tcp. Port 8883 = 0x22B3.
    {
        LOG_I("waiting for daemon ESTAB connection to printer %s:8883 (max 180s)...",
              lan_ip.c_str());
        double estab_deadline = now_s() + 180.0;
        bool estab = false;
        // Build the hex representation of the printer's IPv4 address in the
        // format used by /proc/net/tcp6 (IPv4-mapped: 0000000000000000FFFF0000 + addr_BE_hex)
        // and /proc/net/tcp (addr in little-endian hex).
        // We just search for the port ":22B3" in ESTAB state (state 01).
        while (!estab && now_s() < estab_deadline) {
            // Check if daemon is still alive.
            if (kill(daemon_pid, 0) != 0) {
                LOG_E("daemon PID %d died while waiting for ESTAB", (int)daemon_pid);
                break;
            }
            // Read /proc/<pid>/net/tcp6 and /proc/<pid>/net/tcp.
            // Format: "sl  local_address rem_address st ..."
            // state 01 = TCP_ESTABLISHED. Port in rem_address after ':'.
            for (const char* proto : {"tcp6", "tcp"}) {
                char netpath[128];
                snprintf(netpath, sizeof(netpath),
                         "/proc/%d/net/%s", (int)daemon_pid, proto);
                FILE* nf = fopen(netpath, "r");
                if (!nf) continue;
                char line[512];
                while (fgets(line, sizeof(line), nf) && !estab) {
                    // Find state field (3rd column).
                    char local[128], remote[128], state_hex[8];
                    if (sscanf(line, "%*d: %127s %127s %7s", local, remote, state_hex) != 3)
                        continue;
                    if (strcmp(state_hex, "01") != 0) continue; // must be ESTAB
                    // Check remote port = 22B3 (8883 decimal).
                    const char* colon = strrchr(remote, ':');
                    if (colon && strncasecmp(colon + 1, "22B3", 4) == 0) {
                        estab = true;
                        LOG_I("ESTAB to printer:8883 detected (proto=%s line=%.80s)", proto, line);
                    }
                }
                fclose(nf);
                if (estab) break;
            }
            if (!estab) usleep(200 * 1000); // poll every 200ms
        }
        if (!estab) {
            LOG_W("no ESTAB to :8883 detected within 180s — attaching anyway");
            LOG_W("signing thread may not yet exist; DR0 may miss first few pulses");
        }
        // No extra post-ESTAB wait: WD_V2_FAKE_TRACEME suppresses the VMP
        // sentinel, so we can arm DR0 on existing threads safely. The
        // warmup_s wait below gives the plugin time to initialize.
    }

    // ---- VMP warm-up: attach before signing thread spawns ----
    // The signing thread spawns at daemon+~6.4s (first gcode-cmd pulse).
    // We must attach BEFORE that spawn so PTRACE_EVENT_CLONE arms DR0 on
    // the new thread from the start. If we attach AFTER the signing thread
    // already exists, PTRACE_INTERRUPT-based arm leaves the thread in a state
    // where the sign path bypasses the accumulator (0 traps). 4s warmup
    // gives the plugin time to dlopen and init (libbambu maps at daemon+0.5s)
    // while guaranteeing we attach before the signing thread clone at +6.4s.
    // The 35s VMP CRC is well after our ~12s total wall time.
    //
    // BBL_SEIZE_DELAY=N: wait N seconds after ESTAB before attaching.
    // This allows VMP's anti-debug self-test to fire and be handled by the
    // process's own SIGTRAP handler (no ptrace interference). After N seconds,
    // VMP has passed its self-test and signing proceeds normally under ptrace.
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
                        restore_h2s_supervisor();
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
                        restore_h2s_supervisor();
                        return 7;
                    }
                }
                LOG_I("VMP warm-up complete");
            }
        }
    }

    // ---- Arm DR0 and capture ----
    // NOTE: BBL_ARM_ALL_TIDS=1 is set ONLY when explicitly overridden.
    // Default: arm ONLY the main thread (not all threads) to avoid
    // PTRACE_INTERRUPT-based timing disruption of the sign thread.
    // The sign thread will be armed via PTRACE_EVENT_CLONE when it spawns,
    // or via int3 software breakpoints (TBD).
    // setenv("BBL_ARM_ALL_TIDS", "1", 1);  // DISABLED for diagnostic

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

    // Restore H2S bridge supervisor (restart the bridge we stopped).
    restore_h2s_supervisor();

    if (!cap.ok) {
        LOG_E("capture failed: only %zu bytes (need %d)",
              cap.stream.size(), version_02_05_03_63::TOTAL_BYTES);
        if (cap.total_traps > 0)
            LOG_W("trap count = %d (expected multiples of 256)", cap.total_traps);
        // Print daemon log tail for debugging.
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

    // ---- Write JSON output ----
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

    return 0;
}
