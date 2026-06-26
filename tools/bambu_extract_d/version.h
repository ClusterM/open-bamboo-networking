#pragma once
#include <cstdint>
#include <string>
#include <sys/stat.h>

// ===========================================================================
// Version-locked constants for libbambu_networking v02.05.03.63 (linux)
// ===========================================================================
namespace version_02_05_03_63 {
    // Offsets from the libbambu_networking r-xp mapping base.
    // WRAPPING_FN_OFFSET: entry of the RSA CRT modexp wrapper function.
    // BYTE_LOAD_OFFSET:   movzx edx,[rcx] — loads each CRT key byte.
    // ACCUMULATOR_OFFSET: mov [rsp+0x48],edx — accumulator instruction in
    //                     libbambu_networking v02.05.03.63 (HW-BP target).
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

    // Public RSA modulus N for slicer key in this version.
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

extern const VersionProfile PROFILES[];

const VersionProfile* identify_version(const std::string& plugin_path);
