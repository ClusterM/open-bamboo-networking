// Lifted from BambuBridge-vmp-devirt/agent_epsilon_phase22/ on 2026-06-14.
// AGPL-3.0 — see LICENSE.

// BigIntModExp.cpp — minimal fixed-size big-integer modexp for RSA-2048.
//
// Self-contained: no external library dependency. Provides a single
// entry point:
//
//   void big_modexp_rsa2048(const uint8_t base_be[256],
//                           const uint8_t exp_be[/*<=256*/], size_t exp_len,
//                           const uint8_t mod_be[256],
//                           uint8_t out_be[256]);
//
// Implementation: Montgomery exponentiation, 64-bit limbs little-endian
// (32 limbs = 2048 bits). Uses GCC/Clang/MinGW __uint128_t for 64x64=128
// multiplication. Constant-time-ish; this code embeds a real private key
// so we still avoid data-dependent branches in the inner loops but no
// formal side-channel claims are made.

#include "BigIntModExp.hpp"

#include <cstring>
#include <cstdint>
#include <cstddef>
#include <stdexcept>

namespace bambu_signing {

namespace {

using u64 = std::uint64_t;
using u128 = unsigned __int128;

// 2048 bits / 64 = 32 limbs.
constexpr std::size_t kLimbs = 32;

struct BigU {
    u64 v[kLimbs];
};

inline void set_zero(BigU& a) { std::memset(a.v, 0, sizeof(a.v)); }

// Big-endian byte input (256 bytes) → little-endian limb array.
void be256_to_limbs(const std::uint8_t in[256], BigU& out) {
    set_zero(out);
    for (std::size_t i = 0; i < kLimbs; ++i) {
        u64 w = 0;
        // byte 0 of limb (least significant byte of limb) comes from the
        // big-endian end. limb i covers bytes [255 - 8*i - 7 .. 255 - 8*i].
        const std::uint8_t* p = in + 256 - 8 * (i + 1);
        for (int b = 0; b < 8; ++b) {
            w |= static_cast<u64>(p[b]) << (8 * (7 - b));
        }
        out.v[i] = w;
    }
}

// Little-endian limb array → big-endian 256-byte output.
void limbs_to_be256(const BigU& in, std::uint8_t out[256]) {
    for (std::size_t i = 0; i < kLimbs; ++i) {
        u64 w = in.v[i];
        std::uint8_t* p = out + 256 - 8 * (i + 1);
        for (int b = 0; b < 8; ++b) {
            p[b] = static_cast<std::uint8_t>(w >> (8 * (7 - b)));
        }
    }
}

// Compare two BigU as unsigned. Returns -1/0/+1.
int cmp(const BigU& a, const BigU& b) {
    for (std::size_t i = kLimbs; i-- > 0;) {
        if (a.v[i] < b.v[i]) return -1;
        if (a.v[i] > b.v[i]) return 1;
    }
    return 0;
}

// out = a - b assuming a >= b; returns borrow (0 here).
u64 sub(BigU& out, const BigU& a, const BigU& b) {
    u64 borrow = 0;
    for (std::size_t i = 0; i < kLimbs; ++i) {
        u128 t = static_cast<u128>(a.v[i]) - b.v[i] - borrow;
        out.v[i] = static_cast<u64>(t);
        borrow = static_cast<u64>((t >> 64) & 1);
    }
    return borrow;
}

// Conditional subtract: if a >= n then a -= n.
void cond_sub(BigU& a, const BigU& n) {
    BigU t;
    u64 borrow = sub(t, a, n);
    if (borrow == 0) a = t;
}

// Compute n0' = -n^{-1} mod 2^64 (Montgomery constant) using Hensel's
// lemma starting from x = 1.
u64 mont_n0_prime(u64 n0) {
    // Requires n0 odd; for RSA modulus this is always true.
    u64 x = 1;
    for (int i = 0; i < 6; ++i) {  // converges in 6 doublings for 64-bit
        x = x * (2 - n0 * x);
    }
    return 0u - x;
}

// Montgomery multiplication: out = a * b * R^{-1} mod n, where
// R = 2^(64*kLimbs). Assumes a, b < n. n0p = -n^{-1} mod 2^64.
void mont_mul(BigU& out, const BigU& a, const BigU& b, const BigU& n, u64 n0p) {
    // CIOS variant. t is 33 limbs (kLimbs + 1).
    u64 t[kLimbs + 2];
    std::memset(t, 0, sizeof(t));
    for (std::size_t i = 0; i < kLimbs; ++i) {
        // t = t + a * b[i]
        u64 carry = 0;
        const u64 bi = b.v[i];
        for (std::size_t j = 0; j < kLimbs; ++j) {
            u128 s = static_cast<u128>(a.v[j]) * bi
                     + t[j] + carry;
            t[j] = static_cast<u64>(s);
            carry = static_cast<u64>(s >> 64);
        }
        u128 s2 = static_cast<u128>(t[kLimbs]) + carry;
        t[kLimbs] = static_cast<u64>(s2);
        t[kLimbs + 1] += static_cast<u64>(s2 >> 64);

        // m = t[0] * n0p mod 2^64
        u64 m = t[0] * n0p;

        // t = t + m * n; t low limb becomes 0
        carry = 0;
        for (std::size_t j = 0; j < kLimbs; ++j) {
            u128 s = static_cast<u128>(n.v[j]) * m
                     + t[j] + carry;
            t[j] = static_cast<u64>(s);
            carry = static_cast<u64>(s >> 64);
        }
        u128 s3 = static_cast<u128>(t[kLimbs]) + carry;
        t[kLimbs] = static_cast<u64>(s3);
        t[kLimbs + 1] += static_cast<u64>(s3 >> 64);

        // Shift right by one limb.
        for (std::size_t j = 0; j < kLimbs + 1; ++j) t[j] = t[j + 1];
        t[kLimbs + 1] = 0;
    }
    BigU r;
    for (std::size_t i = 0; i < kLimbs; ++i) r.v[i] = t[i];
    // If t[kLimbs] != 0 OR r >= n, subtract n.
    if (t[kLimbs] != 0) {
        // r = r + 2^(64*kLimbs); subtract n once is enough since
        // r < 2 * n (Montgomery property).
        BigU s;
        sub(s, r, n);
        r = s;
    } else {
        cond_sub(r, n);
    }
    out = r;
}

// Compute R^2 mod n by mont-mul(R, R) where R = compute_r_mod_n.
// More directly: square R once with classical schoolbook, reduce.
// Easier: doubling 2048 + 2048 times keeps it simple.
void compute_r2_mod_n(BigU& out, const BigU& n) {
    // out = 1 doubled 2 * 64 * kLimbs times mod n.
    set_zero(out);
    out.v[0] = 1;
    for (int i = 0; i < 2 * 64 * (int)kLimbs; ++i) {
        u64 carry = 0;
        for (std::size_t j = 0; j < kLimbs; ++j) {
            u64 lo = (out.v[j] << 1) | carry;
            carry = out.v[j] >> 63;
            out.v[j] = lo;
        }
        if (carry) {
            BigU t;
            sub(t, out, n);
            out = t;
        } else {
            cond_sub(out, n);
        }
    }
}

}  // namespace

void big_modexp_rsa2048(const std::uint8_t base_be[256],
                        const std::uint8_t* exp_be,
                        std::size_t exp_len,
                        const std::uint8_t mod_be[256],
                        std::uint8_t out_be[256]) {
    BigU n, base;
    be256_to_limbs(mod_be, n);
    be256_to_limbs(base_be, base);

    if ((n.v[0] & 1) == 0) {
        throw std::runtime_error("big_modexp_rsa2048: modulus must be odd");
    }

    // base must be < n. RSA EM is always < n because EM has its high bit
    // controlled by leading 0x00 byte; we don't enforce here, just
    // ensure mathematically we reduce once if needed.
    if (cmp(base, n) >= 0) {
        BigU t;
        sub(t, base, n);
        base = t;
    }

    u64 n0p = mont_n0_prime(n.v[0]);

    BigU r2;
    compute_r2_mod_n(r2, n);

    // base_mont = base * R mod n = mont_mul(base, R^2)
    BigU base_mont;
    mont_mul(base_mont, base, r2, n, n0p);

    // result_mont = 1 * R mod n = mont_mul(1, R^2)
    BigU one;
    set_zero(one);
    one.v[0] = 1;
    BigU result_mont;
    mont_mul(result_mont, one, r2, n, n0p);

    // Square-and-multiply from MSB of exp.
    // Find first non-zero byte in exp_be to skip leading zeros.
    std::size_t first = 0;
    while (first < exp_len && exp_be[first] == 0) ++first;
    if (first == exp_len) {
        // exp == 0 → result is 1
        BigU r;
        set_zero(r);
        r.v[0] = 1;
        limbs_to_be256(r, out_be);
        return;
    }

    // Walk bits MSB→LSB of exp_be[first..exp_len-1].
    // For the first byte, skip leading zero bits.
    int top_byte_bits = 8;
    {
        std::uint8_t b = exp_be[first];
        while ((b & 0x80) == 0) { b <<= 1; --top_byte_bits; }
    }

    bool started = false;
    for (std::size_t bi = first; bi < exp_len; ++bi) {
        std::uint8_t byte = exp_be[bi];
        int bits = (bi == first) ? top_byte_bits : 8;
        int shift = (bi == first) ? (top_byte_bits - 1) : 7;
        for (int k = 0; k < bits; ++k) {
            if (started) {
                BigU t;
                mont_mul(t, result_mont, result_mont, n, n0p);
                result_mont = t;
            }
            int bit = (byte >> (shift - k)) & 1;
            if (bit) {
                if (!started) {
                    // First 1 bit just sets result_mont = base_mont
                    result_mont = base_mont;
                    started = true;
                } else {
                    BigU t;
                    mont_mul(t, result_mont, base_mont, n, n0p);
                    result_mont = t;
                }
            }
        }
    }

    // Convert out of Montgomery form: mont_mul(result_mont, 1)
    BigU out_norm;
    mont_mul(out_norm, result_mont, one, n, n0p);

    limbs_to_be256(out_norm, out_be);
}

}  // namespace bambu_signing
