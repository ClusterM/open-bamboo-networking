#pragma once
#include <cstdint>
#include <string>
#include <vector>

// ===========================================================================
// Bignum helpers built on top of vendored Montgomery modexp.
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
    static int cmp(const BigInt& a, const BigInt& b);
};

// Used by mod_inverse internals; exposed so capture.cpp doesn't need to pull in bignum.h.
struct SignedBI { BigInt val; bool neg = false; };

BigInt from_bytes_be(const uint8_t* p, size_t n);
BigInt from_hex(const std::string& in);
void   to_bytes_be_fixed(const BigInt& a, uint8_t* out, size_t n);
std::string to_hex_str(const BigInt& a, bool with_0x = true);

BigInt add(const BigInt& a, const BigInt& b);
BigInt sub(const BigInt& a, const BigInt& b);
BigInt mul_small(const BigInt& a, uint32_t s);
BigInt div_small(const BigInt& a, uint32_t s, uint32_t* rem_out = nullptr);
BigInt mul(const BigInt& a, const BigInt& b);
BigInt mod(const BigInt& a, const BigInt& b);
BigInt div(const BigInt& a, const BigInt& b, BigInt* rem_out = nullptr);

int      cmp_s(const SignedBI& a, const SignedBI& b);
SignedBI add_s(const SignedBI& a, const SignedBI& b);
SignedBI sub_s(const SignedBI& a, const SignedBI& b);
SignedBI mul_s(const SignedBI& a, const SignedBI& b);
BigInt   mod_inverse(const BigInt& a_in, const BigInt& n);

}  // namespace bn
