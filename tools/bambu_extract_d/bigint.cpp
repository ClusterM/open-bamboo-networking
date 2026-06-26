#include "bigint.h"
#include <cstring>
#include <algorithm>

namespace bn {

int BigInt::cmp(const BigInt& a, const BigInt& b) {
    if (a.v.size() != b.v.size()) return a.v.size() < b.v.size() ? -1 : 1;
    for (size_t i = a.v.size(); i-- > 0;) {
        if (a.v[i] != b.v[i]) return a.v[i] < b.v[i] ? -1 : 1;
    }
    return 0;
}

BigInt from_bytes_be(const uint8_t* p, size_t n) {
    BigInt r;
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

BigInt from_hex(const std::string& in) {
    std::string s = in;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s = s.substr(2);
    }
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

void to_bytes_be_fixed(const BigInt& a, uint8_t* out, size_t n) {
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

std::string to_hex_str(const BigInt& a, bool with_0x) {
    if (a.v.empty()) return with_0x ? "0x0" : "0";
    std::string r;
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

BigInt add(const BigInt& a, const BigInt& b) {
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

BigInt sub(const BigInt& a, const BigInt& b) {
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

BigInt mul_small(const BigInt& a, uint32_t s) {
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

BigInt div_small(const BigInt& a, uint32_t s, uint32_t* rem_out) {
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

BigInt mul(const BigInt& a, const BigInt& b) {
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

BigInt mod(const BigInt& a, const BigInt& b) {
    if (BigInt::cmp(a, b) < 0) return a;
    if (b.v.size() == 1) {
        uint32_t rem = 0;
        div_small(a, b.v[0], &rem);
        return BigInt(rem);
    }
    BigInt r;
    int top = a.bit_length();
    for (int i = top - 1; i >= 0; --i) {
        uint32_t carry = 0;
        for (size_t k = 0; k < r.v.size(); ++k) {
            uint64_t s = (uint64_t(r.v[k]) << 1) | carry;
            r.v[k] = uint32_t(s);
            carry = uint32_t(s >> 32);
        }
        if (carry) r.v.push_back(carry);
        size_t limb = i / 32, bit = i % 32;
        if (limb < a.v.size() && ((a.v[limb] >> bit) & 1)) {
            if (r.v.empty()) r.v.push_back(1u); else r.v[0] |= 1u;
        }
        r.trim();
        if (BigInt::cmp(r, b) >= 0) r = sub(r, b);
    }
    return r;
}

BigInt div(const BigInt& a, const BigInt& b, BigInt* rem_out) {
    if (BigInt::cmp(a, b) < 0) { if (rem_out) *rem_out = a; return BigInt(0); }
    BigInt q, r;
    int top = a.bit_length();
    q.v.assign((top + 31) / 32, 0);
    for (int i = top - 1; i >= 0; --i) {
        uint32_t carry = 0;
        for (size_t k = 0; k < r.v.size(); ++k) {
            uint64_t s = (uint64_t(r.v[k]) << 1) | carry;
            r.v[k] = uint32_t(s);
            carry = uint32_t(s >> 32);
        }
        if (carry) r.v.push_back(carry);
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

int cmp_s(const SignedBI& a, const SignedBI& b) {
    if (a.neg != b.neg) {
        bool a_zero = a.val.is_zero(), b_zero = b.val.is_zero();
        if (a_zero && b_zero) return 0;
        return a.neg ? -1 : 1;
    }
    int c = BigInt::cmp(a.val, b.val);
    return a.neg ? -c : c;
}

SignedBI add_s(const SignedBI& a, const SignedBI& b) {
    SignedBI r;
    if (a.neg == b.neg) { r.val = add(a.val, b.val); r.neg = a.neg && !r.val.is_zero(); return r; }
    int c = BigInt::cmp(a.val, b.val);
    if (c >= 0) { r.val = sub(a.val, b.val); r.neg = a.neg && !r.val.is_zero(); }
    else        { r.val = sub(b.val, a.val); r.neg = b.neg && !r.val.is_zero(); }
    return r;
}

SignedBI sub_s(const SignedBI& a, const SignedBI& b) {
    SignedBI nb = b; if (!nb.val.is_zero()) nb.neg = !nb.neg;
    return add_s(a, nb);
}

SignedBI mul_s(const SignedBI& a, const SignedBI& b) {
    SignedBI r; r.val = mul(a.val, b.val);
    r.neg = (a.neg != b.neg) && !r.val.is_zero();
    return r;
}

BigInt mod_inverse(const BigInt& a_in, const BigInt& n) {
    SignedBI old_r{a_in, false}, r{n, false};
    SignedBI old_s{BigInt(1), false}, s{BigInt(0), false};
    while (!r.val.is_zero()) {
        BigInt rem;
        BigInt q = div(old_r.val, r.val, &rem);
        SignedBI sq; sq.val = q; sq.neg = (old_r.neg != r.neg);
        SignedBI mul_qr = mul_s(sq, r);
        SignedBI new_r  = sub_s(old_r, mul_qr);
        old_r = r; r = new_r;
        SignedBI mul_qs = mul_s(sq, s);
        SignedBI new_s  = sub_s(old_s, mul_qs);
        old_s = s; s = new_s;
    }
    if (BigInt::cmp(old_r.val, BigInt(1)) != 0) return BigInt(0);
    SignedBI res = old_s;
    while (res.neg && !res.val.is_zero()) res = add_s(res, SignedBI{n, false});
    res.val = mod(res.val, n);
    return res.val;
}

}  // namespace bn
