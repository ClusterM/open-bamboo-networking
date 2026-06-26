#include "reconstruct.h"
#include <cstring>
#include "vendored/Sha256Portable.hpp"
#include "vendored/BigIntModExp.hpp"

bool factor_one(const bn::BigInt& dp_cand,
                int E,
                const bn::BigInt& N,
                int max_k,
                bn::BigInt& p_out,
                bn::BigInt& q_out,
                int& k_out) {
    if (dp_cand.is_zero()) return false;
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
        bn::BigInt N_rem = bn::mod(N, p);
        if (!N_rem.is_zero()) continue;
        bn::BigInt other = bn::div(N, p);
        bn::BigInt prod = bn::mul(other, p);
        if (bn::BigInt::cmp(prod, N) != 0) continue;
        if (bn::BigInt::cmp(other, bn::BigInt(1)) <= 0) continue;
        p_out = p; q_out = other; k_out = k;
        return true;
    }
    return false;
}

bool compute_d(const bn::BigInt& p, const bn::BigInt& q, int E, bn::BigInt& d) {
    bn::BigInt p_minus_1 = bn::sub(p, bn::BigInt(1));
    bn::BigInt q_minus_1 = bn::sub(q, bn::BigInt(1));
    bn::BigInt phi = bn::mul(p_minus_1, q_minus_1);
    d = bn::mod_inverse(bn::BigInt(uint32_t(E)), phi);
    return !d.is_zero();
}

int validate_envelopes(const bn::BigInt& d, const bn::BigInt& N,
                       const std::vector<Envelope>& envs,
                       int* first_fail_ix) {
    uint8_t N_be[256], d_be[256];
    bn::to_bytes_be_fixed(N, N_be, 256);
    bn::to_bytes_be_fixed(d, d_be, 256);
    size_t d_first = 0;
    while (d_first < 256 && d_be[d_first] == 0) ++d_first;
    size_t exp_len = 256 - d_first;
    const uint8_t* exp_ptr = d_be + d_first;

    int passed = 0;
    for (size_t ix = 0; ix < envs.size(); ++ix) {
        const auto& env = envs[ix];
        auto h = bambu_signing::Sha256Portable::hash(env.to_sign);
        uint8_t EM[256];
        pkcs1_v15_pad_sha256(h.data(), EM);
        uint8_t sig[256];
        bambu_signing::big_modexp_rsa2048(EM, exp_ptr, exp_len, N_be, sig);
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

DRecon reconstruct(const std::vector<uint8_t>& stream,
                   const bn::BigInt& N,
                   int E,
                   int max_k,
                   const std::vector<Envelope>& head_envs,
                   int min_matches) {
    DRecon R;
    if (stream.size() != 256) return R;

    const int H = 128;
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
            bn::BigInt p2, q2; int k2 = 0;
            if (factor_one(dq, E, N, max_k, p2, q2, k2)) {
                p = q2; q = p2; k = k2;
                got = true;
            }
        }
        if (!got) continue;

        bn::BigInt d;
        if (!compute_d(p, q, E, d)) continue;

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
