#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "bigint.h"
#include "envelope.h"

// ===========================================================================
// Factor recovery + d reconstruction
// ===========================================================================

struct DRecon {
    bool ok = false;
    bn::BigInt p, q, dp, dq, d;
    int k_found = 0;
    std::string mode;  // C_crt_be (dp=first half, dq=second half) or D_crt_be_swap
};

bool factor_one(const bn::BigInt& dp_cand,
                int E,
                const bn::BigInt& N,
                int max_k,
                bn::BigInt& p_out,
                bn::BigInt& q_out,
                int& k_out);

bool compute_d(const bn::BigInt& p, const bn::BigInt& q, int E, bn::BigInt& d);

int validate_envelopes(const bn::BigInt& d, const bn::BigInt& N,
                       const std::vector<Envelope>& envs,
                       int* first_fail_ix = nullptr);

DRecon reconstruct(const std::vector<uint8_t>& stream,
                   const bn::BigInt& N,
                   int E,
                   int max_k,
                   const std::vector<Envelope>& head_envs,
                   int min_matches);
