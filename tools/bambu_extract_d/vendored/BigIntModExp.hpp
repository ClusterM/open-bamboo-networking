// BigIntModExp.hpp — fixed-size RSA-2048 modular exponentiation.
//
// One entry point; no class state. Used by NativeSigner to compute the
// raw RSA sign: out = base^exp mod n, where all three operands fit in
// 2048 bits.
//
// Big-endian byte order matches RSA standard and the slicer key's hex
// representation.

#pragma once

#include <cstddef>
#include <cstdint>

namespace bambu_signing {

// Compute out_be = base_be ^ exp_be mod mod_be. All bigints are 256-byte
// big-endian. exp_be may be shorter than 256 bytes and may contain
// leading zeros. mod_be must be odd.
//
// Throws std::runtime_error if the modulus is even (we use Montgomery).
void big_modexp_rsa2048(const std::uint8_t base_be[256],
                        const std::uint8_t* exp_be,
                        std::size_t exp_len,
                        const std::uint8_t mod_be[256],
                        std::uint8_t out_be[256]);

}  // namespace bambu_signing
