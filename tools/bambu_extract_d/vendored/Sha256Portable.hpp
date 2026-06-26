// Sha256Portable.hpp — header-only portable SHA-256.
//
// Drop-in for environments where libcrypto isn't available (Windows
// MinGW cross-build). Identical output to OpenSSL SHA256().

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

namespace bambu_signing {

class Sha256Portable {
public:
    Sha256Portable() { reset(); }

    void reset() {
        m_state[0] = 0x6a09e667u; m_state[1] = 0xbb67ae85u;
        m_state[2] = 0x3c6ef372u; m_state[3] = 0xa54ff53au;
        m_state[4] = 0x510e527fu; m_state[5] = 0x9b05688cu;
        m_state[6] = 0x1f83d9abu; m_state[7] = 0x5be0cd19u;
        m_bitlen = 0;
        m_buflen = 0;
    }

    void update(const std::uint8_t* data, std::size_t len) {
        while (len > 0) {
            std::size_t cap = 64 - m_buflen;
            std::size_t take = (len < cap) ? len : cap;
            std::memcpy(m_buf + m_buflen, data, take);
            m_buflen += take;
            data += take;
            len -= take;
            m_bitlen += static_cast<std::uint64_t>(take) * 8;
            if (m_buflen == 64) {
                transform(m_buf);
                m_buflen = 0;
            }
        }
    }

    void update(const std::string& s) {
        update(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
    }

    void final_bytes(std::uint8_t out[32]) {
        // Append 0x80, pad with zeros, append 8-byte big-endian bitlen.
        m_buf[m_buflen++] = 0x80;
        if (m_buflen > 56) {
            while (m_buflen < 64) m_buf[m_buflen++] = 0;
            transform(m_buf);
            m_buflen = 0;
        }
        while (m_buflen < 56) m_buf[m_buflen++] = 0;
        std::uint64_t bl = m_bitlen;
        for (int i = 0; i < 8; ++i) {
            m_buf[56 + i] = static_cast<std::uint8_t>(bl >> (56 - 8 * i));
        }
        transform(m_buf);
        for (int i = 0; i < 8; ++i) {
            out[4 * i + 0] = static_cast<std::uint8_t>(m_state[i] >> 24);
            out[4 * i + 1] = static_cast<std::uint8_t>(m_state[i] >> 16);
            out[4 * i + 2] = static_cast<std::uint8_t>(m_state[i] >> 8);
            out[4 * i + 3] = static_cast<std::uint8_t>(m_state[i]);
        }
        reset();
    }

    static std::array<std::uint8_t, 32> hash(const std::uint8_t* data,
                                              std::size_t len) {
        Sha256Portable h;
        h.update(data, len);
        std::array<std::uint8_t, 32> out{};
        h.final_bytes(out.data());
        return out;
    }

    static std::array<std::uint8_t, 32> hash(const std::string& s) {
        return hash(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
    }

private:
    static std::uint32_t rotr(std::uint32_t x, std::uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    void transform(const std::uint8_t blk[64]) {
        static const std::uint32_t K[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
            0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
            0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
            0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
            0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
            0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
            0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
            0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
            0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
            0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
            0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
            0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
            0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u };
        std::uint32_t W[64];
        for (int i = 0; i < 16; ++i) {
            W[i] = (static_cast<std::uint32_t>(blk[4*i]) << 24)
                 | (static_cast<std::uint32_t>(blk[4*i+1]) << 16)
                 | (static_cast<std::uint32_t>(blk[4*i+2]) << 8)
                 |  static_cast<std::uint32_t>(blk[4*i+3]);
        }
        for (int i = 16; i < 64; ++i) {
            std::uint32_t s0 = rotr(W[i-15], 7) ^ rotr(W[i-15], 18) ^ (W[i-15] >> 3);
            std::uint32_t s1 = rotr(W[i-2], 17) ^ rotr(W[i-2], 19) ^ (W[i-2] >> 10);
            W[i] = W[i-16] + s0 + W[i-7] + s1;
        }
        std::uint32_t a=m_state[0],b=m_state[1],c=m_state[2],d=m_state[3];
        std::uint32_t e=m_state[4],f=m_state[5],g=m_state[6],h=m_state[7];
        for (int i = 0; i < 64; ++i) {
            std::uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            std::uint32_t ch = (e & f) ^ (~e & g);
            std::uint32_t t1 = h + S1 + ch + K[i] + W[i];
            std::uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            std::uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            std::uint32_t t2 = S0 + mj;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        m_state[0]+=a; m_state[1]+=b; m_state[2]+=c; m_state[3]+=d;
        m_state[4]+=e; m_state[5]+=f; m_state[6]+=g; m_state[7]+=h;
    }

    std::uint32_t m_state[8] {};
    std::uint64_t m_bitlen {0};
    std::uint8_t  m_buf[64] {};
    std::size_t   m_buflen {0};
};

}  // namespace bambu_signing
