// TUTK IOTC client for the printer's camera: LAN search, master JOIN and
// rendezvous (direct P2P when possible, relay otherwise), DTLS-PSK and the
// DTLS ApplicationData channel the AV layer (TutkSession) runs on.
// See research/08.11 for the wire format.

#include "obn/net_compat.hpp"
#include "obn/endian_compat.hpp"   // htole32/le32toh etc. — <endian.h> is POSIX-only

#include "IotcProtocol.hpp"

#if defined(_WIN32)
#include <iphlpapi.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#endif

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include "obn/log.hpp"

namespace obn {
namespace camera {
namespace tutk {

// ==========================================================================
// Windows / MSVC portability shim
// ==========================================================================
//
// This translation unit is written against POSIX sockets (ssize_t,
// struct-timeval SO_RCVTIMEO, errno-based EAGAIN checks). obn/net_compat.hpp
// pulls in winsock2 and gives us socket_t / close_socket / kInvalid; the
// in-namespace sendto/recvfrom/setsockopt wrappers below let the bare calls
// in this file keep POSIX semantics on Windows.
//
// The wrappers:
//   * take void* / const void* buffers (Winsock wants char*; this casts),
//   * return ssize_t,
//   * translate WSAGetLastError() into a POSIX errno value (EWOULDBLOCK /
//     ETIMEDOUT / EINTR / EBADF) after a failed call, so the existing
//     `errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT`
//     timeout checks keep working unchanged.
#if defined(_WIN32)

#if defined(_MSC_VER) && !defined(__MINGW32__)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

#ifndef EWOULDBLOCK
#  define EWOULDBLOCK WSAEWOULDBLOCK
#endif
#ifndef ETIMEDOUT
#  define ETIMEDOUT WSAETIMEDOUT
#endif

namespace win_compat {

// Map the last WinSock error onto errno so POSIX-style `errno == EAGAIN`
// checks in this file behave correctly.  Called only on the error path.
inline void set_errno_from_wsa()
{
    int e = ::WSAGetLastError();
    switch (e) {
        case WSAEWOULDBLOCK: errno = EAGAIN;     break;
        case WSAETIMEDOUT:   errno = ETIMEDOUT;  break;
        case WSAEINTR:       errno = EINTR;      break;
        case WSAENOTSOCK:
        case WSAEBADF:       errno = EBADF;      break;
        default:             errno = e;          break;
    }
}

} // namespace win_compat

inline ssize_t sendto(obn::net::socket_t s, const void* buf, size_t len, int flags,
                      const struct sockaddr* to, int tolen)
{
    int r = ::sendto(s, static_cast<const char*>(buf), static_cast<int>(len),
                     flags, to, tolen);
    if (r < 0) win_compat::set_errno_from_wsa();
    return r;
}

inline ssize_t recvfrom(obn::net::socket_t s, void* buf, size_t len, int flags,
                        struct sockaddr* from, int* fromlen)
{
    int r = ::recvfrom(s, static_cast<char*>(buf), static_cast<int>(len),
                       flags, from, fromlen);
    if (r < 0) win_compat::set_errno_from_wsa();
    return r;
}

// Winsock's setsockopt() takes the option blob as `const char*`; POSIX takes
// `const void*`.  This wrapper lets the bare setsockopt() call sites in this
// file pass int* / sockaddr-ish pointers unchanged.  NOTE: SO_RCVTIMEO /
// SO_SNDTIMEO are handled separately (DWORD-ms vs struct timeval) and must NOT
// go through this path with a timeval.
inline int setsockopt(obn::net::socket_t s, int level, int optname,
                      const void* optval, int optlen)
{
    return ::setsockopt(s, level, optname,
                        static_cast<const char*>(optval), optlen);
}

#else
using ::sendto;
using ::recvfrom;
#endif // _WIN32

// getaddrinfo error string: on Windows `gai_strerror` is a UNICODE-aware
// macro that can resolve to gai_strerrorW (wchar_t*).  Force the ANSI variant
// so the result is always a `const char*` printable with %s.
#if defined(_WIN32)
inline const char* gai_strerror_portable(int rc) { return ::gai_strerrorA(rc); }
#else
inline const char* gai_strerror_portable(int rc) { return ::gai_strerror(rc); }
#endif

// Portable receive timeout: POSIX uses struct timeval, Winsock uses a DWORD
// of milliseconds for SO_RCVTIMEO/SO_SNDTIMEO.
inline void set_socket_recv_timeout(obn::net::socket_t fd, int ms)
{
#if defined(_WIN32)
    DWORD tv = static_cast<DWORD>(ms < 0 ? 0 : ms);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

// ==========================================================================
// Internal utilities
// ==========================================================================

static uint32_t rand32()
{
    // Non-cryptographic random for packet nonces the printer only echoes.
    static uint64_t state = 0;
    if (!state) { RAND_bytes((unsigned char*)&state, sizeof(state)); }
    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
    return (uint32_t)state;
}

// ==========================================================================
// UDP socket helpers
// ==========================================================================

static void set_recv_timeout(obn::net::socket_t fd, int ms)
{
    set_socket_recv_timeout(fd, ms);
}

// ==========================================================================
// TransCodePartial — TUTK datagram obfuscation
// ==========================================================================
//
//   KEY = "Charlie is the d" (16 bytes, a fixed string in the SDK)
//
// Algorithm (16-byte blocks):
//   rot[] = {1, 5, 9, 13}  (rotation amounts per dword)
//
//   decode_block(raw[16]) → plain[16]:
//     1. dw[i] = ROR32(raw_dw[i], rot[i]) ^ key_dw[i]    i=0..3
//        (raw_dw read as little-endian uint32_t)
//     2. t[j*4+k] = (dw[j] >> (8*k)) & 0xff              expand to bytes
//     3. o0 = ROR32((t[15]<<24)|(t[8]<<16)|(t[9]<<8)|t[11], 3)
//        o1 = ROR32((t[14]<<24)|(t[12]<<16)|(t[10]<<8)|t[13], 7)
//        o2 = ROR32((t[0]<<24)|(t[5]<<16)|(t[1]<<8)|t[2], 11)
//        o3 = ROR32((t[3]<<24)|(t[7]<<16)|(t[4]<<8)|t[6], 15)
//     4. Write o0..o3 as LE bytes → 16 plaintext bytes
//
//   encode_block is the exact inverse (verified: decode(encode(x)) == x).
//
//   Tail bytes (len % 16 != 0): XOR each with KEY[i % 16].

static const uint8_t kTransKey[16] = {
    'C','h','a','r','l','i','e',' ','i','s',' ','t','h','e',' ','d'
};

static inline uint32_t ror32(uint32_t v, unsigned n) { n &= 31; return (v >> n) | (v << (32-n)); }
static inline uint32_t rol32(uint32_t v, unsigned n) { n &= 31; return (v << n) | (v >> (32-n)); }

static inline uint32_t read_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}
static inline uint16_t read_be16(const uint8_t* p) {
    return ((uint16_t)p[0] << 8) | p[1];
}
static inline uint64_t read_be48(const uint8_t* p) {
    return ((uint64_t)p[0] << 40) | ((uint64_t)p[1] << 32)
         | ((uint64_t)p[2] << 24) | ((uint64_t)p[3] << 16)
         | ((uint64_t)p[4] <<  8) |  (uint64_t)p[5];
}

static void decode_block(const uint8_t* in, uint8_t* out)
{
    const uint8_t* k = kTransKey;
    const unsigned rot[4] = {1, 5, 9, 13};

    uint32_t o[4];
    memcpy(o, in, 16);

    uint32_t tmp0 = rol32(o[0], 3);
    uint32_t tmp1 = rol32(o[1], 7);
    uint32_t tmp2 = rol32(o[2], 11);
    uint32_t tmp3 = rol32(o[3], 15);

    uint8_t t[16];
    t[0]  = (tmp2 >> 24) & 0xff;
    t[1]  = (tmp2 >>  8) & 0xff;
    t[2]  = (tmp2 >>  0) & 0xff;
    t[3]  = (tmp3 >> 24) & 0xff;
    t[4]  = (tmp3 >>  8) & 0xff;
    t[5]  = (tmp2 >> 16) & 0xff;
    t[6]  = (tmp3 >>  0) & 0xff;
    t[7]  = (tmp3 >> 16) & 0xff;
    t[8]  = (tmp0 >> 16) & 0xff;
    t[9]  = (tmp0 >>  8) & 0xff;
    t[10] = (tmp1 >>  8) & 0xff;
    t[11] = (tmp0 >>  0) & 0xff;
    t[12] = (tmp1 >> 16) & 0xff;
    t[13] = (tmp1 >>  0) & 0xff;
    t[14] = (tmp1 >> 24) & 0xff;
    t[15] = (tmp0 >> 24) & 0xff;

    uint32_t dw[4];
    for (int j = 0; j < 4; ++j)
        dw[j] = (uint32_t)t[j*4]
              | ((uint32_t)t[j*4+1] << 8)
              | ((uint32_t)t[j*4+2] << 16)
              | ((uint32_t)t[j*4+3] << 24);

    uint32_t key_dw[4];
    memcpy(key_dw, k, 16);

    uint32_t raw_dw[4];
    for (int i = 0; i < 4; ++i)
        raw_dw[i] = rol32(dw[i] ^ key_dw[i], rot[i]);

    memcpy(out, raw_dw, 16);
}

static void encode_block(const uint8_t* in, uint8_t* out)
{
    const uint8_t* k = kTransKey;
    const unsigned rot[4] = {1, 5, 9, 13};

    uint32_t raw_dw[4];
    memcpy(raw_dw, in, 16);

    uint32_t key_dw[4];
    memcpy(key_dw, k, 16);

    uint32_t dw[4];
    for (int i = 0; i < 4; ++i)
        dw[i] = ror32(raw_dw[i], rot[i]) ^ key_dw[i];

    uint8_t t[16];
    for (int j = 0; j < 4; ++j)
        for (int b = 0; b < 4; ++b)
            t[j*4+b] = (dw[j] >> (8*b)) & 0xff;

    uint32_t o0 = ror32((uint32_t)(t[15]<<24)|(t[8]<<16)|(t[9]<<8)|t[11], 3);
    uint32_t o1 = ror32((uint32_t)(t[14]<<24)|(t[12]<<16)|(t[10]<<8)|t[13], 7);
    uint32_t o2 = ror32((uint32_t)(t[0]<<24)|(t[5]<<16)|(t[1]<<8)|t[2], 11);
    uint32_t o3 = ror32((uint32_t)(t[3]<<24)|(t[7]<<16)|(t[4]<<8)|t[6], 15);

    memcpy(out,    &o0, 4);
    memcpy(out+4,  &o1, 4);
    memcpy(out+8,  &o2, 4);
    memcpy(out+12, &o3, 4);
}

static const uint8_t kTailPerm8[8] = {7, 4, 3, 2, 1, 6, 5, 0};

static void reverse_trans_code_partial(uint8_t* data, size_t len)
{
    size_t full = (len / 16) * 16;
    uint8_t tmp[16];
    for (size_t i = 0; i < full; i += 16) {
        decode_block(data + i, tmp);
        memcpy(data + i, tmp, 16);
    }
    size_t rem = len - full;
    if (rem == 8) {
        uint8_t tail[8];
        for (size_t k = 0; k < 8; ++k) {
            tail[kTailPerm8[k]] = data[full + k] ^ kTransKey[kTailPerm8[k]];
        }
        memcpy(data + full, tail, 8);
    } else {
        for (size_t i = full; i < len; ++i)
            data[i] ^= kTransKey[i % 16];
    }
}

static void trans_code_partial(uint8_t* data, size_t len)
{
    size_t full = (len / 16) * 16;
    uint8_t tmp[16];
    for (size_t i = 0; i < full; i += 16) {
        encode_block(data + i, tmp);
        memcpy(data + i, tmp, 16);
    }
    size_t rem = len - full;
    if (rem == 8) {
        uint8_t tail[8];
        for (size_t k = 0; k < 8; ++k) {
            tail[k] = data[full + kTailPerm8[k]] ^ kTransKey[kTailPerm8[k]];
        }
        memcpy(data + full, tail, 8);
    } else {
        for (size_t i = full; i < len; ++i)
            data[i] ^= kTransKey[i % 16];
    }
}

// Control packets (header byte [3] = 0x02) are scrambled whole; data packets
// ([3] = 0x0b, DTLS inside) only in their first 64 bytes.
static constexpr size_t kDataScrambleLen = 64;

static void descramble_rx(uint8_t* data, size_t len)
{
    if (len < 16) {
        reverse_trans_code_partial(data, len);
        return;
    }
    reverse_trans_code_partial(data, 16);
    const size_t end = (data[3] == 0x0b) ? std::min(len, kDataScrambleLen) : len;
    reverse_trans_code_partial(data + 16, end - 16);
}

#ifdef OBN_TESTING
void trans_code_partial_test(uint8_t* data, size_t len)         { trans_code_partial(data, len); }
void reverse_trans_code_partial_test(uint8_t* data, size_t len) { reverse_trans_code_partial(data, len); }
#endif

// ==========================================================================
// IOTC DTLS frame encoder / decoder
// ==========================================================================
//
// DTLS records travel behind a 28-byte IOTC header + sub-header; only the
// first 64 bytes of the datagram are scrambled.
//
// IOTC header (16 bytes):
//   [0..1]  04 02 magic, [2] 0x1c, [3] 0x0b (DTLS payload)
//   [4..5]  payload length LE (= 12 + DTLS length)
//   [6..7]  per-direction datagram counter
//   [8..10] message type: 07 04 21 client -> printer, 08 04 12 back
//           (04 05 24 / 03 05 42 through the relay)
//   [12..13] session token [0..1], [14..15] 00 01
//
// Sub-header (12 bytes):
//   [0]     0x0c
//   [1..2]  epoch, big-endian (0 on the LAN path)
//   [3]     0x00
//   [4..11] session token

static int send_dtls_packet(obn::net::socket_t sock, const struct sockaddr_in* dst,
                             uint32_t epoch,
                             const uint8_t session_token[8],
                             const uint8_t* dtls_data, size_t dtls_len,
                             uint16_t pkt_seq, uint32_t relay_tag = 0)
{
    if (dtls_len > 0xffff - 12) return -1;
    size_t total = 28 + dtls_len;
    std::vector<uint8_t> pkt(total, 0);

    uint16_t payload_len = (uint16_t)(12 + dtls_len);
    bool is_relay = (dst && ntohs(dst->sin_port) == 3478);

    // IOTC header
    pkt[0] = 0x04; pkt[1] = 0x02;
    pkt[2] = 0x1c;
    pkt[3] = 0x0b;
    pkt[4] = (uint8_t)(payload_len & 0xff);
    pkt[5] = (uint8_t)(payload_len >> 8);

    // Per-direction datagram counter; the printer drops a repeated value as a
    // retransmission.
    pkt[6] = (uint8_t)(pkt_seq & 0xff);
    pkt[7] = (uint8_t)(pkt_seq >> 8);

    if (is_relay) {
        pkt[8]  = 0x04; pkt[9]  = 0x05; pkt[10] = 0x24;
        pkt[11] = 0x00;
        pkt[12] = (uint8_t)(relay_tag & 0xff);
        pkt[13] = (uint8_t)((relay_tag >> 8) & 0xff);
        pkt[14] = (uint8_t)((relay_tag >> 16) & 0xff);
        pkt[15] = 0x01;

        // Sub-header (12 bytes)
        pkt[16] = 0x0c;
        pkt[17] = 0x00;
        pkt[18] = 0x00;
        pkt[19] = 0x00;
        memcpy(pkt.data() + 20, session_token, 8);
    } else {
        pkt[8]  = 0x07; pkt[9]  = 0x04; pkt[10] = 0x21;
        pkt[11] = 0x00;
        pkt[12] = session_token[0];
        pkt[13] = session_token[1];
        pkt[14] = 0x00; pkt[15] = 0x01;

        // Sub-header
        pkt[16] = 0x0c;
        pkt[17] = (uint8_t)((epoch >> 8) & 0xff);  // epoch low16, big-endian
        pkt[18] = (uint8_t)(epoch & 0xff);
        pkt[19] = 0x00;
        memcpy(pkt.data() + 20, session_token, 8);
    }

    // DTLS payload
    if (dtls_len > 0)
        memcpy(pkt.data() + 28, dtls_data, dtls_len);

    trans_code_partial(pkt.data(), std::min(total, kDataScrambleLen));

    ssize_t n = sendto(sock, pkt.data(), total, 0,
                       (const struct sockaddr*)dst, sizeof(*dst));
    return (n == (ssize_t)total) ? 0 : -1;
}

// Retries on non-DTLS IOTC packets (e.g., stray type 0x33 echoes before ServerHello).
// Returns DTLS payload length on success, -1 on timeout/error.
static int recv_dtls_packet(obn::net::socket_t sock, const struct sockaddr_in* peer,
                             uint8_t* dtls_out, size_t buf_size,
                             uint32_t* epoch_out,
                             uint8_t session_token_out[8],
                             int timeout_ms)
{
    set_recv_timeout(sock, 100);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    while (std::chrono::steady_clock::now() < deadline) {
        uint8_t raw[2048];
        struct sockaddr_in src{};
        socklen_t src_len = sizeof(src);
        ssize_t n = recvfrom(sock, raw, sizeof(raw), 0,
                              (struct sockaddr*)&src, &src_len);
        if (n < 24) continue;

        // Ignore stray packets from other rendezvous servers or unknown peers
        if (peer && (src.sin_addr.s_addr != peer->sin_addr.s_addr ||
                     src.sin_port != peer->sin_port)) {
            continue;
        }

        descramble_rx(raw, (size_t)n);

        if (raw[0] != 0x04 || raw[1] != 0x02) continue;  // discard non-IOTC

        // Relay keepalive ping: 0x23 0x05 0x42 (24 bytes)
        if (n == 24 && raw[8] == 0x23 && raw[9] == 0x05 && raw[10] == 0x42) {
            uint8_t pong[24];
            memcpy(pong, raw, 24);
            pong[2] = 0x1c;
            pong[8] = 0x24; pong[9] = 0x05; pong[10] = 0x24;
            trans_code_partial(pong, sizeof(pong));
            obn::camera::tutk::sendto(sock, pong, sizeof(pong), 0,
                                        (const struct sockaddr*)&src, (int)sizeof(src));
            OBN_DEBUG("iotc dtls: answered relay ping 23 05 42 with pong 24 05 24 during handshake");
            continue;
        }

        if (n < 28) continue;

        // Skip non-DTLS IOTC packets (type 0x33 echoes, stray rendezvous packets):
        // DTLS content starts with 0x16 (Handshake), 0x14 (CCS), or 0x15 (Alert).
        size_t dtls_len = (size_t)(n - 28);
        if (dtls_len < 1 || (raw[28] != 0x16 && raw[28] != 0x14 && raw[28] != 0x15)) {
            OBN_DEBUG("iotc dtls: recv: skipping non-DTLS IOTC pkt (n=%zd type=0x%02x)", n, dtls_len > 0 ? raw[28] : 0);
            continue;
        }

        if (epoch_out) {
            uint32_t ep = 0;
            if (raw[8] == 0x03 && raw[9] == 0x05 && raw[10] == 0x42) {
                if (n >= 33) ep = ((uint32_t)raw[31] << 8) | raw[32];
            } else {
                ep = ((uint32_t)raw[17] << 8) | raw[18];
            }
            *epoch_out = ep;
        }
        if (session_token_out)
            memcpy(session_token_out, raw + 20, 8);

        if (dtls_len > buf_size) {
            OBN_WARN("iotc dtls: recv: dropping oversized record (%zu > %zu)", dtls_len, buf_size);
            continue;
        }
        memcpy(dtls_out, raw + 28, dtls_len);
        return (int)dtls_len;
    }
    return -1;
}

// 02 04 33 control packet (52 bytes), sent between ClientHello and
// ServerHello on the off-LAN direct path; the printer echoes it back.
//   [16..35] UID, [36..43] session token, rest zero.

static int send_ctrl0x33(obn::net::socket_t sock, const struct sockaddr_in* dst,
                          const char* uid_upper,
                          const uint8_t session_token[8])
{
    uint8_t pkt[52];
    memset(pkt, 0, sizeof(pkt));

    pkt[0] = 0x04; pkt[1] = 0x02;
    pkt[2] = 0x1c;
    pkt[3] = 0x02;  // flags=0x02 for control packets
    pkt[4] = 0x24;  // payload_len=36 LE
    pkt[8]  = 0x02; pkt[9]  = 0x04; pkt[10] = 0x33;

    memcpy(pkt + 16, uid_upper, kUidLen);
    memcpy(pkt + 36, session_token, 8);

    trans_code_partial(pkt, sizeof(pkt));

    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0,
                       (const struct sockaddr*)dst, sizeof(*dst));
    return (n == sizeof(pkt)) ? 0 : -1;
}

// ==========================================================================
// DTLS-PSK handshake — TUTK custom wire format
// ==========================================================================
//
// Standard DTLS 1.2 records and handshake headers inside the IOTC framing
// (see send_dtls_packet).
//
//   Cipher suites: 0xC038 (ECDHE_PSK_WITH_AES_256_CBC_SHA384, with
//   Encrypt-then-MAC) and 0xCCAC (ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256),
//   both with Extended Master Secret and X25519.
//
//   PSK identity: "AUTHPWD_" + account ("AUTHPWD_admin").
//   PSK: SHA256 of the URL's "passwd" value, zero-filled from its first 0x00
//   byte on (the printer keeps the digest as a C string), 32 bytes long.
//
//   ServerKeyExchange body (RFC 5489):
//     psk_hint_len(2=0) + curve_type(1=3) + named_curve(2=0x001d) + key_len(1=32) + key(32)
//   ClientKeyExchange body:
//     psk_id_len(2) + psk_identity(N) + ec_point_len(1) + client_pub_key(32)
//
// Flights:
//   C -> P: ClientHello
//   P -> C: ServerHello + ServerKeyExchange + ServerHelloDone
//   C -> P: ClientKeyExchange + ChangeCipherSpec + Finished
//   P -> C: NewSessionTicket, ChangeCipherSpec, Finished (several datagrams)

// TLS 1.2 PRF: P_hash expansion (generic for SHA-256 or SHA-384).
// label_seed = label_bytes || seed_bytes
static bool tls12_prf_generic(const EVP_MD* md,
                               const uint8_t* secret, size_t secret_len,
                               const char* label,
                               const uint8_t* seed, size_t seed_len,
                               uint8_t* out, size_t out_len)
{
    size_t llen = strlen(label);
    std::vector<uint8_t> label_seed(llen + seed_len);
    memcpy(label_seed.data(), label, llen);
    memcpy(label_seed.data() + llen, seed, seed_len);

    uint8_t a[EVP_MAX_MD_SIZE];
    unsigned int md_len = (unsigned int)EVP_MD_size(md);
    unsigned int hmac_len = md_len;
    HMAC(md, secret, (int)secret_len,
         label_seed.data(), label_seed.size(), a, &hmac_len);

    size_t done = 0;
    while (done < out_len) {
        std::vector<uint8_t> hmac_in(md_len + label_seed.size());
        memcpy(hmac_in.data(), a, md_len);
        memcpy(hmac_in.data() + md_len, label_seed.data(), label_seed.size());

        uint8_t block[EVP_MAX_MD_SIZE];
        HMAC(md, secret, (int)secret_len,
             hmac_in.data(), hmac_in.size(), block, &hmac_len);

        size_t copy = std::min((size_t)md_len, out_len - done);
        memcpy(out + done, block, copy);
        done += copy;

        HMAC(md, secret, (int)secret_len, a, md_len, a, &hmac_len);
    }
    return true;
}

static bool tls12_prf(const uint8_t* secret, size_t secret_len,
                       const char* label,
                       const uint8_t* seed, size_t seed_len,
                       uint8_t* out, size_t out_len)
{
    return tls12_prf_generic(EVP_sha256(), secret, secret_len, label, seed, seed_len, out, out_len);
}

static bool tls12_prf_sha384(const uint8_t* secret, size_t secret_len,
                              const char* label,
                              const uint8_t* seed, size_t seed_len,
                              uint8_t* out, size_t out_len)
{
    return tls12_prf_generic(EVP_sha384(), secret, secret_len, label, seed, seed_len, out, out_len);
}

// Build a 12-byte DTLS nonce for the TUTK ChaCha20-Poly1305 AEAD format:
//   nonce = iv XOR (0x00[4B] || epoch[2B BE] || seq[6B BE]) (RFC 7905)
static void build_relay_nonce(uint8_t nonce[12], const uint8_t iv[12],
                               uint16_t epoch, uint64_t seq)
{
    memcpy(nonce, iv, 12);
    nonce[4] ^= (uint8_t)(epoch >> 8);
    nonce[5] ^= (uint8_t)(epoch     );
    for (int i = 0; i < 6; ++i)
        nonce[6 + i] ^= (uint8_t)(seq >> (40 - 8*i));
}

#ifdef OBN_TESTING
void build_relay_nonce_test(uint8_t nonce[12], const uint8_t iv[12],
                             uint32_t epoch, uint64_t seq)
{
    build_relay_nonce(nonce, iv, (uint16_t)epoch, seq);
}
#endif

// Build a standard DTLS 1.2 record header (13 bytes).
// Field layout: version=0xFEFD, epoch=2B, seq=6B.
static void build_dtls_record_hdr(uint8_t* buf, uint8_t content_type,
                                   uint16_t epoch, uint64_t seq, uint16_t length)
{
    buf[0] = content_type;
    buf[1] = 0xfe; buf[2] = 0xfd;              // DTLS 1.2
    buf[3] = (uint8_t)(epoch >> 8);            // epoch (2 bytes, big-endian)
    buf[4] = (uint8_t)(epoch     );
    buf[5] = (uint8_t)(seq >> 40);             // seq (6 bytes, big-endian)
    buf[6] = (uint8_t)(seq >> 32);
    buf[7] = (uint8_t)(seq >> 24);
    buf[8] = (uint8_t)(seq >> 16);
    buf[9] = (uint8_t)(seq >>  8);
    buf[10]= (uint8_t)(seq       );
    buf[11]= (uint8_t)(length >> 8);
    buf[12]= (uint8_t)(length     );
}

// Build a standard DTLS 1.2 handshake header (12 bytes).
// Field layout: frag_offset=3B, frag_len=3B (standard, not TUTK-custom).
static void build_dtls_hs_hdr(uint8_t* buf, uint8_t hs_type,
                                uint32_t body_len, uint16_t msg_seq)
{
    buf[0] = hs_type;
    buf[1] = (uint8_t)(body_len >> 16);
    buf[2] = (uint8_t)(body_len >>  8);
    buf[3] = (uint8_t)(body_len      );
    buf[4] = (uint8_t)(msg_seq >> 8);
    buf[5] = (uint8_t)(msg_seq     );
    buf[6] = 0; buf[7] = 0; buf[8] = 0;       // frag_offset = 0
    buf[9] = (uint8_t)(body_len >> 16);        // frag_len = body_len (no fragmentation)
    buf[10]= (uint8_t)(body_len >>  8);
    buf[11]= (uint8_t)(body_len      );
}

// TLS limit on a record's plaintext (RFC 5246 6.2.1).
static constexpr size_t kMaxRecordPlaintext = 16384;

struct CipherCtxFree { void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); } };
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxFree>;

// Additional data authenticated with each record, both as the EtM MAC prefix
// and as AEAD associated data: epoch || seq || type || version || length.
static void build_additional_data(uint8_t out[13], uint8_t content_type,
                                  uint16_t epoch, uint64_t seq, uint16_t length)
{
    out[0] = (uint8_t)(epoch >> 8);
    out[1] = (uint8_t)(epoch     );
    for (int i = 0; i < 6; ++i)
        out[2 + i] = (uint8_t)(seq >> (40 - 8*i));
    out[8]  = content_type;
    out[9]  = 0xfe; out[10] = 0xfd;
    out[11] = (uint8_t)(length >> 8);
    out[12] = (uint8_t)(length     );
}

static void etm_mac(const uint8_t* mac_key, const uint8_t ad[13],
                    const uint8_t* fragment, size_t fragment_len, uint8_t mac[48])
{
    std::vector<uint8_t> in(ad, ad + 13);
    in.insert(in.end(), fragment, fragment + fragment_len);
    unsigned int mac_len = 48;
    HMAC(EVP_sha384(), mac_key, 48, in.data(), in.size(), mac, &mac_len);
}

// AES-256-CBC with Encrypt-then-MAC (RFC 7366): IV || ciphertext || HMAC-SHA384.
static bool encrypt_record_cbc_etm(const uint8_t* key, const uint8_t* mac_key,
                                   uint8_t content_type, uint16_t epoch, uint64_t seq,
                                   const uint8_t* plain, size_t plain_len,
                                   std::vector<uint8_t>& out_rec)
{
    const size_t pad_len = 16 - (plain_len % 16);
    std::vector<uint8_t> fragment(16 + plain_len + pad_len);
    uint8_t* iv = fragment.data();
    if (RAND_bytes(iv, 16) != 1) return false;
    std::vector<uint8_t> padded(plain, plain + plain_len);
    padded.insert(padded.end(), pad_len, (uint8_t)(pad_len - 1));

    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    int outl = 0;
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key, iv) <= 0 ||
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0) <= 0 ||
        EVP_EncryptUpdate(ctx.get(), fragment.data() + 16, &outl,
                          padded.data(), (int)padded.size()) <= 0 ||
        (size_t)outl != padded.size())
        return false;

    uint8_t ad[13], mac[48];
    build_additional_data(ad, content_type, epoch, seq, (uint16_t)fragment.size());
    etm_mac(mac_key, ad, fragment.data(), fragment.size(), mac);

    uint8_t rec_hdr[13];
    build_dtls_record_hdr(rec_hdr, content_type, epoch, seq, (uint16_t)(fragment.size() + 48));
    out_rec.assign(rec_hdr, rec_hdr + 13);
    out_rec.insert(out_rec.end(), fragment.begin(), fragment.end());
    out_rec.insert(out_rec.end(), mac, mac + 48);
    return true;
}

static int decrypt_record_cbc_etm(const uint8_t* key, const uint8_t* mac_key,
                                  const uint8_t* rec_hdr,
                                  const uint8_t* payload, size_t payload_len,
                                  uint8_t* plain_out, size_t plain_max)
{
    const uint16_t epoch    = read_be16(rec_hdr + 3);
    const uint64_t seq      = read_be48(rec_hdr + 5);
    const uint16_t wire_len = read_be16(rec_hdr + 11);
    if (payload_len < wire_len || wire_len < 16 + 16 + 48) return -1;

    const size_t frag_len   = wire_len - 48;
    const size_t cipher_len = frag_len - 16;
    if (cipher_len % 16 != 0) return -1;

    uint8_t ad[13], mac[48];
    build_additional_data(ad, rec_hdr[0], epoch, seq, (uint16_t)frag_len);
    etm_mac(mac_key, ad, payload, frag_len, mac);
    if (CRYPTO_memcmp(mac, payload + frag_len, 48) != 0) {
        OBN_WARN("iotc dtls: bad record MAC (epoch=%u seq=%llu)", epoch, (unsigned long long)seq);
        return -1;
    }

    std::vector<uint8_t> decrypted(cipher_len);
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    int outl = 0;
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key, payload) <= 0 ||
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0) <= 0 ||
        EVP_DecryptUpdate(ctx.get(), decrypted.data(), &outl,
                          payload + 16, (int)cipher_len) <= 0 ||
        (size_t)outl != cipher_len || cipher_len == 0)
        return -1;

    const uint8_t pad_val   = decrypted[cipher_len - 1];
    const size_t  pad_count = (size_t)pad_val + 1;
    if (pad_count > cipher_len) return -1;
    for (size_t i = 0; i < pad_count; ++i)
        if (decrypted[cipher_len - 1 - i] != pad_val) return -1;

    const size_t plain_len = cipher_len - pad_count;
    if (plain_len > plain_max) return -1;
    memcpy(plain_out, decrypted.data(), plain_len);
    return (int)plain_len;
}

// ChaCha20-Poly1305 (RFC 7905): ciphertext || 16-byte tag.
static bool aead_seal(const DtlsSession& ds, uint8_t content_type,
                      const uint8_t* plain, size_t plain_len, std::vector<uint8_t>& out_rec)
{
    uint8_t nonce[12], ad[13];
    build_relay_nonce(nonce, ds.client_write_iv, (uint16_t)ds.epoch, ds.tx_seq);
    build_additional_data(ad, content_type, (uint16_t)ds.epoch, ds.tx_seq, (uint16_t)plain_len);

    std::vector<uint8_t> sealed(plain_len + 16);
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    int outl = 0, fin = 0;
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) <= 0 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, ds.client_write_key, nonce) <= 0 ||
        EVP_EncryptUpdate(ctx.get(), nullptr, &outl, ad, 13) <= 0 ||
        EVP_EncryptUpdate(ctx.get(), sealed.data(), &outl, plain, (int)plain_len) <= 0 ||
        EVP_EncryptFinal_ex(ctx.get(), sealed.data() + outl, &fin) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16, sealed.data() + plain_len) <= 0)
        return false;

    uint8_t rec_hdr[13];
    build_dtls_record_hdr(rec_hdr, content_type, (uint16_t)ds.epoch, ds.tx_seq, (uint16_t)sealed.size());
    out_rec.assign(rec_hdr, rec_hdr + 13);
    out_rec.insert(out_rec.end(), sealed.begin(), sealed.end());
    return true;
}

static int aead_open(const DtlsSession& ds, const uint8_t* rec_hdr,
                     const uint8_t* payload, size_t payload_len,
                     uint8_t* plain_out, size_t plain_max)
{
    const uint16_t epoch      = read_be16(rec_hdr + 3);
    const uint64_t seq        = read_be48(rec_hdr + 5);
    const uint16_t sealed_len = read_be16(rec_hdr + 11);
    if (payload_len < sealed_len || sealed_len < 16) return -1;
    const size_t plain_len = sealed_len - 16u;
    if (plain_len > plain_max) return -1;

    uint8_t nonce[12], ad[13];
    build_relay_nonce(nonce, ds.server_write_iv, epoch, seq);
    build_additional_data(ad, rec_hdr[0], epoch, seq, (uint16_t)plain_len);

    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    int outl = 0, fin = 0;
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, 16,
                            const_cast<uint8_t*>(payload + plain_len)) <= 0 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, ds.server_write_key, nonce) <= 0 ||
        EVP_DecryptUpdate(ctx.get(), nullptr, &outl, ad, 13) <= 0 ||
        EVP_DecryptUpdate(ctx.get(), plain_out, &outl, payload, (int)plain_len) <= 0 ||
        EVP_DecryptFinal_ex(ctx.get(), plain_out + outl, &fin) <= 0) {
        OBN_WARN("iotc dtls: AEAD authentication failed (epoch=%u seq=%llu)",
                 epoch, (unsigned long long)seq);
        return -1;
    }
    return (int)plain_len;
}

static bool dtls_encrypt_record(DtlsSession* ds, uint8_t content_type,
                                const uint8_t* plain, size_t plain_len,
                                std::vector<uint8_t>& out_rec)
{
    if (plain_len > kMaxRecordPlaintext) return false;
    const bool ok = ds->cipher_suite == 0xC038
        ? encrypt_record_cbc_etm(ds->client_write_key, ds->client_write_mac_key, content_type,
                                 (uint16_t)ds->epoch, ds->tx_seq, plain, plain_len, out_rec)
        : aead_seal(*ds, content_type, plain, plain_len, out_rec);
    if (ok) ds->tx_seq++;
    return ok;
}

static int dtls_decrypt_record(DtlsSession* ds,
                               const uint8_t* dtls_rec, size_t rec_len,
                               uint8_t* plain_out, size_t plain_max)
{
    if (rec_len < 13) return -1;
    return ds->cipher_suite == 0xC038
        ? decrypt_record_cbc_etm(ds->server_write_key, ds->server_write_mac_key,
                                 dtls_rec, dtls_rec + 13, rec_len - 13, plain_out, plain_max)
        : aead_open(*ds, dtls_rec, dtls_rec + 13, rec_len - 13, plain_out, plain_max);
}

// ---------------------------------------------------------------------------
// DTLS-PSK handshake
// ---------------------------------------------------------------------------

struct EvpPkeyFree    { void operator()(EVP_PKEY* p) const     { EVP_PKEY_free(p); } };
struct EvpPkeyCtxFree { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
using PkeyPtr    = std::unique_ptr<EVP_PKEY, EvpPkeyFree>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxFree>;

// Cipher suites and extensions the stock client offers, trimmed to what this
// client implements.
static const uint8_t kCipherSuites[] = {
    0xC0, 0x38,   // TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
    0xCC, 0xAC,   // TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    0x00, 0xFF,   // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
};

static const uint8_t kExtensions[] = {
    0x00, 0x52,                                      // extensions length (82)
    0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,  // ec_point_formats
    0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a,              // supported_groups:
    0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e,              //   x25519, secp256r1, x448,
    0x00, 0x19, 0x00, 0x18,                          //   secp521r1, secp384r1
    0x00, 0x23, 0x00, 0x00,                          // session_ticket
    0x00, 0x16, 0x00, 0x00,                          // encrypt_then_mac
    0x00, 0x17, 0x00, 0x00,                          // extended_master_secret
    0x00, 0x0d, 0x00, 0x2a, 0x00, 0x28,              // signature_algorithms
    0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07,
    0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b,
    0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01,
    0x05, 0x01, 0x06, 0x01, 0x03, 0x03, 0x03, 0x01,
    0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02,
};

static void append(std::vector<uint8_t>& v, const uint8_t* p, size_t n) { v.insert(v.end(), p, p + n); }

// ClientHello record (epoch 0, record version DTLS 1.0 as RFC 6347 4.2.1
// allows); its handshake message goes into the transcript.
static std::vector<uint8_t> build_client_hello(const DtlsSession& ds,
                                               std::vector<uint8_t>& transcript)
{
    std::vector<uint8_t> body;
    body.push_back(0xfe); body.push_back(0xfd);          // DTLS 1.2
    append(body, ds.client_random, 32);
    body.push_back(0x00);                                // session_id
    body.push_back(0x00);                                // cookie
    body.push_back(0x00); body.push_back((uint8_t)sizeof(kCipherSuites));
    append(body, kCipherSuites, sizeof(kCipherSuites));
    body.push_back(0x01); body.push_back(0x00);          // null compression
    append(body, kExtensions, sizeof(kExtensions));

    uint8_t hs_hdr[12];
    build_dtls_hs_hdr(hs_hdr, 0x01, (uint32_t)body.size(), 0);
    uint8_t rec_hdr[13];
    build_dtls_record_hdr(rec_hdr, 0x16, 0, 0, (uint16_t)(12 + body.size()));
    rec_hdr[2] = 0xff;

    append(transcript, hs_hdr, 12);
    append(transcript, body.data(), body.size());

    std::vector<uint8_t> rec;
    append(rec, rec_hdr, 13);
    append(rec, hs_hdr, 12);
    append(rec, body.data(), body.size());
    return rec;
}

static const char* alert_name(uint8_t desc)
{
    switch (desc) {
    case 10: return "unexpected_message";
    case 20: return "bad_record_mac";
    case 40: return "handshake_failure";
    case 47: return "illegal_parameter";
    case 70: return "protocol_version";
    default: return "other";
    }
}

// Parse the ServerHello + ServerKeyExchange + ServerHelloDone flight (one
// datagram): negotiated suite and extensions into ds, the server's X25519
// key into server_pub, the messages into the transcript.
static int parse_server_hello_flight(const uint8_t* raw, size_t len, DtlsSession* ds,
                                     std::vector<uint8_t>& transcript,
                                     uint8_t server_pub[32])
{
    if (len >= 15 && raw[0] == 0x15) {
        OBN_ERROR("iotc dtls: server alert level=%u desc=%u (%s)",
                  raw[13], raw[14], alert_name(raw[14]));
        return -1;
    }
    if (len < 13 + 12 + 2 + 32 + 1 || raw[0] != 0x16 || raw[13] != 0x02) {
        OBN_ERROR("iotc dtls: expected ServerHello, got record 0x%02x (%zu bytes)", raw[0], len);
        return -1;
    }

    ds->cipher_suite = 0;
    ds->use_ems = ds->use_etm = false;
    bool have_key = false;

    size_t pos = 0;
    while (pos + 13 + 12 <= len) {
        const uint8_t* rec  = raw + pos;
        const size_t   rlen = read_be16(rec + 11);
        if (pos + 13 + rlen > len) break;
        pos += 13 + rlen;
        if (rec[0] != 0x16 || rlen < 12) continue;

        const uint8_t* hs    = rec + 13;
        const uint8_t  htype = hs[0];
        const size_t   hlen  = ((size_t)hs[1] << 16) | ((size_t)hs[2] << 8) | hs[3];
        if (12 + hlen > rlen) continue;
        const uint8_t* body = hs + 12;

        if (htype == 0x0e) {
            // ServerHelloDone goes into the transcript in its canonical form
            // (msg_seq 2, no fragmentation).
            static const uint8_t kServerHelloDone[12] = {
                0x0e, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            append(transcript, kServerHelloDone, 12);
            continue;
        }
        append(transcript, hs, 12 + hlen);

        if (htype == 0x02) {
            // version(2) random(32) session_id cipher_suite(2) compression(1) extensions
            if (hlen < 2 + 32 + 1) return -1;
            memcpy(ds->server_random, body + 2, 32);
            size_t off = 2 + 32 + 1 + body[34];
            if (off + 3 > hlen) return -1;
            ds->cipher_suite = read_be16(body + off);
            off += 3;
            if (off + 2 <= hlen) {
                size_t e_end = std::min(hlen, off + 2 + read_be16(body + off));
                for (size_t e = off + 2; e + 4 <= e_end; e += 4 + read_be16(body + e + 2)) {
                    uint16_t etype = read_be16(body + e);
                    if (etype == 0x0016) ds->use_etm = true;
                    if (etype == 0x0017) ds->use_ems = true;
                }
            }
        } else if (htype == 0x0c) {
            // psk_hint_len(2) = 0, curve_type(1) = 3, named_curve(2) = x25519,
            // key_len(1) = 32, key(32)
            if (hlen >= 38 && body[0] == 0 && body[1] == 0 && body[2] == 0x03 &&
                read_be16(body + 3) == 0x001d && body[5] == 32) {
                memcpy(server_pub, body + 6, 32);
                have_key = true;
            }
        }
    }

    if (ds->cipher_suite != 0xC038 && ds->cipher_suite != 0xCCAC) {
        OBN_ERROR("iotc dtls: server chose unsupported cipher suite 0x%04x", ds->cipher_suite);
        return -1;
    }
    if (!have_key) {
        OBN_ERROR("iotc dtls: no X25519 ServerKeyExchange");
        return -1;
    }
    return 0;
}

// Ephemeral X25519 key pair; the shared secret with the server's key.
static bool x25519_exchange(const uint8_t server_pub[32], uint8_t client_pub[32],
                            uint8_t shared[32])
{
    EVP_PKEY* raw_key = nullptr;
    PkeyCtxPtr kctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
    if (!kctx || EVP_PKEY_keygen_init(kctx.get()) <= 0 ||
        EVP_PKEY_keygen(kctx.get(), &raw_key) <= 0)
        return false;
    PkeyPtr key(raw_key);

    size_t pub_len = 32;
    PkeyPtr peer(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, server_pub, 32));
    PkeyCtxPtr dctx(EVP_PKEY_CTX_new(key.get(), nullptr));
    size_t shared_len = 32;
    return EVP_PKEY_get_raw_public_key(key.get(), client_pub, &pub_len) > 0 &&
           peer && dctx &&
           EVP_PKEY_derive_init(dctx.get()) > 0 &&
           EVP_PKEY_derive_set_peer(dctx.get(), peer.get()) > 0 &&
           EVP_PKEY_derive(dctx.get(), shared, &shared_len) > 0 &&
           shared_len == 32;
}

// SHA256(passwd), zero-filled from its first zero byte on: the printer keeps
// the digest as a C string but still uses all 32 bytes.
static void derive_psk(const char* passwd, uint8_t psk[32])
{
    SHA256(reinterpret_cast<const uint8_t*>(passwd), strlen(passwd), psk);
    if (auto* nul = static_cast<uint8_t*>(memchr(psk, 0, 32)))
        memset(nul, 0, 32 - static_cast<size_t>(nul - psk));
}

// PRF of the negotiated suite: SHA-384 for 0xC038, SHA-256 for 0xCCAC.
static void suite_prf(const DtlsSession& ds, const uint8_t* secret, size_t secret_len,
                      const char* label, const uint8_t* seed, size_t seed_len,
                      uint8_t* out, size_t out_len)
{
    if (ds.cipher_suite == 0xC038)
        tls12_prf_sha384(secret, secret_len, label, seed, seed_len, out, out_len);
    else
        tls12_prf(secret, secret_len, label, seed, seed_len, out, out_len);
}

static size_t transcript_hash(const DtlsSession& ds, const std::vector<uint8_t>& t,
                              uint8_t out[48])
{
    if (ds.cipher_suite == 0xC038) {
        SHA384(t.data(), t.size(), out);
        return 48;
    }
    SHA256(t.data(), t.size(), out);
    return 32;
}

// Master secret (RFC 7627 when negotiated) and the key block.
static void derive_session_keys(DtlsSession* ds, const uint8_t* premaster, size_t premaster_len,
                                const std::vector<uint8_t>& transcript)
{
    if (ds->use_ems) {
        uint8_t hash[48];
        size_t hlen = transcript_hash(*ds, transcript, hash);
        suite_prf(*ds, premaster, premaster_len, "extended master secret",
                  hash, hlen, ds->master_secret, 48);
    } else {
        uint8_t seed[64];
        memcpy(seed,      ds->client_random, 32);
        memcpy(seed + 32, ds->server_random, 32);
        suite_prf(*ds, premaster, premaster_len, "master secret", seed, 64, ds->master_secret, 48);
    }

    uint8_t seed[64];
    memcpy(seed,      ds->server_random, 32);
    memcpy(seed + 32, ds->client_random, 32);
    if (ds->cipher_suite == 0xC038) {
        // mac keys 2x48, cipher keys 2x32, IVs 2x16
        uint8_t kb[192];
        suite_prf(*ds, ds->master_secret, 48, "key expansion", seed, 64, kb, sizeof(kb));
        memcpy(ds->client_write_mac_key, kb,       48);
        memcpy(ds->server_write_mac_key, kb + 48,  48);
        memcpy(ds->client_write_key,     kb + 96,  32);
        memcpy(ds->server_write_key,     kb + 128, 32);
        memcpy(ds->client_write_iv,      kb + 160, 16);
        memcpy(ds->server_write_iv,      kb + 176, 16);
    } else {
        // cipher keys 2x32, IVs 2x12
        uint8_t kb[88];
        suite_prf(*ds, ds->master_secret, 48, "key expansion", seed, 64, kb, sizeof(kb));
        memcpy(ds->client_write_key, kb,      32);
        memcpy(ds->server_write_key, kb + 32, 32);
        memcpy(ds->client_write_iv,  kb + 64, 12);
        memcpy(ds->server_write_iv,  kb + 76, 12);
    }
}

static void finished_verify_data(const DtlsSession& ds, const std::vector<uint8_t>& transcript,
                                 const char* label, uint8_t out[12])
{
    uint8_t hash[48];
    size_t hlen = transcript_hash(ds, transcript, hash);
    suite_prf(ds, ds.master_secret, 48, label, hash, hlen, out, 12);
}

// The server's last flight ([NewSessionTicket] ChangeCipherSpec Finished) can
// span several datagrams. The ticket (epoch 0) is part of the transcript the
// server's verify_data covers. Returns the decrypted Finished length.
static int recv_server_finished(obn::net::socket_t sock, const struct sockaddr_in* dst,
                                DtlsSession* ds, std::vector<uint8_t>& transcript,
                                uint8_t fin[64])
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    while (std::chrono::steady_clock::now() < deadline) {
        uint8_t raw[1024];
        int n = recv_dtls_packet(sock, dst, raw, sizeof(raw), nullptr, nullptr, 1000);
        if (n < 13) continue;
        for (size_t off = 0; off + 13 <= (size_t)n;) {
            const uint8_t* rec  = raw + off;
            const size_t   rlen = 13 + read_be16(rec + 11);
            if (off + rlen > (size_t)n) break;
            off += rlen;
            if (rec[0] == 0x15) {
                OBN_ERROR("iotc dtls: server alert level=%d desc=%d (%s)",
                          rlen >= 15 ? rec[13] : -1, rlen >= 15 ? rec[14] : -1,
                          rlen >= 15 ? alert_name(rec[14]) : "?");
                return -1;
            }
            if (rec[0] != 0x16) continue;
            if (read_be16(rec + 3) == 0) {
                append(transcript, rec + 13, rlen - 13);
                continue;
            }
            return dtls_decrypt_record(ds, rec, rlen, fin, 64);
        }
    }
    OBN_ERROR("iotc dtls: no server Finished");
    return -1;
}

// DTLS-PSK handshake with the peer at dst. uid_upper, when set, sends the
// 02 04 33 packet the printer needs on the off-LAN direct path.
static int dtls_psk_handshake(obn::net::socket_t sock, const struct sockaddr_in* dst,
                              const uint8_t session_token[8], const char* uid_upper,
                              const char* passwd, const char* account,
                              DtlsSession* out, uint32_t relay_tag)
{
    memset(out, 0, sizeof(*out));
    out->relay_tag = relay_tag;
    if (RAND_bytes(out->client_random, 32) != 1) return -1;

    std::vector<uint8_t> transcript;
    const std::vector<uint8_t> hello = build_client_hello(*out, transcript);
    const uint16_t hello_seq = out->pkt_seq++;
    auto send_hello = [&] {
        return send_dtls_packet(sock, dst, 0, session_token, hello.data(), hello.size(),
                                hello_seq, relay_tag);
    };
    // Sent twice up front against early loss; repeats reuse the datagram
    // counter so the printer treats them as retransmissions.
    if (send_hello() != 0) {
        OBN_ERROR("iotc dtls: ClientHello send failed");
        return -1;
    }
    send_hello();
    if (uid_upper && uid_upper[0] && send_ctrl0x33(sock, dst, uid_upper, session_token) != 0) {
        OBN_ERROR("iotc dtls: 02 04 33 send failed");
        return -1;
    }

    uint8_t flight[1024];
    int flight_len = -1;
    for (int attempt = 0; attempt < 3 && flight_len < 13; ++attempt) {
        if (attempt > 0) send_hello();
        flight_len = recv_dtls_packet(sock, dst, flight, sizeof(flight), nullptr, nullptr, 1000);
    }
    if (flight_len < 13) {
        OBN_ERROR("iotc dtls: no ServerHello");
        return -1;
    }
    uint8_t server_pub[32];
    if (parse_server_hello_flight(flight, (size_t)flight_len, out, transcript, server_pub) != 0)
        return -1;
    OBN_DEBUG("iotc dtls: cipher=0x%04x ems=%d etm=%d",
              out->cipher_suite, out->use_ems, out->use_etm);

    uint8_t client_pub[32], ecdh[32];
    if (!x25519_exchange(server_pub, client_pub, ecdh)) {
        OBN_ERROR("iotc dtls: X25519 exchange failed");
        return -1;
    }

    // ECDHE-PSK premaster (RFC 5489): len(ecdh) || ecdh || len(psk) || psk
    uint8_t premaster[2 + 32 + 2 + 32] = {0x00, 0x20};
    memcpy(premaster + 2, ecdh, 32);
    premaster[34] = 0x00; premaster[35] = 0x20;
    derive_psk(passwd, premaster + 36);

    // ClientKeyExchange: psk_identity_len(2) psk_identity ec_point_len(1) ec_point
    const std::string identity = std::string("AUTHPWD_") + account;
    std::vector<uint8_t> cke;
    cke.push_back((uint8_t)(identity.size() >> 8));
    cke.push_back((uint8_t)identity.size());
    append(cke, reinterpret_cast<const uint8_t*>(identity.data()), identity.size());
    cke.push_back(32);
    append(cke, client_pub, 32);

    uint8_t cke_hs[12], cke_rec[13];
    build_dtls_hs_hdr(cke_hs, 0x10, (uint32_t)cke.size(), 1);
    build_dtls_record_hdr(cke_rec, 0x16, 0, 1, (uint16_t)(12 + cke.size()));
    append(transcript, cke_hs, 12);
    append(transcript, cke.data(), cke.size());

    derive_session_keys(out, premaster, sizeof(premaster), transcript);

    uint8_t ccs[14];
    build_dtls_record_hdr(ccs, 0x14, 0, 2, 1);
    ccs[13] = 0x01;

    uint8_t fin[24];
    build_dtls_hs_hdr(fin, 0x14, 12, 2);
    finished_verify_data(*out, transcript, "client finished", fin + 12);
    append(transcript, fin, sizeof(fin));

    out->epoch  = 1;
    out->tx_seq = 0;
    std::vector<uint8_t> fin_rec;
    if (!dtls_encrypt_record(out, 0x16, fin, sizeof(fin), fin_rec)) return -1;

    std::vector<uint8_t> flight2;
    append(flight2, cke_rec, 13);
    append(flight2, cke_hs, 12);
    append(flight2, cke.data(), cke.size());
    append(flight2, ccs, sizeof(ccs));
    append(flight2, fin_rec.data(), fin_rec.size());
    if (send_dtls_packet(sock, dst, 0, session_token, flight2.data(), flight2.size(),
                         out->pkt_seq++, relay_tag) != 0) {
        OBN_ERROR("iotc dtls: ClientKeyExchange flight send failed");
        return -1;
    }

    uint8_t srv_fin[64];
    int srv_fin_len = recv_server_finished(sock, dst, out, transcript, srv_fin);
    if (srv_fin_len < 24) {
        if (srv_fin_len >= 0) OBN_ERROR("iotc dtls: short server Finished (%d)", srv_fin_len);
        return -1;
    }
    uint8_t expected[12];
    finished_verify_data(*out, transcript, "server finished", expected);
    if (CRYPTO_memcmp(srv_fin + 12, expected, 12) != 0) {
        OBN_ERROR("iotc dtls: server Finished does not verify");
        return -1;
    }

    out->tx_seq = 1;
    out->rx_seq = 1;
    out->handshake_complete = true;
    OBN_DEBUG("iotc dtls: handshake complete");
    return 0;
}

// ==========================================================================
// Relay path
// ==========================================================================
//
// Used when LAN search finds nothing. The master
// ({region}-c-master-{relay_id}.iotcplatform.com:10240/udp) hands out a relay:
//   1. JOIN (54B): UID + relay_id + 0x0600
//   2. KNOCK x5 (88B): UID + SDK version + session token + fixed flags
//   3. relay assignment (200B), bytes [188..191] echo the session token
//   4. one more KNOCK, then DTLS-PSK and the AV layer on top.

// relay_id: first 16 chars of the 20-char relay subdomain.
static int send_relay_join(obn::net::socket_t sock, const struct sockaddr_in* dst,
                            const char* uid_upper, const char* relay_id)
{
    uint8_t pkt[54];
    memset(pkt, 0, sizeof(pkt));

    // bytes [8..10] = 0x07, 0x10, 0x18 (same as MSG_QUERY_DEVICE5)
    pkt[0] = 0x04; pkt[1] = 0x02;
    pkt[2] = 0x1c;
    pkt[3] = 0x02;
    pkt[4] = 0x26;  // payload_len=38 LE
    pkt[8]  = 0x07; pkt[9]  = 0x10; pkt[10] = 0x18;

    memcpy(pkt + 16, uid_upper, kUidLen);
    size_t relay_copy = strnlen(relay_id, 16);
    memcpy(pkt + 36, relay_id, relay_copy);
    pkt[52] = 0x06;
    pkt[53] = 0x00;

    trans_code_partial(pkt, sizeof(pkt));
    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0,
                       (const struct sockaddr*)dst, sizeof(*dst));
    return (n == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

// Build and send an 88-byte KNOCK packet.
// session_token: 8 random bytes generated by client.
// directed=false: initial knock (pre-assignment), flags[64]=0x01.
// directed=true:  post-assignment knock, flags[64]=0x02.
// Both flag patterns confirmed from protocol capture.
static int send_relay_knock(obn::net::socket_t sock, const struct sockaddr_in* dst,
                             const char* uid_upper,
                             const uint8_t session_token[8],
                             bool directed = false)
{
    uint8_t pkt[88];
    memset(pkt, 0, sizeof(pkt));

    // bytes [8..10] = 0x01, 0x06, 0x21
    pkt[0] = 0x04; pkt[1] = 0x02;
    pkt[2] = 0x1c;
    pkt[3] = 0x02;
    pkt[4] = 0x48;  // payload_len=72 LE
    pkt[8]  = 0x01; pkt[9]  = 0x06; pkt[10] = 0x21;

    memcpy(pkt + 16, uid_upper, kUidLen);
    // [36..51] = zeros (already zeroed)

    uint32_t sdk_ver = htole32(0x04030304);  // TUTK SDK 4.3.3.4 at [52..55]
    memcpy(pkt + 52, &sdk_ver, 4);
    memcpy(pkt + 56, session_token, 8);  // [56..63]

    // 24-byte flags at [64..87]:
    //   initial KNOCKs (directed=false): byte[64]=0x01, includes NAT timing hints
    //   post-assignment KNOCK (directed=true): byte[64]=0x02, simplified
    // Both patterns inferred from relay protocol captures.
    if (!directed) {
        static const uint8_t kInitKnockFlags[24] = {
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x64, 0x64, 0x35, 0x35, 0x36, 0x63,
            0x63, 0x04, 0x13, 0x13, 0x66, 0x0c, 0x0c, 0x05
        };
        memcpy(pkt + 64, kInitKnockFlags, 24);
    } else {
        static const uint8_t kDirKnockFlags[24] = {
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x63, 0x04, 0x13, 0x13, 0x04, 0x0c, 0x0c, 0x63
        };
        memcpy(pkt + 64, kDirKnockFlags, 24);
    }

    trans_code_partial(pkt, sizeof(pkt));
    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0,
                       (const struct sockaddr*)dst, sizeof(*dst));
    return (n == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

// ==========================================================================
// Off-LAN reflexive + candidate rendezvous.
//
// When the printer is behind NAT it does not send its rendezvous directly.
// The client completes a rendezvous with the servers the master lists in its
// reply (the :3478 endpoints): it presents the auth key, learns the printer's
// candidate addresses, and asks the servers to coordinate a punch. The printer
// then sends its 02 06 12 rendezvous from its media address, which the caller
// adopts as the peer. All packets use the same TransCodePartial obfuscation.
// ==========================================================================

// Shared 16-byte IOTC control header (channel 0x1c, flags 0x02).
static void write_rdv_hdr(uint8_t* p, uint32_t body_len,
                          uint8_t t0, uint8_t t1, uint8_t t2)
{
    memset(p, 0, 16);
    p[0] = 0x04; p[1] = 0x02; p[2] = 0x1c; p[3] = 0x02;
    uint32_t bl = htole32(body_len);
    memcpy(p + 4, &bl, 4);
    p[8] = t0; p[9] = t1; p[10] = t2;
}

static bool read_addr_rec(const uint8_t* p, struct sockaddr_in* a)
{
    if (p[0] != 0x02 || p[1] != 0x00) return false;
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    memcpy(&a->sin_port, p + 2, 2);
    memcpy(&a->sin_addr, p + 4, 4);
    return a->sin_addr.s_addr != 0 && a->sin_port != 0;
}

// Rendezvous-server (:3478) addresses from the master's 08 10 83 reply.
static int parse_rdv_servers(const uint8_t* reply, size_t len,
                             struct sockaddr_in* out, int max_out)
{
    int n = 0;
    for (size_t i = 16; i + 8 <= len && n < max_out; ++i) {
        struct sockaddr_in a;
        if (read_addr_rec(reply + i, &a) && ntohs(a.sin_port) == 3478) {
            bool dup = false;
            for (int k = 0; k < n; ++k)
                if (out[k].sin_addr.s_addr == a.sin_addr.s_addr) { dup = true; break; }
            if (!dup) out[n++] = a;
        }
    }
    return n;
}

// Client's own reflexive address from the master reply: the first address
// record that is not one of the :3478 rendezvous servers.
static bool parse_reflexive(const uint8_t* reply, size_t len, struct sockaddr_in* out)
{
    for (size_t i = 16; i + 8 <= len; ++i) {
        struct sockaddr_in a;
        if (read_addr_rec(reply + i, &a) && ntohs(a.sin_port) != 3478) { *out = a; return true; }
    }
    return false;
}

// Printer candidate addresses from a 01 03 43 reply: records at [36], [52], ...
// Candidate records use family byte 0x02 (public) or 0x00 (LAN) at [+0]; the
// nonzero port+ip guard keeps runs of zero padding from parsing as addresses.
static int parse_candidates(const uint8_t* reply, size_t len,
                            struct sockaddr_in* out, int max_out)
{
    int n = 0;
    for (size_t i = 36; i + 8 <= len && n < max_out; i += 16) {
        const uint8_t* p = reply + i;
        if (p[1] != 0x00 || (p[0] != 0x00 && p[0] != 0x02)) continue;
        struct sockaddr_in a; memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        memcpy(&a.sin_port, p + 2, 2);
        memcpy(&a.sin_addr, p + 4, 4);
        if (a.sin_addr.s_addr != 0 && a.sin_port != 0) {
            bool dup = false;
            for (int k = 0; k < n; ++k) {
                if (out[k].sin_addr.s_addr == a.sin_addr.s_addr && out[k].sin_port == a.sin_port) {
                    dup = true; break;
                }
            }
            if (!dup) out[n++] = a;
        }
    }
    return n;
}

// 14 02 24: UID + auth key (8 ASCII bytes from the URL, null-padded at [40..48)).
static int send_rdv_authkey(obn::net::socket_t sock, const struct sockaddr_in* dst,
                            const char* uid_upper, const char* authkey)
{
    uint8_t pkt[48];
    write_rdv_hdr(pkt, 32, 0x14, 0x02, 0x24);
    memset(pkt + 16, 0, 32);
    memcpy(pkt + 16, uid_upper, kUidLen);
    memcpy(pkt + 40, authkey, strnlen(authkey, 8));
    trans_code_partial(pkt, sizeof(pkt));
    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0, (const struct sockaddr*)dst, sizeof(*dst));
    return (n == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

// 0a 02 24: UID + session token [36..44) + auth key [56..64) (pre-check).
static int send_rdv_token(obn::net::socket_t sock, const struct sockaddr_in* dst,
                          const char* uid_upper, const uint8_t token[8],
                          const char* authkey)
{
    uint8_t pkt[64];
    write_rdv_hdr(pkt, 48, 0x0a, 0x02, 0x24);
    memset(pkt + 16, 0, 48);
    memcpy(pkt + 16, uid_upper, kUidLen);
    memcpy(pkt + 36, token, 8);
    pkt[44] = 0x3c;                    // observed constant
    memcpy(pkt + 56, authkey, strnlen(authkey, 8));
    trans_code_partial(pkt, sizeof(pkt));
    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0, (const struct sockaddr*)dst, sizeof(*dst));
    return (n == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

// Determine local IPv4 and bound port routed to remote address
static bool get_local_endpoint(const struct sockaddr_in* remote, struct sockaddr_in* local_out, uint16_t local_port)
{
    obn::net::socket_t s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == obn::net::kInvalid) return false;
    bool ok = false;
    if (connect(s, (const struct sockaddr*)remote, sizeof(*remote)) == 0) {
        socklen_t len = sizeof(*local_out);
        if (getsockname(s, (struct sockaddr*)local_out, &len) == 0) {
            local_out->sin_port = htons(local_port);
            ok = true;
        }
    }
    obn::net::close_socket(s);
    return ok;
}

// 04 08 24: Client Candidate Registration with rendezvous server (544 bytes).
// Carries the session token [68..76), the local LAN endpoint [76..84), and the
// client's reflexive WAN endpoint [140..148).
static int send_rdv_punch(obn::net::socket_t sock, const struct sockaddr_in* server,
                          const char* uid_upper,
                          const uint8_t token[8],
                          const struct sockaddr_in* local_ep,
                          const struct sockaddr_in* reflexive)
{
    uint8_t pkt[544];
    memset(pkt, 0, sizeof(pkt));
    write_rdv_hdr(pkt, 528, 0x04, 0x08, 0x24);
    memcpy(pkt + 16, uid_upper, kUidLen);
    static const uint8_t kPunchConst[16] = {
        0x00, 0x02, 0xff, 0x04, 0xa6, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x03, 0x03, 0x04
    };
    memcpy(pkt + 52, kPunchConst, 16);
    memcpy(pkt + 68, token, 8);
    pkt[76] = 0x00; pkt[77] = 0x00;
    memcpy(pkt + 78, &local_ep->sin_port, 2);
    memcpy(pkt + 80, &local_ep->sin_addr, 4);
    pkt[140] = 0x02; pkt[141] = 0x00;
    memcpy(pkt + 142, &reflexive->sin_port, 2);
    memcpy(pkt + 144, &reflexive->sin_addr, 4);
    pkt[540] = 0x42; pkt[541] = 0x02; pkt[542] = 0x00; pkt[543] = 0x00;

    trans_code_partial(pkt, sizeof(pkt));
    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0, (const struct sockaddr*)server, sizeof(*server));
    return (n == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

// 03 80 3f: reflexive probe. Body = 8-byte transaction id.
static int send_stun_probe(obn::net::socket_t sock, const struct sockaddr_in* dst,
                           const uint8_t txn[8])
{
    uint8_t pkt[24];
    write_rdv_hdr(pkt, 8, 0x03, 0x80, 0x3f);
    memcpy(pkt + 16, txn, 8);
    trans_code_partial(pkt, sizeof(pkt));
    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0, (const struct sockaddr*)dst, sizeof(*dst));
    return (n == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

// 03 02 34: announce local endpoint, token, and authkey (288 bytes).
static int send_rdv_random(obn::net::socket_t sock, const struct sockaddr_in* dst,
                           const char* uid_upper, const struct sockaddr_in* local_ep,
                           const uint8_t token[8], const char* authkey)
{
    uint8_t pkt[288];
    memset(pkt, 0, sizeof(pkt));
    write_rdv_hdr(pkt, 272, 0x03, 0x02, 0x34);
    memcpy(pkt + 16, uid_upper, kUidLen);
    pkt[36] = 0x00; pkt[37] = 0x00;
    memcpy(pkt + 38, &local_ep->sin_port, 2);
    memcpy(pkt + 40, &local_ep->sin_addr, 4);
    memcpy(pkt + 100, token, 8);
    pkt[108] = 0x02;
    if (authkey && authkey[0]) {
        size_t klen = std::min(strlen(authkey), (size_t)8);
        memcpy(pkt + 272, authkey, klen);
    }
    trans_code_partial(pkt, sizeof(pkt));
    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0, (const struct sockaddr*)dst, sizeof(*dst));
    return (n == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

// 01 04 33: punch directly to a printer candidate address (52 bytes).
static int send_punch_to_candidate(obn::net::socket_t sock, const struct sockaddr_in* cand,
                                   const char* uid_upper, const uint8_t token[8])
{
    uint8_t pkt[52];
    memset(pkt, 0, sizeof(pkt));
    write_rdv_hdr(pkt, 36, 0x01, 0x04, 0x33);
    memcpy(pkt + 16, uid_upper, kUidLen);
    memcpy(pkt + 36, token, 8);
    uint32_t r = rand32();
    memcpy(pkt + 48, &r, 4);
    trans_code_partial(pkt, sizeof(pkt));
    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0, (const struct sockaddr*)cand, sizeof(*cand));
    return (n == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

// 09 02 24: follow-up after candidate punch. UID + session token [20..28) + trailer [32..44).
static int send_rdv_punch2(obn::net::socket_t sock, const struct sockaddr_in* dst,
                           const char* uid_upper, const uint8_t token[8])
{
    uint8_t pkt[60];
    write_rdv_hdr(pkt, 44, 0x09, 0x02, 0x24);
    memset(pkt + 16, 0, 44);
    memcpy(pkt + 16, uid_upper, kUidLen);
    memcpy(pkt + 36, token, 8);
    pkt[44] = 0x01;  // Relay request flag: 01 00 00 00 (mandatory for NAT relay fallback)
    static const uint8_t kTrailer[12] = {
        0x04, 0x03, 0x03, 0x04, 0x1c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00
    };
    memcpy(pkt + 48, kTrailer, 12);
    trans_code_partial(pkt, sizeof(pkt));
    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0, (const struct sockaddr*)dst, sizeof(*dst));
    return (n == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

// 0c 03 24: acknowledge a 03 03 43 reply. UID + session token; tag echoed at [12..16).
static int send_rdv_ack(obn::net::socket_t sock, const struct sockaddr_in* dst,
                        const char* uid_upper, const uint8_t token[8], uint32_t tag)
{
    uint8_t pkt[44];
    write_rdv_hdr(pkt, 28, 0x0c, 0x03, 0x24);
    uint32_t t = htole32(tag);
    memcpy(pkt + 12, &t, 4);
    memset(pkt + 16, 0, 28);
    memcpy(pkt + 16, uid_upper, kUidLen);
    memcpy(pkt + 36, token, 8);
    trans_code_partial(pkt, sizeof(pkt));
    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0, (const struct sockaddr*)dst, sizeof(*dst));
    return (n == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

// Full off-LAN multi-server rendezvous across all rendezvous servers simultaneously.
// Message order per genuine TUTK trace (bambu_studio_4g.pcapng):
//   Client -> All Servers: 03 80 3f (probe) + 14 02 24 (authkey)
//   Servers -> Client:     27 02 42 (challenge)
//   Client -> All Servers: 04 08 24 (candidate registration) + 03 80 3f + 14 02 24
//   Servers -> Client:     15 02 42 (prepared session)
//   Client -> All Servers: 03 02 34 (random) + 0a 02 24 (token)
//   Servers -> Client:     01 03 43 (candidates)
//   Client -> Candidates:  01 04 33 (direct punch)
//   Client -> All Servers: 09 02 24 (punch2) + 14 02 24 (authkey)
//   Servers -> Client:     03 03 43 (pairing confirmed with relay tag)
//   Client -> Server:      0c 03 24 (ack) -> server relay DTLS
// Direct P2P: 02 06 12 or 01 04 33 / 02 04 33 directly from printer candidate.
// Returns true if printer rendezvous or server relay pairing succeeds.
static bool offlan_rendezvous(obn::net::socket_t sock,
                              const uint8_t* master_reply, size_t reply_len,
                              const char* uid_upper, const char* authkey,
                              const uint8_t session_token[8],
                              struct sockaddr_in* peer_out,
                              uint32_t* tag_out)
{
    if (!authkey || !authkey[0]) return false;

    struct sockaddr_in servers[4];
    int ns = parse_rdv_servers(master_reply, reply_len, servers, 4);
    if (ns == 0) {
        OBN_WARN("iotc rdv: no rendezvous servers found in master reply");
        return false;
    }
    OBN_DEBUG("iotc rdv: discovered %d rendezvous server(s)", ns);

    struct sockaddr_in reflexive{};
    bool have_reflexive = parse_reflexive(master_reply, reply_len, &reflexive);
    if (!have_reflexive) {
        OBN_DEBUG("iotc rdv: master reply has no reflexive record; seeding from server 0");
        reflexive = servers[0];
    }

    struct sockaddr_in local_ep{};
    socklen_t local_len = sizeof(local_ep);
    uint16_t bound_port = 0;
    if (getsockname(sock, (struct sockaddr*)&local_ep, &local_len) == 0) {
        bound_port = ntohs(local_ep.sin_port);
    }
    get_local_endpoint(&servers[0], &local_ep, bound_port);

    uint8_t txn[8];
    { uint32_t a = rand32(), b = rand32();
      memcpy(txn, &a, 4); memcpy(txn + 4, &b, 4); }

    // Initial broadcast to all servers
    for (int s = 0; s < ns; ++s) {
        send_stun_probe(sock, &servers[s], txn);
        send_rdv_authkey(sock, &servers[s], uid_upper, authkey);
    }

    set_recv_timeout(sock, 100);
    struct sockaddr_in candidates[4];
    int num_candidates = 0;

    auto start_time = std::chrono::steady_clock::now();
    auto deadline = start_time + std::chrono::seconds(15);
    auto last_probe_broadcast = start_time;
    auto last_challenge_broadcast = start_time - std::chrono::seconds(1);
    auto last_session_broadcast = start_time - std::chrono::seconds(1);
    auto last_cand_punch = start_time - std::chrono::seconds(1);

    while (std::chrono::steady_clock::now() < deadline) {
        auto now = std::chrono::steady_clock::now();

        // If candidates are known, keep punching them periodically (~250ms)
        if (num_candidates > 0) {
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_cand_punch).count() >= 250) {
                last_cand_punch = now;
                for (int c = 0; c < num_candidates; ++c) {
                    send_punch_to_candidate(sock, &candidates[c], uid_upper, session_token);
                }
                for (int s = 0; s < ns; ++s) {
                    send_rdv_punch2(sock, &servers[s], uid_upper, session_token);
                    send_rdv_authkey(sock, &servers[s], uid_upper, authkey);
                }
            }
        } else {
            // Periodic retry of initial probe/authkey broadcast if no response yet (~2s)
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_probe_broadcast).count() >= 2000) {
                last_probe_broadcast = now;
                OBN_DEBUG("iotc rdv: re-broadcasting initial probes and authkey to %d servers", ns);
                for (int s = 0; s < ns; ++s) {
                    send_stun_probe(sock, &servers[s], txn);
                    send_rdv_authkey(sock, &servers[s], uid_upper, authkey);
                }
            }
        }

        uint8_t resp[1024];
        struct sockaddr_in src{}; socklen_t sl = sizeof(src);
        ssize_t n = recvfrom(sock, resp, sizeof(resp), 0, (struct sockaddr*)&src, &sl);
        if (n < 16) continue;
        reverse_trans_code_partial(resp, (size_t)n);
        if (resp[0] != 0x04 || resp[1] != 0x02) continue;
        OBN_DEBUG("iotc rdv: reply %zd bytes type=%02x %02x %02x from %s:%u",
                  n, resp[8], resp[9], resp[10],
                  inet_ntoa(src.sin_addr), ntohs(src.sin_port));

        // Probe reply (04 80 4f): learn reflexive WAN address
        if (resp[8] == 0x04 && resp[9] == 0x80) {
            struct sockaddr_in mine{};
            if (read_addr_rec(resp + 16, &mine) && ntohs(mine.sin_port) != 3478) {
                reflexive = mine;
                OBN_DEBUG("iotc rdv: reflexive learned %s:%u", inet_ntoa(mine.sin_addr), ntohs(mine.sin_port));
            }
            continue;
        }

        // Direct printer rendezvous (02 06 12) from printer P2P address
        if (resp[8] == 0x02 && resp[9] == 0x06 && resp[10] == 0x12) {
            *peer_out = src;
            if (tag_out) *tag_out = 0;
            OBN_DEBUG("iotc rdv: direct printer rendezvous 02 06 12 received from %s:%u",
                     inet_ntoa(src.sin_addr), ntohs(src.sin_port));
            return true;
        }

        // Direct printer punch probe (01 04 33 or 02 04 33) from printer P2P candidate:
        // Respond with ctrl0x33 to assist punch exchange, but do NOT abort rendezvous loop.
        // Wait for authoritative relay confirmation (03 03 43) or direct rendezvous (02 06 12).
        if ((resp[8] == 0x01 || resp[8] == 0x02) && resp[9] == 0x04 && resp[10] == 0x33) {
            send_ctrl0x33(sock, &src, uid_upper, session_token);
            OBN_DEBUG("iotc rdv: candidate punch probe %02x 04 33 from %s:%u (probe exchanged, awaiting relay/rendezvous)",
                      resp[8], inet_ntoa(src.sin_addr), ntohs(src.sin_port));
            continue;
        }

        // Server challenge (27 02 42): triggers candidate registration 04 08 24 broadcast
        if (resp[8] == 0x27 && resp[9] == 0x02 && resp[10] == 0x42) {
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_challenge_broadcast).count() >= 150) {
                last_challenge_broadcast = now;
                OBN_DEBUG("iotc rdv: server challenge 27 02 42 -> broadcasting 04 08 24 to %d servers", ns);
                for (int s = 0; s < ns; ++s) {
                    send_rdv_punch(sock, &servers[s], uid_upper, session_token, &local_ep, &reflexive);
                    send_stun_probe(sock, &servers[s], txn);
                    send_rdv_authkey(sock, &servers[s], uid_upper, authkey);
                }
            }
            continue;
        }

        // Prepared session response (15 02 42): triggers 03 02 34 and 0a 02 24 broadcast
        if (resp[8] == 0x15 && resp[9] == 0x02 && resp[10] == 0x42) {
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_session_broadcast).count() >= 150) {
                last_session_broadcast = now;
                OBN_DEBUG("iotc rdv: prepared session 15 02 42 -> broadcasting 03 02 34 and 0a 02 24 to %d servers", ns);
                for (int s = 0; s < ns; ++s) {
                    send_rdv_random(sock, &servers[s], uid_upper, &local_ep, session_token, authkey);
                    send_rdv_token(sock, &servers[s], uid_upper, session_token, authkey);
                }
            }
            continue;
        }

        // Candidate list from printer (01 03 43)
        if (resp[8] == 0x01 && resp[9] == 0x03 && resp[10] == 0x43) {
            num_candidates = parse_candidates(resp, (size_t)n, candidates, 4);
            OBN_DEBUG("iotc rdv: received 01 03 43 with %d candidate(s)", num_candidates);
            for (int rep = 0; rep < 3; ++rep) {
                for (int c = 0; c < num_candidates; ++c) {
                    send_punch_to_candidate(sock, &candidates[c], uid_upper, session_token);
                }
            }
            for (int s = 0; s < ns; ++s) {
                send_rdv_punch2(sock, &servers[s], uid_upper, session_token);
                send_rdv_authkey(sock, &servers[s], uid_upper, authkey);
            }
            continue;
        }

        // Pairing confirmed / relay ready (03 03 43)
        if (resp[8] == 0x03 && resp[9] == 0x03 && resp[10] == 0x43) {
            uint32_t tag = 0;
            if (n >= 40) memcpy(&tag, resp + 36, 4);
            uint32_t tag_h = le32toh(tag);
            OBN_INFO("iotc rdv: pairing confirmed 03 03 43 from %s:%u with tag=%u",
                     inet_ntoa(src.sin_addr), ntohs(src.sin_port), tag_h);
            send_rdv_ack(sock, &src, uid_upper, session_token, tag_h);
            send_rdv_ack(sock, &src, uid_upper, session_token, tag_h);

            *peer_out = src;
            if (tag_out) *tag_out = tag_h;

            // Drain any stray packets remaining in socket queue from other servers
            set_recv_timeout(sock, 10);
            uint8_t drain_buf[1024];
            struct sockaddr_in drain_src{};
            socklen_t drain_len = sizeof(drain_src);
            while (recvfrom(sock, drain_buf, sizeof(drain_buf), 0, (struct sockaddr*)&drain_src, &drain_len) > 0) {}

            return true;
        }
    }

    OBN_WARN("iotc rdv: rendezvous timed out after 15s");
    return false;
}

// JOIN + KNOCK×5 + receive 200B relay assignment + post-KNOCK.
int iotc_relay_connect(const char* uid_upper, const char* relay_id,
                       const char* region_str, const char* authkey,
                       IotcConn* out)
{
    if (!uid_upper || strlen(uid_upper) != kUidLen || !relay_id || !region_str || !out) return -1;
    if (!authkey) authkey = "";
    memset(out, 0, sizeof(*out));
    out->sock = -1;

    std::vector<std::string> candidate_hosts;
    if (region_str && region_str[0]) {
        candidate_hosts.push_back(std::string(region_str) + "-m1.iotcplatform.com");
        candidate_hosts.push_back(std::string(region_str) + "-m2.iotcplatform.com");
    }
    candidate_hosts.push_back("m1.iotcplatform.com");
    candidate_hosts.push_back("m2.iotcplatform.com");
    candidate_hosts.push_back("m3.iotcplatform.com");

    struct sockaddr_in masters[4];
    int nmasters = 0;
    char resolved_host[256] = "";

    struct addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", 10240);

    for (const auto& host : candidate_hosts) {
        if (nmasters >= 4) break;
        struct addrinfo* res = nullptr;
        int rc = getaddrinfo(host.c_str(), port_str, &hints, &res);
        if (rc == 0 && res) {
            for (struct addrinfo* ai = res; ai && nmasters < 4; ai = ai->ai_next) {
                if (ai->ai_family == AF_INET) {
                    masters[nmasters++] = *reinterpret_cast<struct sockaddr_in*>(ai->ai_addr);
                }
            }
            freeaddrinfo(res);
            // Keep collecting instead of stopping at the first hit: regional
            // shards like us-m1 have been observed to accept DNS but black-hole
            // UDP (verified live: us-m1 silent, m1 replies). The SDK races every
            // master the same way; a JOIN to a dead one is a harmless drop.
            if (resolved_host[0] == '\0')
                snprintf(resolved_host, sizeof(resolved_host), "%s", host.c_str());
        }
    }

    if (nmasters == 0) {
        OBN_ERROR("iotc relay: no IPv4 master address found for region %s", region_str);
        return -1;
    }
    struct sockaddr_in master_addr = masters[0];

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &master_addr.sin_addr, ip_str, sizeof(ip_str));
    OBN_DEBUG("iotc relay: resolved %d master(s) (first: %s -> %s:10240)", nmasters, resolved_host, ip_str);

    obn::net::socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == obn::net::kInvalid) {
        OBN_ERROR("iotc relay: socket() failed: %s", strerror(errno));
        return -1;
    }

    uint8_t session_token[8];
    {
        uint32_t a = rand32(), b = rand32();
        memcpy(session_token + 0, &a, 4);
        memcpy(session_token + 4, &b, 4);
    }

    // Query every resolved master in parallel (the SDK races them). The client
    // does not KNOCK the master; the printer's rendezvous / off-LAN candidate
    // exchange follows from the JOIN.
    int njoined = 0;
    for (int m = 0; m < nmasters; ++m)
        if (send_relay_join(sock, &masters[m], uid_upper, relay_id) == 0) ++njoined;
    if (njoined == 0) {
        OBN_ERROR("iotc relay: JOIN send failed: %s", strerror(errno));
        obn::net::close_socket(sock);
        return -1;
    }
    OBN_DEBUG("iotc relay: JOIN sent to %d master(s)", njoined);

    set_recv_timeout(sock, 3000);
    bool got_assignment = false;
    // The rendezvous (02 06 12) is sent by the printer from its own P2P media
    // address, not by the master server. That source address is the peer we must
    // punch and run DTLS/media against; the master only brokers the rendezvous.
    struct sockaddr_in peer_addr{};
    uint8_t master_reply[256];
    size_t  master_reply_len = 0;
    for (int attempt = 0; attempt < 3; ++attempt) {
        uint8_t resp[256];
        struct sockaddr_in src{};
        socklen_t src_len = sizeof(src);
        ssize_t n = recvfrom(sock, resp, sizeof(resp), 0,
                              (struct sockaddr*)&src, &src_len);
        if (n < 0) {
            OBN_DEBUG("iotc relay: recv timeout attempt %d", attempt + 1);
            continue;
        }

        OBN_DEBUG("iotc relay: received %zd bytes", n);

        if (n < 16) continue;
        reverse_trans_code_partial(resp, (size_t)n);

        if (resp[0] != 0x04 || resp[1] != 0x02) {
            OBN_WARN("iotc relay: bad IOTC magic %02x%02x", resp[0], resp[1]);
            continue;
        }

        // The master's 08 10 83 reply lists the rendezvous servers and our own
        // reflexive address; keep it for the off-LAN fallback below.
        if (resp[8] == 0x08 && resp[9] == 0x10 && resp[10] == 0x83) {
            master_reply_len = (size_t)n < sizeof(master_reply) ? (size_t)n : sizeof(master_reply);
            memcpy(master_reply, resp, master_reply_len);
            continue;
        }

        if (resp[8] != 0x02 || resp[9] != 0x06 || resp[10] != 0x12) {  // printer rendezvous
            OBN_WARN("iotc relay: unexpected msg type %02x%02x%02x (expected 02 06 12)", resp[8], resp[9], resp[10]);
            continue;
        }

        if (n >= 192) {  // verify session_token echo at [188..191]
            if (resp[188] != session_token[0] || resp[189] != session_token[1] ||
                resp[190] != session_token[2] || resp[191] != session_token[3]) {
                OBN_WARN("iotc relay: session_token echo mismatch: got %02x%02x%02x%02x expected %02x%02x%02x%02x",
                        resp[188], resp[189], resp[190], resp[191],
                        session_token[0], session_token[1],
                        session_token[2], session_token[3]);
                // Log but don't reject — the echo offset may differ by firmware
            } else {
                OBN_DEBUG("iotc relay: session_token echo verified");
            }
        }

        peer_addr = src;
        got_assignment = true;
        {
            char pip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &peer_addr.sin_addr, pip, sizeof(pip));
            OBN_DEBUG("iotc relay: rendezvous received; peer = %s:%u",
                      pip, ntohs(peer_addr.sin_port));
        }
        break;
    }

    // Off-LAN fallback: the printer did not send a direct rendezvous, so run the
    // reflexive/candidate exchange with the servers the master listed. On success
    // peer_addr is the printer's P2P media address or the rendezvous relay server.
    uint32_t relay_tag = 0;
    if (!got_assignment && master_reply_len > 0) {
        OBN_DEBUG("iotc relay: no direct rendezvous; trying off-LAN candidate exchange");
        if (offlan_rendezvous(sock, master_reply, master_reply_len,
                              uid_upper, authkey, session_token, &peer_addr, &relay_tag)) {
            got_assignment = true;
            char pip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &peer_addr.sin_addr, pip, sizeof(pip));
            OBN_DEBUG("iotc relay: off-LAN rendezvous succeeded; peer = %s:%u (tag=%u)",
                      pip, ntohs(peer_addr.sin_port), relay_tag);
        }
    }

    if (!got_assignment) {
        OBN_WARN("iotc relay: no rendezvous received");
        obn::net::close_socket(sock);
        return -1;
    }

    // Punch and run the session against the peer's own address (from the
    // rendezvous), not the master server. Only send knock if direct P2P.
    if (ntohs(peer_addr.sin_port) != 3478) {
        if (send_relay_knock(sock, &peer_addr, uid_upper, session_token, true) != 0) {
            OBN_ERROR("iotc relay: post-assignment KNOCK failed: %s", strerror(errno));
            obn::net::close_socket(sock);
            return -1;
        }
        OBN_DEBUG("iotc relay: post-assignment KNOCK sent to peer");
    }

    out->sock = sock;
    out->peer = peer_addr;
    memcpy(out->session_token, session_token, 8);
    out->relay_tag = relay_tag;
    out->is_relay = (ntohs(peer_addr.sin_port) == 3478);
    if (uid_upper) {
        strncpy(out->uid_upper, uid_upper, sizeof(out->uid_upper) - 1);
        out->uid_upper[sizeof(out->uid_upper) - 1] = '\0';
    }
    memset(&out->dtls, 0, sizeof(out->dtls));
    out->dtls.relay_tag = relay_tag;
    memset(out->relay_cookie, 0, sizeof(out->relay_cookie));
    out->have_relay_cookie = false;

    return 0;
}

// ==========================================================================
// LAN discovery
// ==========================================================================
//
// With the client on the printer's LAN the SDK finds it by broadcast instead of
// the master: 01 06 21 search to UDP 32761, the printer answers 02 06 12 from
// its P2P media port, and the session (DTLS included) runs directly against
// that address.

static constexpr uint16_t kLanSearchPort = 32761;

// 01 06 21 LAN search: UID at [16..36), SDK version 4.3.3.4 at [52..56),
// session token at [56..64), 1 at [64..68), authkey (ASCII) at [74..82).
static void build_lan_search(uint8_t pkt[88], const char* uid_upper,
                             const uint8_t session_token[8], const char* authkey)
{
    memset(pkt, 0, 88);
    write_rdv_hdr(pkt, 88 - 16, 0x01, 0x06, 0x21);
    memcpy(pkt + 16, uid_upper, std::min<size_t>(strlen(uid_upper), kUidLen));
    static const uint8_t kSdkVersion[4] = {0x04, 0x03, 0x03, 0x04};
    memcpy(pkt + 52, kSdkVersion, 4);
    memcpy(pkt + 56, session_token, 8);
    pkt[64] = 0x01;
    memcpy(pkt + 74, authkey, std::min<size_t>(strlen(authkey), 8));
    trans_code_partial(pkt, 88);
}

// IPv4 broadcast address of every up, non-loopback interface, plus the
// limited broadcast as a fallback.
static std::vector<struct sockaddr_in> lan_broadcast_targets()
{
    std::vector<struct sockaddr_in> out;
    auto add = [&out](uint32_t bcast_be) {
        for (const auto& a : out)
            if (a.sin_addr.s_addr == bcast_be) return;
        struct sockaddr_in a{};
        a.sin_family      = AF_INET;
        a.sin_port        = htons(kLanSearchPort);
        a.sin_addr.s_addr = bcast_be;
        out.push_back(a);
    };
#if defined(_WIN32)
    ULONG size = 0;
    if (GetIpAddrTable(nullptr, &size, FALSE) == ERROR_INSUFFICIENT_BUFFER && size > 0) {
        std::vector<uint8_t> buf(size);
        auto* table = reinterpret_cast<MIB_IPADDRTABLE*>(buf.data());
        if (GetIpAddrTable(table, &size, FALSE) == NO_ERROR) {
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                const auto& row = table->table[i];
                if (row.dwAddr == 0 || row.dwAddr == htonl(INADDR_LOOPBACK)) continue;
                add(row.dwAddr | ~row.dwMask);
            }
        }
    }
#else
    struct ifaddrs* ifs = nullptr;
    if (getifaddrs(&ifs) == 0) {
        for (struct ifaddrs* i = ifs; i; i = i->ifa_next) {
            if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
            if (!(i->ifa_flags & IFF_UP) || (i->ifa_flags & IFF_LOOPBACK)) continue;
            if (!(i->ifa_flags & IFF_BROADCAST) || !i->ifa_broadaddr) continue;
            add(reinterpret_cast<struct sockaddr_in*>(i->ifa_broadaddr)->sin_addr.s_addr);
        }
        freeifaddrs(ifs);
    }
#endif
    add(htonl(INADDR_BROADCAST));
    return out;
}

int iotc_lan_connect(const char* uid_upper, const char* authkey, int timeout_ms,
                     IotcConn* out)
{
    if (!uid_upper || strlen(uid_upper) != kUidLen || !out) return -1;
    if (!authkey) authkey = "";
    memset(out, 0, sizeof(*out));
    out->sock = -1;

    obn::net::socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == obn::net::kInvalid) {
        OBN_ERROR("iotc lan: socket() failed: %s", strerror(errno));
        return -1;
    }
    int on = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));

    uint8_t session_token[8];
    RAND_bytes(session_token, sizeof(session_token));

    uint8_t search[88];
    build_lan_search(search, uid_upper, session_token, authkey);
    const auto targets = lan_broadcast_targets();

    struct sockaddr_in peer{};
    bool found = false;
    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(timeout_ms);
    auto next_send = std::chrono::steady_clock::now();
    while (!found && std::chrono::steady_clock::now() < deadline) {
        if (std::chrono::steady_clock::now() >= next_send) {
            for (const auto& t : targets)
                sendto(sock, search, sizeof(search), 0,
                       (const struct sockaddr*)&t, sizeof(t));
            next_send += std::chrono::milliseconds(250);
        }
        set_recv_timeout(sock, 50);
        uint8_t resp[512];
        struct sockaddr_in src{};
        socklen_t src_len = sizeof(src);
        ssize_t n = recvfrom(sock, resp, sizeof(resp), 0, (struct sockaddr*)&src, &src_len);
        if (n < 200) continue;
        reverse_trans_code_partial(resp, (size_t)n);
        if (resp[0] != 0x04 || resp[1] != 0x02 ||
            resp[8] != 0x02 || resp[9] != 0x06 || resp[10] != 0x12)
            continue;
        if (memcmp(resp + 16, uid_upper, kUidLen) != 0) continue;
        if (memcmp(resp + 188, session_token, 8) != 0) continue;
        peer  = src;
        found = true;
    }
    if (!found) {
        OBN_DEBUG("iotc lan: no LAN search reply within %d ms", timeout_ms);
        obn::net::close_socket(sock);
        return -1;
    }

    // Stock repeats the search unicast to the printer before starting DTLS.
    sendto(sock, search, sizeof(search), 0, (const struct sockaddr*)&peer, sizeof(peer));

    char pip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer.sin_addr, pip, sizeof(pip));
    OBN_DEBUG("iotc lan: printer answered LAN search from %s:%u", pip, ntohs(peer.sin_port));

    out->sock       = sock;
    out->peer = peer;
    memcpy(out->session_token, session_token, 8);
    out->is_relay   = false;
    out->is_lan     = true;
    snprintf(out->uid_upper, sizeof(out->uid_upper), "%s", uid_upper);
    return 0;
}

// epoch=0, type-0x33 auth packet sent only for off-LAN direct P2P (omitted for
// the relay server and on the LAN, where stock sends none either).
int iotc_dtls_handshake(IotcConn* rc,
                    const char* passwd, const char* account)
{
    if (!rc || rc->sock < 0) return -1;

    return dtls_psk_handshake(rc->sock, &rc->peer,
                               rc->session_token,
                               (rc->is_relay || rc->is_lan) ? nullptr : rc->uid_upper,
                               passwd, account,
                               &rc->dtls,
                               rc->relay_tag);
}

int iotc_send_app_data(IotcConn* rc,
                              const uint8_t* data, size_t len)
{
    if (!rc || rc->sock < 0) return -1;
    DtlsSession& ds = rc->dtls;

    std::vector<uint8_t> dtls_rec;
    if (!dtls_encrypt_record(&ds, 0x17 /*ApplicationData*/, data, len, dtls_rec)) {
        OBN_ERROR("iotc relay-send: encrypt ApplicationData failed (len=%zu)", len);
        return -1;
    }

    // Stock keeps the sub-header epoch at 0 on the LAN path.
    int rc_send = send_dtls_packet(rc->sock, &rc->peer,
                                   rc->is_lan ? 0 : ds.epoch, rc->session_token,
                                   dtls_rec.data(), dtls_rec.size(),
                                   ds.pkt_seq++, rc->relay_tag);
    if (rc_send != 0) {
        OBN_ERROR("iotc relay-send: send_dtls_packet failed (len=%zu, dtls_len=%zu)", len, dtls_rec.size());
    } else {
        OBN_DEBUG("iotc relay-send: sent %zu B app data (dtls_len=%zu, epoch=%u)", len, dtls_rec.size(), ds.epoch);
    }
    return rc_send;
}

// 24-byte direct P2P session control: 16-byte header (flags 0x0a) + session
// token. 27 04 21 is the client alive (the printer answers 28 04 12), 17 04 21
// closes the session.
static void send_p2p_session_ctrl(const IotcConn* rc, uint8_t t0)
{
    uint8_t pkt[24];
    write_rdv_hdr(pkt, 8, t0, 0x04, 0x21);
    pkt[3] = 0x0a;
    memcpy(pkt + 16, rc->session_token, 8);
    trans_code_partial(pkt, sizeof(pkt));
    obn::camera::tutk::sendto(rc->sock, pkt, sizeof(pkt), 0,
                                (const struct sockaddr*)&rc->peer, (int)sizeof(rc->peer));
}

static int64_t steady_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

int iotc_recv_app_data(IotcConn* rc,
                              uint8_t* out_buf, size_t out_size,
                              int timeout_ms)
{
    if (!rc || rc->sock < 0) return -1;
    DtlsSession& ds = rc->dtls;

    // Stock sends the alive every ~2 s; the printer otherwise keeps probing.
    if (!rc->is_relay && steady_ms() - rc->last_alive_ms >= 2000) {
        send_p2p_session_ctrl(rc, 0x27);
        rc->last_alive_ms = steady_ms();
    }

    auto start_time = std::chrono::steady_clock::now();
    auto deadline = start_time + std::chrono::milliseconds(timeout_ms > 0 ? timeout_ms : 0);

    do {
        int remain_ms = (timeout_ms <= 0) ? 0 :
            (int)std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remain_ms < 0) break;

        int step_timeout = (timeout_ms <= 0) ? 0 : std::max(1, std::min(remain_ms, 200));
        set_recv_timeout(rc->sock, step_timeout);

        uint8_t raw[65536 + 64];
        struct sockaddr_in src{};
        socklen_t src_len = sizeof(src);
        ssize_t n = recvfrom(rc->sock, raw, sizeof(raw), 0,
                              (struct sockaddr*)&src, &src_len);
        if (n < 0) {
#if defined(_WIN32)
            int err = ::WSAGetLastError();
            if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
                if (std::chrono::steady_clock::now() >= deadline)
                    return 0;
                continue;
            }
            OBN_ERROR("iotc relay-recv: recvfrom error: WSA %d", err);
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT) {
                if (std::chrono::steady_clock::now() >= deadline)
                    return 0;
                continue;
            }
            OBN_ERROR("iotc relay-recv: recvfrom error: %s", strerror(errno));
#endif
            return -1;
        }

        if (n < 16) continue;

        // Ignore stray packets from other rendezvous servers or unknown peers
        if (src.sin_addr.s_addr != rc->peer.sin_addr.s_addr ||
            src.sin_port != rc->peer.sin_port) {
            continue;
        }

        descramble_rx(raw, (size_t)n);

        if (raw[0] != 0x04 || raw[1] != 0x02) continue;

        // If server re-sends 03 03 43 pairing confirmed, ACK it so server stops retrying
        if (raw[8] == 0x03 && raw[9] == 0x03 && raw[10] == 0x43) {
            uint32_t tag = 0;
            if (n >= 40) memcpy(&tag, raw + 36, 4);
            uint32_t tag_h = le32toh(tag);
            send_rdv_ack(rc->sock, &src, rc->uid_upper, rc->session_token, tag_h);
            OBN_DEBUG("iotc relay-recv: re-ACKed 03 03 43 from relay (tag=%u)", tag_h);
            continue;
        }

        // Relay notification: peer disconnected / channel closed (0x13 0x05 0x42)
        if (rc->is_relay && n == 24 && raw[8] == 0x13 && raw[9] == 0x05 && raw[10] == 0x42) {
            OBN_WARN("iotc relay-recv: peer disconnected by relay (type=0x13 0x05 0x42)");
            return -2;
        }

        // Relay keepalive ping: 0x23 0x05 0x42 (24 bytes)
        if (rc->is_relay && n == 24 && raw[8] == 0x23 && raw[9] == 0x05 && raw[10] == 0x42) {
            memcpy(rc->relay_cookie, raw + 16, 8);
            rc->have_relay_cookie = true;

            uint8_t pong[24];
            memcpy(pong, raw, 24);
            pong[2] = 0x1c;
            pong[8] = 0x24; pong[9] = 0x05; pong[10] = 0x24;
            trans_code_partial(pong, sizeof(pong));
            obn::camera::tutk::sendto(rc->sock, pong, sizeof(pong), 0,
                                        (const struct sockaddr*)&rc->peer, (int)sizeof(rc->peer));
            OBN_DEBUG("iotc relay-recv: answered relay ping 23 05 42 with pong 24 05 24 (tag=%u)", rc->relay_tag);
            continue;
        }

        // Verify DTLS packet encapsulation:
        // Relay: raw[8..10] == {0x03, 0x05, 0x42}
        // Direct P2P: raw[8..10] == {0x08, 0x04, 0x12} (printer -> client;
        // {0x07, 0x04, 0x21} is the client -> printer direction)
        bool is_dtls = rc->is_relay
            ? (raw[8] == 0x03 && raw[9] == 0x05 && raw[10] == 0x42)
            : (raw[9] == 0x04 && ((raw[8] == 0x08 && raw[10] == 0x12) ||
                                  (raw[8] == 0x07 && raw[10] == 0x21)));
        if (!is_dtls) {
            OBN_DEBUG("iotc relay-recv: skipping non-DTLS packet: len=%zd type=%02x %02x %02x",
                      n, raw[8], raw[9], raw[10]);
            continue;
        }

        if (n < 28 + 13) continue;  // too short for IOTC header + DTLS record header

        uint8_t content_type = raw[28];

        // Skip non-ApplicationData records (handshake/alerts)
        if (content_type != 0x17) {
            OBN_DEBUG("iotc relay-recv: skipping DTLS record type 0x%02x", content_type);
            continue;
        }

        const uint8_t* dtls_rec = raw + 28;
        size_t dtls_len = (size_t)(n - 28);
        int plain_len = dtls_decrypt_record(&ds, dtls_rec, dtls_len, out_buf, out_size);
        if (plain_len >= 0) {
            ds.rx_seq++;
            return plain_len;
        } else {
            OBN_WARN("iotc relay-recv: dtls_decrypt_record failed (err=%d, dtls_len=%zu)", plain_len, dtls_len);
        }
    } while (std::chrono::steady_clock::now() < deadline);

    return 0;  // timed out without an AppData packet
}

void iotc_close(IotcConn* rc)
{
    if (!rc) return;
    if (rc->sock >= 0) {
        if (rc->is_relay && rc->relay_tag != 0) {
            // Burst 5x 0x14 0x05 0x24 relay close packets to ThroughTek relay server
            // so the server tears down the relay tag immediately and sends 0x13 0x05 0x42
            // to the printer to release its liveview worker.
            uint8_t pkt[24] = {0};
            pkt[0] = 0x04; pkt[1] = 0x02;
            pkt[2] = 0x1c; pkt[3] = 0x0a;
            pkt[4] = 0x08; pkt[5] = 0x00; pkt[6] = 0x00; pkt[7] = 0x00;
            pkt[8] = 0x14; pkt[9] = 0x05; pkt[10] = 0x24; pkt[11] = 0x00;
            uint32_t tag_le = htole32(rc->relay_tag);
            memcpy(pkt + 12, &tag_le, 4);
            if (rc->have_relay_cookie) {
                memcpy(pkt + 16, rc->relay_cookie, 8);
            } else {
                memcpy(pkt + 16, rc->session_token, 8);
            }
            trans_code_partial(pkt, sizeof(pkt));
            for (int i = 0; i < 5; ++i) {
                obn::camera::tutk::sendto(rc->sock, pkt, sizeof(pkt), 0,
                                            (const struct sockaddr*)&rc->peer, (int)sizeof(rc->peer));
            }
            OBN_DEBUG("iotc relay-close: sent 5x relay close packets (type=0x14 0x05 0x24, tag=%u)", rc->relay_tag);
        } else if (!rc->is_relay) {
            for (int i = 0; i < 3; ++i)
                send_p2p_session_ctrl(rc, 0x17);
        }
        obn::net::close_socket(rc->sock);
        rc->sock = -1;
    }
    memset(rc, 0, sizeof(*rc));
    rc->sock = -1;
}

} // namespace tutk
} // namespace camera
} // namespace obn
