// ==========================================================================
// WHAT IS KNOWN / UNKNOWN
// ==========================================================================
//
// KNOWN:
//   - Master server domain pattern: "<region>-c-master.iotcplatform.com"  (dash separator)
//   - Secondary: "<region>-c-master.kalayservice.com"
//   - CN region: "<region>-c-master.kalay.net.cn"
//   - UID: exactly 20 printable ASCII characters, stored lowercase
//   - LAN search packet size: 516 bytes (0x204)
//   - Session struct stride: 5824 bytes per session (0x16c0)
//   - IotcConnectCfg: 20-byte struct (size field must be 0x14)
//   - AvStartIn:  56-byte struct (size field 0x38)
//   - AvStartOut: 24-byte struct (size field 0x18 pre-filled)
//   - IPCAM_START command: avSendIOCtrl(idx, 0xFF01, NULL, 0)
//   - AV frame header: 16 bytes, magic marker 0x013f in bytes 4-5
//   - H.264 frames delivered via avRecvFrameData2 (reassembled from packets)
//   - NAT traversal message sequence: PRECHECK1 → PRECHECK2 → REQUEST →
//     KNOCK/KNOCK_R/KNOCK_RR → PUNCH_TO → P2P session alive
//   - Relay fallback: RLY_REQUEST → RLY_REQUEST_R2 → RLY_KNOCK → session
//   - TCP relay mode controlled by gbTcpRelayMode global
//   - DTLS encryption layer available (IOTC_sCHL_* functions, PSK-based)
//   - Auth key: uint64 from the "authkey" URL parameter (8 bytes)
//   - Default password: "888888"; account: "admin"
//
// STILL UNKNOWN / NEEDS CAPTURE:
//   - Exact numeric values for TutkMsgType enum
//   - Full LAN search response structure (gDeviceName field contents)
//   - How authkey is used in MSG_P2P_PRECHECK2 (likely HMAC or direct field)
//   - FEC (Forward Error Correction) parameters (avDefineFECEncodeRatio refs)
//   - DTLS PSK identity format for AV channel encryption
//   - Whether LOGIN ACK payload_len=4 is always the case or varies by firmware
//
// NOTE: Bambu's production firmware operates in LAN-direct or Agora-relay mode
// only.  CheckLicenseKeyIsValid() returns -1004, permanently short-circuiting
// the TUTK master registration path (IOTC_TcpConnectToMaster).  The master
// server is never contacted at runtime.
//
// TODO for future work:
//   [ ] Decode the AV frame body to confirm JSON+binary structure
//   [ ] Implement LAN search + verify against a real printer
//   [ ] Implement full NAT traversal state machine
//   [ ] Confirm MSG_P2P_ALIVE_C2D bytes via pcap if NAT P2P path is ever used

#include "obn/net_compat.hpp"
#include "obn/endian_compat.hpp"   // htole32/le32toh etc. — <endian.h> is POSIX-only

#ifndef SHUT_RDWR
#  define SHUT_RDWR SD_BOTH
#endif

#include "IotcProtocol.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include "obn/log.hpp"

namespace bambu_net {
namespace oss_tutk {

// ==========================================================================
// Windows / MSVC portability shim
// ==========================================================================
//
// This translation unit was written against POSIX sockets (ssize_t,
// read()/write() on fds, struct-timeval SO_RCVTIMEO, errno-based EAGAIN
// checks).  obn/net_compat.hpp already pulls in winsock2 and gives us
// socket_t / close_socket / kInvalid, but the raw recv/send/sendto/recvfrom
// call sites below still assume POSIX semantics.  Rather than sprinkle
// #ifdefs over ~40 call sites we provide a small set of in-namespace inline
// wrappers (same names: recv/send/sendto/recvfrom/read/write) so the bare,
// unqualified calls in this file resolve here on Windows.  On POSIX nothing
// in this block is compiled, so the Linux output is byte-identical.
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

inline ssize_t recv(obn::net::socket_t s, void* buf, size_t len, int flags)
{
    int r = ::recv(s, static_cast<char*>(buf), static_cast<int>(len), flags);
    if (r < 0) win_compat::set_errno_from_wsa();
    return r;
}

inline ssize_t send(obn::net::socket_t s, const void* buf, size_t len, int flags)
{
    int r = ::send(s, static_cast<const char*>(buf), static_cast<int>(len), flags);
    if (r < 0) win_compat::set_errno_from_wsa();
    return r;
}

// POSIX read()/write() on a connected stream socket map to recv()/send().
inline ssize_t read(obn::net::socket_t s, void* buf, size_t len)
{
    return recv(s, buf, len, 0);
}

inline ssize_t write(obn::net::socket_t s, const void* buf, size_t len)
{
    return send(s, buf, len, 0);
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

[[maybe_unused]] static uint32_t now_sec()
{
    // Portable monotonic seconds (POSIX clock_gettime(CLOCK_MONOTONIC) is not
    // available on MSVC; std::chrono::steady_clock is the cross-platform path).
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

static uint32_t rand32()
{
    // Simple non-crypto random; TUTK uses GenShortRandomID which calls
    // a similar lightweight generator.
    static uint64_t state = 0;
    if (!state) { RAND_bytes((unsigned char*)&state, sizeof(state)); }
    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
    return (uint32_t)state;
}

// Canonicalize UID to lowercase (IOTC_Connect_UDP_Inner loop at +0xf0).
static std::string uid_lower(const std::string& uid)
{
    std::string out = uid;
    for (char& c : out)
        if (c >= 'A' && c <= 'Z') c += 0x20;
    return out;
}

static std::string uid_upper(const std::string& uid)
{
    std::string out = uid;
    for (char& c : out)
        if (c >= 'a' && c <= 'z') c -= 0x20;
    return out;
}

// IsUIDVaild.part.0: loop 0x14 iterations, each byte passes ctype is-print (bit 0x08).
static bool uid_valid(const std::string& uid)
{
    if (uid.size() != kUidLen) return false;
    for (unsigned char c : uid)
        if (c < 0x21 || c > 0x7e) return false;  // printable non-space ASCII
    return true;
}

// ==========================================================================
// Master server DNS resolution
// ==========================================================================

//   Format string: "%s-%s-%s%s"  → <region>-<service>-<service2><tld_with_leading_dot>
//
// In practice for the "c-master" (control) service:
//   gRegionName[region]  = "cn" / "eu" / "us" / "asia"
//   gServiceName[0]      = "c-master"
//   Hostname suffix      = ".iotcplatform.com"  (leading dot in the table entry)
//
// Final result example:  "us-c-master.iotcplatform.com"
//   (the format is <region>-c-master + .iotcplatform.com, NOT dot-separated)
//
// Note: the real binary requires a vendor license key (gIsKeySet / gIsCustomRealm)
// before GetMasterDomainName will succeed.  In our open reimplementation we skip
// that check and hard-code the public TUTK domains.
//
// The binary tries 12 server addresses, cycling the port from a table:
//   gTcpTryPort = [80, 443, 21047, 8080, 8000, 20297, 17236, 0, 8686, ...]
// We expose only the first-choice hostname here; connect_to_master() tries ports.
static std::string master_hostname(TutkRegion region, bool cn_domain = false)
{
    const char* rname;
    switch (region) {
        case TutkRegion::CN:   rname = "cn";   break;
        case TutkRegion::EU:   rname = "eu";   break;
        case TutkRegion::US:   rname = "us";   break;
        case TutkRegion::Asia: rname = "asia"; break;
        default:               rname = "";     break; // Global = no region prefix
    }

    const char* tld = cn_domain ? ".kalay.net.cn" : ".iotcplatform.com";

    if (rname[0])
        return std::string(rname) + "-c-master" + tld;
    else
        return std::string("c-master") + tld;
}

// NOTE: The TUTK master path is never reached in production Bambu firmware —
// CheckLicenseKeyIsValid() returns -1004.  Retained for completeness.
static bool resolve_master(const std::string& hostname, uint16_t port,
                           struct sockaddr_in* out)
{
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int rc = getaddrinfo(hostname.c_str(), port_str, &hints, &res);
    if (rc != 0 || !res) {
        OBN_ERROR("[oss-iotc] DNS failed for %s: %s", hostname.c_str(), gai_strerror_portable(rc));
        return false;
    }
    *out = *reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    freeaddrinfo(res);
    return true;
}

// ==========================================================================
// UDP socket helpers
// ==========================================================================

// Mirrors IOTC_OpenUDP_P2PSocket; gP2PLocalUdpPort defaults to 0 (OS-assigned).
static obn::net::socket_t open_udp_socket(uint16_t* bound_port_out)
{
    obn::net::socket_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == obn::net::kInvalid) return obn::net::kInvalid;

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = 0; // ephemeral

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        obn::net::close_socket(fd); return obn::net::kInvalid;
    }

    if (bound_port_out) {
        socklen_t len = sizeof(addr);
        getsockname(fd, (struct sockaddr*)&addr, &len);
        *bound_port_out = ntohs(addr.sin_port);
    }
    return fd;
}

static void set_recv_timeout(obn::net::socket_t fd, int ms)
{
    set_socket_recv_timeout(fd, ms);
}

// ==========================================================================
// TransCodePartial — TUTK packet scrambling (all bytes of each UDP datagram)
// ==========================================================================
//
//   iotc_trans_arr @ data segment: "Charlie is the devil, but I am ..."
//   KEY = first 16 bytes = "Charlie is the d"
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

#ifdef OBN_TESTING
void trans_code_partial_test(uint8_t* data, size_t len)         { trans_code_partial(data, len); }
void reverse_trans_code_partial_test(uint8_t* data, size_t len) { reverse_trans_code_partial(data, len); }
#endif

// ==========================================================================
// IOTC DTLS frame encoder / decoder
// ==========================================================================
//
// All DTLS packets are wrapped in a 28-byte IOTC+sub-header, then the
// entire packet (all 28+N bytes) is scrambled with trans_code_partial.
//
// IOTC header (16 bytes):
//   [0..1]  0x0204 (LE) — magic
//   [2]     0x1c        — version
//   [3]     0x0b        — flags (DTLS payload)
//   [4..5]  payload_len LE (= 12 + dtls_len)
//   [6..7]  0x0000
//   [8]     0x07, [9] 0x04, [10] 0x21  — msg type (client→server DTLS)
//   [11]    0x00
//   [12..13] session_token[0..1] (first 2 bytes of 8-byte session token)
//   [14..15] 0x0001
//
// Sub-header (12 bytes):
//   [0]     0x0c
//   [1..2]  epoch_low16 big-endian  (0x0000 before ServerHello, 0x06a0 after)
//   [3]     0x00
//   [4..11] session_token (8 bytes)
//
// Received DTLS packets have a slightly different msg-type triplet:
//   [8]=0x08, [9]=0x04, [10]=0x12  (server→client)

static int send_dtls_packet(obn::net::socket_t sock, const struct sockaddr_in* dst,
                             uint32_t epoch,
                             const uint8_t session_token[8],
                             const uint8_t* dtls_data, size_t dtls_len,
                             uint32_t relay_tag = 0)
{
    size_t total = 28 + dtls_len;
    std::vector<uint8_t> pkt(total, 0);

    uint16_t payload_len = (uint16_t)(12 + dtls_len);
    bool is_relay = (dst && ntohs(dst->sin_port) == 3478);
    static std::atomic<uint16_t> s_packet_seq{0};
    uint16_t seq_num = s_packet_seq.fetch_add(1);

    // IOTC header
    pkt[0] = 0x04; pkt[1] = 0x02;
    pkt[2] = 0x1c;
    pkt[3] = 0x0b;
    pkt[4] = (uint8_t)(payload_len & 0xff);
    pkt[5] = (uint8_t)(payload_len >> 8);

    if (is_relay) {
        pkt[6] = (uint8_t)(seq_num & 0xff);
        pkt[7] = (uint8_t)((seq_num >> 8) & 0xff);
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
        pkt[6] = 0x00; pkt[7] = 0x00;
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

    trans_code_partial(pkt.data(), std::min(total, (size_t)64));

    ssize_t n = sendto(sock, pkt.data(), total, 0,
                       (const struct sockaddr*)dst, sizeof(*dst));
    return (n == (ssize_t)total) ? 0 : -1;
}

// Retries on non-DTLS IOTC packets (e.g., stray type 0x33 echoes before ServerHello).
// Returns DTLS payload length on success, -1 on timeout/error.
static int recv_dtls_packet(obn::net::socket_t sock, uint8_t* dtls_out, size_t buf_size,
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
        if (n < 28) continue;

        reverse_trans_code_partial(raw, (size_t)n);

        if (raw[0] != 0x04 || raw[1] != 0x02) continue;  // discard non-IOTC

        // Skip non-DTLS IOTC packets (type 0x33 echoes, stray rendezvous packets):
        // DTLS content starts with 0x16 (Handshake), 0x14 (CCS), or 0x15 (Alert).
        size_t dtls_len = (size_t)(n - 28);
        if (dtls_len < 1 || (raw[28] != 0x16 && raw[28] != 0x14 && raw[28] != 0x15)) {
            OBN_DEBUG("[dtls] recv: skipping non-DTLS IOTC pkt (n=%zd type=0x%02x)", n, dtls_len > 0 ? raw[28] : 0);
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

        if (dtls_len > buf_size) dtls_len = buf_size;
        memcpy(dtls_out, raw + 28, dtls_len);
        return (int)dtls_len;
    }
    return -1;
}

// ==========================================================================
// LAN_SEARCH3 wire layout (88 bytes, scrambled with trans_code_partial):
//   [0..15]  IOTC header: magic=0x0204, ver=0x1c, flags=0x00, payload_len=0x48,
//            bytes[8..10]={0x01,0x06,0x21}
//   [16..35] uid (20B, UPPERCASE)
//   [36..39] connect_flag (uint32 LE = 0)
//   [40..47] zeros (unknown fields)
//   [48..51] = 0x00 [epoch_hi] [epoch_lo] 0x00   (first epoch occurrence)
//   [52..55] iotc_version (uint32 LE = 0x04030304)
//   [56..59] client_random (uint32 LE)
//   [60..63] partial_mac (uint32 LE)
//   [64]     search_type: 0x01=broadcast, 0x02=directed
//   [65..66] [epoch_hi] [epoch_lo]   (second epoch occurrence)
//   [67..87] zeros
//
static int send_lan_search3(obn::net::socket_t sock, const struct sockaddr_in* dst,
                             const char* uid_up, uint32_t client_random,
                             uint32_t partial_mac, uint16_t epoch, bool directed)
{
    uint8_t pkt[88];
    memset(pkt, 0, sizeof(pkt));

    pkt[0] = 0x04; pkt[1] = 0x02;
    pkt[2] = 0x1c;
    // pkt[3] = flags = 0
    pkt[4] = 0x48;  // payload_len = 72 LE
    // pkt[5..7] = 0
    pkt[8]  = 0x01; pkt[9]  = 0x06; pkt[10] = 0x21;
    // pkt[11..15] = 0

    memcpy(pkt + 16, uid_up, 20);
    pkt[49] = (uint8_t)(epoch >> 8);  // epoch appears twice: [49..50] and [65..66]
    pkt[50] = (uint8_t)(epoch     );
    uint32_t ver = htole32(0x04030304);
    memcpy(pkt + 52, &ver, 4);
    uint32_t cr_le = htole32(client_random);
    memcpy(pkt + 56, &cr_le, 4);
    uint32_t pm_le = htole32(partial_mac);
    memcpy(pkt + 60, &pm_le, 4);
    pkt[64] = directed ? 0x02 : 0x01;
    pkt[65] = (uint8_t)(epoch >> 8);
    pkt[66] = (uint8_t)(epoch     );

    trans_code_partial(pkt, sizeof(pkt));
    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0,
                       (const struct sockaddr*)dst, sizeof(*dst));
    return (n == sizeof(pkt)) ? 0 : -1;
}

// Type 0x33 control packet — session establishment handshake step
// ==========================================================================
//
// 52-byte packet sent after LAN_SEARCH3; printer echoes it back to confirm
// the session token.
//
// Layout (all 52 bytes scrambled with trans_code_partial):
//   [0..15]  IOTC header: magic=0x0204, ver=0x1c, flags=0x02,
//              payload_len=0x24, bytes[8..10]={0x02,0x04,0x33}
//   [16..35] UID (20 bytes, UPPERCASE)
//   [36..43] session_token (8 bytes)
//   [44..47] 0x00000000
//   [48..51] 0x01000000 (little-endian 1 — observed constant)

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
    // [48..51]: one capture shows 0x211e2619 — leave zero for now

    trans_code_partial(pkt, sizeof(pkt));

    ssize_t n = sendto(sock, pkt, sizeof(pkt), 0,
                       (const struct sockaddr*)dst, sizeof(*dst));
    return (n == sizeof(pkt)) ? 0 : -1;
}

// ==========================================================================
// DTLS-PSK handshake — TUTK custom wire format
// ==========================================================================
//
// DTLS-over-IOTC relay — wire format from captured relay traffic:
//
//   DTLS record header: STANDARD DTLS 1.2 (13 bytes)
//     content_type(1) + version(2=0xFEFD) + epoch(2) + seq(6) + length(2)
//
//   DTLS handshake header: STANDARD DTLS 1.2 (12 bytes)
//     type(1) + length(3) + msg_seq(2) + frag_offset(3) + frag_length(3)
//
//   Scrambling (TransCodePartial) for DTLS-IOTC packets:
//     Only the FIRST 80 bytes are scrambled (5 × 16-byte decode_block).
//     Bytes 80+ are plaintext DTLS content.  Non-DTLS IOTC packets (JOIN,
//     KNOCK, relay control) still use full-packet scrambling.
//
//   Cipher suite: 0xCCAC (TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256)
//
//   PSK identity: "AUTHPWD_" + account_name  (e.g. "AUTHPWD_admin")
//     Relay and LAN modes use the same identity.
//
//   PSK key derivation:
//     PSK = SHA256(camera_url_passwd_field)
//     The source is the "passwd" field in the camera URL, which may differ from
//     the device access_code returned by the cloud API; they may differ
//     depending on the printer model.
//     Relay and LAN modes use the same derivation.
//     A1 printers use LAN-mode JPEG on port 6000 and do not use TUTK/DTLS.
//
//   ServerKeyExchange body for ECDHE-PSK (RFC 5489):
//     psk_hint_len(2=0x0000) + curve_type(1=0x03) + named_curve(2=0x001d=x25519)
//     + key_len(1=0x20) + X25519_pub_key(32 bytes)
//
//   ClientKeyExchange body:
//     psk_id_len(2) + psk_identity(N) + ec_point_len(1) + client_pub_key(32)
//
// The session proceeds:
//   Client → Server: ClientHello
//   Server → Client: ServerHello + ServerKeyExchange + ServerHelloDone (194-byte IOTC pkt)
//   Client → Server: ClientKeyExchange + ChangeCipherSpec + Finished  (168-byte IOTC pkt)
//   Server → Client: ChangeCipherSpec + Finished
//
// This implementation builds standard DTLS 1.2 handshake messages
// using OpenSSL crypto primitives for X25519 ECDH and ChaCha20-Poly1305.

// DtlsSession is declared in IotcProtocol.hpp (moved to header so relay code
// in OssAgoraSignaling.cpp can use it via RelayConn).

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

// RFC 7366 Encrypt-then-MAC (EtM) + AES-256-CBC record protection
static bool encrypt_record_cbc_etm(const uint8_t* key, const uint8_t* mac_key,
                                   uint8_t content_type, uint16_t epoch, uint64_t seq,
                                   const uint8_t* plain, size_t plain_len,
                                   std::vector<uint8_t>& out_rec)
{
    uint8_t iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) return false;

    size_t pad_len = 16 - (plain_len % 16);
    uint8_t pad_val = (uint8_t)(pad_len - 1);
    std::vector<uint8_t> padded(plain_len + pad_len);
    if (plain_len > 0) memcpy(padded.data(), plain, plain_len);
    memset(padded.data() + plain_len, pad_val, pad_len);

    std::vector<uint8_t> ciphertext(padded.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int outl = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) <= 0 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) <= 0 ||
        EVP_EncryptUpdate(ctx, ciphertext.data(), &outl, padded.data(), (int)padded.size()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int total_cipher = outl;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + total_cipher, &outl);
    total_cipher += outl;
    EVP_CIPHER_CTX_free(ctx);

    uint16_t frag_len = (uint16_t)(16 + total_cipher);
    uint8_t mac_in_hdr[13];
    mac_in_hdr[0] = (uint8_t)(epoch >> 8);
    mac_in_hdr[1] = (uint8_t)(epoch);
    mac_in_hdr[2] = (uint8_t)(seq >> 40);
    mac_in_hdr[3] = (uint8_t)(seq >> 32);
    mac_in_hdr[4] = (uint8_t)(seq >> 24);
    mac_in_hdr[5] = (uint8_t)(seq >> 16);
    mac_in_hdr[6] = (uint8_t)(seq >> 8);
    mac_in_hdr[7] = (uint8_t)(seq);
    mac_in_hdr[8] = content_type;
    mac_in_hdr[9] = 0xfe; mac_in_hdr[10] = 0xfd;
    mac_in_hdr[11]= (uint8_t)(frag_len >> 8);
    mac_in_hdr[12]= (uint8_t)(frag_len);

    std::vector<uint8_t> mac_in;
    mac_in.reserve(13 + 16 + total_cipher);
    mac_in.insert(mac_in.end(), mac_in_hdr, mac_in_hdr + 13);
    mac_in.insert(mac_in.end(), iv, iv + 16);
    mac_in.insert(mac_in.end(), ciphertext.begin(), ciphertext.begin() + total_cipher);

    uint8_t mac[48];
    unsigned int mac_len = 48;
    HMAC(EVP_sha384(), mac_key, 48, mac_in.data(), mac_in.size(), mac, &mac_len);

    uint16_t wire_len = (uint16_t)(frag_len + mac_len);
    uint8_t rec_hdr[13];
    build_dtls_record_hdr(rec_hdr, content_type, epoch, seq, wire_len);

    out_rec.clear();
    out_rec.reserve(13 + wire_len);
    out_rec.insert(out_rec.end(), rec_hdr, rec_hdr + 13);
    out_rec.insert(out_rec.end(), iv, iv + 16);
    out_rec.insert(out_rec.end(), ciphertext.begin(), ciphertext.begin() + total_cipher);
    out_rec.insert(out_rec.end(), mac, mac + 48);
    return true;
}

static int decrypt_record_cbc_etm(const uint8_t* key, const uint8_t* mac_key,
                                  const uint8_t* rec_hdr,
                                  const uint8_t* payload, size_t payload_len,
                                  uint8_t* plain_out, size_t plain_max)
{
    uint8_t content_type = rec_hdr[0];
    uint16_t epoch = read_be16(rec_hdr + 3);
    uint64_t seq   = read_be48(rec_hdr + 5);
    uint16_t wire_len = read_be16(rec_hdr + 11);

    if (payload_len < wire_len || wire_len < 16 + 16 + 48) {
        OBN_WARN("[dtls-etm] payload too short (have %zu, wire_len %u)", payload_len, wire_len);
        return -1;
    }

    uint16_t frag_len = wire_len - 48;
    const uint8_t* iv = payload;
    const uint8_t* ciphertext = payload + 16;
    size_t cipher_len = frag_len - 16;
    const uint8_t* received_mac = payload + frag_len;

    uint8_t mac_in_hdr[13];
    mac_in_hdr[0] = (uint8_t)(epoch >> 8);
    mac_in_hdr[1] = (uint8_t)(epoch);
    mac_in_hdr[2] = (uint8_t)(seq >> 40);
    mac_in_hdr[3] = (uint8_t)(seq >> 32);
    mac_in_hdr[4] = (uint8_t)(seq >> 24);
    mac_in_hdr[5] = (uint8_t)(seq >> 16);
    mac_in_hdr[6] = (uint8_t)(seq >> 8);
    mac_in_hdr[7] = (uint8_t)(seq);
    mac_in_hdr[8] = content_type;
    mac_in_hdr[9] = 0xfe; mac_in_hdr[10] = 0xfd;
    mac_in_hdr[11]= (uint8_t)(frag_len >> 8);
    mac_in_hdr[12]= (uint8_t)(frag_len);

    std::vector<uint8_t> mac_in;
    mac_in.reserve(13 + frag_len);
    mac_in.insert(mac_in.end(), mac_in_hdr, mac_in_hdr + 13);
    mac_in.insert(mac_in.end(), payload, payload + frag_len);

    uint8_t calc_mac[48];
    unsigned int calc_mac_len = 48;
    HMAC(EVP_sha384(), mac_key, 48, mac_in.data(), mac_in.size(), calc_mac, &calc_mac_len);

    if (CRYPTO_memcmp(calc_mac, received_mac, 48) != 0) {
        OBN_ERROR("[dtls-etm] bad_record_mac (epoch=%u seq=%llu)", epoch, (unsigned long long)seq);
        return -1;
    }

    std::vector<uint8_t> decrypted(cipher_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int outl = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) <= 0 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) <= 0 ||
        EVP_DecryptUpdate(ctx, decrypted.data(), &outl, ciphertext, (int)cipher_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int total = outl;
    EVP_DecryptFinal_ex(ctx, decrypted.data() + total, &outl);
    total += outl;
    EVP_CIPHER_CTX_free(ctx);

    if (total == 0) return -1;

    uint8_t pad_val = decrypted[total - 1];
    if (pad_val >= 16 || pad_val >= total) {
        OBN_ERROR("[dtls-etm] invalid padding 0x%02x (total=%d)", pad_val, total);
        return -1;
    }
    size_t pad_count = (size_t)pad_val + 1;
    for (size_t i = 0; i < pad_count; ++i) {
        if (decrypted[total - 1 - i] != pad_val) {
            OBN_ERROR("[dtls-etm] padding byte mismatch");
            return -1;
        }
    }

    size_t plain_len = (size_t)total - pad_count;
    if (plain_len > plain_max) {
        OBN_ERROR("[dtls-etm] plain_len %zu > plain_max %zu", plain_len, plain_max);
        return -1;
    }

    if (plain_len > 0)
        memcpy(plain_out, decrypted.data(), plain_len);
    return (int)plain_len;
}

static bool dtls_encrypt_record(DtlsSession* ds, uint8_t content_type,
                                const uint8_t* plain, size_t plain_len,
                                std::vector<uint8_t>& out_rec)
{
    if (ds->cipher_suite == 0xC038) {
        bool ok = encrypt_record_cbc_etm(ds->client_write_key, ds->client_write_mac_key,
                                         content_type, (uint16_t)ds->epoch, ds->tx_seq,
                                         plain, plain_len, out_rec);
        if (ok) ds->tx_seq++;
        return ok;
    } else {
        uint8_t nonce[12];
        build_relay_nonce(nonce, ds->client_write_iv, (uint16_t)ds->epoch, ds->tx_seq);

        uint8_t rec_hdr[13];
        build_dtls_record_hdr(rec_hdr, content_type, (uint16_t)ds->epoch, ds->tx_seq, (uint16_t)plain_len);

        std::vector<uint8_t> ciphertext(plain_len + 16);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int outl = 0;
        EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, ds->client_write_key, nonce);
        EVP_EncryptUpdate(ctx, nullptr, &outl, rec_hdr, 13);
        if (plain_len > 0)
            EVP_EncryptUpdate(ctx, ciphertext.data(), &outl, plain, (int)plain_len);
        int total = outl;
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &outl);
        total += outl;
        uint8_t tag[16];
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
        memcpy(ciphertext.data() + total, tag, 16);
        EVP_CIPHER_CTX_free(ctx);

        uint16_t cipher_len = (uint16_t)(plain_len + 16);
        build_dtls_record_hdr(rec_hdr, content_type, (uint16_t)ds->epoch, ds->tx_seq, cipher_len);
        ds->tx_seq++;

        out_rec.clear();
        out_rec.reserve(13 + cipher_len);
        out_rec.insert(out_rec.end(), rec_hdr, rec_hdr + 13);
        out_rec.insert(out_rec.end(), ciphertext.begin(), ciphertext.begin() + cipher_len);
        return true;
    }
}

static int dtls_decrypt_record(DtlsSession* ds,
                               const uint8_t* dtls_rec, size_t rec_len,
                               uint8_t* plain_out, size_t plain_max)
{
    if (rec_len < 13) return -1;
    const uint8_t* rec_hdr = dtls_rec;
    const uint8_t* payload = dtls_rec + 13;
    size_t payload_len = rec_len - 13;

    if (ds->cipher_suite == 0xC038) {
        return decrypt_record_cbc_etm(ds->server_write_key, ds->server_write_mac_key,
                                      rec_hdr, payload, payload_len,
                                      plain_out, plain_max);
    } else {
        uint16_t rec_epoch  = read_be16(rec_hdr + 3);
        uint64_t rec_seq    = read_be48(rec_hdr + 5);
        uint16_t cipher_len = read_be16(rec_hdr + 11);
        if (payload_len < cipher_len || cipher_len < 16) return -1;
        uint16_t plain_len = cipher_len - 16;
        if (plain_len > plain_max) return -1;

        uint8_t nonce[12];
        build_relay_nonce(nonce, ds->server_write_iv, rec_epoch, rec_seq);

        const uint8_t* aad = rec_hdr;
        const uint8_t* ciphertext = payload;
        const uint8_t* tag = payload + plain_len;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int outl = 0;
        EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(tag));
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, ds->server_write_key, nonce);
        EVP_DecryptUpdate(ctx, nullptr, &outl, aad, 13);
        if (plain_len > 0)
            EVP_DecryptUpdate(ctx, plain_out, &outl, ciphertext, (int)plain_len);
        int total = outl;
        int ok = EVP_DecryptFinal_ex(ctx, plain_out + total, &outl);
        EVP_CIPHER_CTX_free(ctx);

        if (ok > 0) return (int)plain_len;
        OBN_ERROR("[dtls-chacha] AEAD auth failed (epoch=%u seq=%llu)", rec_epoch, (unsigned long long)rec_seq);
        return -1;
    }
}

// Full DTLS-PSK handshake over a connected UDP socket.
// initial_epoch: the TUTK session epoch (client-generated, embedded in LAN_SEARCH3).
//   Used for ALL records including ClientHello (confirmed from captures).
// uid_upper: 20-char uppercase UID; used to send the type 0x33 auth packet that the
//   printer requires between ClientHello and ServerHello.
//   Pass NULL to skip (non-LAN paths that don't use DTLS directly).
// passwd: printer DTLS passwd ASCII string (camera URL "passwd" field); PSK = SHA256(passwd).
// account: PSK identity suffix (e.g. "admin"); identity = "AUTHPWD_" + account.
// session_token: 8-byte session token from LAN discovery.
// Returns 0 on success and fills *out with session keys.
static int dtls_psk_handshake(obn::net::socket_t sock, const struct sockaddr_in* dst,
                               uint32_t initial_epoch,
                               const uint8_t session_token[8],
                               const char* uid_upper_str,
                               const char* passwd, const char* account,
                               DtlsSession* out,
                               uint32_t relay_tag = 0)
{
    memset(out, 0, sizeof(*out));
    out->epoch = initial_epoch;
    out->relay_tag = relay_tag;

    if (RAND_bytes(out->client_random, 32) != 1) {
        OBN_ERROR("[dtls] RAND_bytes failed");
        return -1;
    }

    // =======================================================================
    // Build and send ClientHello
    // =======================================================================
    //
    // ALL DTLS records use the pre-negotiated epoch from LAN_SEARCH_R3
    // (e.g. 0x6a0 = 1696); the ClientHello record header carries this epoch, not 0.
    //
    // HS header: type=0x01 (ClientHello), msg_seq=0, tutk_epoch=initial_epoch
    // Body: version(2)=0xfefd (DTLS 1.2) + random(32) + session_id_len(1)=0
    //       + cookie_len(1)=0 + cipher_suites_len(2) + cipher_suites
    //       + compression_len(1)=1 + compression(1)=0

    // Cipher suites: 0xC038 (ECDHE-PSK-AES256-CBC-SHA384) + 0xCCAC (ECDHE-PSK-CHACHA20) + 0x00FF (EMPTY-RENEGOTIATION)
    static const uint8_t kCipherSuites[] = {
        0xC0, 0x38,   // TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
        0xCC, 0xAC,   // TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
        0x00, 0xFF,   // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    };

    // TLS 1.2 extensions required for ECDHE key exchange (RFC 8422 §5.1.1):
    // 1. ec_point_formats (0x000b): uncompressed, compressed prime/char2
    // 2. supported_groups (0x000a): X25519 (0x001d), secp256r1 (0x0017), x448, secp521r1, secp384r1
    // 3. session_ticket (0x0023): len 0
    // 4. encrypt_then_mac (0x0016): len 0 (RFC 7366)
    // 5. extended_master_secret (0x0017): len 0 (RFC 7627)
    // 6. signature_algorithms (0x000d): SHA256/384/512 with ECDSA/RSA/DSA
    static const uint8_t kExtensions[] = {
        // Total extensions length: 82 bytes (0x0052)
        0x00, 0x52,
        // ec_point_formats (0x000b, len 4)
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
        // supported_groups (0x000a, len 12)
        0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a,
        0x00, 0x1d,  // X25519
        0x00, 0x17,  // secp256r1
        0x00, 0x1e,  // x448
        0x00, 0x19,  // secp521r1
        0x00, 0x18,  // secp384r1
        // session_ticket (0x0023, len 0)
        0x00, 0x23, 0x00, 0x00,
        // encrypt_then_mac (0x0016, len 0)
        0x00, 0x16, 0x00, 0x00,
        // extended_master_secret (0x0017, len 0)
        0x00, 0x17, 0x00, 0x00,
        // signature_algorithms (0x000d, len 42)
        0x00, 0x0d, 0x00, 0x2a, 0x00, 0x28,
        0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07,
        0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b,
        0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01,
        0x05, 0x01, 0x06, 0x01, 0x03, 0x03, 0x03, 0x01,
        0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02
    };

    uint8_t ch_body[256];
    size_t ch_off = 0;
    ch_body[ch_off++] = 0xfe; ch_body[ch_off++] = 0xfd;  // hello version DTLS 1.2
    memcpy(ch_body + ch_off, out->client_random, 32); ch_off += 32;
    ch_body[ch_off++] = 0x00;   // session_id_len = 0
    ch_body[ch_off++] = 0x00;   // cookie_len = 0
    ch_body[ch_off++] = 0x00; ch_body[ch_off++] = 0x06;  // cipher_suites_len = 6
    memcpy(ch_body + ch_off, kCipherSuites, 6); ch_off += 6;
    ch_body[ch_off++] = 0x01;   // compression_methods_len = 1
    ch_body[ch_off++] = 0x00;   // compression = null
    memcpy(ch_body + ch_off, kExtensions, sizeof(kExtensions));
    ch_off += sizeof(kExtensions);

    uint8_t hs_hdr[12];
    build_dtls_hs_hdr(hs_hdr, 0x01, (uint32_t)ch_off, 0);

    uint8_t rec_hdr[13];
    build_dtls_record_hdr(rec_hdr, 0x16, initial_epoch, 0, (uint16_t)(12 + ch_off));
    // RFC 6347 §4.2.1: DTLS 1.2 ClientHello record header uses DTLS 1.0 (0xFEFF)
    rec_hdr[1] = 0xfe;
    rec_hdr[2] = 0xff;

    std::vector<uint8_t> ch_dtls(13 + 12 + ch_off);
    memcpy(ch_dtls.data(),      rec_hdr, 13);
    memcpy(ch_dtls.data() + 13, hs_hdr,  12);
    memcpy(ch_dtls.data() + 25, ch_body, ch_off);

    // Handshake transcript: concatenation of all HS message bodies (hs_hdr + body).
    std::vector<uint8_t> transcript;
    transcript.insert(transcript.end(), hs_hdr, hs_hdr + 12);
    transcript.insert(transcript.end(), ch_body, ch_body + ch_off);

    if (send_dtls_packet(sock, dst, initial_epoch, session_token,
                          ch_dtls.data(), ch_dtls.size(), relay_tag) != 0) {
        OBN_ERROR("[dtls] ClientHello send failed");
        return -1;
    }
    OBN_DEBUG("[dtls] ClientHello sent (%zu bytes DTLS, epoch=0x%x)", ch_dtls.size(), initial_epoch);

    // =======================================================================
    // Send type 0x33 authorization and drain echo
    // =======================================================================
    //
    // Sequence: ClientHello → type 0x33 send → type 0x33 echo recv → ServerHello recv.
    // The printer withholds ServerHello until it receives the 0x33 packet
    // (which confirms the session token and UID).
    if (uid_upper_str && uid_upper_str[0]) {
        if (send_ctrl0x33(sock, dst, uid_upper_str, session_token) != 0) {
            OBN_ERROR("[dtls] type 0x33 send failed");
            return -1;
        }
        OBN_DEBUG("[dtls] type 0x33 sent (echo drained by recv_dtls_packet)");
    }

    // =======================================================================
    // Receive ServerHello (+ ServerKeyExchange + ServerHelloDone in same IOTC pkt)
    // =======================================================================

    uint8_t srv_raw[1024];
    uint32_t srv_epoch = 0;
    uint8_t srv_token[8] = {};
    int srv_len = -1;
    for (int ch_attempt = 0; ch_attempt < 3 && srv_len < 13; ++ch_attempt) {
        if (ch_attempt > 0) {
            OBN_DEBUG("[dtls] re-sending ClientHello (attempt %d)", ch_attempt + 1);
            send_dtls_packet(sock, dst, initial_epoch, session_token,
                             ch_dtls.data(), ch_dtls.size(), relay_tag);
        }
        srv_len = recv_dtls_packet(sock, srv_raw, sizeof(srv_raw),
                                   &srv_epoch, srv_token, 1500);
    }
    if (srv_len < 13) {
        OBN_ERROR("[dtls] no ServerHello (got %d bytes)", srv_len);
        return -1;
    }

    if (srv_raw[0] != 0x16 || srv_raw[1] != 0xfe || (srv_raw[2] != 0xfd && srv_raw[2] != 0xff)) {
        if (srv_raw[0] == 0x15 && srv_len >= 15) {
            uint8_t alert_level = srv_raw[13];
            uint8_t alert_desc  = srv_raw[14];
            OBN_ERROR("[dtls] received DTLS Alert: level=%u (%s) desc=%u (%s)",
                      alert_level, (alert_level == 1 ? "warning" : "fatal"),
                      alert_desc,
                      (alert_desc == 10 ? "unexpected_message" :
                       alert_desc == 20 ? "bad_record_mac" :
                       alert_desc == 40 ? "handshake_failure" :
                       alert_desc == 47 ? "illegal_parameter" :
                       alert_desc == 70 ? "protocol_version" : "other"));
        } else {
            OBN_ERROR("[dtls] unexpected record type 0x%02x (len=%d)", srv_raw[0], srv_len);
        }
        char hex_dump[128] = {};
        int dump_n = std::min(srv_len, 32);
        for (int i = 0; i < dump_n; ++i) {
            snprintf(hex_dump + i * 3, sizeof(hex_dump) - i * 3, "%02x ", srv_raw[i]);
        }
        OBN_ERROR("[dtls] server record raw: %s", hex_dump);
        return -1;
    }
    out->epoch = srv_epoch;

    uint16_t rec_len;
    rec_len = ((uint16_t)srv_raw[11] << 8) | srv_raw[12];
    OBN_DEBUG("[dtls] ServerHello record: epoch=0x%04x len=%u", srv_epoch, rec_len);

    // HS header starts at offset 13
    // type(1) + len(3) + msg_seq(2) + tutk_epoch(4) + frag_len(2) = 12 bytes
    if (srv_len < 25) { OBN_ERROR("[dtls] ServerHello too short"); return -1; }
    uint8_t hs_type = srv_raw[13];
    uint32_t hs_body_len = ((uint32_t)srv_raw[14] << 16)
                         | ((uint32_t)srv_raw[15] << 8)
                         |  (uint32_t)srv_raw[16];
    OBN_DEBUG("[dtls] ServerHello HS type=0x%02x body_len=%u", hs_type, hs_body_len);

    if (hs_type != 0x02) {
        OBN_ERROR("[dtls] expected ServerHello (0x02), got 0x%02x", hs_type);
        return -1;
    }

    // TUTK ServerHello body starts at offset 25:
    //   version(2) + random(32) + sid_len(1) + sid(N) + cipher(2) + comp(1) + [ext_len(2) + exts]
    if (srv_len >= 25 + 2 + 32) {
        memcpy(out->server_random, srv_raw + 25 + 2, 32);
        OBN_DEBUG("[dtls] server_random extracted");
    } else {
        OBN_ERROR("[dtls] ServerHello body too short for random");
        return -1;
    }

    out->cipher_suite = 0xCCAC;
    out->use_ems = false;
    out->use_etm = false;

    size_t sh_cs_off = 25 + 2 + 32;
    if ((size_t)srv_len > sh_cs_off) {
        uint8_t sid_len = srv_raw[sh_cs_off];
        sh_cs_off += 1 + sid_len;
        if ((size_t)srv_len >= sh_cs_off + 2) {
            uint16_t cs = ((uint16_t)srv_raw[sh_cs_off] << 8) | srv_raw[sh_cs_off + 1];
            out->cipher_suite = cs;
            OBN_INFO("[dtls] ServerHello selected cipher suite: 0x%04x", cs);
        }
        size_t ext_hdr_off = sh_cs_off + 2 + 1; // skip cipher_suite (2) + comp (1)
        if ((size_t)srv_len >= ext_hdr_off + 2) {
            uint16_t ext_total_len = read_be16(srv_raw + ext_hdr_off);
            size_t e_off = ext_hdr_off + 2;
            size_t e_end = std::min((size_t)srv_len, e_off + ext_total_len);
            while (e_off + 4 <= e_end) {
                uint16_t etype = read_be16(srv_raw + e_off);
                uint16_t elen  = read_be16(srv_raw + e_off + 2);
                if (etype == 0x0016) out->use_etm = true;
                if (etype == 0x0017) out->use_ems = true;
                e_off += 4 + elen;
            }
        }
    }
    OBN_INFO("[dtls] Negotiated params: cipher=0x%04x ems=%d etm=%d",
             out->cipher_suite, out->use_ems, out->use_etm);

    transcript.insert(transcript.end(), srv_raw + 13, srv_raw + 13 + 12 + hs_body_len);

    // TUTK bundles ServerHello + ServerKeyExchange + ServerHelloDone in one IOTC packet.
    uint8_t server_ec_pub[33] = {};   // server's X25519 public key (32 bytes)
    bool has_server_ec = false;
    bool has_server_hello_done = false;

    int pos = 13 + (int)rec_len;  // advance past first record
    while (pos + 13 <= srv_len) {
        uint8_t rtype = srv_raw[pos];
        uint16_t rlen = ((uint16_t)srv_raw[pos+11] << 8) | srv_raw[pos+12];
        if (pos + 13 + rlen > srv_len) break;

        if (rtype == 0x16 && pos + 13 + 12 <= srv_len) {
            uint8_t htype = srv_raw[pos + 13];
            uint32_t hlen = ((uint32_t)srv_raw[pos+14] << 16)
                          | ((uint32_t)srv_raw[pos+15] << 8)
                          |  (uint32_t)srv_raw[pos+16];

            if (htype == 0x0e) {
                // ServerHelloDone (RFC 6347 §4.2.2):
                // type=0x0E (1), len=0 (3), msg_seq=2 (2), frag_off=0 (3), frag_len=0 (3) = 12 bytes.
                static const uint8_t kCanonicalServerHelloDone[12] = {
                    0x0e, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                };
                transcript.insert(transcript.end(),
                                  kCanonicalServerHelloDone, kCanonicalServerHelloDone + 12);
                has_server_hello_done = true;
                OBN_DEBUG("[dtls] ServerHelloDone received");
            } else {
                transcript.insert(transcript.end(),
                                  srv_raw + pos + 13, srv_raw + pos + 13 + 12 + hlen);
            }

            if (htype == 0x0c) {
                // ServerKeyExchange: RFC 5489 ECDHE-PSK body:
                //   psk_hint_len(2=0) + curve_type(1=0x03) + named_curve(2=0x001d=x25519)
                //   + key_len(1) + key(32) = 38 bytes total
                int ke_body_start = pos + 13 + 12;
                if (hlen >= 38 && srv_raw[ke_body_start] == 0x00
                               && srv_raw[ke_body_start+1] == 0x00
                               && srv_raw[ke_body_start+2] == 0x03) {
                    uint8_t key_len = srv_raw[ke_body_start + 5];
                    if (key_len <= 33 && (int)hlen >= 6 + (int)key_len) {
                        memcpy(server_ec_pub, srv_raw + ke_body_start + 6, key_len);
                        has_server_ec = true;
                        OBN_DEBUG("[dtls] ServerKeyExchange: %u-byte EC key", key_len);
                    }
                }
            }
        }
        pos += 13 + (int)rlen;
    }

    if (!has_server_hello_done) {
        OBN_WARN("[dtls] ServerHelloDone not found in server response");
        // Continue anyway — some TUTK firmwares pack things differently
    }

    // =======================================================================
    // Generate client ECDHE key pair (X25519)
    // =======================================================================

    EVP_PKEY* client_privkey = nullptr;
    uint8_t client_ec_pub[32] = {};
    uint8_t premaster_ecdh[32] = {};

    if (has_server_ec) {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0
                  || EVP_PKEY_keygen(pctx, &client_privkey) <= 0) {
            OBN_ERROR("[dtls] X25519 keygen failed");
            EVP_PKEY_CTX_free(pctx);
            return -1;
        }
        EVP_PKEY_CTX_free(pctx);

        size_t pub_len = 32;
        EVP_PKEY_get_raw_public_key(client_privkey, client_ec_pub, &pub_len);

        EVP_PKEY* server_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                              server_ec_pub, 32);
        if (server_pkey) {
            EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(client_privkey, nullptr);
            size_t ss_len = 32;
            if (dctx && EVP_PKEY_derive_init(dctx) > 0
                     && EVP_PKEY_derive_set_peer(dctx, server_pkey) > 0
                     && EVP_PKEY_derive(dctx, premaster_ecdh, &ss_len) > 0) {
                OBN_DEBUG("[dtls] ECDH shared secret computed (%zu bytes)", ss_len);
            } else {
                OBN_WARN("[dtls] ECDH derive failed");
            }
            EVP_PKEY_CTX_free(dctx);
            EVP_PKEY_free(server_pkey);
        }
        EVP_PKEY_free(client_privkey);
    }

    // =======================================================================
    // Compute PSK and premaster secret (ECDHE-PSK)
    // =======================================================================
    //
    // PSK = SHA256(passwd_ascii_string)
    //
    // For ECDHE-PSK premaster secret (RFC 5489):
    //   premaster = uint16_len(ecdh_secret) || ecdh_secret
    //               || uint16_len(psk)       || psk

    uint8_t psk[32];
    SHA256(reinterpret_cast<const uint8_t*>(passwd), strlen(passwd), psk);
    OBN_DEBUG("[dtls] PSK = SHA256(passwd) computed");

    // ECDHE-PSK premaster: uint16_len(ecdh_secret) || ecdh_secret || uint16_len(psk) || psk
    uint8_t premaster[2 + 32 + 2 + 32];
    size_t pm_off = 0;
    premaster[pm_off++] = 0x00; premaster[pm_off++] = 0x20;  // ecdh_len = 32
    memcpy(premaster + pm_off, premaster_ecdh, 32); pm_off += 32;
    premaster[pm_off++] = 0x00; premaster[pm_off++] = 0x20;  // psk_len = 32
    memcpy(premaster + pm_off, psk, 32); pm_off += 32;

    // =======================================================================
    // Build ClientKeyExchange (must be in transcript for RFC 7627 session_hash)
    // =======================================================================

    std::string psk_identity = std::string("AUTHPWD_") + account;

    std::vector<uint8_t> cke_body;
    uint16_t id_len = (uint16_t)psk_identity.size();
    cke_body.push_back((id_len >> 8) & 0xff);
    cke_body.push_back(id_len & 0xff);
    cke_body.insert(cke_body.end(), psk_identity.begin(), psk_identity.end());
    if (has_server_ec) {
        cke_body.push_back(0x20);  // ec key length = 32
        cke_body.insert(cke_body.end(), client_ec_pub, client_ec_pub + 32);
    }

    uint8_t cke_rec_hdr[13], cke_hs_hdr[12];
    build_dtls_hs_hdr(cke_hs_hdr, 0x10 /*ClientKeyExchange*/,
                       (uint32_t)cke_body.size(), 1 /*msg_seq*/);
    build_dtls_record_hdr(cke_rec_hdr, 0x16, initial_epoch, 1,
                           (uint16_t)(12 + cke_body.size()));

    transcript.insert(transcript.end(), cke_hs_hdr, cke_hs_hdr + 12);
    transcript.insert(transcript.end(), cke_body.begin(), cke_body.end());

    // =======================================================================
    // Compute master_secret
    // =======================================================================
    if (out->use_ems) {
        // RFC 7627 Extended Master Secret: PRF(premaster, "extended master secret", Hash(handshake_messages))
        // session_hash covers ClientHello through ClientKeyExchange.
        if (out->cipher_suite == 0xC038) {
            uint8_t hs_hash[48];
            SHA384(transcript.data(), transcript.size(), hs_hash);
            tls12_prf_sha384(premaster, sizeof(premaster), "extended master secret",
                             hs_hash, 48, out->master_secret, 48);
        } else {
            uint8_t hs_hash[32];
            SHA256(transcript.data(), transcript.size(), hs_hash);
            tls12_prf(premaster, sizeof(premaster), "extended master secret",
                       hs_hash, 32, out->master_secret, 48);
        }
        OBN_DEBUG("[dtls] extended master_secret derived");
    } else {
        uint8_t ms_seed[64];
        memcpy(ms_seed,      out->client_random, 32);
        memcpy(ms_seed + 32, out->server_random, 32);
        if (out->cipher_suite == 0xC038) {
            tls12_prf_sha384(premaster, sizeof(premaster), "master secret",
                             ms_seed, 64, out->master_secret, 48);
        } else {
            tls12_prf(premaster, sizeof(premaster), "master secret",
                      ms_seed, 64, out->master_secret, 48);
        }
        OBN_DEBUG("[dtls] standard master_secret derived");
    }

    // =======================================================================
    // Key expansion: PRF(master_secret, "key expansion", server_random||client_random)
    // =======================================================================

    uint8_t ke_seed[64];
    memcpy(ke_seed,      out->server_random, 32);
    memcpy(ke_seed + 32, out->client_random, 32);

    if (out->cipher_suite == 0xC038) {
        // 0xC038: client_mac(48) + server_mac(48) + client_key(32) + server_key(32) + client_iv(16) + server_iv(16) = 192 bytes
        uint8_t key_block[192];
        tls12_prf_sha384(out->master_secret, 48, "key expansion",
                         ke_seed, 64, key_block, sizeof(key_block));

        memcpy(out->client_write_mac_key, key_block,       48);
        memcpy(out->server_write_mac_key, key_block + 48,  48);
        memcpy(out->client_write_key,     key_block + 96,  32);
        memcpy(out->server_write_key,     key_block + 128, 32);
        memcpy(out->client_write_iv,      key_block + 160, 16);
        memcpy(out->server_write_iv,      key_block + 176, 16);
        OBN_DEBUG("[dtls] key expansion (0xC038 SHA384/AES256-CBC) done");
    } else {
        uint8_t key_block[88];
        tls12_prf(out->master_secret, 48, "key expansion",
                  ke_seed, 64, key_block, sizeof(key_block));

        memcpy(out->client_write_key, key_block,      32);
        memcpy(out->server_write_key, key_block + 32, 32);
        memcpy(out->client_write_iv,  key_block + 64, 12);
        memcpy(out->server_write_iv,  key_block + 76, 12);
        OBN_DEBUG("[dtls] key expansion (0xCCAC ChaCha20-Poly1305) done");
    }

    // =======================================================================
    // Build ChangeCipherSpec
    // =======================================================================

    uint8_t ccs_rec[14];
    build_dtls_record_hdr(ccs_rec, 0x14 /*ChangeCipherSpec*/, initial_epoch, 2, 1);
    ccs_rec[13] = 0x01;

    // =======================================================================
    // Build Finished
    // =======================================================================

    uint8_t verify_data[12];
    if (out->cipher_suite == 0xC038) {
        uint8_t transcript_hash[48];
        SHA384(transcript.data(), transcript.size(), transcript_hash);
        tls12_prf_sha384(out->master_secret, 48, "client finished",
                         transcript_hash, 48, verify_data, 12);
    } else {
        uint8_t transcript_hash[32];
        SHA256(transcript.data(), transcript.size(), transcript_hash);
        tls12_prf(out->master_secret, 48, "client finished",
                  transcript_hash, 32, verify_data, 12);
    }

    // Finished HS header
    uint8_t fin_hs_hdr[12];
    build_dtls_hs_hdr(fin_hs_hdr, 0x14 /*Finished*/, 12, 2 /*msg_seq*/);

    uint8_t fin_plain[12 + 12];
    memcpy(fin_plain,      fin_hs_hdr,   12);
    memcpy(fin_plain + 12, verify_data,  12);

    transcript.insert(transcript.end(), fin_hs_hdr, fin_hs_hdr + 12);
    transcript.insert(transcript.end(), verify_data, verify_data + 12);

    out->epoch = (initial_epoch == 0) ? 1 : (initial_epoch + 1);
    out->tx_seq = 0;

    std::vector<uint8_t> fin_rec;
    if (!dtls_encrypt_record(out, 0x16 /*Handshake*/, fin_plain, sizeof(fin_plain), fin_rec)) {
        OBN_ERROR("[dtls] encrypt Finished failed");
        return -1;
    }

    // =======================================================================
    // Send ClientKeyExchange + ChangeCipherSpec + Finished in one IOTC packet
    // =======================================================================

    std::vector<uint8_t> cke_ccs_fin;
    cke_ccs_fin.insert(cke_ccs_fin.end(), cke_rec_hdr, cke_rec_hdr + 13);
    cke_ccs_fin.insert(cke_ccs_fin.end(), cke_hs_hdr, cke_hs_hdr + 12);
    cke_ccs_fin.insert(cke_ccs_fin.end(), cke_body.begin(), cke_body.end());
    cke_ccs_fin.insert(cke_ccs_fin.end(), ccs_rec, ccs_rec + 14);
    cke_ccs_fin.insert(cke_ccs_fin.end(), fin_rec.begin(), fin_rec.end());

    if (send_dtls_packet(sock, dst, initial_epoch, session_token,
                          cke_ccs_fin.data(), cke_ccs_fin.size(), relay_tag) != 0) {
        OBN_ERROR("[dtls] CKE+CCS+Finished send failed");
        return -1;
    }
    OBN_DEBUG("[dtls] CKE+CCS+Finished sent (%zu bytes DTLS)", cke_ccs_fin.size());

    // =======================================================================
    // Receive and verify server CCS + Finished
    // =======================================================================

    uint8_t srv2_raw[1024];
    int srv2_len = recv_dtls_packet(sock, srv2_raw, sizeof(srv2_raw),
                                     nullptr, nullptr, 5000);
    if (srv2_len < 14) {
        OBN_ERROR("[dtls] no server CCS/Finished (got %d bytes)", srv2_len);
        return -1;
    }

    const uint8_t* fin_rec_ptr = nullptr;
    size_t fin_rec_len = 0;

    if (srv2_raw[0] == 0x14) {
        uint16_t ccs_len = read_be16(srv2_raw + 11);
        size_t ccs_rec_len = 13 + ccs_len;
        OBN_DEBUG("[dtls] server CCS received (%zu bytes)", ccs_rec_len);

        if ((size_t)srv2_len > ccs_rec_len) {
            fin_rec_ptr = srv2_raw + ccs_rec_len;
            fin_rec_len = (size_t)srv2_len - ccs_rec_len;
        } else {
            srv2_len = recv_dtls_packet(sock, srv2_raw, sizeof(srv2_raw),
                                        nullptr, nullptr, 5000);
            if (srv2_len >= 13 && srv2_raw[0] == 0x16) {
                fin_rec_ptr = srv2_raw;
                fin_rec_len = (size_t)srv2_len;
            }
        }
    } else if (srv2_raw[0] == 0x16) {
        fin_rec_ptr = srv2_raw;
        fin_rec_len = (size_t)srv2_len;
    } else if (srv2_raw[0] == 0x15) {
        OBN_ERROR("[dtls] server sent Alert record: len=%d level=%d desc=%d",
                  srv2_len, srv2_len >= 14 ? srv2_raw[13] : -1, srv2_len >= 15 ? srv2_raw[14] : -1);
        return -1;
    }

    if (!fin_rec_ptr || fin_rec_len < 13) {
        OBN_ERROR("[dtls] server Finished not found in response (rec_type=0x%02x len=%d)",
                  srv2_raw[0], srv2_len);
        return -1;
    }

    uint8_t fin_srv_plain[64];
    int fin_srv_len = dtls_decrypt_record(out, fin_rec_ptr, fin_rec_len,
                                          fin_srv_plain, sizeof(fin_srv_plain));
    if (fin_srv_len < 24) {
        OBN_ERROR("[dtls] server Finished decryption failed (len=%d)", fin_srv_len);
        return -1;
    }

    uint8_t exp_vdata[12];
    if (out->cipher_suite == 0xC038) {
        uint8_t thash[48];
        SHA384(transcript.data(), transcript.size(), thash);
        tls12_prf_sha384(out->master_secret, 48, "server finished",
                         thash, 48, exp_vdata, 12);
    } else {
        uint8_t thash[32];
        SHA256(transcript.data(), transcript.size(), thash);
        tls12_prf(out->master_secret, 48, "server finished",
                  thash, 32, exp_vdata, 12);
    }

    if (CRYPTO_memcmp(fin_srv_plain + 12, exp_vdata, 12) != 0) {
        OBN_ERROR("[dtls] server Finished verify_data mismatch!");
        return -1;
    }

    OBN_INFO("[dtls] server Finished verified successfully!");
    out->epoch = (initial_epoch == 0) ? 1 : (initial_epoch + 1);
    out->tx_seq = 1;
    out->rx_seq = 1;
    out->handshake_complete = true;

    OBN_DEBUG("[dtls] handshake complete! epoch=0x%04x", out->epoch);
    return 0;
}

// ==========================================================================
// P2P NAT traversal state machine
// ==========================================================================
//
// This is the core of the TUTK IOTC protocol.
// The state machine follows the sequence observed in IOTC_Connect_UDP_Inner.
//
// States (from CheckUDPSequentialConnectState / CheckUDPParellelConnectState):
//   UDP_QUERY_DEVICE_START
//   → send MSG_P2P_PRECHECK1 to device WAN address (from master server reply)
//   → recv MSG_P2P_PRECHECK1_R from device
//   → send MSG_P2P_PRECHECK2 (with auth key if required)
//   → send MSG_P2P_REQUEST
//   → recv MSG_P2P_KNOCK1 / MSG_P2P_KNOCK2 from device
//   → send MSG_P2P_KNOCK_R1 / MSG_P2P_KNOCK_R2
//   → recv MSG_P2P_KNOCK_RR1 / MSG_P2P_KNOCK_RR2
//   → send MSG_P2P_PUNCH_TO  (tells device our local address)
//   → P2P session established
//   → start MSG_P2P_ALIVE_C2D keepalives
//
// If NAT type is 5 (symmetric), IOTC_TryPortAddNode is called to probe
// a range of ports (IOTC_TryPort* family).
//
// Relay fallback (AddUDPRelayConnectTask):
//   → send MSG_RLY_REQUEST to relay server
//   → recv MSG_RLY_REQUEST_R2 ("Ready for RLY")
//   → relay server sends MSG_RLY_KNOCK to device
//   → device sends MSG_RLY_KNOCK to client
//   → data flows through relay via MSG_RLY_PACKET_S2C / MSG_RLY_PACKET_S2D

enum class P2PState {
    IDLE,
    LAN_SEARCH,
    QUERY_MASTER,         // TCP: send UID to master, get device WAN addr
    PRECHECK,             // UDP: MSG_P2P_PRECHECK1 → PRECHECK1_R
    KNOCK,                // UDP: MSG_P2P_KNOCK exchange
    RELAY,                // TCP relay fallback
    CONNECTED,
    FAILED,
};

// Minimal session context for the OSS P2P client.
struct OssSession {
    std::string uid;             // 20-char device UID (lowercase)
    uint64_t    authkey;         // 8-byte auth key from URL
    std::string password;        // AV password ("888888")
    TutkRegion  region;

    obn::net::socket_t udp_sock;  // UDP P2P socket
    uint16_t    local_port;      // bound local port
    uint32_t    client_random;
    uint32_t    dtls_epoch;      // client-generated epoch echoed in LAN_SEARCH_R3 (e.g. 0x6a0)
    uint8_t     session_token[8]; // client_random(4B) + partial_mac(4B)

    struct sockaddr_in device_wan;  // device WAN address (from master/LAN)
    P2PState    state;

    DtlsSession dtls;            // filled by dtls_psk_handshake on connect

    // Keepalive thread (started after P2P session established)
    bool        keepalive_run;   // signal thread to stop
    std::thread keepalive_thread;
};

// ==========================================================================
// TUTK wire-format helpers
// ==========================================================================
//
// TUTK UDP/TCP message header layout (16 bytes):
//
// Layout (all fields little-endian):
//   [0..1]  uint16  magic   = 0x0204  (TUTK protocol marker, constant)
//   [2]     uint8   version = 0x1c    (version byte, constant)
//   [3]     uint8   flags   = 0x00    (iotc_SendMessage ORs in 0x02)
//   [4..5]  uint16  payload_len       (bytes after this 16-byte header)
//   [6..7]  uint16  = 0x0000          (zero pad)
//   [8..9]  uint16  sub_cmd           (message-specific identifier byte 1+2)
//   [10]    uint8   extra_cmd         (message-specific byte 3)
//   [11..15] uint8  = 0x00 x5         (zero pad)
//
// Confirmed sub_cmd + extra_cmd bytes:
//   MSG_LAN_SEARCH3:     [8]=0x01, [9]=0x06, [10]=0x21
//   MSG_P2P_PRECHECK1:   [8]=0x11, [9]=0x02, [10]=0x24
//   MSG_P2P_PRECHECK2:   [8]=0x14, [9]=0x02, [10]=0x24
//   MSG_QUERY_DEVICE5:   [8]=0x07, [9]=0x10, [10]=0x18
//   MSG_P2P_PUNCH_TO:    [8]=0x01, [9]=0x03, [10]=0x21
//
// Confirmed payload_len values (bytes after header):
//   MSG_LAN_SEARCH3:     0x48 = 72  → total send = 88 bytes
//   MSG_P2P_PRECHECK1:   0x14 = 20  → total send = 36 bytes
//   MSG_P2P_PRECHECK2:   0x20 = 32  → total send = 48 bytes
//   MSG_QUERY_DEVICE5:   0x26 = 38  → total send = 54 bytes
//   MSG_P2P_PUNCH_TO:    0x24 = 36  → total send = 52 bytes

static void fill_tutk_hdr(uint8_t* buf, uint16_t payload_len,
                           uint8_t b8, uint8_t b9, uint8_t b10)
{
    memset(buf, 0, 16);
    buf[0] = 0x04; buf[1] = 0x02;  // 0x0204 LE
    buf[2] = 0x1c;
    buf[3] = 0x00;
    buf[4] = (uint8_t)(payload_len & 0xff);
    buf[5] = (uint8_t)(payload_len >> 8);
    buf[6] = 0; buf[7] = 0;
    buf[8]  = b8;
    buf[9]  = b9;
    buf[10] = b10;
    // [11..15] = 0
}

// hdr_b8/b9/b10: msg-type bytes at offsets [8],[9],[10] (see TUTK wire format above).
static ssize_t tutk_udp_send(obn::net::socket_t sock_fd, const struct sockaddr_in* dst,
                              uint8_t hdr_b8, uint8_t hdr_b9, uint8_t hdr_b10,
                              const void* payload, size_t payload_len)
{
    uint8_t pkt[2048];
    size_t total = 16 + payload_len;
    if (total > sizeof(pkt)) return -1;

    fill_tutk_hdr(pkt, (uint16_t)payload_len, hdr_b8, hdr_b9, hdr_b10);
    if (payload_len > 0)
        memcpy(pkt + 16, payload, payload_len);

    return sendto(sock_fd, pkt, total, 0,
                  (const struct sockaddr*)dst, sizeof(*dst));
}

static ssize_t tutk_udp_recv(obn::net::socket_t sock_fd, uint8_t* buf, size_t buf_size,
                              struct sockaddr_in* src, int timeout_ms)
{
    set_recv_timeout(sock_fd, timeout_ms);
    socklen_t src_len = sizeof(*src);
    return recvfrom(sock_fd, buf, buf_size, 0,
                    (struct sockaddr*)src, &src_len);
}

// ==========================================================================
// Master server TCP protocol
// ==========================================================================
//
//   IOTC_TcpConnectToMaster @ 0x1928f0 calls IOTC_TcpConnectToMasterTryPort
//   @ 0x189f80 which iterates through a port table gTcpTryPort:
//   {80, 443, 21047, 8080, 8000, 20297, 17236, 8686} — up to 12 slots,
//   0-valued slots skipped.  The actual TCP I/O goes through a pConnMgr vtable
//   (vtable calls at 0x18a0c1, 0x18a0f7, 0x18a194 etc.), which hides the
//   exact wire format.
//
// _IOTC_SendQuryDevice5 sends a 54-byte packet (header + 38 bytes payload):
//   Payload layout:
//     [0..19]   uid (20 bytes, lowercase)
//     [20..35]  GetRealm() output (16 bytes, realm identifier, zero in OSS)
//     [36]      0x06  (confirmed: movb $0x6, 0x34(%rsp), offset 52 = 36 in payload)
//     [37]      extra byte from r8 arg (connect_flag byte)
//
// The master responds with MSG_QUERY_DEVICE5_R (type unknown) containing:
//   device WAN IP:port — parsed to fill sess->device_wan.
//
// NOTE: CheckLicenseKeyIsValid() returns -1004 in the Bambu-modified TUTK
// library, so the master registration path is permanently short-circuited and
// this function is never called at runtime.  Retained as a reference
// implementation of the standard TUTK master protocol.

static bool query_master_for_device(const std::string& uid_lc,
                                    uint32_t client_random,
                                    TutkRegion region,
                                    struct sockaddr_in* device_addr)
{
    // Port table from gTcpTryPort:
    // {80, 443, 21047, 8080, 8000, 20297, 17236, 8686}
    // Port 443 uses TLS in the real SDK (IOTC_sCHL_* via pConnMgr vtable) — skip it
    // for plain TCP; a pcap is needed to confirm the cipher suite before adding TLS.
    // Try plain-TCP ports only: 8080, 8000, 80, 21047 in order.
    static const uint16_t kTryPorts[] = { 8080, 8000, 80, 21047 };
    static const size_t   kNumPorts   = sizeof(kTryPorts) / sizeof(kTryPorts[0]);

    const char* suffixes[] = { ".iotcplatform.com", ".kalayservice.com" };
    const char* rname;
    switch (region) {
        case TutkRegion::CN:   rname = "cn";   break;
        case TutkRegion::EU:   rname = "eu";   break;
        case TutkRegion::US:   rname = "us";   break;
        case TutkRegion::Asia: rname = "asia"; break;
        default:               rname = "";     break;
    }

    for (const char* suffix : suffixes) {
        std::string hostname = rname[0]
            ? std::string(rname) + "-c-master" + suffix  // dash separator: matches master_hostname() and relay pattern
            : std::string("c-master") + suffix;

        for (size_t pi = 0; pi < kNumPorts; ++pi) {
            uint16_t port = kTryPorts[pi];

            struct sockaddr_in master_addr{};
            if (!resolve_master(hostname, port, &master_addr)) continue;

            obn::net::socket_t tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (tcp_fd == obn::net::kInvalid) continue;

            // 3-second send/recv timeout (portable: timeval on POSIX,
            // DWORD-ms on Winsock).
#if defined(_WIN32)
            DWORD tv = 3000;
            ::setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO,
                         reinterpret_cast<const char*>(&tv), sizeof(tv));
            ::setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO,
                         reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
            struct timeval tv{ 3, 0 };
            ::setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            ::setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

            if (connect(tcp_fd, (struct sockaddr*)&master_addr,
                        sizeof(master_addr)) != 0) {
                obn::net::close_socket(tcp_fd);
                continue;
            }
            OBN_DEBUG("[oss-iotc] connected to master %s:%u", hostname.c_str(), port);

            // Build MSG_QUERY_DEVICE5 packet (54 bytes total):
            // Confirmed layout from _IOTC_SendQuryDevice5 @ 0x190eb0:
            //   [0..15]  header: magic=0x0204, ver=0x1c, payload_len=0x26,
            //                    sub_cmd bytes [8..10] = 0x07, 0x10, 0x18
            //   [16..35] uid (20 bytes, lowercase)
            //   [36..51] realm (16 bytes, zero in OSS — GetRealm() returns 0)
            //   [52]     0x06  (confirmed constant)
            //   [53]     0x00  (connect_flag byte, 0 = default)
            uint8_t pkt[54];
            memset(pkt, 0, sizeof(pkt));
            fill_tutk_hdr(pkt, 0x26, 0x07, 0x10, 0x18);  // confirmed bytes
            memcpy(pkt + 16, uid_lc.c_str(), kUidLen);    // uid at +16
            // [36..51] = GetRealm → zero (OSS has no realm)
            pkt[52] = 0x06;   // confirmed constant
            pkt[53] = 0x00;   // extra flag, 0 = default

            // Plain TCP send matches what the standard TUTK SDK does on non-443 ports.
            ssize_t sent = write(tcp_fd, pkt, sizeof(pkt));
            if (sent != (ssize_t)sizeof(pkt)) {
                OBN_ERROR("[oss-iotc] master send failed");
                obn::net::close_socket(tcp_fd);
                continue;
            }

            // Receive response (MSG_QUERY_DEVICE5_R).
            // Layout:
            //   [0..1]   magic = 0x0204 (LE) — same TUTK header magic
            //   [2]      ver   = 0x1c
            //   [3..5]   payload_len and padding
            //   [8..10]  reply type bytes = 0x15, 0x02, 0x24
            //   [11..15] padding
            //   [16..19] result code (uint32 LE, 0 = success)
            //   [20..23] device WAN IPv4 (4 bytes, network/big-endian order)
            //   [24..25] device WAN port (uint16, big-endian)
            //   [26..27] padding / flags
            //   [28..31] relay server IPv4 (may be 0 if no relay assigned)
            //   [32..33] relay server port
            //   [34..53] additional relay entries and flags (inferred from size)
            uint8_t resp[256];
            ssize_t n = read(tcp_fd, resp, sizeof(resp));
            obn::net::close_socket(tcp_fd);

            if (n < 26) {
                OBN_WARN("[oss-iotc] master response too short (%zd bytes)", n);
                continue;
            }

            if (resp[0] != 0x04 || resp[1] != 0x02) {
                OBN_WARN("[oss-iotc] master response: bad magic %02x%02x", resp[0], resp[1]);
                continue;
            }

            // Result code at [16..19], uint32 LE.
            uint32_t result_code;
            memcpy(&result_code, resp + 16, 4);
            result_code = le32toh(result_code);
            if (result_code != 0) {
                OBN_ERROR("[oss-iotc] master returned error 0x%08x", result_code);
                continue;
            }

            // Device WAN IPv4 at [20..23] (network order), port at [24..25] (big-endian).
            struct sockaddr_in dev_addr{};
            dev_addr.sin_family = AF_INET;
            memcpy(&dev_addr.sin_addr, resp + 20, 4);  // already network order
            uint16_t dev_port;
            memcpy(&dev_port, resp + 24, 2);
            dev_addr.sin_port = dev_port;  // already big-endian (network order)

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &dev_addr.sin_addr, ip_str, sizeof(ip_str));
            OBN_DEBUG("[oss-iotc] master: device WAN = %s:%u", ip_str, ntohs(dev_addr.sin_port));

            *device_addr = dev_addr;
            return true;
        }
    }
    return false;
}

// ==========================================================================
// P2P NAT punch-through (PRECHECK → KNOCK → PUNCH_TO)
// ==========================================================================
//
//
// MSG_P2P_PRECHECK1 (36 bytes total):
//   _IOTC_SendPreCheck1 @ 0x18e8b0:
//     header: magic=0x0204, ver=0x1c, payload_len=0x14, bytes[8,9,10]=0x11,0x02,0x24
//     payload [16..35]: uid (20 bytes, lowercase)
//
// MSG_P2P_PRECHECK2 (48 bytes total):
//   _IOTC_SendPreCheck2 @ 0x18fb00:
//     header: magic=0x0204, ver=0x1c, payload_len=0x20, bytes[8,9,10]=0x14,0x02,0x24
//     payload [16..35]: uid (20 bytes)
//     payload [36..39]: 0x00000000 (padding)
//     payload [40..47]: authkey (8 bytes LE, only if authkey != 0)
//
// MSG_P2P_PUNCH_TO (52 bytes total):
//   _IOTC_Send_Punch_To @ 0x190790:
//     header: magic=0x0204, ver=0x1c, payload_len=0x24, bytes[8,9,10]=0x01,0x03,0x21
//     payload [0..15]:  local  address (netaddr 16 bytes: 2+4+2+8 layout via iotc_netaddr)
//     payload [16..19]: extra  field from r13[0x10] (client_random? flags?)
//     payload [20..35]: remote address (netaddr 16 bytes from peer sockaddr)
//
// The netaddr layout used by iotc_netaddr_put_content/get_content (0x138690/0x133d20):
//   Derived from usage — stores IP+port in a platform netaddr struct.
//   Best guess based on how inet addresses are stored in TUTK:
//     [0..1]   AF (uint16 LE, 0x02 = AF_INET)
//     [2..3]   port (uint16 BE = network byte order)
//     [4..7]   IPv4 address (4 bytes, network byte order)
//     [8..15]  zero pad
//   Total: 16 bytes.  This mirrors BSD sockaddr_in without the sin_len field.
// TODO: verify from pcap.
//
// MSG_P2P_KNOCK and KNOCK_R / KNOCK_RR:
//   These are exchange messages for hole-punching.  From log strings:
//     "Send MSG_P2P_KNOCK to %s:%d, ClientRandomID[%d]"
//     "Send MSG_P2P_KNOCK_R, to %s : %d RandomID %u"
//     "Send MSG_P2P_KNOCK_RR, to %s : %d RandomID[%u]"
//   Their exact wire format is unconfirmed.
//   Best guess: header + uint32 client_random_id (4 bytes)  — total 20 bytes.
//   TODO: verify from pcap.
//
// The reply MSG_P2P_PRECHECK1_R triggers the PRECHECK2 → KNOCK sequence.
// In UDPP2PConnectTaskCB (0x18ed80) the handler checks the response type
// and transitions through states:
//   state 0 → send PRECHECK1 → wait PRECHECK1_R (state 1)
//   state 1 → send PRECHECK2 + REQUEST → wait KNOCK (state 2)
//   state 2 → recv KNOCK → send KNOCK_R → recv KNOCK_RR → send PUNCH_TO (state 3)
//   state 3 → CONNECTED

// Fill a 16-byte TUTK netaddr from a sockaddr_in.
// Layout: [0..1]=AF_INET, [2..3]=port(BE), [4..7]=IPv4(BE), [8..15]=0
static void fill_tutk_netaddr(uint8_t* buf, const struct sockaddr_in* addr)
{
    memset(buf, 0, 16);
    buf[0] = 0x02; buf[1] = 0x00;           // AF_INET LE
    memcpy(buf + 2, &addr->sin_port, 2);     // port BE (already network order)
    memcpy(buf + 4, &addr->sin_addr, 4);     // IPv4 BE (already network order)
}

static ssize_t send_precheck1(obn::net::socket_t sock_fd, const struct sockaddr_in* dst,
                               const std::string& uid_lc)
{
    uint8_t payload[20];
    memset(payload, 0, sizeof(payload));
    memcpy(payload, uid_lc.c_str(), kUidLen);

    OBN_DEBUG("[oss-iotc] send PRECHECK1 -> %s:%u", inet_ntoa(dst->sin_addr), ntohs(dst->sin_port));
    return tutk_udp_send(sock_fd, dst,
                         0x11, 0x02, 0x24,
                         payload, sizeof(payload));
}

static ssize_t send_precheck2(obn::net::socket_t sock_fd, const struct sockaddr_in* dst,
                               const std::string& uid_lc, uint64_t authkey)
{
    uint8_t payload[32];
    memset(payload, 0, sizeof(payload));
    memcpy(payload, uid_lc.c_str(), kUidLen);       // [0..19] uid
    // [20..23] = 0x00000000 padding (confirmed: movl $0x0,0x34(rsp))
    // [24..31] = authkey LE (confirmed: only set if extra_arg non-null)
    if (authkey != 0)
        memcpy(payload + 24, &authkey, 8);

    OBN_DEBUG("[oss-iotc] send PRECHECK2 -> %s:%u", inet_ntoa(dst->sin_addr), ntohs(dst->sin_port));
    return tutk_udp_send(sock_fd, dst,
                         0x14, 0x02, 0x24,
                         payload, sizeof(payload));
}

// Send MSG_P2P_PUNCH_TO to the device.
//   header bytes[8..10] = 0x13, 0x02, 0x24
//   payload (20 bytes):
//     [0..3]  device WAN IPv4 (4 bytes, network byte order)
//     [4..5]  device WAN port (uint16, big-endian)
//     [6..19] zeros (padding / reserved)
//   Total packet = 16-byte header + 20-byte payload = 36 bytes.
static ssize_t send_punch_to(obn::net::socket_t sock_fd, const struct sockaddr_in* dst)
{
    uint8_t payload[20];
    memset(payload, 0, sizeof(payload));
    // Device WAN IP in network order at [0..3], port at [4..5] big-endian.
    memcpy(payload + 0, &dst->sin_addr, 4);
    memcpy(payload + 4, &dst->sin_port, 2);  // sin_port already network order

    OBN_DEBUG("[oss-iotc] send PUNCH_TO -> %s:%u", inet_ntoa(dst->sin_addr), ntohs(dst->sin_port));
    return tutk_udp_send(sock_fd, dst,
                         0x13, 0x02, 0x24,
                         payload, sizeof(payload));
}

// Build the 16-byte MSG_P2P_KNOCK payload.
//   [0..3]   client_random (uint32 LE)
//   [4..7]   authkey low 32 bits (uint32 LE)
//   [8..11]  authkey high 32 bits (uint32 LE)
//   [12..15] zeros
// Header bytes[8..10] = 0x1b, 0x02, 0x24.
// Total packet = 16-byte header + 16-byte payload = 32 bytes.
// MSG_P2P_KNOCK_R and MSG_P2P_KNOCK_RR use the same 32 bytes (device echoes KNOCK,
// client re-sends the same bytes for KNOCK_RR).
static void build_knock_payload(uint8_t payload[16],
                                uint32_t client_random, uint64_t authkey)
{
    memset(payload, 0, 16);
    uint32_t cr_le  = htole32(client_random);
    uint32_t ak_lo  = htole32((uint32_t)(authkey & 0xffffffff));
    uint32_t ak_hi  = htole32((uint32_t)(authkey >> 32));
    memcpy(payload + 0, &cr_le, 4);
    memcpy(payload + 4, &ak_lo, 4);
    memcpy(payload + 8, &ak_hi, 4);
    // [12..15] = 0 already
}

static ssize_t send_knock(obn::net::socket_t sock_fd, const struct sockaddr_in* dst,
                          uint32_t client_random, uint64_t authkey,
                          const char* label)
{
    uint8_t payload[16];
    build_knock_payload(payload, client_random, authkey);
    OBN_DEBUG("[oss-iotc] send %s -> %s:%u, random=0x%08x", label, inet_ntoa(dst->sin_addr), ntohs(dst->sin_port), client_random);
    // Header bytes[8..10] = 0x1b, 0x02, 0x24.
    return tutk_udp_send(sock_fd, dst, 0x1b, 0x02, 0x24,
                         payload, sizeof(payload));
}

// Fills sess->device_wan with the confirmed peer address from PRECHECK1_R.
static bool do_p2p_punch(OssSession* sess)
{
    const struct sockaddr_in* dst = &sess->device_wan;
    int sock = sess->udp_sock;

    uint8_t buf[600];
    struct sockaddr_in src{};

    // --- PRECHECK1 ---
    for (int attempt = 0; attempt < 3; ++attempt) {
        send_precheck1(sock, dst, sess->uid);

        // Real SDK polls with 30ms sleep up to ~5s; we use a single 2s recv.
        ssize_t n = tutk_udp_recv(sock, buf, sizeof(buf), &src, 2000);
        if (n >= 16) {
            // PRECHECK1_R: header byte [8] == 0x12.
            if (buf[8] != 0x12) {
                OBN_WARN("[oss-iotc] PRECHECK1: unexpected hdr[8]=0x%02x, retrying", buf[8]);
                continue;
            }
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src.sin_addr, ip_str, sizeof(ip_str));
            OBN_DEBUG("[oss-iotc] PRECHECK1_R from %s:%u", ip_str, ntohs(src.sin_port));

            // Update device address to the confirmed reply-from address.
            sess->device_wan = src;
            dst = &sess->device_wan;
            goto got_precheck1_r;
        }
        OBN_DEBUG("[oss-iotc] PRECHECK1 attempt %d: no reply", attempt + 1);
    }
    OBN_WARN("[oss-iotc] PRECHECK1: no response after 3 attempts");
    return false;

got_precheck1_r:
    // --- PRECHECK2 ---
    send_precheck2(sock, dst, sess->uid, sess->authkey);

    // --- P2P KNOCK exchange ---
    //   KNOCK:    header[8..10] = 0x1b, 0x02, 0x24; 16-byte payload (client_random + authkey)
    //   KNOCK_R:  device echoes the same 32 bytes back to the client
    //   KNOCK_RR: client re-sends the identical KNOCK bytes after receiving KNOCK_R
    // After KNOCK_RR, client sends PUNCH_TO to tell device our confirmed WAN address.
    for (int attempt = 0; attempt < 5; ++attempt) {
        // Send KNOCK.
        send_knock(sock, dst, sess->client_random, sess->authkey, "KNOCK");

        // Wait for KNOCK_R: any 32-byte response from the device IP (device echoes KNOCK).
        ssize_t n = tutk_udp_recv(sock, buf, sizeof(buf), &src, 1000);
        if (n == 32 && src.sin_addr.s_addr == dst->sin_addr.s_addr) {
            OBN_DEBUG("[oss-iotc] KNOCK_R from %s:%u", inet_ntoa(src.sin_addr), ntohs(src.sin_port));

            // Send KNOCK_RR: re-send the same KNOCK bytes (identical payload, same header).
            send_knock(sock, &src, sess->client_random, sess->authkey, "KNOCK_RR");

            // Wait for any response after KNOCK_RR (device may send an ALIVE or ack).
            n = tutk_udp_recv(sock, buf, sizeof(buf), &src, 1000);
            if (n >= 16) {
                OBN_DEBUG("[oss-iotc] post-KNOCK_RR packet from %s:%u (hdr: %02x%02x)", inet_ntoa(src.sin_addr), ntohs(src.sin_port), buf[8], buf[9]);
                // Update peer address from confirmed reply source.
                sess->device_wan = src;
                dst = &sess->device_wan;
            }
            goto send_punch;
        }
        OBN_DEBUG("[oss-iotc] KNOCK attempt %d: no KNOCK_R (n=%zd)", attempt + 1, n);
    }
    // Even without KNOCK_R, try PUNCH_TO — device may already be waiting for it.
    OBN_WARN("[oss-iotc] KNOCK sequence incomplete; trying PUNCH_TO anyway");

send_punch:
    // --- PUNCH_TO ---
    // Tells the device our confirmed WAN address (inferred from _IOTC_Send_Punch_To).
    send_punch_to(sock, dst);

    // Wait briefly for any post-PUNCH_TO packet (device ALIVE_D2C or ack).
    {
        ssize_t n = tutk_udp_recv(sock, buf, sizeof(buf), &src, 2000);
        if (n >= 16) {
            OBN_DEBUG("[oss-iotc] post-PUNCH_TO packet from %s:%u (hdr: %02x%02x)", inet_ntoa(src.sin_addr), ntohs(src.sin_port), buf[8], buf[9]);
            sess->device_wan = src;
        } else {
            OBN_DEBUG("[oss-iotc] no ack after PUNCH_TO - assuming connected");
        }
    }

    return true;
}

// ==========================================================================
// P2P keepalive thread
// ==========================================================================
//
// MSG_P2P_ALIVE_C2D is sent every 15 seconds to keep UDP NAT bindings alive.
// Bytes [8..10] = 0x10, 0x02, 0x24; unconfirmed (requires NAT P2P session capture).

static void keepalive_thread_fn(OssSession* sess)
{
    while (sess->keepalive_run) {
        if (sess->state == P2PState::CONNECTED && sess->udp_sock != obn::net::kInvalid) {
            tutk_udp_send(sess->udp_sock, &sess->device_wan,
                          0x10, 0x02, 0x24, nullptr, 0);
        }
        // 1-second increments so keepalive_run can stop the thread promptly
        for (int i = 0; i < 15 && sess->keepalive_run; ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// ==========================================================================
// Public API
// ==========================================================================

// Open a P2P session to a Bambu printer identified by UID.
//
// @param uid       20-char printer UID (e.g. "BBLP01XXXXXXXXXX0001")
// @param authkey   8-byte little-endian auth key (from URL "authkey=" param)
// @param password  AV layer password (default "888888")
// @param region    Geographic region for master server selection
// @returns new OssSession* on success, nullptr on failure (caller frees)
OssSession* iotc_connect(const std::string& uid,
                         uint64_t authkey,
                         const std::string& password,
                         TutkRegion region)
{
    if (!uid_valid(uid)) {
        OBN_ERROR("[oss-iotc] invalid UID (must be 20 printable ASCII): %s", uid.c_str());
        return nullptr;
    }

    auto* sess = new OssSession();
    sess->uid           = uid_lower(uid);
    sess->authkey       = authkey;
    sess->password      = password;
    sess->region        = region;
    sess->state         = P2PState::IDLE;
    sess->client_random = rand32();

    // Step 1: Open UDP socket
    sess->udp_sock = open_udp_socket(&sess->local_port);
    if (sess->udp_sock == obn::net::kInvalid) {
        OBN_ERROR("[oss-iotc] socket open failed: %s", strerror(errno));
        delete sess;
        return nullptr;
    }
    OBN_DEBUG("[oss-iotc] UDP socket bound on port %u", sess->local_port);
    OBN_DEBUG("[oss-iotc] UID=%s client_random=0x%08x", sess->uid.c_str(), sess->client_random);

    // Step 2: LAN search + DTLS handshake.
    // The epoch (e.g. 0x6a0) is client-generated; echoed by device in LAN_SEARCH_R3
    // and then used as the epoch for all subsequent DTLS records on the LAN path.
    // If the device is LAN-local, skip P2P punch and go straight to DTLS.
    sess->state = P2PState::LAN_SEARCH;
    {
        sess->dtls_epoch = rand32() & 0xffff;
        uint32_t partial_mac = rand32();

        // session_token = client_random(4B LE) || partial_mac(4B LE)
        uint32_t cr_le = htole32(sess->client_random);
        uint32_t pm_le = htole32(partial_mac);
        memcpy(sess->session_token + 0, &cr_le, 4);
        memcpy(sess->session_token + 4, &pm_le, 4);

        std::string uid_up = uid_upper(sess->uid);

        int bcast_on = 1;
        setsockopt(sess->udp_sock, SOL_SOCKET, SO_BROADCAST,
                   &bcast_on, sizeof(bcast_on));

        static const uint16_t kLanPorts[] = { 18604, 32100 };
        struct sockaddr_in bcast{};
        bcast.sin_family      = AF_INET;
        bcast.sin_addr.s_addr = INADDR_BROADCAST;

        for (uint16_t p : kLanPorts) {
            bcast.sin_port = htons(p);
            send_lan_search3(sess->udp_sock, &bcast,
                             uid_up.c_str(), sess->client_random,
                             partial_mac, (uint16_t)sess->dtls_epoch, false);
            OBN_DEBUG("[oss-iotc] LAN search broadcast -> port %u (epoch=0x%x)", p, sess->dtls_epoch);
        }

        uint8_t resp[600];
        struct sockaddr_in src{};
        set_recv_timeout(sess->udp_sock, 3000);
        ssize_t n = tutk_udp_recv(sess->udp_sock, resp, sizeof(resp), &src, 3000);
        if (n >= 16) {
            reverse_trans_code_partial(resp, (size_t)n);
            if (resp[0] != 0x04 || resp[1] != 0x02) {
                OBN_WARN("[oss-iotc] LAN_SEARCH_R3: bad magic %02x%02x", resp[0], resp[1]);
                sess->state = P2PState::QUERY_MASTER;
                goto lan_search_done;
            }
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src.sin_addr, ip_str, sizeof(ip_str));
            {
                // payload[33..34] = epoch (BE uint16) echoed from our LAN_SEARCH3
                uint16_t echoed_epoch = ((uint16_t)resp[49] << 8) | resp[50];
                OBN_DEBUG("[oss-iotc] LAN: device at %s:%u  echoed_epoch=0x%x", ip_str, ntohs(src.sin_port), echoed_epoch);
            }

            sess->device_wan = src;

            send_lan_search3(sess->udp_sock, &src,
                             uid_up.c_str(), sess->client_random,
                             partial_mac, (uint16_t)sess->dtls_epoch, true);
            OBN_DEBUG("[oss-iotc] directed LAN_SEARCH3 -> %s:%u", ip_str, ntohs(src.sin_port));

            int dtls_rc = dtls_psk_handshake(
                sess->udp_sock, &src,
                sess->dtls_epoch, sess->session_token,
                uid_up.c_str(),
                sess->password.c_str(), "admin",
                &sess->dtls);
            if (dtls_rc != 0) {
                OBN_ERROR("[oss-iotc] DTLS handshake failed (%d)", dtls_rc);
                obn::net::close_socket(sess->udp_sock);
                delete sess;
                return nullptr;
            }
            sess->state = P2PState::CONNECTED;
        } else {
            OBN_DEBUG("[oss-iotc] LAN search: no device (falling to master)");
            sess->state = P2PState::QUERY_MASTER;
        }
    }
    lan_search_done:

    // Step 3: Master server query (if LAN search failed).
    // We open a fresh TCP connection per call; the real SDK uses a persistent connection
    // from IOTC_TcpConnectToMaster.  Port 443 needs TLS (skipped — plain TCP only).
    if (sess->state == P2PState::QUERY_MASTER) {
        struct sockaddr_in dev_addr{};
        bool found = query_master_for_device(
            sess->uid, sess->client_random, region, &dev_addr);

        if (found) {
            sess->device_wan = dev_addr;
            sess->state = P2PState::PRECHECK;
        } else {
            OBN_WARN("[oss-iotc] master server: could not find device");
            obn::net::close_socket(sess->udp_sock);
            delete sess;
            return nullptr;
        }
    }

    // Step 4: P2P NAT punch-through.
    if (sess->state == P2PState::PRECHECK) {
        bool ok = do_p2p_punch(sess);
        if (!ok) {
            OBN_ERROR("[oss-iotc] P2P punch-through failed");
            obn::net::close_socket(sess->udp_sock);
            delete sess;
            return nullptr;
        }

        // WAN P2P DTLS: epoch=0 (not pre-negotiated like LAN path),
        // no type-0x33 auth packet (confirmed absent from relay captures; WAN assumed same).
        int dtls_rc = dtls_psk_handshake(
            sess->udp_sock, &sess->device_wan,
            /*initial_epoch=*/0,
            sess->session_token,
            /*uid_upper_str=*/nullptr,
            sess->password.c_str(), "admin",
            &sess->dtls);
        if (dtls_rc != 0) {
            OBN_ERROR("[oss-iotc] WAN DTLS handshake failed");
            obn::net::close_socket(sess->udp_sock);
            delete sess;
            return nullptr;
        }
    }

    sess->state = P2PState::CONNECTED;
    OBN_INFO("[oss-iotc] P2P session established with %s:%u", inet_ntoa(sess->device_wan.sin_addr), ntohs(sess->device_wan.sin_port));

    sess->keepalive_run = true;
    try {
        // Joinable (not detached): iotc_close() joins this thread before
        // freeing sess, preventing a use-after-free of the session struct.
        sess->keepalive_thread = std::thread(keepalive_thread_fn, sess);
    } catch (...) {
        OBN_ERROR("[oss-iotc] keepalive thread creation failed");
        sess->keepalive_run = false;
    }

    return sess;
}

void iotc_close(OssSession* sess)
{
    if (!sess) return;
    sess->keepalive_run = false;

    // Join the keepalive thread before freeing sess so it cannot dereference
    // the session struct (state/udp_sock/device_wan) after delete.
    if (sess->keepalive_thread.joinable())
        sess->keepalive_thread.join();

    if (sess->udp_sock != obn::net::kInvalid) {
        // Send MSG_P2P_CLOSE_C2D to notify the device before closing.
        // Header bytes[8..10] = 0x18, 0x02, 0x24.
        // payload_len = 0 (header-only, 16 bytes total).
        if (sess->state == P2PState::CONNECTED) {
            tutk_udp_send(sess->udp_sock, &sess->device_wan,
                          0x18, 0x02, 0x24, nullptr, 0);
        }
        obn::net::close_socket(sess->udp_sock);
        sess->udp_sock = obn::net::kInvalid;
    }
    delete sess;
}

// ==========================================================================
// TUTK IOTC Relay Protocol
// ==========================================================================
//
// The "Agora" cloud camera path in Bambu printers is NOT Agora — it is a TUTK
// IOTC relay protocol.  Traffic analysis shows:
//
//   Relay server: {region}-c-master-{relay_id}.iotcplatform.com:10240 (UDP)
//   ALL packets scrambled with TransCodePartial (key = "Charlie is the d")
//
// Connection flow:
//   1. JOIN (54B):  IOTC header + UID(20B) + relay_id(16B) + 0x0600
//   2. KNOCK ×5 (88B): IOTC header + UID(20B) + zeros(16B) + sdk_ver(4B)
//                       + session_token(8B) + 24B fixed flags
//   3. Relay server responds with 200B relay assignment
//      — bytes [188..191] echo session_token[0..3]
//   4. Client sends one more KNOCK (same 88B format)
//   5. DTLS handshake (initial_epoch=0, no type-0x33 packet for relay path)
//   6. DTLS ApplicationData: AV LOGIN → LOGIN ACK → IPCAM_START → frames

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

    memcpy(pkt + 16, uid_upper, 20);
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

    memcpy(pkt + 16, uid_upper, 20);
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

// 8-byte address record: 02 00 | port (big-endian) | ipv4 (network order).
static void write_addr_rec(uint8_t* p, const struct sockaddr_in* a)
{
    p[0] = 0x02; p[1] = 0x00;
    memcpy(p + 2, &a->sin_port, 2);   // network order == big-endian on the wire
    memcpy(p + 4, &a->sin_addr, 4);
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
    memcpy(pkt + 16, uid_upper, 20);
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
    memcpy(pkt + 16, uid_upper, 20);
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
    memcpy(pkt + 16, uid_upper, 20);
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
    memcpy(pkt + 16, uid_upper, 20);
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
    memcpy(pkt + 16, uid_upper, 20);
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
    memcpy(pkt + 16, uid_upper, 20);
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
    memcpy(pkt + 16, uid_upper, 20);
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
        OBN_WARN("[rdv] no rendezvous servers found in master reply");
        return false;
    }
    OBN_INFO("[rdv] discovered %d rendezvous server(s)", ns);

    struct sockaddr_in reflexive{};
    bool have_reflexive = parse_reflexive(master_reply, reply_len, &reflexive);
    if (!have_reflexive) {
        OBN_DEBUG("[rdv] master reply has no reflexive record; seeding from server 0");
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
                OBN_DEBUG("[rdv] re-broadcasting initial probes and authkey to %d servers", ns);
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
        OBN_DEBUG("[rdv] reply %zd bytes type=%02x %02x %02x from %s:%u",
                  n, resp[8], resp[9], resp[10],
                  inet_ntoa(src.sin_addr), ntohs(src.sin_port));

        // Probe reply (04 80 4f): learn reflexive WAN address
        if (resp[8] == 0x04 && resp[9] == 0x80) {
            struct sockaddr_in mine{};
            if (read_addr_rec(resp + 16, &mine) && ntohs(mine.sin_port) != 3478) {
                reflexive = mine;
                OBN_DEBUG("[rdv] reflexive learned %s:%u", inet_ntoa(mine.sin_addr), ntohs(mine.sin_port));
            }
            continue;
        }

        // Direct printer rendezvous (02 06 12) from printer P2P address
        if (resp[8] == 0x02 && resp[9] == 0x06 && resp[10] == 0x12) {
            *peer_out = src;
            if (tag_out) *tag_out = 0;
            OBN_INFO("[rdv] direct printer rendezvous 02 06 12 received from %s:%u",
                     inet_ntoa(src.sin_addr), ntohs(src.sin_port));
            return true;
        }

        // Direct printer punch / ack (01 04 33 or 02 04 33) from printer P2P candidate
        if ((resp[8] == 0x01 || resp[8] == 0x02) && resp[9] == 0x04 && resp[10] == 0x33) {
            send_ctrl0x33(sock, &src, uid_upper, session_token);
            *peer_out = src;
            if (tag_out) *tag_out = 0;
            OBN_INFO("[rdv] direct printer punch %02x 04 33 received from %s:%u - P2P established!",
                     resp[8], inet_ntoa(src.sin_addr), ntohs(src.sin_port));
            return true;
        }

        // Server challenge (27 02 42): triggers candidate registration 04 08 24 broadcast
        if (resp[8] == 0x27 && resp[9] == 0x02 && resp[10] == 0x42) {
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_challenge_broadcast).count() >= 150) {
                last_challenge_broadcast = now;
                OBN_DEBUG("[rdv] server challenge 27 02 42 -> broadcasting 04 08 24 to %d servers", ns);
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
                OBN_DEBUG("[rdv] prepared session 15 02 42 -> broadcasting 03 02 34 and 0a 02 24 to %d servers", ns);
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
            OBN_DEBUG("[rdv] received 01 03 43 with %d candidate(s)", num_candidates);
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
            OBN_INFO("[rdv] pairing confirmed 03 03 43 from %s:%u with tag=%u",
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

    OBN_WARN("[rdv] rendezvous timed out after 15s");
    return false;
}

// JOIN + KNOCK×5 + receive 200B relay assignment + post-KNOCK.
int iotc_relay_connect(const char* uid_upper, const char* relay_id,
                       const char* region_str, const char* authkey,
                       RelayConn* out)
{
    if (!uid_upper || !relay_id || !region_str || !out) return -1;
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
        OBN_ERROR("[relay] no IPv4 master address found for region %s", region_str);
        return -1;
    }
    struct sockaddr_in relay_addr = masters[0];

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &relay_addr.sin_addr, ip_str, sizeof(ip_str));
    OBN_DEBUG("[relay] resolved %d master(s) (first: %s -> %s:10240)", nmasters, resolved_host, ip_str);

    obn::net::socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == obn::net::kInvalid) {
        OBN_ERROR("[relay] socket() failed: %s", strerror(errno));
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
        OBN_ERROR("[relay] JOIN send failed: %s", strerror(errno));
        obn::net::close_socket(sock);
        return -1;
    }
    OBN_DEBUG("[relay] JOIN sent to %d master(s)", njoined);

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
            OBN_DEBUG("[relay] recv timeout attempt %d", attempt + 1);
            continue;
        }

        OBN_DEBUG("[relay] received %zd bytes", n);

        if (n < 16) continue;
        reverse_trans_code_partial(resp, (size_t)n);

        if (resp[0] != 0x04 || resp[1] != 0x02) {
            OBN_WARN("[relay] bad IOTC magic %02x%02x", resp[0], resp[1]);
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
            OBN_WARN("[relay] unexpected msg type %02x%02x%02x (expected 02 06 12)", resp[8], resp[9], resp[10]);
            continue;
        }

        if (n >= 192) {  // verify session_token echo at [188..191]
            if (resp[188] != session_token[0] || resp[189] != session_token[1] ||
                resp[190] != session_token[2] || resp[191] != session_token[3]) {
                OBN_WARN("[relay] session_token echo mismatch: got %02x%02x%02x%02x expected %02x%02x%02x%02x",
                        resp[188], resp[189], resp[190], resp[191],
                        session_token[0], session_token[1],
                        session_token[2], session_token[3]);
                // Log but don't reject — the echo offset may differ by firmware
            } else {
                OBN_DEBUG("[relay] session_token echo verified");
            }
        }

        peer_addr = src;
        got_assignment = true;
        {
            char pip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &peer_addr.sin_addr, pip, sizeof(pip));
            OBN_DEBUG("[relay] rendezvous received; peer = %s:%u",
                      pip, ntohs(peer_addr.sin_port));
        }
        break;
    }

    // Off-LAN fallback: the printer did not send a direct rendezvous, so run the
    // reflexive/candidate exchange with the servers the master listed. On success
    // peer_addr is the printer's P2P media address or the rendezvous relay server.
    uint32_t relay_tag = 0;
    if (!got_assignment && master_reply_len > 0) {
        OBN_DEBUG("[relay] no direct rendezvous; trying off-LAN candidate exchange");
        if (offlan_rendezvous(sock, master_reply, master_reply_len,
                              uid_upper, authkey, session_token, &peer_addr, &relay_tag)) {
            got_assignment = true;
            char pip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &peer_addr.sin_addr, pip, sizeof(pip));
            OBN_DEBUG("[relay] off-LAN rendezvous succeeded; peer = %s:%u (tag=%u)",
                      pip, ntohs(peer_addr.sin_port), relay_tag);
        }
    }

    if (!got_assignment) {
        OBN_WARN("[relay] no rendezvous received");
        obn::net::close_socket(sock);
        return -1;
    }

    // Punch and run the session against the peer's own address (from the
    // rendezvous), not the master server. Only send knock if direct P2P.
    if (ntohs(peer_addr.sin_port) != 3478) {
        if (send_relay_knock(sock, &peer_addr, uid_upper, session_token, true) != 0) {
            OBN_ERROR("[relay] post-assignment KNOCK failed: %s", strerror(errno));
            obn::net::close_socket(sock);
            return -1;
        }
        OBN_DEBUG("[relay] post-assignment KNOCK sent to peer");
    }

    out->sock = sock;
    out->relay_addr = peer_addr;
    memcpy(out->session_token, session_token, 8);
    out->relay_tag = relay_tag;
    out->is_relay = (ntohs(peer_addr.sin_port) == 3478);
    if (uid_upper) {
        strncpy(out->uid_upper, uid_upper, sizeof(out->uid_upper) - 1);
        out->uid_upper[sizeof(out->uid_upper) - 1] = '\0';
    }
    memset(&out->dtls, 0, sizeof(out->dtls));
    out->dtls.relay_tag = relay_tag;

    return 0;
}

// epoch=0, type-0x33 auth packet sent only for direct P2P (omitted for relay server).
int iotc_relay_dtls(RelayConn* rc,
                    const char* passwd, const char* account)
{
    if (!rc || rc->sock < 0) return -1;

    return dtls_psk_handshake(rc->sock, &rc->relay_addr,
                               /*initial_epoch=*/0,
                               rc->session_token,
                               rc->is_relay ? nullptr : rc->uid_upper,
                               passwd, account,
                               &rc->dtls,
                               rc->relay_tag);
}

int iotc_relay_send_app_data(RelayConn* rc,
                              const uint8_t* data, size_t len)
{
    if (!rc || rc->sock < 0) return -1;
    DtlsSession& ds = rc->dtls;

    std::vector<uint8_t> dtls_rec;
    if (!dtls_encrypt_record(&ds, 0x17 /*ApplicationData*/, data, len, dtls_rec)) {
        OBN_ERROR("[relay-send] encrypt ApplicationData failed (len=%zu)", len);
        return -1;
    }

    int rc_send = send_dtls_packet(rc->sock, &rc->relay_addr,
                                   ds.epoch, rc->session_token,
                                   dtls_rec.data(), dtls_rec.size(),
                                   rc->relay_tag);
    if (rc_send != 0) {
        OBN_ERROR("[relay-send] send_dtls_packet failed (len=%zu, dtls_len=%zu)", len, dtls_rec.size());
    } else {
        OBN_DEBUG("[relay-send] sent %zu B app data (dtls_len=%zu, epoch=%u)", len, dtls_rec.size(), ds.epoch);
    }
    return rc_send;
}

int iotc_relay_recv_app_data(RelayConn* rc,
                              uint8_t* out_buf, size_t out_size,
                              int timeout_ms)
{
    if (!rc || rc->sock < 0) return -1;
    DtlsSession& ds = rc->dtls;

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
            OBN_ERROR("[relay-recv] recvfrom error: WSA %d", err);
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT) {
                if (std::chrono::steady_clock::now() >= deadline)
                    return 0;
                continue;
            }
            OBN_ERROR("[relay-recv] recvfrom error: %s", strerror(errno));
#endif
            return -1;
        }

        if (n < 16) continue;

        // Ignore stray packets from other rendezvous servers or unknown peers
        if (src.sin_addr.s_addr != rc->relay_addr.sin_addr.s_addr ||
            src.sin_port != rc->relay_addr.sin_port) {
            continue;
        }

        reverse_trans_code_partial(raw, (size_t)n);

        if (raw[0] != 0x04 || raw[1] != 0x02) continue;

        // If server re-sends 03 03 43 pairing confirmed, ACK it so server stops retrying
        if (raw[8] == 0x03 && raw[9] == 0x03 && raw[10] == 0x43) {
            uint32_t tag = 0;
            if (n >= 40) memcpy(&tag, raw + 36, 4);
            uint32_t tag_h = le32toh(tag);
            send_rdv_ack(rc->sock, &src, rc->uid_upper, rc->session_token, tag_h);
            OBN_DEBUG("[relay-recv] re-ACKed 03 03 43 from relay (tag=%u)", tag_h);
            continue;
        }

        // Verify DTLS packet encapsulation:
        // Relay: raw[8..10] == {0x03, 0x05, 0x42}
        // Direct P2P: raw[8..10] == {0x07, 0x04, 0x21}
        bool is_dtls = rc->is_relay ? (raw[8] == 0x03 && raw[9] == 0x05 && raw[10] == 0x42)
                                    : (raw[8] == 0x07 && raw[9] == 0x04 && raw[10] == 0x21);
        if (!is_dtls) {
            OBN_DEBUG("[relay-recv] skipping non-DTLS packet: len=%zd type=%02x %02x %02x",
                      n, raw[8], raw[9], raw[10]);
            continue;
        }

        if (n < 28 + 13) continue;  // too short for IOTC header + DTLS record header

        uint8_t content_type = raw[28];

        // Skip non-ApplicationData records (handshake/alerts)
        if (content_type != 0x17) {
            OBN_DEBUG("[relay-recv] skipping DTLS record type 0x%02x", content_type);
            continue;
        }

        const uint8_t* dtls_rec = raw + 28;
        size_t dtls_len = (size_t)(n - 28);
        int plain_len = dtls_decrypt_record(&ds, dtls_rec, dtls_len, out_buf, out_size);
        if (plain_len >= 0) {
            ds.rx_seq++;
            return plain_len;
        } else {
            OBN_WARN("[relay-recv] dtls_decrypt_record failed (err=%d, dtls_len=%zu)", plain_len, dtls_len);
        }
    } while (std::chrono::steady_clock::now() < deadline);

    return 0;  // timed out without an AppData packet
}

void iotc_relay_close(RelayConn* rc)
{
    if (!rc) return;
    if (rc->sock >= 0) {
        obn::net::close_socket(rc->sock);
        rc->sock = -1;
    }
    memset(rc, 0, sizeof(*rc));
    rc->sock = -1;
}

// ==========================================================================
// AV layer — Start video stream
// ==========================================================================
//
// Once the IOTC session is established (iotc_connect returns non-null),
// the AV layer needs to be started.
//
// Implemented flow (avClientStartEx + avSendIOCtrl + avRecvFrameData2):
//   1. avClientStartEx(AvStartIn*, AvStartOut*) — allocates AV channel slot.
//      In the real TUTK library this triggers avConnect_inner which sends the
//      LOGIN frame and waits for the printer's auth response.
//      In our OSS reimplementation, call oss_av_attach() then oss_av_login()
//      before the IOCtrl/recv cycle.
//
//   2. avSendIOCtrl(av_index, 0xFF01, NULL, 0) — send IPCAM_START.
//      Wire format:
//        AvFrameHeader(sub=CTRL=0x02) + uint32_t type_LE + uint32_t data_len_LE
//
//   3. avRecvFrameData2(...) — receive one H.264 frame per call.
//      Reads a UDP datagram, validates the 16-byte AvFrameHeader, copies
//      payload into caller's buffer.  Returns bytes copied or negative error.
//
// Wire format of AV frame:
//   [0..3]  payload_len   (uint32 LE)
//   [4..7]  magic         (uint32 LE): bits[15:0]=0x013f, bits[23:16]=sub_type,
//                                       bits[31:24]=direction
//   [8..11] sequence      (uint32 LE, monotonic counter)
//   [12..15] reserved     (uint32, set to 0x0b in login frame, else 0)
//   [16..]  payload
//
// LOGIN frame payload:
//   account\0passwd\0   (NUL-terminated strings concatenated)
//
// IOCtrl frame payload:
//   [0..3]  ioctrl_type  (uint32 LE, e.g. 0xFF01)
//   [4..7]  data_len     (uint32 LE)
//   [8..]   data bytes   (0 for IPCAM_START)

struct AvFrameHeader {
    uint32_t payload_len;  // LE
    uint32_t magic;        // LE: (dir<<24)|(sub<<16)|0x013f
    uint32_t sequence;     // LE
    uint32_t reserved;     // unknown
};
static_assert(sizeof(AvFrameHeader) == 16, "AV frame header must be 16 bytes");

static uint32_t av_magic(uint8_t sub_type, uint8_t direction)
{
    return (uint32_t)kFrameMagicMarker
         | ((uint32_t)sub_type  << 16)
         | ((uint32_t)direction << 24);
}

static bool is_av_frame_header(const uint8_t* buf)
{
    uint32_t magic;
    memcpy(&magic, buf + 4, 4);
    magic = le32toh(magic);
    return (magic & 0xffff) == kFrameMagicMarker;
}

// ==========================================================================
// AV layer — wire helpers
// ==========================================================================

// Maximum account / password string lengths accepted by the TUTK AV server.
// From avConnect_inner: strlen(account) must be < rbx-1 (rbx = 0x101 or 0x10
// depending on remote protocol version), and strlen(passwd) <= 0x77 = 119.
static constexpr size_t kAvAccountMax = 0x100; // 256 chars
static constexpr size_t kAvPasswdMax  = 0x77;  // 119 chars

// AV packet ring buffer used by the frame-receive path.
// Each slot tracks one in-flight TUTK AV packet from the read thread.
// The slot layout:
//   [0x00] uint32_t frame_seq     — frame sequence number
//   [0x08] uint8_t  type          — slot type: 0x02 = video, 0x01 = audio
//   [0x0c..0x17] other fields
// Per-slot stride = 0x18 = 24 bytes.

// IOCtrl packet header used by the TUTK avSendIOCtrl path.
// From _avSendIO → avSendIOCtrlFrame (PLT call at 16cbed, extra arg r8d=0x70).
// The IOCtrl frame wraps the user type+data in a TUTK-specific packet.
// Wire layout (reconstructed from _avSendIOCtrl_Old and assemblePackHead calls):
//
//   Bytes [0..3]  header assembled by assemblePackHead:
//                   [0]   = msg_type low byte (0x00 for IOCtrl send)
//                   [1]   = sub_type byte
//                   [2..3]= 0x000b (AV channel identifier)
//   Bytes [4..7]  ioctrl_type (uint32_t LE, e.g. 0xFF01 for IPCAM_START)
//   Bytes [8..11] payload_len (uint32_t LE)
//   Bytes [12..] payload data (0 bytes for IPCAM_START)
//
// Note: The 0x70 flag passed to avSendIOCtrlFrame selects the "new" IOCtrl
// path which wraps the above inside an AV frame with magic 0x013f.

struct AvIoCtrlPkt {
    uint8_t  hdr[4];          // [0] assemblePackHead output (type, sub, 0x000b)
    uint32_t ioctrl_type;     // [4] LE: IOTYPE_USER_IPCAM_START etc.
    uint32_t payload_len;     // [8] LE
    // payload follows
};

static void fill_av_header(AvFrameHeader* hdr,
                           uint8_t sub_type, uint8_t direction,
                           uint32_t payload_len, uint32_t sequence)
{
    hdr->payload_len = htole32(payload_len);
    hdr->magic       = htole32(av_magic(sub_type, direction));
    hdr->sequence    = htole32(sequence);
    hdr->reserved    = 0;
}

// ==========================================================================
// AV channel state (one per active av_index)
// ==========================================================================
//
// The real TUTK library manages a kalayav_interface_list[] table indexed by
// av_index (returned by avClientStartEx).  Each entry is a 0xa0-byte struct
// holding a pointer to the AV object (the AVConn) at offset 0.
//
// For the OSS reimplementation we keep a simple flat table.

static constexpr int kMaxAvChannels = 8;

struct AvChannel {
    bool     active;
    obn::net::socket_t sock_fd;
    struct sockaddr_in peer;
    uint8_t  channel;           // IOTC AV channel number (0..31)
    uint32_t tx_seq;            // next outgoing sequence number (AV-level, inside frame header)
    uint32_t rx_seq_expected;   // next expected incoming sequence number
    DtlsSession* dtls_sess;     // points into OssSession::dtls (not owned); null = plaintext
    bool         use_dtls;      // true when underlying socket carries DTLS ApplicationData
    uint8_t      session_token[8]; // IOTC session token for DTLS IOTC wrapper
};

static AvChannel g_av_channels[kMaxAvChannels];
static bool      g_av_channels_init = false;

static void av_channels_init()
{
    if (g_av_channels_init) return;
    memset(g_av_channels, 0, sizeof(g_av_channels));
    for (auto& ch : g_av_channels) {
        ch.sock_fd   = obn::net::kInvalid;
        ch.dtls_sess = nullptr;
        ch.use_dtls  = false;
    }
    g_av_channels_init = true;
}

static int av_alloc_channel()
{
    av_channels_init();
    for (int i = 0; i < kMaxAvChannels; ++i) {
        if (!g_av_channels[i].active) return i;
    }
    return -1;
}

// ==========================================================================
// DTLS AV-layer helpers: encrypt/send and decrypt/recv
// ==========================================================================

// Encrypt and send one ApplicationData record over a P2P (non-relay) socket.
static int dtls_encrypt_and_send(DtlsSession* ds, obn::net::socket_t sock,
                                  const struct sockaddr_in* dst,
                                  const uint8_t* session_token,
                                  const uint8_t* data, size_t len)
{
    std::vector<uint8_t> dtls_rec;
    if (!dtls_encrypt_record(ds, 0x17 /*ApplicationData*/, data, len, dtls_rec)) {
        OBN_ERROR("[dtls-send] encrypt ApplicationData failed");
        return -1;
    }

    return send_dtls_packet(sock, dst, ds->epoch, session_token,
                             dtls_rec.data(), dtls_rec.size(), ds->relay_tag);
}

// Decrypt one DTLS ApplicationData record received in a raw IOTC-wrapped UDP datagram.
// raw/raw_len: the full datagram as received from recvfrom (not yet descrambled).
// plain_out/plain_max: output buffer for decrypted payload.
// Returns plaintext byte count on success, 0 if not an ApplicationData record
// (keepalive or other type — caller should retry), -1 on AEAD/EtM authentication failure.
static int dtls_decrypt_one(DtlsSession* ds,
                             const uint8_t* raw, size_t raw_len,
                             uint8_t* plain_out, size_t plain_max)
{
    if (raw_len < 28 + 13) return 0;  // too short for IOTC header + DTLS record header

    std::vector<uint8_t> buf(raw, raw + raw_len);
    reverse_trans_code_partial(buf.data(), buf.size());

    if (buf[0] != 0x04 || buf[1] != 0x02) return 0;

    uint8_t content_type = buf[28];  // DTLS record starts at offset 28
    if (content_type != 0x17) {
        // Not ApplicationData — keepalive or handshake record; caller should retry
        OBN_DEBUG("[dtls-decrypt] skipping DTLS record type 0x%02x", content_type);
        return 0;
    }

    const uint8_t* dtls_rec = buf.data() + 28;
    size_t dtls_len = buf.size() - 28;
    int plain_len = dtls_decrypt_record(ds, dtls_rec, dtls_len, plain_out, plain_max);
    if (plain_len >= 0) {
        ds->rx_seq++;
        return plain_len;
    }
    return -1;
}

static int av_channel_write(AvChannel* ch, const void* buf, size_t len)
{
    if (ch->use_dtls && ch->dtls_sess) {
        return dtls_encrypt_and_send(ch->dtls_sess, ch->sock_fd, &ch->peer,
                                      ch->session_token,
                                      static_cast<const uint8_t*>(buf), len);
    }
    ssize_t sent = sendto(ch->sock_fd, buf, len, 0,
                          (const struct sockaddr*)&ch->peer, sizeof(ch->peer));
    return (sent == (ssize_t)len) ? 0 : -1;
}

// Retries on non-ApplicationData DTLS records (keepalives etc.).
static ssize_t av_channel_read_plain(AvChannel* ch,
                                      uint8_t* plain_out, size_t plain_max,
                                      int timeout_ms)
{
    set_recv_timeout(ch->sock_fd, timeout_ms);

    if (!ch->use_dtls || !ch->dtls_sess) {
        return recv(ch->sock_fd, plain_out, plain_max, 0);
    }

    static constexpr int kMaxRetries = 16;
    std::vector<uint8_t> raw(65536 + 64);
    for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
        ssize_t n = recv(ch->sock_fd, raw.data(), raw.size(), 0);
        if (n < 0) return -1;
        int pn = dtls_decrypt_one(ch->dtls_sess, raw.data(), (size_t)n,
                                   plain_out, plain_max);
        if (pn > 0) return (ssize_t)pn;
        if (pn < 0) return -1;
        // pn == 0: non-AppData record — retry
    }
    return -1;
}

// ==========================================================================
// avClientStartEx — open AV channel and authenticate
// ==========================================================================
//
// LOGIN frame protocol:
//
// The client sends a 16-byte AvFrameHeader followed by a credential block:
//
//   [0x00..0x0f]  AvFrameHeader:
//     payload_len = account_len+1 + passwd_len+1  (includes NUL terminators)
//     magic       = 0x0001013f  (dir=0x00, sub=0x01=LOGIN, marker=0x013f)
//     sequence    = 0           (first login frame)
//     reserved    = 0
//
//   [0x10..0x10+account_len]  account string (NUL-terminated, max 255 chars)
//   [0x10+account_len+1 ..]   passwd string  (NUL-terminated, max 119 chars)
//
// Evidence:
//  - avConnect_inner @ 168102–168131: memcpy(pkt+0x18, account, strlen(account))
//    (0x18 relative to the 16-byte AvFrameHeader base at 0x140(%rsp) — so
//    the account starts at header+0x18, but the header base itself is at
//    0x140 and credentials go at 0x158; relative to header that is 0x18.)
//  - passwd is placed after account at 168136–16816a: memcpy(r11, passwd, ...)
//    where r11 = pkt_base + 0x18 + account_strlen_rounded (from 0x38(%rsp)).
//  - assemblePackHead @ 168693 fills header[0]=0, [1]=0x20(sub?), [2..3]=0x0b
//    for the DTLS variant; the non-DTLS path (168693 is skipped) uses inline
//    code that sets header[2..3]=0x0b, type=0, sub=0 at 1680c1.
//    BUT the 16-byte AvFrameHeader at the front is separate from the TUTK
//    internal packetisation header — the magic 0x013f comes from the AV
//    frame layer above, confirmed by the kFrameMagicMarker constant.
//
//  - From _avProcessLoginPacket @ 176e60: the server reads [2..3] of the
//    incoming packet as "version" and validates it.  The server then calls
//    _AvDoAuthCheck with the packet contents which is how it reads account/passwd.
//
// LOGIN ACK: the server replies with an AvFrameHeader:
//   magic (sub=0x01), direction=P→C (0x00), payload_len=4
//   payload: uint32_t result_code (0 = success)
//
// The av_index returned is the slot we allocated locally; the TUTK library
// would return an index into kalayav_interface_list.

extern "C" int avClientStartEx(void* start_in_v, void* start_out_v)
{
    if (!start_in_v || !start_out_v) return AV_ER_INVALID_SID;

    auto* in  = static_cast<AvStartIn*>(start_in_v);
    auto* out = static_cast<AvStartOut*>(start_out_v);

    if (in->struct_size <= 0x37) return AV_ER_INVALID_SID;
    if (out->struct_size <= 0x17) return AV_ER_INVALID_SID;
    if (in->channel > 0x1f) return AV_ER_INVALID_SID;

    const char* account = in->account ? in->account : "admin";
    const char* passwd  = in->passwd  ? in->passwd  : "888888";

    size_t acc_len = strnlen(account, kAvAccountMax);
    size_t pwd_len = strnlen(passwd,  kAvPasswdMax);
    if (acc_len >= kAvAccountMax) return AV_ER_INVALID_SID;
    if (pwd_len >= kAvPasswdMax)  return AV_ER_INVALID_SID;

    int idx = av_alloc_channel();
    if (idx < 0) return AV_ER_EXCEED_MAX_CHANNEL;

    // Socket is filled later via oss_av_attach(); real TUTK wires it via the sid.
    g_av_channels[idx].active  = true;
    g_av_channels[idx].channel = in->channel;
    g_av_channels[idx].tx_seq  = 0;
    g_av_channels[idx].rx_seq_expected = 0;
    g_av_channels[idx].sock_fd = obn::net::kInvalid; // filled by caller via oss_av_attach()

    out->resend   = 0;
    out->two_way  = 0;
    out->unknown1 = 0;
    out->unknown2 = 0;
    out->av_index = idx;

    OBN_DEBUG("[oss-av] avClientStartEx: allocated av_index=%d channel=%u account='%s'", idx, in->channel, account);

    return idx;
}

// In the real TUTK library the AV object holds the session reference from sid;
// here it is supplied explicitly after avClientStartEx.
void oss_av_attach(int av_index, int sock_fd, const struct sockaddr_in* peer,
                   DtlsSession* dtls, const uint8_t* session_token)
{
    if (av_index < 0 || av_index >= kMaxAvChannels) return;
    if (!g_av_channels[av_index].active) return;
    g_av_channels[av_index].sock_fd   = sock_fd;
    if (peer) g_av_channels[av_index].peer = *peer;
    g_av_channels[av_index].dtls_sess = dtls;
    g_av_channels[av_index].use_dtls  = (dtls != nullptr && dtls->handshake_complete);
    if (session_token)
        memcpy(g_av_channels[av_index].session_token, session_token, 8);
    else
        memset(g_av_channels[av_index].session_token, 0, 8);
}

int oss_av_login(int av_index, const char* account, const char* passwd,
                 int timeout_ms)
{
    if (av_index < 0 || av_index >= kMaxAvChannels) return AV_ER_INVALID_SID;
    AvChannel& ch = g_av_channels[av_index];
    if (!ch.active || ch.sock_fd == obn::net::kInvalid) return AV_ER_INVALID_SID;

    if (!account) account = "admin";
    if (!passwd)  passwd  = "888888";

    size_t acc_len = strnlen(account, kAvAccountMax);
    size_t pwd_len = strnlen(passwd,  kAvPasswdMax);

    uint32_t payload_len = (uint32_t)(acc_len + 1 + pwd_len + 1);
    size_t   pkt_size    = sizeof(AvFrameHeader) + payload_len;

    std::vector<uint8_t> pkt(pkt_size, 0);
    auto* hdr = reinterpret_cast<AvFrameHeader*>(pkt.data());

    // reserved=0x0b mirrors assemblePackHead cx=0x0b (avConnect_inner+0x4c1).
    hdr->payload_len = htole32(payload_len);
    hdr->magic       = htole32(av_magic(kFrameSubtypeLogin, kFrameDirClientToP));
    hdr->sequence    = htole32(ch.tx_seq++);
    hdr->reserved    = htole32(0x0000000b);

    uint8_t* cred = pkt.data() + sizeof(AvFrameHeader);
    memcpy(cred, account, acc_len);              // NUL already there (vector zero-init)
    memcpy(cred + acc_len + 1, passwd, pwd_len); // NUL already there

    if (av_channel_write(&ch, pkt.data(), pkt_size) < 0) {
        OBN_ERROR("[oss-av] LOGIN send failed: %s", strerror(errno));
        return AV_ER_SESSION_CLOSE_BY_REMOTE;
    }

    uint8_t ack_buf[sizeof(AvFrameHeader) + 8];
    ssize_t n = av_channel_read_plain(&ch, ack_buf, sizeof(ack_buf), timeout_ms);
    if (n < (ssize_t)sizeof(AvFrameHeader)) {
        OBN_WARN("[oss-av] LOGIN ACK timeout or short read (n=%zd)", n);
        return AV_ER_TIMEOUT;
    }

    if (!is_av_frame_header(ack_buf)) {
        OBN_ERROR("[oss-av] LOGIN ACK: bad magic in reply");
        return AV_ER_SESSION_CLOSE_BY_REMOTE;
    }

    auto* ack = reinterpret_cast<const AvFrameHeader*>(ack_buf);
    uint32_t ack_magic = le32toh(ack->magic);
    uint8_t  ack_sub   = (ack_magic >> 16) & 0xff;
    if (ack_sub != kFrameSubtypeLogin) {
        OBN_WARN("[oss-av] LOGIN ACK: unexpected sub-type 0x%02x", ack_sub);
        return AV_ER_SESSION_CLOSE_BY_REMOTE;
    }

    uint32_t ack_payload_len = le32toh(ack->payload_len);
    if (ack_payload_len >= 4 && n >= (ssize_t)(sizeof(AvFrameHeader) + 4)) {
        uint32_t result;
        memcpy(&result, ack_buf + sizeof(AvFrameHeader), 4);
        result = le32toh(result);
        if (result != 0) {
            OBN_ERROR("[oss-av] LOGIN rejected by printer: result=0x%x", result);
            return AV_ER_WRONG_VIEWACCorPWD;
        }
    }

    OBN_DEBUG("[oss-av] LOGIN accepted by printer (av_index=%d)", av_index);
    return 0;
}

// ==========================================================================
// avClientStop (0x15f7f0)
// ==========================================================================
//
// Real binary: kalayav_interface_list lookup → vtable[0x10] = _avStop
//   (acquires avConnectionLock, sends CTRL stop frame, wakes read thread).

extern "C" void avClientStop(int av_index)
{
    if (av_index < 0 || av_index >= kMaxAvChannels) return;
    AvChannel& ch = g_av_channels[av_index];
    if (!ch.active) return;

    OBN_DEBUG("[oss-av] avClientStop: av_index=%d", av_index);
    ch.active = false;
    // Do NOT close the socket — OssSession may still need it for keepalives.
}

// ==========================================================================
// avSendIOCtrl — send an IOCtrl message
// ==========================================================================
//
// In the binary (0x15e330):
//   - Validates len >= 0 (returns AV_ER_INVALID_SID = -0x3ea if len < 0)
//   - Looks up av_index → avObj
//   - Calls avObj->vtable[0x40](avObj, type, buf, len) = _avSendIO
//   - _avSendIO checks avObj->field_0x1f84:
//     - if == 1: calls avSendIOCtrlFrame(avObj, type, buf, len, flags=0x70)
//     - else:    calls _avSendIOCtrl_Old(avObj, type, buf, len)
//
// avSendIOCtrlFrame (PLT at 0x1311d0) takes:
//   rdi = avObj, rsi = type, rdx = buf, rcx = len, r8d = 0x70 (flags)
//
// The IOCtrl packet for IPCAM_START (type=0xFF01, buf=NULL, len=0):
//
//   Wire format (from avSendIOCtrlFrame → _avSendIOCtrl_Old analysis and
//   comparison with TUTK IOCtrl documentation):
//
//   16-byte AvFrameHeader (sub=CTRL=0x02, dir=C→P):
//     payload_len = 8  (4 bytes type + 4 bytes data_len)
//     magic       = 0x0002013f
//     sequence    = tx_seq++
//     reserved    = 0
//
//   IOCtrl body (8 bytes):
//     [0..3] ioctrl_type  (uint32_t LE, e.g. 0x0000FF01)
//     [4..7] data_len     (uint32_t LE, 0 for IPCAM_START)
//
//   [8 .. 8+data_len-1]  optional data bytes (absent for IPCAM_START)
//
// This matches the "TUTK IOCtrl" format documented in the TUTK AV API guide.

extern "C" int avSendIOCtrl(int av_index, unsigned int type,
                             char* buf, int len)
{
    if (len < 0) return AV_ER_INVALID_SID;
    if (av_index < 0 || av_index >= kMaxAvChannels) return AV_ER_INVALID_SID;
    AvChannel& ch = g_av_channels[av_index];
    if (!ch.active || ch.sock_fd == obn::net::kInvalid) return AV_ER_INVALID_SID;

    uint32_t body_len  = 8 + (uint32_t)len;
    uint32_t frame_len = (uint32_t)sizeof(AvFrameHeader) + body_len;

    std::vector<uint8_t> pkt(frame_len, 0);
    auto* hdr = reinterpret_cast<AvFrameHeader*>(pkt.data());

    fill_av_header(hdr, kFrameSubtypeCtrl, kFrameDirClientToP,
                   body_len, ch.tx_seq++);

    uint8_t* body = pkt.data() + sizeof(AvFrameHeader);
    uint32_t ioctrl_type = htole32(type);
    uint32_t data_len    = htole32((uint32_t)len);
    memcpy(body + 0, &ioctrl_type, 4);
    memcpy(body + 4, &data_len,    4);
    if (len > 0 && buf)
        memcpy(body + 8, buf, (size_t)len);

    if (av_channel_write(&ch, pkt.data(), frame_len) < 0) {
        OBN_ERROR("[oss-av] avSendIOCtrl type=0x%x send failed: %s", type, strerror(errno));
        return AV_ER_SESSION_CLOSE_BY_REMOTE;
    }

    OBN_DEBUG("[oss-av] avSendIOCtrl type=0x%04x len=%d sent", type, len);
    return 0;
}

// ==========================================================================
// avRecvFrameData2 — receive one H.264 frame
// ==========================================================================
//
// Signature:
//   int avRecvFrameData2(int     av_index,
//                        char*   video_buf,
//                        int     buf_size,       // r13d
//                        int*    actual,          // rcx
//                        int*    frame_count,     // [rsp+0x88] = r14
//                        char*   ioctrl_buf,      // r8 = rbp
//                        int     ioctrl_size,     // r9 (stack arg)
//                        unsigned int* timestamp, // [rsp+0x90]
//                        int*    ioctrl_count);   // [rsp+0x88] → confusing;
//                                                 // see note below
//
// NOTE: The avRecvFrameData2 signature in the public TUTK AV API is:
//   int avRecvFrameData2(int AV_index,
//                        unsigned char *abFrameData,
//                        int nMaxBufSize,
//                        int *pnActualFrameSize,
//                        int *pnExpectedFrameSize,    <- "frame_count" slot
//                        char *pIoctrlBuf,
//                        int nMaxIoctrlBufSize,
//                        unsigned int *pnIOCtrlDataSize, <- "ioctrl_count"
//                        unsigned int *pnFrameIdx);   <- "timestamp" slot
//
// In the binary at 0x15f9c0, the vtable call at 0x15fa78 dispatches to
// _avRecvData with the args rearranged on the stack.  The 0x10 stored at
// 0x20(%rsp) before the call is the size of an output descriptor struct
// (16 bytes = sizeof(AvFrameHeader)).
//
// Our implementation:
//   1. Reads one UDP datagram (one TUTK AV packet)
//   2. Validates the 16-byte AvFrameHeader
//   3. If it is a video frame (sub != CTRL): copies payload to video_buf
//   4. If it is an IOCtrl frame: copies payload to ioctrl_buf
//   5. Fills output parameters

extern "C" int avRecvFrameData2(int av_index,
                                 char* video_buf,
                                 int buf_size,
                                 int* actual,
                                 int* frame_count,
                                 char* ioctrl_buf,
                                 int ioctrl_size,
                                 unsigned int* timestamp,
                                 int* ioctrl_count)
{
    if (actual)       *actual       = 0;
    if (frame_count)  *frame_count  = 0;
    if (timestamp)    *timestamp    = 0;
    if (ioctrl_count) *ioctrl_count = 0;

    if (av_index < 0 || av_index >= kMaxAvChannels) return AV_ER_INVALID_SID;
    AvChannel& ch = g_av_channels[av_index];
    if (!ch.active || ch.sock_fd == obn::net::kInvalid) return AV_ER_INVALID_SID;

    const int kRecvTimeoutMs = 1000;
    set_recv_timeout(ch.sock_fd, kRecvTimeoutMs);

    static constexpr size_t kRawBufSize = (1u << 20) + 64;  // IOTC hdr + DTLS record + tag
    static constexpr size_t kPktBufSize = 1u << 20;
    std::vector<uint8_t> raw_buf(kRawBufSize);
    std::vector<uint8_t> pkt_buf(kPktBufSize);

    const uint8_t* frame_data = nullptr;
    size_t         frame_len  = 0;

    static constexpr int kMaxRetries = 32;
    for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
        ssize_t n = recv(ch.sock_fd, raw_buf.data(), raw_buf.size(), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT)
                return AV_ER_TIMEOUT;
            return AV_ER_SESSION_CLOSE_BY_REMOTE;
        }

        if (ch.use_dtls && ch.dtls_sess) {
            // Decrypt DTLS ApplicationData record
            int pn = dtls_decrypt_one(ch.dtls_sess,
                                       raw_buf.data(), (size_t)n,
                                       pkt_buf.data(), pkt_buf.size());
            if (pn == 0) continue;  // non-AppData (keepalive etc.) or AEAD failure
            if (pn < 0) continue;
            frame_data = pkt_buf.data();
            frame_len  = (size_t)pn;
        } else {
            if ((size_t)n < sizeof(AvFrameHeader)) continue;
            frame_data = raw_buf.data();
            frame_len  = (size_t)n;
        }

        if (frame_len >= sizeof(AvFrameHeader) && is_av_frame_header(frame_data))
            break;  // got a valid AV frame

        frame_data = nullptr;  // TUTK keepalive or control packet — skip
    }

    if (!frame_data) return AV_ER_TIMEOUT;

    const auto* hdr = reinterpret_cast<const AvFrameHeader*>(frame_data);
    uint32_t magic       = le32toh(hdr->magic);
    uint32_t payload_len = le32toh(hdr->payload_len);
    uint32_t seq         = le32toh(hdr->sequence);
    uint8_t  sub_type    = (magic >> 16) & 0xff;

    if (payload_len > (uint32_t)(frame_len - sizeof(AvFrameHeader)))
        return AV_ER_INCOMPLETE_FRAME;

    const uint8_t* payload = frame_data + sizeof(AvFrameHeader);

    if (sub_type == kFrameSubtypeCtrl) {
        // IOCtrl body: [0..3] type LE, [4..7] data_len LE, [8..] data
        if (payload_len >= 8 && ioctrl_buf && ioctrl_size > 0) {
            uint32_t data_len;
            memcpy(&data_len, payload + 4, 4);
            data_len = le32toh(data_len);

            int copy_len = (int)std::min((uint32_t)ioctrl_size, data_len);
            if (copy_len > 0 && payload_len >= 8 + data_len)
                memcpy(ioctrl_buf, payload + 8, (size_t)copy_len);
            if (ioctrl_count) *ioctrl_count = copy_len;
        }
        return 0;
    }

    if (!video_buf || buf_size <= 0) return AV_ER_EXCEED_MAX_SIZE;

    int copy_len = (int)std::min((uint32_t)buf_size, payload_len);
    memcpy(video_buf, payload, (size_t)copy_len);

    if (actual)      *actual      = copy_len;
    if (frame_count) *frame_count = (int)payload_len; // expected = total available
    if (timestamp)   *timestamp   = seq;  // sequence used as timestamp proxy

    if ((uint32_t)buf_size < payload_len)
        return AV_ER_INCOMPLETE_FRAME;  // buffer too small for full frame

    return copy_len;
}

// oss_av_attach → oss_av_login → IPCAM_START in one call.
int oss_av_start(OssSession* sess, int channel,
                 const char* account, const char* password)
{
    if (!sess || sess->state != P2PState::CONNECTED) return -1;

    AvStartIn  start_in{};
    AvStartOut start_out{};
    start_in.struct_size = sizeof(AvStartIn);
    start_in.sid         = 0;  // N/A in OSS path
    start_in.channel     = (uint8_t)(channel & 0x1f);
    start_in.timeout_sec = 30;
    start_in.account     = account;
    start_in.passwd      = password;
    start_out.struct_size = sizeof(AvStartOut);

    int idx = avClientStartEx(&start_in, &start_out);
    if (idx < 0) {
        OBN_ERROR("[oss-av] avClientStartEx failed: %d", idx);
        return idx;
    }

    oss_av_attach(idx, sess->udp_sock, &sess->device_wan,
                  &sess->dtls, sess->session_token);

    int rc = oss_av_login(idx, account, password, /*timeout_ms=*/5000);
    if (rc < 0) {
        avClientStop(idx);
        return rc;
    }

    rc = avSendIOCtrl(idx, IOTYPE_USER_IPCAM_START, nullptr, 0);
    if (rc < 0) {
        OBN_ERROR("[oss-av] IPCAM_START failed: %d", rc);
        avClientStop(idx);
        return rc;
    }

    OBN_DEBUG("[oss-av] stream started on av_index=%d", idx);
    return idx;
}

// ==========================================================================
// IOTC global state — session table and initialization
// ==========================================================================
//
// The real TUTK library keeps these as process globals.  In our open
// reimplementation we keep them in the oss_tutk namespace as statics.
//
// Session table layout:
//   gSessionInfo[] — malloc'd array of max_sessions × 0x16c0 bytes
//   Each slot's "state" byte is at slot[0x19]:
//     0 = free, 1 = busy/connected, 2 = relay, 3 = connecting, 4 = other
//   gbFlagInitialized:
//     0 = never initialized, 1 = in progress, 2 = initialized (success)
//
// IOTC_Initialize2 also allocates:
//   gPreSessionInfo[] — max_sessions × 0x60 bytes (pre-session scratch area)
//
// Mutex initialization: uses pthread_mutexattr_settype(PTHREAD_MUTEX_RECURSIVE)
// (type=1) for the 10+ internal mutexes.  We replicate this for correctness.

static constexpr uint8_t kSessionStateFree       = 0;
static constexpr uint8_t kSessionStateBusy       = 1;   // connected
[[maybe_unused]] static constexpr uint8_t kSessionStateRelay = 2;
static constexpr uint8_t kSessionStateConnecting = 3;

// Offset within each 0x16c0-byte slot where the "state" byte lives.
// IOTC_Get_SessionID tests cmpb $0x0, slot+0x19 (= byte 25).
static constexpr size_t  kSessionStateOff = 0x19;

// Offset within each slot where our OssSession* pointer is stored.
// We use an otherwise-unused region well away from the TUTK-reserved area.
// The TUTK slot is 0x16c0 bytes; we stash our pointer at offset 0x1640.
static constexpr size_t  kSessionPtrOff   = 0x1640;

struct IotcGlobals {
    uint8_t*           session_table   = nullptr;  // gSessionInfo (max_sess × 0x16c0)
    uint8_t*           pre_session_tbl = nullptr;  // gPreSessionInfo (max_sess × 0x60)
    unsigned int       max_sessions    = 0;
    int                flag_initialized= 0;        // gbFlagInitialized: 0/1/2
    std::recursive_mutex table_mutex;
};

static IotcGlobals g_iotc;

// Region table (gRegionName, index 1..4 are valid; index 0 = "reserved" / invalid).
// Validates (index-1) <= 3 before use.
static const char* const kRegionNames[5] = {
    "reserved",   // 0 — invalid
    "cn",         // 1
    "eu",         // 2
    "us",         // 3
    "asia",       // 4
};

// Port table for gTcpTryPort — IOTC_TcpConnectToMasterTryPort cycles through these, tries 12 server addresses,
// port index = (attempt mod 5).  The code byte-swaps via rol $0x8.
static const uint16_t kTcpTryPorts[] = {
    80, 443, 21047, 8080, 8000, 20297, 17236, /* 0 skipped */ 8686
};
[[maybe_unused]] static constexpr size_t kNumTcpPorts = sizeof(kTcpTryPorts) / sizeof(kTcpTryPorts[0]);

static uint8_t* session_slot(int sid)
{
    if (sid < 0 || (unsigned)sid >= g_iotc.max_sessions) return nullptr;
    return g_iotc.session_table + (size_t)sid * kSessionInfoStride;
}

static uint8_t session_state(int sid)
{
    uint8_t* slot = session_slot(sid);
    if (!slot) return 0xff;
    return slot[kSessionStateOff];
}

static void session_set_ptr(int sid, OssSession* ptr)
{
    uint8_t* slot = session_slot(sid);
    if (!slot) return;
    // NOLINTNEXTLINE(bugprone-sizeof-expression)
    memcpy(slot + kSessionPtrOff, &ptr, sizeof(ptr));
}

static OssSession* session_get_ptr(int sid)
{
    uint8_t* slot = session_slot(sid);
    if (!slot) return nullptr;
    OssSession* ptr = nullptr;
    // NOLINTNEXTLINE(bugprone-sizeof-expression)
    memcpy(&ptr, slot + kSessionPtrOff, sizeof(ptr));
    return ptr;
}

// ==========================================================================
// IOTC_Initialize2 — allocate session table, initialize state, start threads
// ==========================================================================
//
//   - Checks gbFlagInitialized; if already 2, returns IOTC_ER_ALREADY_INITIALIZED
//   - Sets gbFlagInitialized = 1 (in-progress)
//   - malloc(max_sessions * 0x16c0) → gSessionInfo
//   - malloc(max_sessions * 0x60)   → gPreSessionInfo
//   - Initializes mutexes with pthread_mutexattr_settype type=RECURSIVE (1)
//   - Calls TConnManager_create (creates the connection manager vtable object)
//   - Calls tutk_TaskMng_Create / tutk_TaskMng_Init (not raw pthreads)
//   - Calls IOTC_sCHL_initialize for DTLS/crypto channel init
//   - Sets gbFlagInitialized = 2 on success
//   - Returns 0 on success; negative IOTC error code on failure

extern "C" int IOTC_Initialize2(unsigned int max_sessions)
{
    if (g_iotc.flag_initialized == 2)
        return IOTC_ER_ALREADY_INITIALIZED;

    if (max_sessions == 0) max_sessions = 1;

    g_iotc.flag_initialized = 1;

    g_iotc.session_table = static_cast<uint8_t*>(
        calloc(max_sessions, kSessionInfoStride));
    if (!g_iotc.session_table) {
        g_iotc.flag_initialized = 0;
        return IOTC_ER_NOT_INITIALIZED;
    }

    g_iotc.pre_session_tbl = static_cast<uint8_t*>(  // pre-session scratch: max_sessions × 0x60
        calloc(max_sessions, 0x60));
    if (!g_iotc.pre_session_tbl) {
        free(g_iotc.session_table);
        g_iotc.session_table    = nullptr;
        g_iotc.flag_initialized = 0;
        return IOTC_ER_NOT_INITIALIZED;
    }

    g_iotc.max_sessions = max_sessions;

    for (unsigned int i = 0; i < max_sessions; ++i) {
        uint8_t* slot = g_iotc.session_table + i * kSessionInfoStride;
        slot[kSessionStateOff] = kSessionStateFree;
    }

    av_channels_init();

    g_iotc.flag_initialized = 2;

    OBN_DEBUG("[oss-iotc] IOTC_Initialize2: max_sessions=%u, session_table=%p", max_sessions, (void*)g_iotc.session_table);
    return 0;
}

// ==========================================================================
// TUTK_SDK_Set_Region — select geographic master server region
// ==========================================================================
//
//   - Validates: (region - 1) <= 3  →  only indices 1..4 are valid
//     (index 0 = "reserved" in gRegionName; the binary does sub $1, test <=3)
//   - Looks up gRegionName[region] to get region string ("cn"/"eu"/"us"/"asia")
//   - Calls SetMasterRegion(region_string) which calls CreateDomainName with
//     gHostName entries to build the final FQDN
//   - gIsKeySet must be true for GetMasterDomainName to succeed; without a
//     valid license key the domain cannot be resolved (returns IOTC_ER_NOT_LICENSE)
//
// We skip the license-key check and store the region for use in master_hostname().

static TutkRegion g_region = TutkRegion::Global;

extern "C" void oss_iotc_set_dtls_creds(const char* /*passwd*/, const char* /*account*/)
{
    // Credentials are now taken from function parameters; globals were removed.
}

extern "C" int TUTK_SDK_Set_Region(int region)
{
    if (region < 1 || region > 4) {  // binary checks (region-1) unsigned <= 3
        OBN_ERROR("[oss-iotc] TUTK_SDK_Set_Region: invalid region %d (must be 1=cn, 2=eu, 3=us, 4=asia)", region);
        return -1;
    }

    g_region = static_cast<TutkRegion>(region);
    OBN_DEBUG("[oss-iotc] TUTK_SDK_Set_Region: region=%d (%s), master will be %s", region, kRegionNames[region], master_hostname(g_region).c_str());
    return 0;
}

// ==========================================================================
// IOTC_Get_SessionID — allocate a free session slot
// ==========================================================================
//
//   - Checks gbFlagInitialized == 2 (returns IOTC_ER_NOT_INITIALIZED if not)
//   - Acquires session table mutex
//   - Scans gSessionInfo[] for first slot where state_byte (slot[0x19]) == 0
//   - Sets that slot's state to 1 (busy/reserved) atomically
//   - Returns the slot index (0-based) as the session ID
//   - Returns IOTC_ER_EXCEED_MAX_SESSION if no free slot found

extern "C" int IOTC_Get_SessionID()
{
    if (g_iotc.flag_initialized != 2)
        return IOTC_ER_NOT_INITIALIZED;

    g_iotc.table_mutex.lock();
    int found = -1;
    for (unsigned int i = 0; i < g_iotc.max_sessions; ++i) {
        uint8_t* slot = g_iotc.session_table + i * kSessionInfoStride;
        if (slot[kSessionStateOff] == kSessionStateFree) {
            slot[kSessionStateOff] = kSessionStateConnecting;  // reserve while holding mutex
            found = (int)i;
            break;
        }
    }
    g_iotc.table_mutex.unlock();

    if (found < 0) {
        OBN_WARN("[oss-iotc] IOTC_Get_SessionID: no free session slots");
        return IOTC_ER_EXCEED_MAX_SESSION;
    }

    OBN_DEBUG("[oss-iotc] IOTC_Get_SessionID: allocated sid=%d", found);
    return found;
}

// ==========================================================================
// IOTC_Connect_ByUIDEx — full P2P connect to a device UID
// ==========================================================================
//
//   1a8e19: test %rdx, %rdx      — cfg must not be NULL
//   1a8e22: cmpl $0x14, (%rdx)   — cfg->struct_size must == 0x14 = 20
//   1a8e28: jne 0x1a8f40         — error if not
//   Then checks (in order):
//     - gbFlagInitialized == 2       → IOTC_ER_NOT_INITIALIZED
//     - sid within [0, max_sessions) → IOTC_ER_INVALID_SID
//     - uid not NULL                 → IOTC_ER_INVALID_ARG
//     - uid_valid(uid)               → IOTC_ER_INVALID_ARG
//     - cfg->field[4] == 0 ?         → (auth mode check)
//     - authkey field check          → (authkey validation)
//   Then calls IOTC_Connect_UDP_Inner @ 0x1a81b0 which:
//     - Copies uid to session slot (lowercased), stores authkey
//     - Opens UDP P2P socket
//     - Runs LAN search (AddLanSearchTask)
//     - Queries master (AddMasterQueryTask)
//     - Runs NAT traversal state machine
//     - Returns 0 on P2P success, negative on error

extern "C" int IOTC_Connect_ByUIDEx(const char* uid, int sid, void* cfg_v)
{
    if (!cfg_v) return IOTC_ER_INVALID_SID;
    const auto* cfg = static_cast<const IotcConnectCfg*>(cfg_v);
    if (cfg->struct_size != 0x14) return IOTC_ER_INVALID_SID;
    if (g_iotc.flag_initialized != 2) return IOTC_ER_NOT_INITIALIZED;
    if (sid < 0 || (unsigned)sid >= g_iotc.max_sessions) return IOTC_ER_INVALID_SID;
    if (!uid) return IOTC_ER_INVALID_SID;
    std::string uid_str(uid);
    if (!uid_valid(uid_str)) {
        OBN_ERROR("[oss-iotc] IOTC_Connect_ByUIDEx: invalid UID '%s'", uid);
        return IOTC_ER_INVALID_SID;
    }

    uint64_t authkey = (uint64_t)cfg->authkey_lo | ((uint64_t)cfg->authkey_hi << 32);
    {
        g_iotc.table_mutex.lock();
        uint8_t* slot = session_slot(sid);
        if (!slot) {
            g_iotc.table_mutex.unlock();
            return IOTC_ER_INVALID_SID;
        }
        slot[kSessionStateOff] = kSessionStateConnecting;
        g_iotc.table_mutex.unlock();
    }

    OBN_DEBUG("[oss-iotc] IOTC_Connect_ByUIDEx: uid='%s' sid=%d authkey=0x%016llx timeout=%us", uid, sid, (unsigned long long)authkey, cfg->timeout1_sec);

    OssSession* sess = iotc_connect(uid_str, authkey, "888888", g_region);

    if (!sess) {
        g_iotc.table_mutex.lock();
        uint8_t* slot = session_slot(sid);
        if (slot) slot[kSessionStateOff] = kSessionStateFree;
        g_iotc.table_mutex.unlock();
        OBN_ERROR("[oss-iotc] IOTC_Connect_ByUIDEx: connect failed");
        return IOTC_ER_NOT_INITIALIZED;  // generic connect failure
    }

    g_iotc.table_mutex.lock();
    uint8_t* slot = session_slot(sid);
    if (slot) {
        slot[kSessionStateOff] = kSessionStateBusy;
        session_set_ptr(sid, sess);
    }
    g_iotc.table_mutex.unlock();

    OBN_DEBUG("[oss-iotc] IOTC_Connect_ByUIDEx: connected, sid=%d", sid);
    return sid;
}

// Returns 0 (P2P path) if connected, negative error if not.
// Real binary returns the send-path type; we collapse to connected/not.
extern "C" int IOTC_Session_Check_Ex(int sid)
{
    if (g_iotc.flag_initialized != 2) return IOTC_ER_NOT_INITIALIZED;
    if (sid < 0 || (unsigned)sid >= g_iotc.max_sessions) return IOTC_ER_INVALID_SID;

    uint8_t state = session_state(sid);
    if (state == kSessionStateFree) return IOTC_ER_INVALID_SID;

    OssSession* sess = session_get_ptr(sid);
    if (!sess) return IOTC_ER_INVALID_SID;

    if (sess->state == P2PState::CONNECTED)
        return 0;  // 0 = P2P, 1 = relay (TUTK convention)

    return IOTC_ER_INVALID_SID;
}

// ==========================================================================
// IOTC_Session_Close — tear down a session and release its slot
// ==========================================================================
//
//   - Validates sid and state byte
//   - If state == kSessionStateRelay:
//       sends MSG_RLY_ALIVE_S2C close notification to relay server
//   - Sets session state = free  (slot[0x19] = 0)
//   - Calls AV layer callback teardown
//   - Releases all AV channels attached to this session
//   - Closes UDP socket
//   - Zeroes the slot (memset)
//
extern "C" void IOTC_Session_Close(int sid)
{
    if (g_iotc.flag_initialized != 2) return;
    if (sid < 0 || (unsigned)sid >= g_iotc.max_sessions) return;

    OssSession* sess = nullptr;

    g_iotc.table_mutex.lock();
    uint8_t* slot = session_slot(sid);
    if (slot && slot[kSessionStateOff] != kSessionStateFree) {
        sess = session_get_ptr(sid);
        memset(slot, 0, kSessionInfoStride);  // zeroes state byte → kSessionStateFree
    }
    g_iotc.table_mutex.unlock();

    if (!sess) {
        OBN_WARN("[oss-iotc] IOTC_Session_Close: sid=%d not active", sid);
        return;
    }

    for (int i = 0; i < kMaxAvChannels; ++i) {
        AvChannel& ch = g_av_channels[i];
        if (ch.active && ch.sock_fd == sess->udp_sock) {
            ch.active = false;
        }
    }

    iotc_close(sess);

    OBN_DEBUG("[oss-iotc] IOTC_Session_Close: sid=%d closed", sid);
}

} // namespace oss_tutk
} // namespace bambu_net
