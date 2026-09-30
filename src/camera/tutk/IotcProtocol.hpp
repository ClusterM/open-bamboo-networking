// Client side of the ThroughTek (TUTK) IOTC transport used by Bambu printers
// for the bambu:///tutk camera stream, as observed on the wire.
//
// Every datagram starts with a 16-byte IOTC header (04 02 1c <flags>, LE
// payload length, datagram counter, 3-byte message type) and is obfuscated
// with TransCodePartial: control datagrams entirely, datagrams carrying DTLS
// only in their first 64 bytes.
//
// A session is set up in one of two ways:
//   - LAN: broadcast a 01 06 21 search to UDP 32761; the printer answers
//     02 06 12 from its P2P port and the session runs directly against it;
//   - relay: JOIN the regional master, rendezvous through the :3478 servers
//     and either reach the printer directly or go through the relay.
// On top of it runs DTLS 1.2 with ECDHE-PSK (identity "AUTHPWD_admin"), and
// inside DTLS the TUTK AV protocol (login, IOCtrl, video slices).

#pragma once

#include "obn/net_compat.hpp"
#include <cstddef>
#include <cstdint>
#include <functional>

namespace obn {
namespace camera {
namespace tutk {

// Device UIDs are exactly 20 printable ASCII characters, sent uppercase.
static constexpr size_t kUidLen = 20;

// AV IOCtrl types that start and stop the camera stream on a channel.
static constexpr uint32_t kIoTypeIpcamStart = 0x01ff;
static constexpr uint32_t kIoTypeIpcamStop  = 0x02ff;
// PrinterFileSystem JSON (Studio's CTRL_TYPE) carried as an IOCtrl.
static constexpr uint32_t kIoTypeCtrl       = 0x3001;

struct DtlsSession {
    uint8_t  client_random[32];
    uint8_t  server_random[32];
    uint8_t  master_secret[48];
    uint8_t  client_write_key[32];
    uint8_t  server_write_key[32];
    uint8_t  client_write_iv[16];
    uint8_t  server_write_iv[16];
    uint8_t  client_write_mac_key[48];
    uint8_t  server_write_mac_key[48];
    uint16_t cipher_suite;         // 0xC038 or 0xCCAC
    bool     use_ems;              // RFC 7627 Extended Master Secret
    bool     use_etm;              // RFC 7366 Encrypt-then-MAC
    uint32_t epoch;
    uint64_t tx_seq;
    uint64_t rx_seq;
    bool     handshake_complete;
    uint32_t relay_tag;            // tag from 03 03 43 (if relayed)
    uint16_t pkt_seq;              // next IOTC datagram counter (header [6..7])
};

// One IOTC session. Plain data: zero-initialise it and release it with
// iotc_close().
struct IotcConn {
    int                sock;              // UDP socket (-1 = closed)
    struct sockaddr_in peer;              // printer or relay server
    uint8_t            session_token[8];  // random, chosen by the client
    DtlsSession        dtls;              // filled by iotc_dtls_handshake()
    uint32_t           relay_tag;
    bool               is_relay;
    char               uid_upper[32];
    uint8_t            relay_cookie[8];   // from the relay ping (23 05 42)
    bool               have_relay_cookie;
    bool               is_lan;            // found by iotc_lan_connect()
    int64_t            last_alive_ms;     // steady-clock ms of the last 27 04 21
};

// Polled while connecting; returning true abandons the attempt (-1).
using IotcCancel = std::function<bool()>;

// Find the printer on the local network by LAN search and prepare a direct
// session to the address it answers from. timeout_ms bounds the search.
// Returns 0 on success, -1 when no printer with this UID answered.
int iotc_lan_connect(const char* uid_upper, const char* authkey, int timeout_ms,
                     IotcConn* out, const IotcCancel& cancelled = {});

// JOIN the master for region_str ("cn", "eu", "us"), rendezvous with the
// printer and adopt its P2P address; if the printer is off-LAN, punch through
// with authkey or fall back to the relay. relay_id is the relay subdomain
// (its first 16 characters are used). Returns 0 on success, -1 on failure.
int iotc_relay_connect(const char* uid_upper, const char* relay_id,
                       const char* region_str, const char* authkey,
                       IotcConn* out, const IotcCancel& cancelled = {});

// DTLS-PSK handshake. The PSK is derived from passwd (the URL's "passwd"
// value); account is the identity suffix ("admin"). Returns 0 on success.
int iotc_dtls_handshake(IotcConn* c, const char* passwd, const char* account);

// Encrypt and send one DTLS ApplicationData record. Returns 0 on success.
int iotc_send_app_data(IotcConn* c, const uint8_t* data, size_t len);

// Receive and decrypt one DTLS ApplicationData record, answering transport
// keepalives on the way. Returns the plaintext length, 0 on timeout, or a
// negative value when the session is gone.
int iotc_recv_app_data(IotcConn* c, uint8_t* out, size_t out_size, int timeout_ms);

// Say goodbye to the peer, close the socket and zero the struct.
void iotc_close(IotcConn* c);

#ifdef OBN_TESTING
void trans_code_partial_test(uint8_t* data, size_t len);
void reverse_trans_code_partial_test(uint8_t* data, size_t len);
void build_relay_nonce_test(uint8_t nonce[12], const uint8_t iv[12],
                            uint32_t epoch, uint64_t seq);
#endif

} // namespace tutk
} // namespace camera
} // namespace obn
