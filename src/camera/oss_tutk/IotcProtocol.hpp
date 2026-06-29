//
// IotcProtocol.hpp — TUTK IOTC P2P protocol wire-format documentation.
//
// ==========================================================================
// EXECUTIVE SUMMARY — How the P2P connection works
// ==========================================================================
//
// The TUTK IOTC protocol is a proprietary P2P networking stack by TUTK
// Technology (Kalay platform, iotcplatform.com / kalayservice.com /
// kalay.net.cn).  The Bambu printer acts as a TUTK "device"; the PC
// client is a TUTK "client".
//
// Connection phases:
//
//   1. INITIALIZATION
//      IOTC_Initialize2() starts internal threads including a UDP receive
//      loop (_IOTC_thread_UDPrecv) and connects to the TUTK master server
//      cluster via TCP (IOTC_TcpConnectToMaster / IOTC_TcpConnectToMasterNB).
//
//      The master server hostname is dynamically resolved:
//        <region>.<prefix>.iotcplatform.com   (primary)
//        <region>.<prefix>.kalayservice.com   (secondary)
//        <region>.<prefix>.kalay.net.cn       (China)
//
//      Region strings (from gRegionName, TUTK_SDK_Set_Region argument):
//        0 = "Global"
//        1 = "cn"
//        2 = "eu"
//        3 = "us"
//        4 = "asia"
//      Encoded as: "c-master" and "p2pod-master" domain prefixes are used;
//      the actual full pattern is "<region>.c-master.iotcplatform.com".
//      Bambu sets region via TUTK_SDK_Set_Region(region_code) where region
//      code maps from the printer URL parameter "region=cn/us/eu/asia/all".
//
//   2. SESSION ALLOCATION
//      IOTC_Get_SessionID() allocates an unused session slot from an internal
//      table (gSessionInfo[], 5824 bytes each, max sessions = gSessionNum).
//      Returns a non-negative integer session-ID (SID) on success.
//
//   3. P2P DISCOVERY  (IOTC_Connect_ByUIDEx → IOTC_Connect_UDP_Inner)
//
//      a) LAN SEARCH
//         The client broadcasts a MSG_LAN_SEARCH3 UDP packet on the local
//         broadcast address to discover if the printer is on the same LAN.
//         The printer replies with MSG_LAN_SEARCH_R_3.
//         The search packet carries: UID (20 bytes), IOTCVersion, ClientRandomID.
//         UID validation: exactly 20 printable ASCII characters.
//         The UID stored internally is lower-cased (loop at 0x1a82a0 maps
//         chars > 'Z' to lowercase).
//
//      b) MASTER SERVER REGISTRATION / RELAY REQUEST
//         If LAN search fails, the client sends MSG_RLY_REQUEST (variants:
//         MSG_RLY_REQUEST3, MSG_RLY_REQUEST4) to the master server via the
//         pre-established TCP connection.  The request contains:
//           UID, ClientRandomID, timeout, target address.
//         The server returns MSG_RLY_REQUEST_R2 with the device's address if
//         it is online.
//
//      c) UDP PRECHECK / NAT PUNCH-THROUGH
//         If the device is behind NAT, the client follows the TUTK NAT
//         traversal procedure:
//           - Send MSG_P2P_PRECHECK1 to the device's reported WAN:port
//           - Device replies MSG_P2P_PRECHECK1_R
//           - Client sends MSG_P2P_PRECHECK2 (with auth key)
//           - Client sends MSG_P2P_REQUEST to the device
//           - Both sides exchange MSG_P2P_KNOCK / MSG_P2P_KNOCK_R /
//             MSG_P2P_KNOCK_RR to punch holes
//           - Client sends MSG_P2P_PUNCH_TO  →  MSG_P2P_ALIVE_C2D
//           - Session established; keepalives via MSG_P2P_ALIVE_C2D /
//             MSG_P2P_ALIVE_D2C
//
//      d) TCP RELAY FALLBACK
//         If UDP P2P fails, TUTK falls back to relay via the master server
//         (MSG_RLY_KNOCK, MSG_RLY_KNOCK_R, MSG_RLY_SESSION_INFO).
//         The relay server address is stored in gRelayTcpAddr / gRelayTcpPort.
//         TCP relay mode flag: gbTcpRelayMode.
//
//      e) "TRY PORT" (NAT type 5 — Symmetric NAT)
//         If NAT type is 5 (symmetric), the client tries connecting to
//         a range of ports at the device's WAN IP:
//           AddUDPP2PConnectTask / IOTC_TryPortAddNode / etc.
//
//   4. AV CHANNEL SETUP
//      avClientStartEx(AvStartIn*, AvStartOut*) opens an AV data channel
//      over the established IOTC session.
//
//   5. STREAM START
//      avSendIOCtrl(av_index, 0xFF01, NULL, 0) sends IOTYPE_USER_IPCAM_START
//      which triggers the printer to begin sending H.264 video frames.
//
//   6. FRAME RECEIVE
//      avRecvFrameData2() returns one frame at a time; the AV layer
//      reassembles TUTK packets (with FEC/resend) into complete frames.
//
// ==========================================================================
// SDK VERSION
// ==========================================================================
//
// TUTK_Get_Version_String() returns: "4.3.3.4-0-gf6d6219_openssl_x64"
// This identifies the TUTK IOTC SDK version.
//
// ==========================================================================

#pragma once

#include "obn/net_compat.hpp"
#include <cstdint>
#include <cstring>

namespace bambu_net {
namespace oss_tutk {

// --------------------------------------------------------------------------
// IOTC session limits
// --------------------------------------------------------------------------

// Size of each gSessionInfo[] slot (imul $0x16c0 in IOTC_Connect_UDP_Inner)
static constexpr size_t kSessionInfoStride = 0x16c0; // 5824 bytes

// Default connect timeout used by IOTC_Connect_ByUIDEx config (0x14 = 20s)
static constexpr uint32_t kConnectTimeoutSec = 20;

// --------------------------------------------------------------------------
// UID format
// --------------------------------------------------------------------------
//
// A Bambu printer UID is exactly 20 printable ASCII characters.
// IsUIDVaild() verifies: loop 0x14 iterations, each byte passes ctype
// is-print (bit 0x08 in the ctype table).  Example format: "BBLP01XXXXXXXXXX0001"
// The protocol stores UIDs as lowercase internally (IOTC_Connect_UDP_Inner
// loop at offset +0xf0 maps chars > 0x5A ('Z') to char - 0x20).
//
// UID encoding in LAN search packet: raw ASCII, null-padded to 20 bytes.
//
// Max UID length from gMyUID: 20 bytes (confirmed by the loop bound 0x14).

static constexpr size_t kUidLen = 20;

// --------------------------------------------------------------------------
// Master server addressing
// --------------------------------------------------------------------------
//
// TUTK_SDK_Set_Region(n) calls SetMasterRegion(gRegionName[n]) where:
//   gRegionName[0] = "Global"
//   gRegionName[1] = "cn"
//   gRegionName[2] = "eu"
//   gRegionName[3] = "us"
//   gRegionName[4] = "asia"
//
// SetMasterRegion() builds the master server hostname.
// The master server domain pattern (observed strings):
//   "c-master" prefix — control/login server
//   "p2pod-master"    — P2P rendezvous server
//   Domain suffix:
//     .iotcplatform.com   (global default)
//     .kalayservice.com   (alternate)
//     .kalay.net.cn       (China region)
//
// Full pattern (inferred from "<region>.<prefix>.<suffix>"):
//   e.g. "us.c-master.iotcplatform.com"
//
// The master server TCP port is not directly visible in strings but TUTK
// documentation puts it at port 443 or
// an alternate like 8080 (standard TUTK uses 443 TLS or 8080 plain).

enum class TutkRegion : int {
    Global = 0,
    CN     = 1,
    EU     = 2,
    US     = 3,
    Asia   = 4,
};

struct MasterServerInfo {
    const char* region_name;
    const char* primary;      // e.g. "us-c-master.iotcplatform.com"
    const char* secondary;    // .kalayservice.com variant
    const char* cn;           // .kalay.net.cn variant
    uint16_t    tcp_port;     // typically 443 (TLS) or 8080
};

// --------------------------------------------------------------------------
// Wire-level packet header (LAN search / UDP messages)
// --------------------------------------------------------------------------
//
// Stack layout of the outgoing search-response packet:
//   [0x00] uint16_t  msg_type   = 0x0204  (MSG_LAN_SEARCH_R variant?)
//   [0x02] uint8_t   ??? = 0x1c  (sub-type or version = 28)
//   [0x04] uint64_t  constant = 0x120602000000b8  (magic / version field)
//   [0x0c] uint16_t  ???
//   [0x10] uint32_t  gMyUID_partial  (first 4 bytes of UID extra field)
//   [0x14..0x14+144] char[144+] device_name (gDeviceName, 144 bytes via 9x XMM)
//   [0xb4] uint8_t   gDeviceName[0x80]
//   [0xb8] uint32_t  constant = 0x4030304  (version bytes 3.3.4?)
//   [0xc4] uint32_t  param (from caller r8)
//
// The search packet is 0x204 = 516 bytes total (allocated on stack,
// zeroed with rep stosq).
//
// The TUTK packet header (shared across all UDP messages) appears to be:
//   Bytes 0-1: message_type (uint16_t big-endian, see MessageType enum)
//   Bytes 2-3: sub_type / flags
//   Bytes 4+:  payload (message-type-specific)

#pragma pack(push, 1)

// Common TUTK UDP packet header (all messages start with this).
// Exact endianness is big-endian (network byte order).
struct TutkMsgHdr {
    uint16_t msg_type;    // see TutkMsgType enum
    uint16_t sub_type;    // version/flags field; 0x1c observed for LAN_SEARCH_R
    // ... payload follows
};

// LAN Search broadcast packet (MSG_LAN_SEARCH3, client → broadcast)
// Inferred from _IOTC_Send_Search log string:
//   "_IOTC_Send_Search UID %s ConnectFlag %u IOTCVersion %u ClientRandomID %u"
struct LanSearch3Pkt {
    TutkMsgHdr hdr;
    char       uid[kUidLen];         // target device UID (ASCII, null-padded)
    uint32_t   connect_flag;         // connection flags
    uint32_t   iotc_version;         // client IOTC version
    uint32_t   client_random_id;     // random nonce for this session
    uint32_t   partial_mac_addr;     // partial MAC (for disambiguation)
    // optional: source IP:port appended for NAT reflection
};

// LAN Search Response (MSG_LAN_SEARCH_R_3, device → unicast)
// Reconstructed from _IOTC_Send_Search_R (0x18dc90):
//   Total size = 0x204 = 516 bytes
//   At offset 0x10 = gMyUID partial; offsets 0x34..0xb3 = gDeviceName (144 bytes)
struct LanSearchR3Pkt {
    TutkMsgHdr hdr;                  // [0x00] msg_type=0x0204 approx, sub_type=0x1c
    uint8_t    _pad1[6];
    uint64_t   magic;                // [0x08] 0x120602000000b8 (SDK version magic)
    uint32_t   uid_partial;          // [0x10] first 4 extra bytes of UID info
    uint8_t    _pad2[0x24 - 0x14];  // gap
    char       device_name[144];     // [0x34] gDeviceName (null-terminated)
    uint8_t    device_name_ext;      // [0xb4] gDeviceName[0x80]
    uint32_t   version_bytes;        // [0xb8] e.g. 0x04030304 = v4.3.3.4
    uint8_t    _pad3[0xc4 - 0xbc];
    uint32_t   nat_info;             // [0xc4] NAT type / extra info
    // ... remainder zero-padded to 516 bytes
};

// IOTC Connect configuration passed to IOTC_Connect_ByUIDEx (3rd argument).
// IotcConnectCfg fields:
//   - First field: struct size = 0x14 = 20 (checked at 1a8e22: cmpl $0x14,(%rdx))
//   - authkey: first 8 bytes from the authkey string (null-padded uint64)
//   - timeout1, timeout2: both 0x14 = 20 seconds
struct IotcConnectCfg {
    uint32_t struct_size;    // [0] must be 0x14 = 20
    uint32_t authkey_lo;     // [4] lower 4 bytes of authkey (little-endian)
    uint32_t authkey_hi;     // [8] upper 4 bytes of authkey
    uint32_t timeout1_sec;   // [12] = 20
    uint32_t timeout2_sec;   // [16] = 20
};
static_assert(sizeof(IotcConnectCfg) == 0x14, "IotcConnectCfg must be 20 bytes");

// avClientStartEx input struct (AvStartIn).
// Key fields accessed at known offsets in avClientStartEx:
//   [0x00] struct_size check: cmpl $0x37, (%rdi) → must be > 0x37 = 55
//   [0x04] sid: uint32  — IOTC session ID
//   [0x08] channel: uint8 — AV channel number; checked: cmpb $0x1f,0x8(%rdi)
//            → must be <= 0x1f = 31 (only lower 5 bits used)
//            Bambu uses channel 0x00 (not 0x38 as commented — see note below)
//   [0x0c] param_u32: uint32 — passed to avClientStart_inner as arg
//   [0x10] account: char* — "admin"
//   [0x18] passwd:  char* — printer password
//   [0x20] timeout_sec: uint32 = 30
//   [0x24] flags: uint32 (r9d = avClientStart_inner arg6)
//   [0x28] flags2: uint32 → pushed as stack arg
//   [0x2c] flags3: uint32 (another avClientStart_inner arg)
//   [0x30] flags4: uint64 or uint32 → pushed as stack arg
//   struct_size field = 0x38 = 56 (meaning the struct is 56 bytes including the size field)
//
// NOTE on channel: The avClientStartEx validator (0x1607f6) does cmpb $0x1f, 0x8(%rdi) and takes
// the error path if channel > 0x1f.  The value 0x38 = 56 in the old code was
// actually stored at struct_size, not channel.  The actual channel for the
// Bambu printer video stream is 0x00 or 0x01.  Future capture needed to confirm.
struct AvStartIn {
    uint32_t struct_size;    // [0x00] = 0x38 (56 bytes, size of this struct)
    uint32_t sid;            // [0x04] IOTC session ID
    uint8_t  channel;        // [0x08] AV channel (0..31); Bambu video = 0?
    uint8_t  _pad1[3];
    uint32_t param;          // [0x0c]
    const char* account;     // [0x10] "admin"
    const char* passwd;      // [0x18] printer password (default "888888")
    uint32_t timeout_sec;    // [0x20] = 30
    uint32_t flags;          // [0x24]
    uint32_t flags2;         // [0x28]
    uint32_t flags3;         // [0x2c]
    uint64_t flags4;         // [0x30]
};
static_assert(sizeof(AvStartIn) == 0x38, "AvStartIn must be 56 bytes");

// avClientStartEx output struct (AvStartOut).
// avClientStartEx writes back these output fields:
//   [0x00] struct_size: must be pre-set to 0x18 = 24
//   [0x04] resend:      bool/uint32 — resend enabled flag
//   [0x08] two_way:     uint32 — two-way streaming flag
//   [0x0c] unknown1:    uint32
//   [0x10] unknown2:    uint32
//   [0x14] av_index:    int32 — returned AV channel index (may be separate retval)
struct AvStartOut {
    uint32_t struct_size;    // [0x00] = 0x18 (pre-fill before call)
    uint32_t resend;         // [0x04] out: resend enabled
    uint32_t two_way;        // [0x08] out: two-way streaming
    uint32_t unknown1;       // [0x0c] out
    uint32_t unknown2;       // [0x10] out
    int32_t  av_index;       // [0x14] out (avClientStartEx return value also gives this)
};
static_assert(sizeof(AvStartOut) == 0x18, "AvStartOut must be 24 bytes");

#pragma pack(pop)

// --------------------------------------------------------------------------
// AV layer frame header
// --------------------------------------------------------------------------
//
// The Bambu-over-TUTK AV data is framed with a 16-byte header:
//   Bytes [0..3]  payload_len:  uint32_t LE  — number of bytes following header
//   Bytes [4..7]  magic:        uint32_t LE  — 0x????013f (lower 16 = 0x013f)
//   Bytes [8..11] sequence:     uint32_t LE  — monotonically increasing
//   Bytes [12..15] ???:         uint32_t     — unknown (observed 0)
//
// Magic field breakdown (from tutk_ssl_log.js frameHeaderLabel):
//   bits [15:0]   = 0x013f (MAGIC_MARKER, identifies frame header vs payload)
//   bits [23:16]  = sub_type:
//                   0x01 = LOGIN
//                   0x02 = CTRL (JSON control messages)
//   bits [31:24]  = direction:
//                   0x01 = Client→Printer
//                   0x00 = Printer→Client
//
// Payload format (for CTRL / 0x02 sub-type):
//   JSON object immediately followed by \n\n and optional binary blob.
//   Example (Bambu IPCAM_START equivalent):
//     {"info":{"command":"get_version"}} \n\n <empty>
//
// avSendIOCtrl(av_index, 0xFF01, NULL, 0):
//   IOTYPE_USER_IPCAM_START = 0xFF01
//   This is a TUTK standard camera-start IOCtrl type from the TUTK AV API.
//   On the wire: avSendIOCtrl wraps the type+data into an IOCtrl frame and
//   delivers it through the session's AV channel.  The exact wire encoding
//   is inside TUTK's avSendIOCtrl_inner / avSendIOCtrlFrame (0x17c4c0).

static constexpr uint32_t kFrameMagicMarker    = 0x013f;
static constexpr uint8_t  kFrameSubtypeLogin   = 0x01;
static constexpr uint8_t  kFrameSubtypeCtrl    = 0x02;
static constexpr uint8_t  kFrameDirClientToP   = 0x01;
static constexpr uint8_t  kFrameDirPrinterToC  = 0x00;

static constexpr uint32_t IOTYPE_USER_IPCAM_START = 0xFF01;
static constexpr uint32_t IOTYPE_USER_IPCAM_STOP  = 0xFF02;

// --------------------------------------------------------------------------
// TUTK message types (from IOTC_Handler_MSG_* function names)
// --------------------------------------------------------------------------
//
// These are the UDP message types handled by the TUTK IOTC stack.
// Exact numeric values are not in the binary strings but the handler names
// give the full message vocabulary.  The numeric assignments follow the
// TUTK IOTC SDK convention (values inferred from similar open-source work
// on Wyze / TP-Link cameras using the same SDK).

enum class TutkMsgType : uint16_t {
    // LAN discovery
    LAN_SEARCH          = 0x30,
    LAN_SEARCH_R        = 0x31,
    LAN_SEARCH3         = 0x32,   // auth-capable search
    LAN_SEARCH_R3       = 0x33,   // auth-capable search response

    // P2P NAT traversal
    P2P_PRECHECK1       = 0x41,   // client → device: "can you hear me?"
    P2P_PRECHECK1_R     = 0x42,   // device → client: "yes"
    P2P_PRECHECK2       = 0x43,   // client → device: "here is my auth key"
    P2P_REQUEST         = 0x44,   // client → device: "please connect"
    P2P_KNOCK           = 0x50,   // hole-punch knock
    P2P_KNOCK_R         = 0x51,   // hole-punch knock reply
    P2P_KNOCK_RR        = 0x52,   // hole-punch knock reply-reply
    P2P_PUNCH_TO        = 0x60,   // "punch to this address"
    P2P_ALIVE_C2D       = 0x70,   // keepalive client→device
    P2P_ALIVE_D2C       = 0x71,   // keepalive device→client
    P2P_CLOSE_C2D       = 0x78,   // disconnect client→device
    P2P_CLOSE_D2C       = 0x79,   // disconnect device→client
    P2P_PACKET_C2D      = 0x80,   // data packet client→device
    P2P_PACKET_D2C      = 0x81,   // data packet device→client

    // Relay (via master server)
    RLY_REQUEST         = 0x90,   // client → master: "help me reach UID"
    RLY_REQUEST_R       = 0x91,   // master → client: result
    RLY_KNOCK           = 0xa0,   // relay knock
    RLY_KNOCK_R         = 0xa1,   // relay knock reply
    RLY_SESSION_INFO    = 0xb0,   // relay session assignment
    RLY_ALIVE_S2C       = 0xc0,   // relay keepalive server→client
    RLY_ALIVE_S2D       = 0xc1,   // relay keepalive server→device
    RLY_PACKET_S2C      = 0xd0,   // relay data server→client
    RLY_PACKET_S2D      = 0xd1,   // relay data server→device

    // Device state
    REGISTER_R          = 0x01,   // server → device: registration ack
    REGISTER_ALIVE_R    = 0x02,
    REGISTER_SLEEP_R    = 0x03,
    HELLO1_R            = 0x10,
    NOTIFY_DEVICE_REGISTER = 0x11,
    DEVICE_NOT_LOGIN    = 0x12,
    DEVICE_IS_SLEEP1    = 0x13,
    DEVICE_IS_SLEEP2    = 0x14,
    NO_TCP_SUPPORT      = 0x15,
    AUTHORIZATION_FAILED= 0x16,
    CHECK_DEVICE_STATUS_R=0x17,
    QUERY_DEVICE5_R     = 0x20,
    QUERY_DEVICE6_R     = 0x21,
};

// --------------------------------------------------------------------------
// TUTK error codes
// --------------------------------------------------------------------------

enum TutkError : int {
    // IOTC errors (negative integers)
    IOTC_ER_NOT_INITIALIZED     = -1,
    IOTC_ER_ALREADY_INITIALIZED = -2,
    IOTC_ER_EXCEED_MAX_SESSION  = -22,   // too many open sessions
    IOTC_ER_DEVICE_EXCEED_MAX_SESSION = -48, // device limit
    IOTC_ER_INVALID_SID         = -14,
    IOTC_ER_SESSION_CLOSE_BY_REMOTE = -18,
    IOTC_ER_REMOTE_TIMEOUT_DISCONNECT = -90, // -0x5a
    IOTC_ER_NOT_INITIALIZED2    = -0x30, // = -48 ?

    // AV errors (around -20000)
    AV_ER_TIMEOUT               = -20012, // no data (non-fatal, retry)
    AV_ER_INCOMPLETE_FRAME      = -20014, // lost packets (non-fatal)
    AV_ER_INCOMPLETE_FRAME2     = -20013,
    AV_ER_SESSION_CLOSE_BY_REMOTE = -20015,
    AV_ER_REMOTE_TIMEOUT_DISCONNECT = -20016,
    AV_ER_NO_PERMISSION         = -20001,
    AV_ER_WRONG_VIEWACCorPWD    = -20026, // bad password
    AV_ER_EXCEED_MAX_SIZE       = -20005,
    AV_ER_BUFPARA_MAXSIZE_INSUFF= -20006,
    AV_ER_DATA_NOREADY          = -20012,
    AV_ER_MEM_INSUFF            = -20003,
    AV_ER_INVALID_SID           = -20002,
    AV_ER_EXCEED_MAX_CHANNEL    = -20004,
    AV_ER_INTERNAL_GET_DTLS_DATA= -20030,
    AV_ER_LOCAL_NOT_SUPPORT_DTLS= -20031,

    // Custom
    TUTK_ER_INVALID_ARG         = -0x3ea, // = -1002 (FFFFFC16)
};

// --------------------------------------------------------------------------
// NAT types (from "Detect NAT type" log strings)
// --------------------------------------------------------------------------

enum TutkNatType : int {
    NAT_UNKNOWN     = 0,
    NAT_NONE        = 1,   // direct / no NAT
    NAT_FULL_CONE   = 2,
    NAT_RESTRICTED  = 3,   // address-restricted cone
    NAT_PORT_REST   = 4,   // port-restricted cone
    NAT_SYMMETRIC   = 5,   // symmetric — triggers "try port" mode
    NAT_BLOCKED     = 6,   // ICMP blocked
};

// --------------------------------------------------------------------------
// DTLS session keys
// --------------------------------------------------------------------------

struct DtlsSession {
    uint8_t  client_random[32];
    uint8_t  server_random[32];
    uint8_t  master_secret[48];
    uint8_t  client_write_key[32];
    uint8_t  server_write_key[32];
    uint8_t  client_write_iv[12];
    uint8_t  server_write_iv[12];
    uint32_t epoch;               // session epoch (0 for relay path)
    uint64_t tx_seq;
    uint64_t rx_seq;
    bool     handshake_complete;
};

// --------------------------------------------------------------------------
// RelayConn — TUTK IOTC relay connection state
// --------------------------------------------------------------------------

struct RelayConn {
    int              sock;            // UDP socket fd (-1 = closed)
    struct sockaddr_in relay_addr;
    uint8_t          session_token[8]; // 8 random bytes generated by client
    DtlsSession      dtls;            // filled by iotc_relay_dtls()
};

// --------------------------------------------------------------------------
// Relay API — implemented in IotcClient.cpp
// --------------------------------------------------------------------------

// JOIN + KNOCK×5 + verify relay assignment + post-KNOCK.
// uid_upper: 20-char UPPERCASE printer UID (e.g. "7PYKKRDZVKWBBU1D111A")
// relay_id:  first 16 chars of the 20-char relay subdomain
// region_str: "cn", "eu", "us" etc.
// out: filled on success.
// Returns 0 on success, -1 on failure.
int iotc_relay_connect(const char* uid_upper, const char* relay_id,
                       const char* region_str, RelayConn* out);

// Run DTLS-PSK handshake over the relay socket.
// Must be called after iotc_relay_connect().
// passwd: the "passwd" field from the camera URL (bambu:///tutk?...&passwd=<value>).
//   This field may differ from the cloud API access_code depending on the printer model.
//   PSK = SHA256(passwd_ascii_string).
// account: PSK identity suffix (e.g. "admin"); full identity = "AUTHPWD_" + account.
// Fills rc->dtls on success.
// Returns 0 on success, -1 on failure.
int iotc_relay_dtls(RelayConn* rc,
                    const char* passwd, const char* account);

// Encrypt and send one DTLS ApplicationData record over the relay socket.
// Returns 0 on success, -1 on failure.
int iotc_relay_send_app_data(RelayConn* rc,
                              const uint8_t* data, size_t len);

// Receive and decrypt one DTLS ApplicationData record.
// Retries internally on non-AppData packets (keepalives etc.) up to a limit.
// timeout_ms: per-receive timeout in milliseconds.
// Returns decrypted length on success, 0 on timeout, -1 on error.
int iotc_relay_recv_app_data(RelayConn* rc,
                              uint8_t* out, size_t out_size,
                              int timeout_ms);

// Close the relay socket and zero the struct.
void iotc_relay_close(RelayConn* rc);

#ifdef OBN_TESTING
// Unit test hooks (defined in IotcClient.cpp).
void trans_code_partial_test(uint8_t* data, size_t len);
void reverse_trans_code_partial_test(uint8_t* data, size_t len);
void build_relay_nonce_test(uint8_t nonce[12], const uint8_t iv[12],
                             uint32_t epoch, uint64_t seq);
#endif

} // namespace oss_tutk
} // namespace bambu_net
