#pragma once

// BambuTunnelLocal wire helpers (TLS :6000 file browser / CTRL RPC).
// See NETWORK_PLUGIN.md §7.5.1.1 and tools/bambu6000_repl.py.

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

typedef struct ssl_st SSL;

namespace obn::tunnel_local {

constexpr std::uint32_t kMagicLoginClient = 0x0101013Fu;
constexpr std::uint32_t kMagicLoginServer = 0x0001013Fu;
constexpr std::uint32_t kMagicCtrlClient  = 0x0102013Fu;
constexpr std::uint32_t kMagicCtrlServer  = 0x0002013Fu;
constexpr std::uint32_t kMagicMarker      = 0x0000013Fu;

constexpr int kMtypeCtrlSetup = 12291;
constexpr int kMtypeCtrlJson  = 12289;

struct FrameHeader {
    std::uint32_t payload_len = 0;
    std::uint32_t magic       = 0;
    std::uint32_t seq         = 0;
};

struct Config {
    std::string username   = "bblp";
    std::string access_code;
    std::string client_id;
    std::string client_ver;  // empty if unknown; URL net_ver/cli_ver when provided
};

enum class HandshakePhase {
    NotStarted,
    LoginSent,
    SetupSent,
    Ready,
    Failed,
};

// Pure helpers (unit-testable without TLS).
std::array<std::uint8_t, 16> build_frame_header(std::uint32_t payload_len,
                                                std::uint32_t magic,
                                                std::uint32_t seq);

bool parse_frame_header(const std::uint8_t* data, std::size_t len, FrameHeader* out);

std::string build_login_payload(const std::string& username,
                                const std::string& access_code);

std::string build_setup_json(const std::string& client_id,
                             const std::string& client_ver);

// Studio ABI JSON -> wire payload with mtype:12289 prefix.
std::string wrap_ctrl_abi(const std::string& abi_json);

// Append one or more complete frames from `data`; returns bytes consumed.
std::size_t consume_frames(const std::uint8_t* data, std::size_t len,
                           std::vector<std::vector<std::uint8_t>>* bodies);

class Session {
public:
    explicit Session(std::uint32_t seq_seed);

    HandshakePhase phase() const { return phase_; }

    // One handshake step per call. Returns 0 when ready, 1 while in progress
    // (caller should poll), -1 on error. `io_mu` serialises SSL access.
    int handshake_step(SSL* ssl, const Config& cfg, std::mutex* io_mu);

    int send_abi_json(SSL* ssl, const std::string& abi_body, std::mutex* io_mu);

    // Blocking read of one framed payload body (may include json\\n\\nbinary).
    int recv_payload(SSL* ssl, std::vector<std::uint8_t>* out, std::mutex* io_mu);

private:
    std::uint32_t             seq_;
    HandshakePhase            phase_ = HandshakePhase::NotStarted;
    std::vector<std::uint8_t> recv_buf_;

    int send_frame(SSL* ssl, std::uint32_t magic, const std::uint8_t* payload,
                   std::size_t payload_len, std::mutex* io_mu);
    int try_read_frames(SSL* ssl, std::mutex* io_mu);
    bool have_login_ack() const;
};

} // namespace obn::tunnel_local
