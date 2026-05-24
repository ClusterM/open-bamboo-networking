#pragma once

// BambuTunnelLocal wire helpers (TLS :6000 file browser / CTRL RPC).
// See NETWORK_PLUGIN.md §7.5.1.1 and tools/bambu6000_repl.py.

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <istream>
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

// ABI JSON optionally followed by \\n\\n + binary blob (FILE_UPLOAD).
std::string wrap_ctrl_abi_with_binary(const std::string& abi_json,
                                      const void* bin, std::size_t bin_len);

// Split a framed payload body into JSON prefix and trailing binary.
bool split_json_prefix(const std::uint8_t* data, std::size_t len,
                       std::string* json_out, std::vector<std::uint8_t>* bin_out);

constexpr int kCmdMediaAbility = 7;
constexpr int kCmdFileUpload   = 5;
constexpr int kCmdFileDel      = 3;

std::string build_media_ability_abi(std::uint32_t sequence);
// Legacy one-shot upload (rejected by P2S firmware; kept for tests / older models).
std::string build_file_upload_abi(std::uint32_t sequence,
                                  const std::string& dest_storage,
                                  const std::string& dest_name,
                                  std::uint64_t size, const std::string& md5);

// Chunked upload phase 1: JSON only (PrinterFileSystem::RequestUploadFile).
std::string build_file_upload_init_abi(std::uint32_t sequence,
                                       const std::string& dest_storage,
                                       const std::string& dest_name,
                                       std::uint64_t total);

// Remove an existing model before overwrite upload (PrinterFileSystem::DeleteFiles).
std::string build_file_delete_abi(std::uint32_t sequence,
                                  const std::string& dest_storage,
                                  const std::string& dest_name);

// Chunked upload phase 2: one fragment + optional file_md5 on the last chunk.
std::string build_file_upload_chunk_abi(std::uint32_t sequence,
                                        std::uint32_t frag_id,
                                        std::uint64_t offset,
                                        std::uint32_t size,
                                        const std::string& file_md5_lower);

// Parses init reply (result CONTINUE/FILE_EXIST). chunk_size is in KB.
bool parse_upload_init_reply(const std::string& wire_json,
                             std::uint32_t* chunk_size_kb,
                             std::uint64_t* offset,
                             int* result_code);

// Firmware wire reply -> ft_job JSON array string (e.g. ["sdcard","emmc"]).
// Returns empty on parse failure.
std::string parse_ability_reply_to_ft_json(const std::string& wire_json);

// Returns progress 0-100 when present (supports float wire values); negative when absent.
// Sets *result_code to wire result field when JSON parses.
double parse_upload_progress_value(const std::string& wire_json, int* result_code);

// Legacy int API (rounded).
int parse_upload_progress(const std::string& wire_json, int* result_code);

// Wire "result" field (-1 when JSON missing / unparsable).
int parse_wire_result(const std::string& wire_json);

// Wire envelope fields (-1 when JSON missing / unparsable).
int parse_wire_cmdtype(const std::string& wire_json);
int parse_wire_sequence(const std::string& wire_json);

// Append one or more complete frames from `data`; returns bytes consumed.
std::size_t consume_frames(const std::uint8_t* data, std::size_t len,
                           std::vector<std::vector<std::uint8_t>>* bodies);

// Human-readable OpenSSL error after send_abi_json_* failure (thread-local).
const char* describe_ssl_io_error(SSL* ssl);

// Pop complete framed JSON bodies already in the session recv buffer.
std::vector<std::string> take_pending_wire_json(std::vector<std::uint8_t>* recv_buf);

class Session {
public:
    explicit Session(std::uint32_t seq_seed);

    HandshakePhase phase() const { return phase_; }

    // One handshake step per call. Returns 0 when ready, 1 while in progress
    // (caller should poll), -1 on error. `io_mu` serialises SSL access.
    int handshake_step(SSL* ssl, const Config& cfg, std::mutex* io_mu);

    int send_abi_json(SSL* ssl, const std::string& abi_body, std::mutex* io_mu);

    int send_abi_json_with_binary(SSL* ssl, const std::string& abi_json,
                                  const void* bin, std::size_t bin_len,
                                  std::mutex* io_mu,
                                  bool poll_rx_after_send = true);

    // FILE_UPLOAD: framed json\\n\\nbinary without copying bin into one std::string.
    // on_wire is invoked for printer progress frames received while binary is still
    // being sent (full-duplex :6000 — must read or the peer resets the connection).
    // on_wire returns false to abort an in-flight upload send.
    // poll_rx_after_send: when false, do not recv after the frame (P2S multi-chunk
    // pipeline — read only once after all chunks are on the wire).
    using WireJsonCallback = std::function<bool(const std::string& wire_json)>;

    int send_abi_json_with_binary_stream(SSL* ssl, const std::string& abi_json,
                                         std::istream& bin_in, std::size_t bin_len,
                                         std::mutex* io_mu,
                                         WireJsonCallback on_wire = {},
                                         bool poll_rx_after_send = true);

    // Blocking read of one framed payload body (may include json\\n\\nbinary).
    int recv_payload(SSL* ssl, std::vector<std::uint8_t>* out, std::mutex* io_mu);

    // JSON bodies from frames already sitting in the session recv buffer.
    std::vector<std::string> drain_pending_wire_json();

private:
    std::uint32_t             seq_;
    HandshakePhase            phase_ = HandshakePhase::NotStarted;
    std::vector<std::uint8_t> recv_buf_;
    std::mutex                recv_buf_mu_;

    int send_frame(SSL* ssl, std::uint32_t magic, const std::uint8_t* payload,
                   std::size_t payload_len, std::mutex* io_mu);
    int try_read_frames(SSL* ssl, std::mutex* io_mu);
    int poll_incoming_wire(SSL* ssl, std::mutex* io_mu, const WireJsonCallback& on_wire);
    bool have_login_ack() const;
};

} // namespace obn::tunnel_local
