#include "obn/tunnel_local.hpp"

#include "obn/json_lite.hpp"

#include <openssl/ssl.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace obn::tunnel_local {
namespace {

void write_u32_le(std::uint8_t* dst, std::uint32_t v)
{
    dst[0] = static_cast<std::uint8_t>(v);
    dst[1] = static_cast<std::uint8_t>(v >> 8);
    dst[2] = static_cast<std::uint8_t>(v >> 16);
    dst[3] = static_cast<std::uint8_t>(v >> 24);
}

std::uint32_t read_u32_le(const std::uint8_t* src)
{
    return static_cast<std::uint32_t>(src[0]) |
           (static_cast<std::uint32_t>(src[1]) << 8) |
           (static_cast<std::uint32_t>(src[2]) << 16) |
           (static_cast<std::uint32_t>(src[3]) << 24);
}

std::string ascii_field(const std::string& s, std::size_t width)
{
    std::string out(width, '\0');
    const std::size_t n = std::min(s.size(), width);
    if (n) std::memcpy(out.data(), s.data(), n);
    return out;
}

// Read up to `cap` bytes (blocking until at least one byte or EOF/error).
int read_some(SSL* ssl, std::uint8_t* buf, std::size_t cap)
{
    if (!ssl || !buf || !cap) return -1;
    const int n = SSL_read(ssl, buf, static_cast<int>(cap));
    if (n > 0) return n;
    if (n == 0) return 0;
    const int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return -2;
    return -1;
}

int ssl_write_all(SSL* ssl, const void* buf, std::size_t len)
{
    const auto* p = static_cast<const std::uint8_t*>(buf);
    std::size_t sent = 0;
    while (sent < len) {
        const int n = SSL_write(ssl, p + sent, static_cast<int>(len - sent));
        if (n <= 0) {
            const int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
            return -1;
        }
        sent += static_cast<std::size_t>(n);
    }
    return 0;
}

} // namespace

std::array<std::uint8_t, 16> build_frame_header(std::uint32_t payload_len,
                                                std::uint32_t magic,
                                                std::uint32_t seq)
{
    std::array<std::uint8_t, 16> hdr{};
    write_u32_le(hdr.data(), payload_len);
    write_u32_le(hdr.data() + 4, magic);
    write_u32_le(hdr.data() + 8, seq);
    return hdr;
}

bool parse_frame_header(const std::uint8_t* data, std::size_t len, FrameHeader* out)
{
    if (!out || len < 16) return false;
    out->payload_len = read_u32_le(data);
    out->magic       = read_u32_le(data + 4);
    out->seq         = read_u32_le(data + 8);
    return true;
}

std::string build_login_payload(const std::string& username,
                                const std::string& access_code)
{
    return ascii_field(username, 8) + ascii_field(access_code, 8);
}

std::string build_setup_json(const std::string& client_id,
                             const std::string& client_ver)
{
    obn::json::Object req;
    req["t_av"]   = obn::json::Value(0.0);
    req["mtype"]  = obn::json::Value(static_cast<double>(kMtypeCtrlJson));
    req["peer_t"] = obn::json::Value(3.0);
    req["pid"]    = obn::json::Value(client_id);
    req["ver"]    = obn::json::Value(client_ver);

    obn::json::Object root;
    root["sequence"] = obn::json::Value(0.0);
    root["mtype"]    = obn::json::Value(static_cast<double>(kMtypeCtrlSetup));
    root["req"]      = obn::json::Value(std::move(req));
    return obn::json::Value(std::move(root)).dump();
}

std::string wrap_ctrl_abi(const std::string& abi_json)
{
    if (abi_json.empty()) return abi_json;
    std::string trimmed = abi_json;
    while (!trimmed.empty() &&
           (trimmed.back() == '\n' || trimmed.back() == '\r' ||
            trimmed.back() == ' ' || trimmed.back() == '\t')) {
        trimmed.pop_back();
    }
    if (trimmed.size() >= 8 && trimmed.compare(0, 8, "{\"mtype\"") == 0) {
        return abi_json;
    }
    if (!trimmed.empty() && trimmed.front() == '{') {
        return "{\"mtype\":" + std::to_string(kMtypeCtrlJson) + ',' +
               trimmed.substr(1);
    }
    return abi_json;
}

std::size_t consume_frames(const std::uint8_t* data, std::size_t len,
                           std::vector<std::vector<std::uint8_t>>* bodies)
{
    if (!bodies) return 0;
    std::size_t i = 0;
    while (i + 16 <= len) {
        FrameHeader hdr{};
        if (!parse_frame_header(data + i, len - i, &hdr)) break;
        const std::size_t frame_len = 16 + hdr.payload_len;
        if (i + frame_len > len) break;
        std::vector<std::uint8_t> body(hdr.payload_len);
        if (hdr.payload_len) {
            std::memcpy(body.data(), data + i + 16, hdr.payload_len);
        }
        bodies->push_back(std::move(body));
        i += frame_len;
    }
    return i;
}

Session::Session(std::uint32_t seq_seed) : seq_(seq_seed) {}

int Session::send_frame(SSL* ssl, std::uint32_t magic, const std::uint8_t* payload,
                        std::size_t payload_len, std::mutex* io_mu)
{
    if (!ssl) return -1;
    const auto hdr = build_frame_header(static_cast<std::uint32_t>(payload_len),
                                        magic, seq_++);
    std::unique_lock<std::mutex> lk;
    if (io_mu) lk = std::unique_lock<std::mutex>(*io_mu);
    if (ssl_write_all(ssl, hdr.data(), hdr.size()) != 0) return -1;
    if (payload_len &&
        ssl_write_all(ssl, payload, payload_len) != 0) {
        return -1;
    }
    return 0;
}

int Session::try_read_frames(SSL* ssl, std::mutex* io_mu)
{
    std::uint8_t chunk[65536];
    int n = 0;
    {
        std::unique_lock<std::mutex> lk;
        if (io_mu) lk = std::unique_lock<std::mutex>(*io_mu);
        n = read_some(ssl, chunk, sizeof(chunk));
    }
    if (n == -2) return 1; // WANT_READ/WRITE — poll again
    if (n < 0) return -1;
    if (n == 0) return -1; // peer closed
    recv_buf_.insert(recv_buf_.end(), chunk, chunk + n);
    return 0;
}

bool Session::have_login_ack() const
{
    if (recv_buf_.size() < 16) return false;
    FrameHeader hdr{};
    if (!parse_frame_header(recv_buf_.data(), recv_buf_.size(), &hdr)) return false;
    if (hdr.magic != kMagicLoginServer) return false;
    return recv_buf_.size() >= 16 + hdr.payload_len;
}

int Session::handshake_step(SSL* ssl, const Config& cfg, std::mutex* io_mu)
{
    if (!ssl) return -1;
    if (phase_ == HandshakePhase::Ready) return 0;
    if (phase_ == HandshakePhase::Failed) return -1;

    std::string client_id = cfg.client_id;
    if (client_id.empty()) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%08x", seq_ & 0xffffffffu);
        client_id = buf;
    }

    if (phase_ == HandshakePhase::NotStarted) {
        const std::string login = build_login_payload(cfg.username, cfg.access_code);
        if (send_frame(ssl, kMagicLoginClient,
                       reinterpret_cast<const std::uint8_t*>(login.data()),
                       login.size(), io_mu) != 0) {
            phase_ = HandshakePhase::Failed;
            return -1;
        }
        phase_ = HandshakePhase::LoginSent;
        return 1;
    }

    if (phase_ == HandshakePhase::LoginSent) {
        const int rr = try_read_frames(ssl, io_mu);
        if (rr < 0) {
            phase_ = HandshakePhase::Failed;
            return -1;
        }
        if (rr > 0 || !have_login_ack()) return 1;
        std::vector<std::vector<std::uint8_t>> bodies;
        const std::size_t consumed =
            consume_frames(recv_buf_.data(), recv_buf_.size(), &bodies);
        if (consumed) {
            recv_buf_.erase(recv_buf_.begin(),
                            recv_buf_.begin() + static_cast<std::ptrdiff_t>(consumed));
        }
        const std::string setup = build_setup_json(client_id, cfg.client_ver);
        if (send_frame(ssl, kMagicCtrlClient,
                       reinterpret_cast<const std::uint8_t*>(setup.data()),
                       setup.size(), io_mu) != 0) {
            phase_ = HandshakePhase::Failed;
            return -1;
        }
        phase_ = HandshakePhase::SetupSent;
        return 1;
    }

    if (phase_ == HandshakePhase::SetupSent) {
        for (int attempt = 0; attempt < 32; ++attempt) {
            std::vector<std::vector<std::uint8_t>> bodies;
            const std::size_t consumed =
                consume_frames(recv_buf_.data(), recv_buf_.size(), &bodies);
            if (consumed) {
                recv_buf_.erase(recv_buf_.begin(),
                                recv_buf_.begin() +
                                    static_cast<std::ptrdiff_t>(consumed));
            }
            for (const auto& body : bodies) {
                if (body.empty()) continue;
                std::string perr;
                auto v = obn::json::parse(
                    std::string(reinterpret_cast<const char*>(body.data()),
                                body.size()),
                    &perr);
                if (!v) continue;
                if (v->find("mtype").as_int() == kMtypeCtrlSetup &&
                    v->find("result").as_int() == 0) {
                    phase_ = HandshakePhase::Ready;
                    return 0;
                }
            }
            const int rr = try_read_frames(ssl, io_mu);
            if (rr < 0) {
                phase_ = HandshakePhase::Failed;
                return -1;
            }
            if (rr > 0) break;
        }
        return 1;
    }

    return -1;
}

int Session::send_abi_json(SSL* ssl, const std::string& abi_body, std::mutex* io_mu)
{
    const std::string wire = wrap_ctrl_abi(abi_body);
    return send_frame(ssl, kMagicCtrlClient,
                      reinterpret_cast<const std::uint8_t*>(wire.data()),
                      wire.size(), io_mu);
}

int Session::recv_payload(SSL* ssl, std::vector<std::uint8_t>* out, std::mutex* io_mu)
{
    if (!ssl || !out) return -1;
    out->clear();
    for (;;) {
        std::vector<std::vector<std::uint8_t>> bodies;
        const std::size_t consumed =
            consume_frames(recv_buf_.data(), recv_buf_.size(), &bodies);
        if (consumed) {
            recv_buf_.erase(recv_buf_.begin(),
                            recv_buf_.begin() +
                                static_cast<std::ptrdiff_t>(consumed));
        }
        if (!bodies.empty()) {
            *out = std::move(bodies.front());
            return 0;
        }
        const int rc = try_read_frames(ssl, io_mu);
        if (rc < 0) return -1;
        if (rc > 0) return 1;
    }
}

} // namespace obn::tunnel_local
