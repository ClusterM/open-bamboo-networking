#include "obn/tunnel_local.hpp"

#include "obn/json_lite.hpp"
#include "obn/os_compat.hpp"
#include "obn/tls_dial.hpp"

#include "obn/net_compat.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <functional>
#include <istream>

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
    if (obn::tls::ssl_write_all(ssl, buf, len) != 0) return -1;
    return 0;
}

const char* ssl_fail_reason(SSL* ssl)
{
    static thread_local char buf[256];
    const unsigned long err = ERR_peek_last_error();
    if (err) {
        ERR_error_string_n(err, buf, sizeof(buf));
        return buf;
    }
    (void)ssl;
    return "SSL I/O error (no OpenSSL error queued)";
}

} // namespace

const char* describe_ssl_io_error(SSL* ssl)
{
    return ssl_fail_reason(ssl);
}

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
    req["t_av"]   = obn::json::Value(1.0);
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

std::string wrap_ctrl_abi_with_binary(const std::string& abi_json,
                                      const void* bin, std::size_t bin_len)
{
    std::string wire = wrap_ctrl_abi(abi_json);
    if (bin && bin_len) {
        wire += "\n\n";
        wire.append(static_cast<const char*>(bin), bin_len);
    }
    return wire;
}

bool split_json_prefix(const std::uint8_t* data, std::size_t len,
                       std::string* json_out, std::vector<std::uint8_t>* bin_out)
{
    if (json_out) json_out->clear();
    if (bin_out) bin_out->clear();
    if (!data || !len) return false;

    std::size_t i = 0;
    if (data[0] != '{') return false;
    int depth = 0;
    bool in_str = false;
    bool esc = false;
    for (; i < len; ++i) {
        const char c = static_cast<char>(data[i]);
        if (in_str) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') in_str = true;
        else if (c == '{') ++depth;
        else if (c == '}') {
            --depth;
            if (depth == 0) {
                ++i;
                break;
            }
        }
    }
    if (depth != 0) return false;
    if (json_out) {
        json_out->assign(reinterpret_cast<const char*>(data), i);
    }
    // Binary follows optional "\n\n" (see wrap_ctrl_abi_with_binary). Do not
    // strip arbitrary whitespace — file chunks may start with space/newline.
    if (i + 1 < len && data[i] == '\n' && data[i + 1] == '\n') {
        i += 2;
    } else if (i + 3 < len && data[i] == '\r' && data[i + 1] == '\n' &&
               data[i + 2] == '\r' && data[i + 3] == '\n') {
        i += 4;
    }
    if (bin_out && i < len) {
        bin_out->assign(data + i, data + len);
    }
    return true;
}

std::string build_media_ability_abi(std::uint32_t sequence)
{
    // Match PrinterFileSystem::RequestMediaAbility (peer + api_version).
    // Empty req{} yields firmware result=2 (kResErrJson) on P2S.
    // The genuine upload-lane query is {api_version:3, peer:"studio",
    // peer_t:3}; older builds sent api_version 2 with no peer_t and P2S
    // firmware is lenient about it, but we mirror the genuine frame.
    // TODO(verify-on-hardware): confirm the ability reply still parses
    // across firmware generations after the api_version bump.
    obn::json::Object req;
    req["peer"]        = obn::json::Value("studio");
    req["peer_t"]      = obn::json::Value(3.0);
    req["api_version"] = obn::json::Value(3.0);

    obn::json::Object root;
    root["cmdtype"]  = obn::json::Value(static_cast<double>(kCmdMediaAbility));
    root["sequence"] = obn::json::Value(static_cast<double>(sequence));
    root["req"]      = obn::json::Value(std::move(req));
    return obn::json::Value(std::move(root)).dump();
}

std::string build_file_upload_init_abi(std::uint32_t sequence,
                                       const std::string& dest_storage,
                                       const std::string& dest_name,
                                       std::uint64_t total)
{
    obn::json::Object req;
    req["type"]  = obn::json::Value("model");
    req["path"]  = obn::json::Value(dest_name);
    req["total"] = obn::json::Value(static_cast<double>(total));
    if (!dest_storage.empty()) {
        req["storage"] = obn::json::Value(dest_storage);
    }

    obn::json::Object root;
    root["cmdtype"]  = obn::json::Value(static_cast<double>(kCmdFileUpload));
    root["sequence"] = obn::json::Value(static_cast<double>(sequence));
    root["req"]      = obn::json::Value(std::move(req));
    return obn::json::Value(std::move(root)).dump();
}

std::string build_file_delete_abi(std::uint32_t sequence,
                                  const std::string& dest_storage,
                                  const std::string& dest_name)
{
    obn::json::Array names;
    names.emplace_back(obn::json::Value(dest_name));

    obn::json::Object req;
    req["delete"] = obn::json::Value(std::move(names));
    if (!dest_storage.empty()) {
        req["storage"] = obn::json::Value(dest_storage);
    }

    obn::json::Object root;
    root["cmdtype"]  = obn::json::Value(static_cast<double>(kCmdFileDel));
    root["sequence"] = obn::json::Value(static_cast<double>(sequence));
    root["req"]      = obn::json::Value(std::move(req));
    return obn::json::Value(std::move(root)).dump();
}

std::string build_file_download_abi(std::uint32_t sequence,
                                    const std::string& path,
                                    std::uint64_t offset,
                                    const std::string& target_path)
{
    obn::json::Object req;
    req["path"]   = obn::json::Value(path);
    req["offset"] = obn::json::Value(static_cast<double>(offset));
    if (!target_path.empty()) {
        req["target_path"] = obn::json::Value(target_path);
    }

    obn::json::Object root;
    root["cmdtype"]  = obn::json::Value(static_cast<double>(kCmdFileDownload));
    root["sequence"] = obn::json::Value(static_cast<double>(sequence));
    root["req"]      = obn::json::Value(std::move(req));
    return obn::json::Value(std::move(root)).dump();
}

std::string build_sub_file_abi(std::uint32_t sequence,
                               const std::vector<std::string>& paths,
                               const std::string& storage)
{
    obn::json::Array path_arr;
    for (const auto& p : paths) {
        path_arr.push_back(obn::json::Value(p));
    }
    obn::json::Object req;
    req["paths"] = obn::json::Value(std::move(path_arr));
    req["api_version"] = obn::json::Value(2.0);
    req["peer"]        = obn::json::Value("studio");
    if (!storage.empty()) {
        req["storage"] = obn::json::Value(storage);
    }

    obn::json::Object root;
    root["cmdtype"]  = obn::json::Value(static_cast<double>(kCmdSubFile));
    root["sequence"] = obn::json::Value(static_cast<double>(sequence));
    root["req"]      = obn::json::Value(std::move(req));
    return obn::json::Value(std::move(root)).dump();
}

std::string build_list_info_abi(std::uint32_t sequence,
                                const std::string& type,
                                const std::string& storage)
{
    obn::json::Object req;
    req["type"]         = obn::json::Value(type);
    req["api_version"]  = obn::json::Value(2.0);
    req["notify"]       = obn::json::Value("DETAIL");
    if (!storage.empty()) {
        req["storage"] = obn::json::Value(storage);
    }

    obn::json::Object root;
    root["cmdtype"]  = obn::json::Value(static_cast<double>(kCmdListInfo));
    root["sequence"] = obn::json::Value(static_cast<double>(sequence));
    root["req"]      = obn::json::Value(std::move(req));
    return obn::json::Value(std::move(root)).dump();
}

std::string build_file_upload_chunk_abi(std::uint32_t sequence,
                                        std::uint32_t frag_id,
                                        std::uint64_t offset,
                                        std::uint32_t size,
                                        const std::string& file_md5_lower)
{
    obn::json::Object req;
    req["frag_id"] = obn::json::Value(static_cast<double>(frag_id));
    req["offset"]  = obn::json::Value(static_cast<double>(offset));
    req["size"]    = obn::json::Value(static_cast<double>(size));
    if (!file_md5_lower.empty()) {
        req["file_md5"] = obn::json::Value(file_md5_lower);
    }

    obn::json::Object root;
    root["cmdtype"]  = obn::json::Value(static_cast<double>(kCmdFileUpload));
    root["sequence"] = obn::json::Value(static_cast<double>(sequence));
    root["req"]      = obn::json::Value(std::move(req));
    return obn::json::Value(std::move(root)).dump();
}

bool parse_upload_init_reply(const std::string& wire_json,
                             std::uint32_t* chunk_size_kb,
                             std::uint64_t* offset,
                             int* result_code)
{
    if (result_code) *result_code = parse_wire_result(wire_json);
    const int rc = result_code ? *result_code : parse_wire_result(wire_json);
    // PrinterFileSystem: SUCCESS=0, CONTINUE=1, FILE_EXIST=19
    if (rc != 1 && rc != 19) return false;

    std::string perr;
    auto root = obn::json::parse(wire_json, &perr);
    if (!root) return false;

    auto reply = root->find("reply");
    if (!reply.is_object()) return false;

    const std::uint32_t kb =
        static_cast<std::uint32_t>(reply.find("chunk_size").as_int(0));
    if (!kb) return false;

    if (chunk_size_kb) *chunk_size_kb = kb;
    if (offset) {
        *offset = static_cast<std::uint64_t>(reply.find("offset").as_int(0));
    }
    return true;
}

std::string build_file_upload_abi(std::uint32_t sequence,
                                  const std::string& dest_storage,
                                  const std::string& dest_name,
                                  std::uint64_t size, const std::string& md5)
{
    std::string path = "/";
    if (!dest_storage.empty()) {
        path += dest_storage;
        if (path.back() != '/') path += '/';
    }
    obn::json::Object req;
    req["path"] = obn::json::Value(path);
    req["file"] = obn::json::Value(dest_name);
    req["size"] = obn::json::Value(static_cast<double>(size));
    req["md5"]  = obn::json::Value(md5);
    if (!dest_storage.empty()) {
        req["storage"] = obn::json::Value(dest_storage);
    }
    req["peer"]        = obn::json::Value("studio");
    req["api_version"] = obn::json::Value(3.0);

    obn::json::Object root;
    root["cmdtype"]  = obn::json::Value(static_cast<double>(kCmdFileUpload));
    root["sequence"] = obn::json::Value(static_cast<double>(sequence));
    root["req"]      = obn::json::Value(std::move(req));
    return obn::json::Value(std::move(root)).dump();
}

std::string parse_ability_reply_to_ft_json(const std::string& wire_json)
{
    std::string perr;
    auto root = obn::json::parse(wire_json, &perr);
    if (!root) return {};

    const int result = static_cast<int>(root->find("result").as_int(-1));
    if (result != 0) return {};

    auto reply = root->find("reply");
    if (!reply.is_object()) return {};

    obn::json::Array storages;
    auto pick_array = [&](const char* key) {
        auto v = reply.find(key);
        if (v.is_array()) storages = v.as_array();
    };
    pick_array("storage");
    if (storages.empty()) pick_array("storage_list");
    if (storages.empty()) pick_array("storages");
    if (storages.empty()) {
        auto ab = reply.find("ability");
        if (ab.is_object()) {
            auto v = ab.find("storage");
            if (v.is_array()) storages = v.as_array();
        }
    }
    if (storages.empty()) return {};

    std::string out = "[";
    for (std::size_t i = 0; i < storages.size(); ++i) {
        if (i) out += ',';
        const std::string s = storages[i].as_string();
        out += '"';
        for (char c : s) {
            if (c == '"') out += "\\\"";
            else out += c;
        }
        out += '"';
    }
    out += ']';
    return out;
}

int parse_upload_progress(const std::string& wire_json, int* result_code)
{
    const double v = parse_upload_progress_value(wire_json, result_code);
    if (v < 0.0) return -1;
    return static_cast<int>(v + 0.5);
}

double parse_upload_progress_value(const std::string& wire_json, int* result_code)
{
    if (result_code) *result_code = parse_wire_result(wire_json);
    if (result_code && *result_code < 0) return -1.0;

    std::string perr;
    auto root = obn::json::parse(wire_json, &perr);
    if (!root) return -1.0;

    auto pick = [](const obn::json::Value& obj) -> double {
        if (!obj.is_object()) return -1.0;
        const auto v = obj.find("progress");
        if (!v.is_number()) return -1.0;
        return v.as_number();
    };

    double progress = pick(root->find("reply"));
    if (progress < 0.0) progress = pick(*root);
    return progress;
}

int parse_wire_result(const std::string& wire_json)
{
    std::string perr;
    auto root = obn::json::parse(wire_json, &perr);
    if (!root) return -1;
    return static_cast<int>(root->find("result").as_int(-1));
}

std::string parse_wire_reply_json(const std::string& wire_json)
{
    std::string perr;
    auto root = obn::json::parse(wire_json, &perr);
    if (!root) return {};
    const auto reply = root->find("reply");
    if (!reply.is_object()) return {};
    return obn::json::Value(reply).dump();
}

int parse_wire_cmdtype(const std::string& wire_json)
{
    std::string perr;
    auto root = obn::json::parse(wire_json, &perr);
    if (!root) return -1;
    return static_cast<int>(root->find("cmdtype").as_int(-1));
}

int parse_wire_sequence(const std::string& wire_json)
{
    std::string perr;
    auto root = obn::json::parse(wire_json, &perr);
    if (!root) return -1;
    return static_cast<int>(root->find("sequence").as_int(-1));
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

std::vector<std::string> take_pending_wire_json(std::vector<std::uint8_t>* recv_buf)
{
    std::vector<std::string> msgs;
    if (!recv_buf) return msgs;
    for (;;) {
        std::vector<std::vector<std::uint8_t>> bodies;
        const std::size_t consumed =
            consume_frames(recv_buf->data(), recv_buf->size(), &bodies);
        if (!consumed) break;
        recv_buf->erase(recv_buf->begin(),
                        recv_buf->begin() + static_cast<std::ptrdiff_t>(consumed));
        for (const auto& body : bodies) {
            if (body.empty()) continue;
            std::string json;
            std::vector<std::uint8_t> bin;
            if (split_json_prefix(body.data(), body.size(), &json, &bin)) {
                if (!json.empty()) msgs.push_back(std::move(json));
            } else {
                msgs.emplace_back(reinterpret_cast<const char*>(body.data()),
                                  body.size());
            }
        }
    }
    return msgs;
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
    {
        std::lock_guard<std::mutex> lk(recv_buf_mu_);
        recv_buf_.insert(recv_buf_.end(), chunk, chunk + n);
    }
    return 0;
}

int Session::poll_incoming_wire(SSL* ssl, std::mutex* io_mu,
                                const WireJsonCallback& on_wire)
{
    if (!ssl || !on_wire) return 0;
    const int fd = SSL_get_fd(ssl);
    if (fd < 0) return 0;
    const obn::os::socket_t sock = static_cast<obn::os::socket_t>(fd);
    if (!obn::os::socket_valid(sock)) return 0;

    auto dispatch = [&]() -> bool {
        std::vector<std::string> pending;
        {
            std::lock_guard<std::mutex> lk(recv_buf_mu_);
            pending = take_pending_wire_json(&recv_buf_);
        }
        for (const auto& json : pending) {
            if (!on_wire(json)) return false;
        }
        return true;
    };

    dispatch();

    for (int pass = 0; pass < 64; ++pass) {
        const int rr = try_read_frames(ssl, io_mu);
        if (rr < 0) return -1;
        if (!dispatch()) return -2;
        if (rr > 0) break; // WANT_READ/WRITE — retry from write path

        short revents = 0;
        if (obn::os::poll_one(sock, obn::net::poll_event::in, 0, &revents) <= 0 ||
            !(revents & obn::net::poll_event::in)) {
            break;
        }
    }
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

int Session::send_abi_json_with_binary(SSL* ssl, const std::string& abi_json,
                                       const void* bin, std::size_t bin_len,
                                       std::mutex* io_mu,
                                       bool poll_rx_after_send)
{
    if (!bin || !bin_len) {
        return send_abi_json(ssl, abi_json, io_mu);
    }
    struct MemBuf : std::streambuf {
        MemBuf(const char* p, std::size_t n)
        {
            char* begin = const_cast<char*>(p);
            setg(begin, begin, begin + n);
        }
    };
    MemBuf mbuf(static_cast<const char*>(bin), bin_len);
    std::istream in(&mbuf);
    return send_abi_json_with_binary_stream(ssl, abi_json, in, bin_len, io_mu,
                                            {}, poll_rx_after_send);
}

int Session::send_abi_json_with_binary_stream(SSL* ssl, const std::string& abi_json,
                                              std::istream& bin_in,
                                              std::size_t bin_len,
                                              std::mutex* io_mu,
                                              WireJsonCallback on_wire,
                                              bool poll_rx_after_send)
{
    if (!ssl) return -1;
    const std::string wire = wrap_ctrl_abi(abi_json);
    static constexpr char kSep[] = "\n\n";

    std::vector<std::uint8_t> body;
    body.reserve(wire.size() + (bin_len ? sizeof(kSep) - 1 + bin_len : 0));
    body.assign(wire.begin(), wire.end());
    if (bin_len > 0) {
        body.insert(body.end(), kSep, kSep + sizeof(kSep) - 1);
        const std::size_t base = body.size();
        body.resize(base + bin_len);
        bin_in.read(reinterpret_cast<char*>(body.data() + base),
                    static_cast<std::streamsize>(bin_len));
        if (static_cast<std::size_t>(bin_in.gcount()) != bin_len) return -1;
    }

    const auto hdr = build_frame_header(static_cast<std::uint32_t>(body.size()),
                                        kMagicCtrlClient, seq_++);

    {
        std::unique_lock<std::mutex> lk;
        if (io_mu) lk = std::unique_lock<std::mutex>(*io_mu);
        if (ssl_write_all(ssl, hdr.data(), hdr.size()) != 0) return -1;
        if (!body.empty() &&
            ssl_write_all(ssl, body.data(), body.size()) != 0) {
            return -1;
        }
    }

    if (!poll_rx_after_send) return 0;

    if (on_wire) {
        for (int pass = 0; pass < 8; ++pass) {
            const int rr = try_read_frames(ssl, io_mu);
            if (rr < 0) break;
        }
        std::vector<std::string> pending;
        {
            std::lock_guard<std::mutex> lk(recv_buf_mu_);
            pending = take_pending_wire_json(&recv_buf_);
        }
        for (const auto& json : pending) {
            if (!on_wire(json)) return -2;
        }
    } else {
        for (int pass = 0; pass < 8; ++pass) {
            const int rr = try_read_frames(ssl, io_mu);
            if (rr <= 0) break;
        }
    }
    return 0;
}

std::vector<std::string> Session::drain_pending_wire_json()
{
    std::lock_guard<std::mutex> lk(recv_buf_mu_);
    return take_pending_wire_json(&recv_buf_);
}

int Session::recv_payload(SSL* ssl, std::vector<std::uint8_t>* out, std::mutex* io_mu)
{
    if (!ssl || !out) return -1;
    out->clear();
    for (;;) {
        std::vector<std::vector<std::uint8_t>> bodies;
        std::size_t consumed = 0;
        {
            std::lock_guard<std::mutex> lk(recv_buf_mu_);
            consumed =
                consume_frames(recv_buf_.data(), recv_buf_.size(), &bodies);
            if (consumed) {
                recv_buf_.erase(recv_buf_.begin(),
                                recv_buf_.begin() +
                                    static_cast<std::ptrdiff_t>(consumed));
            }
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
