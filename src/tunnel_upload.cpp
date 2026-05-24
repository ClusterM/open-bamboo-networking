#include "obn/tunnel_upload.hpp"

#include "obn/bambu_networking.hpp"
#include "obn/lan_tls.hpp"
#include "obn/log.hpp"
#include "obn/tls_dial.hpp"
#include "obn/tunnel_local.hpp"

#include <cstdlib>
#include <fstream>
#include <random>

#include <openssl/evp.h>
#include <openssl/ssl.h>

namespace obn::tunnel_upload {

namespace {

std::string random_uuid()
{
    static thread_local std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<int> dis(0, 15);
    const char* hex = "0123456789abcdef";
    std::string u = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
    for (char& c : u) {
        if (c == 'x') c = hex[dis(gen)];
        else if (c == 'y') c = hex[(dis(gen) & 0x3) | 0x8];
    }
    return u;
}

std::string md5_finalize_lower(EVP_MD_CTX* ctx)
{
    if (!ctx) return {};
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned      len = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &len) != 1) return {};

    static const char kHex[] = "0123456789abcdef";
    std::string hex(len * 2, '\0');
    for (unsigned i = 0; i < len; ++i) {
        hex[2 * i    ] = kHex[(digest[i] >> 4) & 0xF];
        hex[2 * i + 1] = kHex[ digest[i]       & 0xF];
    }
    return hex;
}

obn::tunnel_local::Config session_cfg(const ConnectParams& p)
{
    obn::tunnel_local::Config cfg;
    cfg.username    = p.username;
    cfg.access_code = p.password;
    cfg.client_id   = p.client_id.empty() ? random_uuid() : p.client_id;
    if (!p.client_ver.empty()) {
        cfg.client_ver = p.client_ver;
    } else {
#ifdef OBN_VERSION_STRING
        cfg.client_ver = OBN_VERSION_STRING;
#else
        cfg.client_ver = "02.07.00.55";
#endif
    }
    return cfg;
}

const char* tls_serial_for(const ConnectParams& p)
{
    if (!p.dev_id.empty()) return p.dev_id.c_str();
    if (auto s = obn::lan_tls::registry_lookup_serial(p.dev_ip)) {
        return s->c_str();
    }
    return nullptr;
}

int recv_json_payload(obn::tunnel_local::Session* session, SSL* ssl,
                      std::mutex* io_mu, std::string* json_out)
{
    std::vector<std::uint8_t> payload;
    for (;;) {
        const int rc = session->recv_payload(ssl, &payload, io_mu);
        if (rc == 0) break;
        if (rc < 0) return -1;
    }
    std::vector<std::uint8_t> bin;
    if (!obn::tunnel_local::split_json_prefix(payload.data(), payload.size(),
                                              json_out, &bin)) {
        json_out->assign(reinterpret_cast<const char*>(payload.data()), payload.size());
    }
    return 0;
}

int recv_wire_json(obn::tunnel_local::Session* session, SSL* ssl,
                   std::mutex* io_mu, std::string* json_out,
                   int want_cmdtype, std::uint32_t want_seq,
                   const char* phase, int max_skips = 32)
{
    auto try_accept = [&](const std::string& json) -> bool {
        const int cmd = obn::tunnel_local::parse_wire_cmdtype(json);
        const int seq = obn::tunnel_local::parse_wire_sequence(json);
        if (cmd == want_cmdtype &&
            (want_seq == 0 ||
             static_cast<std::uint32_t>(seq) == want_seq)) {
            *json_out = json;
            return true;
        }
        OBN_WARN("tunnel_upload (%s): skip stale reply cmd=%d seq=%d"
                 " want cmd=%d seq=%u: %.200s",
                 phase, cmd, seq, want_cmdtype, want_seq, json.c_str());
        return false;
    };

    for (const auto& pending : session->drain_pending_wire_json()) {
        if (try_accept(pending)) return 0;
    }
    for (int i = 0; i < max_skips; ++i) {
        std::string json;
        if (recv_json_payload(session, ssl, io_mu, &json) != 0) return -1;
        if (try_accept(json)) return 0;
    }
    return -1;
}

void drain_stale_wire_json(obn::tunnel_local::Session* session, const char* phase)
{
    for (const auto& pending : session->drain_pending_wire_json()) {
        OBN_WARN("tunnel_upload (%s): drain buffered reply: %.200s",
                 phase, pending.c_str());
    }
}

UploadOutcome run_chunked_upload(obn::tunnel_local::Session* session,
                                 SSL* ssl, obn::os::socket_t fd,
                                 std::mutex* io_mu, std::uint32_t seq,
                                 const UploadRequest& req,
                                 UploadCallbacks cb)
{
    UploadOutcome out;

    if (req.dest_storage.empty() || req.dest_name.empty() || req.local_path.empty()) {
        out.error = "missing upload fields";
        return out;
    }

    std::ifstream in(req.local_path, std::ios::binary | std::ios::ate);
    if (!in) {
        out.error = "cannot open local file";
        return out;
    }
    const auto fsize = static_cast<std::uint64_t>(in.tellg());
    in.seekg(0, std::ios::beg);

    drain_stale_wire_json(session, "pre-init");

    const std::string init_abi = obn::tunnel_local::build_file_upload_init_abi(
        seq, req.dest_storage, req.dest_name, fsize);

    OBN_INFO("tunnel_upload: init %s -> %s/%s (%llu bytes)",
             req.local_path.c_str(), req.dest_storage.c_str(), req.dest_name.c_str(),
             static_cast<unsigned long long>(fsize));

    if (obn::os::socket_valid(fd)) {
        obn::tls::set_socket_io_timeout(fd, 120000);
    }

    if (session->send_abi_json(ssl, init_abi, io_mu) != 0) {
        out.error = obn::tunnel_local::describe_ssl_io_error(ssl);
        if (obn::os::socket_valid(fd)) obn::tls::clear_socket_io_timeout(fd);
        return out;
    }

    std::string wire_json;
    if (recv_wire_json(session, ssl, io_mu, &wire_json,
                       obn::tunnel_local::kCmdFileUpload, seq, "init") != 0) {
        out.error = obn::tunnel_local::describe_ssl_io_error(ssl);
        if (obn::os::socket_valid(fd)) obn::tls::clear_socket_io_timeout(fd);
        return out;
    }

    std::uint32_t chunk_size_kb = 0;
    std::uint64_t offset = 0;
    int init_result = -1;
    if (!obn::tunnel_local::parse_upload_init_reply(
            wire_json, &chunk_size_kb, &offset, &init_result)) {
        out.wire_result = init_result;
        out.error = "bad upload init reply";
        if (obn::os::socket_valid(fd)) obn::tls::clear_socket_io_timeout(fd);
        return out;
    }

    const std::size_t buffer_size =
        static_cast<std::size_t>(chunk_size_kb) * 1024;

    if (offset > 0) {
        in.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    }

    std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> md5_ctx(
        EVP_MD_CTX_new(),
        [](EVP_MD_CTX* c) { if (c) EVP_MD_CTX_free(c); });
    if (!md5_ctx || EVP_DigestInit_ex(md5_ctx.get(), EVP_md5(), nullptr) != 1) {
        out.error = "md5 init failed";
        if (obn::os::socket_valid(fd)) obn::tls::clear_socket_io_timeout(fd);
        return out;
    }

    std::vector<char> buffer(buffer_size);
    std::uint32_t frag_id = 0;
    int last_reported_pct = -1;

    while (offset < fsize) {
        if (cb.cancelled && cb.cancelled()) {
            out.error = "cancelled";
            if (obn::os::socket_valid(fd)) obn::tls::clear_socket_io_timeout(fd);
            return out;
        }

        const std::uint64_t remaining = fsize - offset;
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(remaining, buffer_size));
        in.read(buffer.data(), static_cast<std::streamsize>(want));
        const std::streamsize got = in.gcount();
        if (got <= 0) {
            out.error = "read error";
            if (obn::os::socket_valid(fd)) obn::tls::clear_socket_io_timeout(fd);
            return out;
        }
        const auto read_size = static_cast<std::uint32_t>(got);
        if (EVP_DigestUpdate(md5_ctx.get(), buffer.data(), read_size) != 1) {
            out.error = "md5 update failed";
            if (obn::os::socket_valid(fd)) obn::tls::clear_socket_io_timeout(fd);
            return out;
        }

        const bool last_chunk = (offset + read_size >= fsize);
        std::string file_md5;
        if (last_chunk) {
            file_md5 = md5_finalize_lower(md5_ctx.get());
            md5_ctx.reset();
        }

        const std::string chunk_abi =
            obn::tunnel_local::build_file_upload_chunk_abi(
                seq, frag_id, offset, read_size, file_md5);

        if (session->send_abi_json_with_binary(
                ssl, chunk_abi, buffer.data(), read_size,
                io_mu, /*poll_rx_after_send=*/false) != 0) {
            out.error = obn::tunnel_local::describe_ssl_io_error(ssl);
            if (obn::os::socket_valid(fd)) obn::tls::clear_socket_io_timeout(fd);
            return out;
        }

        offset += read_size;
        ++frag_id;

        if (fsize > 0 && cb.progress) {
            const int pct = static_cast<int>((offset * 100) / fsize);
            if (pct != last_reported_pct) {
                last_reported_pct = pct;
                cb.progress(pct);
            }
        }
    }

    int result_code = -1;
    for (int attempt = 0; attempt < 32; ++attempt) {
        wire_json.clear();
        if (recv_wire_json(session, ssl, io_mu, &wire_json,
                           obn::tunnel_local::kCmdFileUpload, seq, "final") != 0) {
            out.error = obn::tunnel_local::describe_ssl_io_error(ssl);
            if (obn::os::socket_valid(fd)) obn::tls::clear_socket_io_timeout(fd);
            return out;
        }
        result_code = obn::tunnel_local::parse_wire_result(wire_json);
        if (result_code == 1) continue;
        break;
    }

    if (obn::os::socket_valid(fd)) {
        obn::tls::clear_socket_io_timeout(fd);
    }

    out.bytes = fsize;
    out.wire_result = result_code;
    if (result_code == 0 || result_code == 19) {
        out.ok = true;
        if (cb.progress) cb.progress(100);
        OBN_INFO("tunnel_upload: done %llu bytes result=%d",
                 static_cast<unsigned long long>(fsize), result_code);
        return out;
    }
    out.error = "upload failed wire result=" + std::to_string(result_code);
    OBN_WARN("tunnel_upload: failed result=%d wire=%.200s",
             result_code, wire_json.c_str());
    return out;
}

} // namespace

struct Connection::Impl {
    obn::os::socket_t                          fd{obn::os::kInvalidSocket};
    SSL*                                       ssl{nullptr};
    std::unique_ptr<obn::tunnel_local::Session> session;
    std::mutex                                 io_mu;
    std::uint32_t                              wire_seq{1};
    ConnectParams                              params;
};

Connection::Connection() : impl_(std::make_unique<Impl>()) {}
Connection::~Connection() { disconnect(); }

int Connection::connect(const ConnectParams& p, std::string* err_out)
{
    disconnect();
    impl_->params = p;

    OBN_INFO("tunnel_upload: dialing tls://%s:%d", p.dev_ip.c_str(), p.port);

    const char* serial = tls_serial_for(p);
    if (obn::tls::dial_tls(p.dev_ip, p.port, /*timeout_ms=*/5000,
                           &impl_->fd, &impl_->ssl, serial) != 0) {
        const char* err = obn::tls::last_error();
        const std::string msg = err && *err ? err : "TLS dial failed";
        if (err_out) *err_out = msg;
        return -1;
    }

    impl_->session = std::make_unique<obn::tunnel_local::Session>(
        static_cast<std::uint32_t>(std::rand()));

    const auto cfg = session_cfg(p);
    obn::tls::set_socket_io_timeout(impl_->fd, 3000);
    for (int attempt = 0; attempt < 64; ++attempt) {
        const int hs = impl_->session->handshake_step(impl_->ssl, cfg, &impl_->io_mu);
        if (hs == 0) {
            obn::tls::clear_socket_io_timeout(impl_->fd);
            OBN_INFO("tunnel_upload: ready (pid=%s ver=%s)",
                     cfg.client_id.c_str(), cfg.client_ver.c_str());
            return 0;
        }
        if (hs < 0) break;
    }
    obn::tls::clear_socket_io_timeout(impl_->fd);
    disconnect();
    const std::string msg = "BambuTunnelLocal handshake failed";
    if (err_out) *err_out = msg;
    return -1;
}

void Connection::disconnect()
{
    obn::os::socket_t fd = obn::os::kInvalidSocket;
    SSL* ssl = nullptr;
    {
        std::lock_guard<std::mutex> lk(impl_->io_mu);
        fd  = impl_->fd;
        ssl = impl_->ssl;
        impl_->fd  = obn::os::kInvalidSocket;
        impl_->ssl = nullptr;
        impl_->session.reset();
    }
    obn::tls::close_tls(&fd, &ssl);
}

bool Connection::is_connected() const
{
    std::lock_guard<std::mutex> lk(impl_->io_mu);
    return impl_->ssl != nullptr;
}

std::uint32_t Connection::next_wire_seq()
{
    std::lock_guard<std::mutex> lk(impl_->io_mu);
    return impl_->wire_seq++;
}

UploadOutcome Connection::upload(const UploadRequest& req, UploadCallbacks cb)
{
    UploadOutcome out;
    if (!is_connected()) {
        out.error = "not connected";
        return out;
    }

    std::uint32_t seq = 0;
    obn::os::socket_t fd = obn::os::kInvalidSocket;
    SSL* ssl = nullptr;
    obn::tunnel_local::Session* session = nullptr;
    {
        std::lock_guard<std::mutex> lk(impl_->io_mu);
        seq = impl_->wire_seq++;
        fd = impl_->fd;
        ssl = impl_->ssl;
        session = impl_->session.get();
    }

    return run_chunked_upload(session, ssl, fd, &impl_->io_mu, seq, req, cb);
}

UploadOutcome Connection::query_media_ability()
{
    UploadOutcome out;
    if (!is_connected()) {
        out.error = "not connected";
        return out;
    }

    std::uint32_t seq = 0;
    SSL* ssl = nullptr;
    obn::tunnel_local::Session* session = nullptr;
    {
        std::lock_guard<std::mutex> lk(impl_->io_mu);
        seq = impl_->wire_seq++;
        ssl = impl_->ssl;
        session = impl_->session.get();
    }

    const std::string req = obn::tunnel_local::build_media_ability_abi(seq);
    if (session->send_abi_json(ssl, req, &impl_->io_mu) != 0) {
        out.error = obn::tunnel_local::describe_ssl_io_error(ssl);
        return out;
    }

    std::string wire_json;
    if (recv_json_payload(session, ssl, &impl_->io_mu, &wire_json) != 0) {
        out.error = obn::tunnel_local::describe_ssl_io_error(ssl);
        return out;
    }

    std::string body = obn::tunnel_local::parse_ability_reply_to_ft_json(wire_json);
    if (body.empty()) {
        out.error = "bad ability reply";
        return out;
    }
    out.ok = true;
    out.json_body = std::move(body);
    return out;
}

int upload_file(const ConnectParams& connect,
                const UploadRequest& upload,
                UploadCallbacks cb,
                UploadOutcome* out,
                int err_code_on_failure)
{
    if (out) *out = {};

#if !OBN_FT_TUNNEL_LOCAL
    (void)connect;
    (void)upload;
    (void)cb;
    return err_code_on_failure;
#else
    Connection conn;
    std::string err;
    if (conn.connect(connect, &err) != 0) {
        OBN_WARN("tunnel_upload: connect failed: %s", err.c_str());
        if (out) out->error = err;
        return err_code_on_failure;
    }

    UploadOutcome result = conn.upload(upload, std::move(cb));
    if (out) *out = result;
    if (result.ok) return 0;

    if (result.error == "cancelled") {
        return BAMBU_NETWORK_ERR_CANCELED;
    }
    return err_code_on_failure;
#endif
}

ConnectParams connect_params_from_print(const std::string& dev_ip,
                                        const std::string& dev_id,
                                        const std::string& password)
{
    ConnectParams p;
    p.dev_ip     = dev_ip;
    p.dev_id     = dev_id;
    p.password   = password;
    return p;
}

} // namespace obn::tunnel_upload
