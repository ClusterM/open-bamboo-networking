#include "obn/tunnel_upload.hpp"

#include "obn/json_lite.hpp"

#include "obn/bambu_networking.hpp"
#include "obn/lan_tls.hpp"
#include "obn/log.hpp"
#include "obn/net_compat.hpp"
#include "obn/tls_dial.hpp"
#include "obn/tunnel_local.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <mutex>
#include <random>
#include <tuple>
#include <utility>
#include <unordered_map>
#include <unordered_set>

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

int wait_ssl_readable(SSL* ssl, int timeout_ms)
{
    const int fd = SSL_get_fd(ssl);
    if (fd < 0) return -1;
    const obn::os::socket_t sock = static_cast<obn::os::socket_t>(fd);
    if (!obn::os::socket_valid(sock)) return -1;
    short revents = 0;
    if (obn::os::poll_one(sock, obn::net::poll_event::in, timeout_ms, &revents) <= 0) {
        return 0;
    }
    return (revents & obn::net::poll_event::in) ? 1 : 0;
}

// A blocking SSL_read waits out a TLS record however slowly it trickles in.
class NonBlockingScope {
public:
    explicit NonBlockingScope(SSL* ssl)
        : fd_(static_cast<obn::os::socket_t>(SSL_get_fd(ssl)))
    {
        ok_ = obn::os::socket_valid(fd_) && obn::os::set_nonblocking(fd_) == 0;
    }
    ~NonBlockingScope()
    {
        if (ok_) obn::os::set_blocking(fd_);
    }
    NonBlockingScope(const NonBlockingScope&)            = delete;
    NonBlockingScope& operator=(const NonBlockingScope&) = delete;
    bool ok() const { return ok_; }

private:
    obn::os::socket_t fd_;
    bool              ok_ = false;
};

int recv_json_payload(obn::tunnel_local::Session* session, SSL* ssl,
                      std::mutex* io_mu, std::string* json_out)
{
    std::vector<std::uint8_t> payload;
    for (;;) {
        const int rc = session->recv_payload(ssl, &payload, io_mu);
        if (rc == 0) break;
        if (rc < 0) return -1;
        if (wait_ssl_readable(ssl, 100) < 0) return -1;
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

int download_progress_pct(const std::string& wire_json)
{
    std::string perr;
    const auto root = obn::json::parse(wire_json, &perr);
    if (!root) return -1;
    const auto reply = root->find("reply");
    if (!reply.is_object()) return -1;
    const double total = reply.find("total").as_number(-1.0);
    if (total <= 0.0) return -1;
    const double offset = reply.find("offset").as_number(0.0);
    const double size   = reply.find("size").as_number(0.0);
    const double pct    = (offset + size) * 100.0 / total;
    if (pct < 0.0) return 0;
    if (pct > 100.0) return 100;
    return static_cast<int>(pct);
}

bool reply_has_mem_dl_param(const std::string& wire_json)
{
    std::string perr;
    const auto root = obn::json::parse(wire_json, &perr);
    if (!root) return false;
    const auto reply = root->find("reply");
    if (!reply.is_object()) return false;
    return reply.find("mem_dl_param_size").is_number() &&
           reply.find("mem_dl_param_size").as_number(0.0) > 0.0;
}

void log_download_magic(const std::vector<std::uint8_t>& data)
{
    if (data.empty()) {
        OBN_DEBUG("tunnel_upload: download payload empty");
        return;
    }
    char magic[32];
    const std::size_t n = std::min(data.size(), std::size_t{16});
    std::snprintf(magic, sizeof(magic), "%02x", data[0]);
    for (std::size_t i = 1; i < n; ++i) {
        char tmp[8];
        std::snprintf(tmp, sizeof(tmp), " %02x", data[i]);
        std::strncat(magic, tmp, sizeof(magic) - std::strlen(magic) - 1);
    }
    OBN_DEBUG("tunnel_upload: download payload %zu bytes, magic: %s",
             data.size(), magic);
}

void maybe_dump_download(const std::vector<std::uint8_t>& data)
{
    const char* path = std::getenv("OBN_FT_DUMP_DOWNLOAD");
    if (!path || !*path || data.empty()) return;
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        OBN_WARN("tunnel_upload: OBN_FT_DUMP_DOWNLOAD open failed: %s", path);
        return;
    }
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    OBN_DEBUG("tunnel_upload: dumped download -> %s (%zu bytes)", path,
             data.size());
}

struct ModelFileEntry {
    std::string  name;
    std::string  path;
    std::int64_t time = 0;
};

struct ListInfoOutcome {
    bool                        ok = false;
    std::vector<ModelFileEntry> files;
    int                         wire_result = 0;
    std::string                 error;
};

struct SubFileRequest {
    std::vector<std::string> paths;
    std::string              storage;
};

struct SubFileOutcome {
    bool                      ok = false;
    std::vector<std::uint8_t> data;
    int                       wire_result = 0;
    std::string               error;
    bool                      timed_out = false;  // set by run_sub_file_data()
};

bool wire_chunk_is_image(const std::vector<std::uint8_t>& chunk)
{
    if (chunk.size() >= 8 &&
        std::memcmp(chunk.data(), "\x89PNG\r\n\x1a\n", 8) == 0) {
        return true;
    }
    return chunk.size() >= 2 && chunk[0] == 0xff && chunk[1] == 0xd8;
}

// Position of the reply's "reply.path" in `paths`; paths.size() when the
// reply names none of them.
std::size_t sub_file_reply_rank(const std::string&              wire_json,
                                const std::vector<std::string>& paths)
{
    std::string perr;
    const auto root = obn::json::parse(wire_json, &perr);
    if (!root) return paths.size();
    const std::string path = root->find("reply.path").as_string();
    for (std::size_t i = 0; i < paths.size(); ++i) {
        if (paths[i] == path) return i;
    }
    return paths.size();
}

SubFileOutcome run_sub_file(obn::tunnel_local::Session* session,
                            SSL* ssl, std::mutex* io_mu, std::uint32_t seq,
                            const SubFileRequest& req)
{
    SubFileOutcome out;
    std::size_t    best_rank = 0;  // rank of out.data when it is set
    if (req.paths.empty()) {
        out.error = "missing sub_file paths";
        return out;
    }

    drain_stale_wire_json(session, "pre-sub_file");

    const std::string abi =
        obn::tunnel_local::build_sub_file_abi(seq, req.paths, req.storage);
    if (session->send_abi_json(ssl, abi, io_mu) != 0) {
        out.error = obn::tunnel_local::describe_ssl_io_error(ssl);
        return out;
    }

    for (;;) {
        std::vector<std::uint8_t> payload;
        for (;;) {
            const int rc = session->recv_payload(ssl, &payload, io_mu);
            if (rc == 0) break;
            if (rc < 0) {
                out.error = obn::tunnel_local::describe_ssl_io_error(ssl);
                return out;
            }
            if (wait_ssl_readable(ssl, 100) < 0) {
                out.error = obn::tunnel_local::describe_ssl_io_error(ssl);
                return out;
            }
        }

        std::string wire_json;
        std::vector<std::uint8_t> chunk;
        if (!obn::tunnel_local::split_json_prefix(payload.data(), payload.size(),
                                                  &wire_json, &chunk)) {
            wire_json.assign(reinterpret_cast<const char*>(payload.data()),
                             payload.size());
        }

        const int cmd = obn::tunnel_local::parse_wire_cmdtype(wire_json);
        const int rs  = obn::tunnel_local::parse_wire_sequence(wire_json);
        if (cmd == obn::tunnel_local::kCmdSubFile &&
            static_cast<std::uint32_t>(rs) == seq) {
            // When reply.path names a requested path, keep the image for the
            // earliest one (tile_thumbnail_sub_paths() lists them best
            // first), whatever order the frames arrive in.
            if (!chunk.empty() && wire_chunk_is_image(chunk)) {
                const std::size_t rank =
                    sub_file_reply_rank(wire_json, req.paths);
                if (out.data.empty() || rank < best_rank) {
                    out.data  = chunk;
                    best_rank = rank;
                }
            }
            const int result = obn::tunnel_local::parse_wire_result(wire_json);
            out.wire_result = result;
            if (result == 1) continue;
            if (result == 0) {
                out.ok = !out.data.empty();
                if (!out.ok) out.error = "sub_file empty payload";
                return out;
            }
            if (!out.data.empty()) {
                out.ok = true;
                return out;
            }
            out.error = "sub_file failed wire result=" + std::to_string(result);
            return out;
        }
    }
}

ListInfoOutcome run_list_info(obn::tunnel_local::Session* session,
                              SSL* ssl, std::mutex* io_mu, std::uint32_t seq,
                              const std::string& storage)
{
    ListInfoOutcome out;
    drain_stale_wire_json(session, "pre-list_info");

    const std::string abi =
        obn::tunnel_local::build_list_info_abi(seq, "model", storage);
    if (session->send_abi_json(ssl, abi, io_mu) != 0) {
        out.error = obn::tunnel_local::describe_ssl_io_error(ssl);
        return out;
    }

    std::string wire_json;
    if (recv_wire_json(session, ssl, io_mu, &wire_json,
                       obn::tunnel_local::kCmdListInfo, seq,
                       "list_info") != 0) {
        out.error = "list_info reply timeout";
        return out;
    }

    out.wire_result = obn::tunnel_local::parse_wire_result(wire_json);
    if (out.wire_result != 0) {
        out.error = "list_info wire result=" + std::to_string(out.wire_result);
        return out;
    }

    std::string perr;
    const auto root = obn::json::parse(wire_json, &perr);
    if (!root) {
        out.error = perr.empty() ? "list_info parse failed" : perr;
        return out;
    }
    const auto lists = root->find("reply.file_lists");
    if (!lists.is_array()) {
        out.error = "list_info missing file_lists";
        return out;
    }
    for (const auto& item : lists.as_array()) {
        if (!item.is_object()) continue;
        ModelFileEntry entry;
        entry.name = item.find("name").as_string();
        entry.path = item.find("path").as_string();
        entry.time = item.find("time").as_int(0);
        if (!entry.path.empty()) {
            out.files.push_back(std::move(entry));
        }
    }
    out.ok = true;
    return out;
}

DownloadOutcome run_download(obn::tunnel_local::Session* session,
                             SSL* ssl, std::mutex* io_mu, std::uint32_t seq,
                             const DownloadRequest& req, DownloadCallbacks cb)
{
    DownloadOutcome out;
    if (req.path.empty()) {
        out.error = "missing download path";
        return out;
    }

    drain_stale_wire_json(session, "pre-download");

    const std::string abi = obn::tunnel_local::build_file_download_abi(
        seq, req.path, /*offset=*/0, req.target_path);
    OBN_DEBUG("tunnel_upload: download req path=%s wire=%.200s",
             req.path.c_str(), abi.c_str());
    if (session->send_abi_json(ssl, abi, io_mu) != 0) {
        out.error = obn::tunnel_local::describe_ssl_io_error(ssl);
        return out;
    }

    std::string last_json;
    int         frames = 0;
    for (;;) {
        if (cb.cancelled && cb.cancelled()) {
            out.error = "cancelled";
            return out;
        }

        std::vector<std::uint8_t> payload;
        for (;;) {
            const int rc = session->recv_payload(ssl, &payload, io_mu);
            if (rc == 0) break;
            if (rc < 0) {
                out.error = obn::tunnel_local::describe_ssl_io_error(ssl);
                return out;
            }
            if (wait_ssl_readable(ssl, 100) < 0) {
                out.error = obn::tunnel_local::describe_ssl_io_error(ssl);
                return out;
            }
        }

        std::string wire_json;
        std::vector<std::uint8_t> chunk;
        if (!obn::tunnel_local::split_json_prefix(payload.data(), payload.size(),
                                                  &wire_json, &chunk)) {
            wire_json.assign(reinterpret_cast<const char*>(payload.data()),
                             payload.size());
        }
        last_json = wire_json;
        ++frames;

        const int result = obn::tunnel_local::parse_wire_result(wire_json);
        out.wire_result  = result;

        OBN_DEBUG("tunnel_upload: download frame=%d result=%d chunk=%zu wire=%.300s",
                 frames, result, chunk.size(), wire_json.c_str());

        if (!chunk.empty() && !reply_has_mem_dl_param(wire_json)) {
            out.data.insert(out.data.end(), chunk.begin(), chunk.end());
        } else if (!chunk.empty()) {
            OBN_DEBUG("tunnel_upload: download skip mem_dl_param chunk (%zu bytes)",
                     chunk.size());
        }

        if (cb.progress) {
            const int pct = download_progress_pct(wire_json);
            if (pct >= 0) cb.progress(pct);
        }

        if (result == 1) continue;
        if (result == 0) {
            out.ok = true;
            out.json_body = obn::tunnel_local::parse_wire_reply_json(wire_json);
            if (out.json_body.empty()) out.json_body = std::move(last_json);
            log_download_magic(out.data);
            maybe_dump_download(out.data);
            return out;
        }
        out.error = "download failed wire result=" + std::to_string(result);
        return out;
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

    std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> md5_ctx(
        EVP_MD_CTX_new(),
        [](EVP_MD_CTX* c) { if (c) EVP_MD_CTX_free(c); });
    if (!md5_ctx || EVP_DigestInit_ex(md5_ctx.get(), EVP_md5(), nullptr) != 1) {
        out.error = "md5 init failed";
        if (obn::os::socket_valid(fd)) obn::tls::clear_socket_io_timeout(fd);
        return out;
    }

    std::vector<char> buffer(buffer_size);

    if (offset > 0) {
        in.seekg(0, std::ios::beg);
        std::uint64_t hashed = 0;
        while (hashed < offset) {
            const std::size_t want = static_cast<std::size_t>(
                std::min<std::uint64_t>(offset - hashed, buffer_size));
            in.read(buffer.data(), static_cast<std::streamsize>(want));
            const std::streamsize got = in.gcount();
            if (got <= 0) {
                out.error = "read error hashing resume prefix";
                if (obn::os::socket_valid(fd)) obn::tls::clear_socket_io_timeout(fd);
                return out;
            }
            const auto read_size = static_cast<std::size_t>(got);
            if (EVP_DigestUpdate(md5_ctx.get(), buffer.data(), read_size) != 1) {
                out.error = "md5 update failed";
                if (obn::os::socket_valid(fd)) obn::tls::clear_socket_io_timeout(fd);
                return out;
            }
            hashed += read_size;
        }
        in.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    }

    std::uint32_t frag_id = 0;
    int last_reported_pct = -1;
    std::string digest_lower;

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
            digest_lower = md5_finalize_lower(md5_ctx.get());
            if (digest_lower.empty()) {
                out.error = "md5 finalize failed";
                if (obn::os::socket_valid(fd)) {
                    obn::tls::clear_socket_io_timeout(fd);
                }
                return out;
            }
            file_md5 = digest_lower;
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
    out.md5_lower = digest_lower;
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

bool ends_with(const std::string& s, const std::string& suf)
{
    return s.size() >= suf.size() &&
           std::equal(suf.rbegin(), suf.rend(), s.rbegin());
}

bool name_matches_model(const std::string& listing_name,
                        const std::string& model_name)
{
    if (listing_name == model_name) return true;
    if (!ends_with(model_name, ".3mf")) {
        if (listing_name == model_name + ".gcode.3mf") return true;
        if (listing_name == model_name + ".3mf") return true;
    }
    return false;
}

const ModelFileEntry* find_model_entry(const ListInfoOutcome& list,
                                       const std::string&     model_name)
{
    const ModelFileEntry* best = nullptr;
    int match_count = 0;

    auto consider = [&](const ModelFileEntry& f) {
        if (!name_matches_model(f.name, model_name)) {
            const auto slash = f.path.rfind('/');
            const std::string base =
                slash != std::string::npos ? f.path.substr(slash + 1) : f.path;
            if (!name_matches_model(base, model_name)) return;
        }
        ++match_count;
        if (!best) {
            best = &f;
            return;
        }
        const auto in_cache = [](const std::string& path) {
            return path.find("/cache/") != std::string::npos;
        };
        const int cache_a = in_cache(f.path) ? 1 : 0;
        const int cache_b = in_cache(best->path) ? 1 : 0;
        if (cache_a != cache_b) {
            if (cache_a > cache_b) best = &f;
            return;
        }
        if (f.time != best->time) {
            if (f.time > best->time) best = &f;
            return;
        }
        const bool gcode_a = ends_with(f.name, ".gcode.3mf");
        const bool gcode_b = ends_with(best->name, ".gcode.3mf");
        if (gcode_a != gcode_b && gcode_a) best = &f;
    };

    for (const auto& f : list.files) consider(f);

    if (best && match_count > 1) {
        OBN_DEBUG("tunnel_upload: %d listing(s) match '%s', picked %s",
                  match_count, model_name.c_str(), best->path.c_str());
    }
    return best;
}

std::vector<std::string> model_list_storages()
{
    return {"", "internal", "emmc"};
}

std::vector<std::string> sub_file_storage_labels(const std::string& list_storage)
{
    if (list_storage.empty()) return {"udisk", ""};
    if (list_storage == "internal") return {"internal", "emmc"};
    if (list_storage == "emmc") return {"emmc", "internal"};
    return {list_storage};
}

// Collects per-storage failures as "'<storage>': <error>; ..." so the final
// cover-fetch error names the wire result instead of a generic message.
void append_storage_failure(std::string*       out,
                            const std::string& storage,
                            const std::string& error)
{
    if (!out->empty()) out->append("; ");
    out->append("'" + storage + "': " + error);
}

std::vector<std::string> tile_thumbnail_sub_paths(const std::string& path,
                                                  int                plate_idx)
{
    if (plate_idx < 1) plate_idx = 1;
    const std::string n = std::to_string(plate_idx);
    std::vector<std::string> out = {
        path + "#Metadata/plate_" + n + ".png",
        path + "#Metadata/plate_no_light_" + n + ".png",
        path + "#thumbnail",
    };
    if (plate_idx != 1) {
        out.push_back(path + "#Metadata/plate_1.png");
        out.push_back(path + "#Metadata/plate_no_light_1.png");
    }
    return out;
}

// --- Fallback: match a print to its file by the 3MF title ------------------

// Bounds a misbehaving peer; a sliced project's 3dmodel.model has no meshes.
constexpr std::size_t kMaxModelXmlBytes = 256 * 1024;

// Only a listing's newest 64 .3mf files are candidates; one fetch can read them all.
constexpr std::size_t kMaxTitleCandidates   = 64;
constexpr int         kMaxTitleReadsPerFetch = 64;

// A silent or trickling reply must not hold the cover worker past the deadline.
constexpr int  kTitleReadPollMs   = 1000;
constexpr auto kTitleReadDeadline = std::chrono::seconds(10);

// Printer x storage scopes kept; past this the title cache starts over.
constexpr std::size_t kMaxTitleScopes = 64;

void append_utf8(std::string* out, unsigned long cp)
{
    if (cp < 0x80) {
        out->push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out->push_back(static_cast<char>(0xc0 | (cp >> 6)));
        out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp < 0x10000) {
        out->push_back(static_cast<char>(0xe0 | (cp >> 12)));
        out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
        out->push_back(static_cast<char>(0xf0 | (cp >> 18)));
        out->push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
        out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
}

// Only predefined entities and character references; anything else stays verbatim.
std::string decode_xml_text(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    std::size_t i = 0;
    while (i < s.size()) {
        const std::size_t semi = s[i] == '&' ? s.find(';', i + 1) : std::string::npos;
        if (semi == std::string::npos || semi - i > 12) {
            out.push_back(s[i++]);
            continue;
        }
        const std::string ent = s.substr(i + 1, semi - i - 1);
        bool ok = true;
        if (ent == "amp") out.push_back('&');
        else if (ent == "lt") out.push_back('<');
        else if (ent == "gt") out.push_back('>');
        else if (ent == "quot") out.push_back('"');
        else if (ent == "apos") out.push_back('\'');
        else if (ent.size() > 1 && ent[0] == '#') {
            const bool hex = ent[1] == 'x' || ent[1] == 'X';
            const char* digits = ent.c_str() + (hex ? 2 : 1);
            char* end = nullptr;
            const unsigned long cp = std::strtoul(digits, &end, hex ? 16 : 10);
            ok = *digits != '\0' && end && *end == '\0' && cp != 0 &&
                 cp <= 0x10ffff && (cp < 0xd800 || cp > 0xdfff);
            if (ok) append_utf8(&out, cp);
        } else {
            ok = false;
        }
        if (!ok) out.append(s, i, semi - i + 1);
        i = semi + 1;
    }
    return out;
}

bool is_xml_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

// Text inside another attribute's value is never taken for an attribute.
bool xml_attribute(const std::string& attrs, const std::string& name,
                   std::string* value)
{
    const std::size_t n = attrs.size();
    std::size_t i = 0;
    while (i < n) {
        while (i < n && is_xml_space(attrs[i])) ++i;
        const std::size_t key_start = i;
        while (i < n && !is_xml_space(attrs[i]) && attrs[i] != '=') ++i;
        const std::string key = attrs.substr(key_start, i - key_start);
        while (i < n && is_xml_space(attrs[i])) ++i;
        if (i >= n || attrs[i] != '=') {
            if (i == key_start) ++i;  // stray character
            continue;
        }
        ++i;
        while (i < n && is_xml_space(attrs[i])) ++i;
        if (i >= n || (attrs[i] != '"' && attrs[i] != '\'')) return false;
        const std::size_t vend = attrs.find(attrs[i], i + 1);
        if (vend == std::string::npos) return false;
        if (key == name) {
            *value = attrs.substr(i + 1, vend - i - 1);
            return true;
        }
        i = vend + 1;
    }
    return false;
}

// A '>' inside a quoted attribute value does not end the tag.
std::size_t xml_tag_end(const std::string& xml, std::size_t pos)
{
    char quote = 0;
    for (; pos < xml.size(); ++pos) {
        const char c = xml[pos];
        if (quote) {
            if (c == quote) quote = 0;
        } else if (c == '"' || c == '\'') {
            quote = c;
        } else if (c == '>') {
            return pos;
        }
    }
    return std::string::npos;
}

// Empty when the element is unterminated or has child elements.
std::string xml_element_text(const std::string& xml, std::size_t pos,
                             const std::string& close_tag)
{
    std::string out;
    while (pos < xml.size()) {
        const std::size_t lt = xml.find('<', pos);
        if (lt == std::string::npos) return {};
        out += decode_xml_text(xml.substr(pos, lt - pos));
        if (xml.compare(lt, 9, "<![CDATA[") == 0) {
            const std::size_t e = xml.find("]]>", lt + 9);
            if (e == std::string::npos) return {};
            out.append(xml, lt + 9, e - lt - 9);
            pos = e + 3;
        } else if (xml.compare(lt, 4, "<!--") == 0) {
            const std::size_t e = xml.find("-->", lt + 4);
            if (e == std::string::npos) return {};
            pos = e + 3;
        } else if (xml.compare(lt, close_tag.size(), close_tag) == 0) {
            return out;
        } else {
            return {};
        }
    }
    return {};
}

// A Title inside a comment, CDATA section or processing instruction does not count.
std::string model_title_from_3dmodel(const std::string& xml)
{
    static const std::string kOpen = "<metadata";
    std::size_t pos = 0;
    while ((pos = xml.find('<', pos)) != std::string::npos) {
        const char* skip_to = nullptr;
        std::size_t skip_from = 0;
        if (xml.compare(pos, 4, "<!--") == 0) {
            skip_to = "-->";
            skip_from = pos + 4;
        } else if (xml.compare(pos, 9, "<![CDATA[") == 0) {
            skip_to = "]]>";
            skip_from = pos + 9;
        } else if (xml.compare(pos, 2, "<?") == 0) {
            skip_to = "?>";
            skip_from = pos + 2;
        }
        if (skip_to) {
            const std::size_t e = xml.find(skip_to, skip_from);
            if (e == std::string::npos) break;
            pos = e + std::strlen(skip_to);
            continue;
        }
        const std::size_t after = pos + kOpen.size();
        if (xml.compare(pos, kOpen.size(), kOpen) != 0 ||
            (after < xml.size() && !is_xml_space(xml[after]) &&
             xml[after] != '>' && xml[after] != '/')) {
            ++pos;  // another element, or <metadatagroup> and the like
            continue;
        }
        const std::size_t tag_end = xml_tag_end(xml, after);
        if (tag_end == std::string::npos) break;
        std::string attrs = xml.substr(after, tag_end - after);
        pos = tag_end + 1;
        const bool self_closing = !attrs.empty() && attrs.back() == '/';
        if (self_closing) attrs.pop_back();
        std::string name;
        if (!xml_attribute(attrs, "name", &name) || name != "Title") continue;
        if (self_closing) return {};
        return xml_element_text(xml, pos, "</metadata");
    }
    return {};
}

// run_sub_file() keeps only images. wire_result 0 with !ok: the reply did not complete.
SubFileOutcome run_sub_file_data(obn::tunnel_local::Session* session,
                                 SSL* ssl, std::mutex* io_mu, std::uint32_t seq,
                                 const std::string& path,
                                 const std::string& storage,
                                 std::size_t        max_bytes)
{
    SubFileOutcome out;
    drain_stale_wire_json(session, "pre-sub_file");

    const std::string abi =
        obn::tunnel_local::build_sub_file_abi(seq, {path}, storage);
    if (session->send_abi_json(ssl, abi, io_mu) != 0) {
        out.error = obn::tunnel_local::describe_ssl_io_error(ssl);
        return out;
    }

    const auto deadline = std::chrono::steady_clock::now() + kTitleReadDeadline;
    const auto fail = [&out](std::string why) {
        out.wire_result = 0;
        out.error = std::move(why);
        return out;
    };
    const NonBlockingScope nonblocking(ssl);
    if (!nonblocking.ok()) return fail("socket not switched to non-blocking");
    for (;;) {
        std::vector<std::uint8_t> payload;
        const int rc = session->recv_payload_until(ssl, &payload, io_mu, deadline);
        if (rc == 2) {
            out.timed_out = true;
            return fail("sub_file reply timeout");
        }
        if (rc < 0) return fail(obn::tunnel_local::describe_ssl_io_error(ssl));
        if (rc > 0) {
            if (wait_ssl_readable(ssl, 100) < 0) {
                return fail(obn::tunnel_local::describe_ssl_io_error(ssl));
            }
            continue;
        }

        std::string wire_json;
        std::vector<std::uint8_t> chunk;
        if (!obn::tunnel_local::split_json_prefix(payload.data(), payload.size(),
                                                  &wire_json, &chunk)) {
            wire_json.assign(reinterpret_cast<const char*>(payload.data()),
                             payload.size());
        }
        if (obn::tunnel_local::parse_wire_cmdtype(wire_json) !=
                obn::tunnel_local::kCmdSubFile ||
            static_cast<std::uint32_t>(
                obn::tunnel_local::parse_wire_sequence(wire_json)) != seq) {
            continue;
        }
        if (out.data.size() < max_bytes) {
            const std::size_t take =
                std::min(chunk.size(), max_bytes - out.data.size());
            out.data.insert(out.data.end(), chunk.begin(),
                            chunk.begin() + static_cast<std::ptrdiff_t>(take));
        }
        const int result = obn::tunnel_local::parse_wire_result(wire_json);
        if (result == 1) continue;
        out.wire_result = result;
        out.ok = result == 0;
        if (!out.ok) {
            out.error = "sub_file failed wire result=" + std::to_string(result);
        }
        return out;
    }
}

// Printer-state codes (research/09.05-ctrl.md) are retried; others are cached as final.
bool title_refusal_is_final(int result)
{
    switch (result) {
    case -1:  // no numeric result
    case 3:   // ERROR_PIPE
    case 4:   // ERROR_CANCEL
    case 5:   // ERROR_RES_BUSY
    case 6:   // ERROR_TIME_OUT
    case 17:  // STORAGE_UNAVAILABLE
    case 20:  // STORAGE_SPACE_NOT_ENOUGH
    case 25:  // SEND_ERR
        return false;
    default:
        return true;
    }
}

// Refused file: answered, empty title. !answered: uncached until a second timeout.
struct TitleRead {
    bool        answered = false;
    std::string title;
    bool        timed_out = false;  // no complete reply before the deadline
};
using TitleReader =
    std::function<TitleRead(const std::string& path, const std::string& storage)>;
using TileFetcher = std::function<bool(
    const ModelFileEntry& hit, const std::string& storage, std::string* failures)>;

// Two timeouts cache a file untitled (research/09.06-commands.md: raw size limit).
struct TitleScope {
    std::unordered_map<std::string, std::string> titles;
    std::unordered_set<std::string>              timed_out;  // once so far
};

// Scope (printer + storage) -> TitleScope by path + '\x01' + mtime, current candidates.
std::mutex g_title_mu;
std::unordered_map<std::string, TitleScope> g_titles;

// With no budget left, stops at the first unknown title: cache history never picks.
const ModelFileEntry* find_model_entry_by_title(const ListInfoOutcome& list,
                                                const std::string& list_storage,
                                                const std::string& scope,
                                                const std::string& model_name,
                                                int*               reads_left,
                                                const TitleReader& read_title,
                                                bool*              transport,
                                                bool*              exhausted)
{
    std::vector<const ModelFileEntry*> order;
    for (const auto& f : list.files) {
        if (ends_with(f.name, ".3mf") || ends_with(f.path, ".3mf")) {
            order.push_back(&f);
        }
    }
    std::stable_sort(order.begin(), order.end(),
                     [](const ModelFileEntry* a, const ModelFileEntry* b) {
                         return a->time > b->time;
                     });
    if (order.size() > kMaxTitleCandidates) order.resize(kMaxTitleCandidates);

    const auto key_of = [](const ModelFileEntry& f) {
        return f.path + "\x01" + std::to_string(f.time);
    };
    {
        // Bounded, and never drops a title a rescan of this listing still needs.
        std::lock_guard<std::mutex> lk(g_title_mu);
        if (g_titles.size() >= kMaxTitleScopes && !g_titles.count(scope)) {
            g_titles.clear();
        }
        auto& cached = g_titles[scope];
        TitleScope kept;
        for (const ModelFileEntry* f : order) {
            const std::string key = key_of(*f);
            const auto it = cached.titles.find(key);
            if (it != cached.titles.end()) kept.titles.emplace(key, it->second);
            if (cached.timed_out.count(key)) kept.timed_out.insert(key);
        }
        std::swap(cached, kept);
    }

    for (const ModelFileEntry* f : order) {
        const std::string key = key_of(*f);
        std::string title;
        bool        known = false;
        {
            std::lock_guard<std::mutex> lk(g_title_mu);
            const auto& cached = g_titles[scope].titles;
            const auto it = cached.find(key);
            if (it != cached.end()) {
                title = it->second;
                known = true;
            }
        }
        if (!known) {
            if (*reads_left <= 0) {
                *exhausted = true;
                return nullptr;
            }
            --*reads_left;
            const TitleRead r = read_title(f->path, list_storage);
            if (!r.answered) {
                *transport = true;
                if (r.timed_out) {
                    std::lock_guard<std::mutex> lk(g_title_mu);
                    auto& s = g_titles[scope];
                    // A title another fetch read meanwhile wins over this timeout.
                    if (!s.titles.count(key) && !s.timed_out.insert(key).second) {
                        s.timed_out.erase(key);
                        s.titles[key] = "";
                        OBN_DEBUG("tunnel_upload: 3MF title of %s: timed out twice",
                                  f->path.c_str());
                    }
                }
                return nullptr;
            }
            title = r.title;
            OBN_DEBUG("tunnel_upload: 3MF title of %s: '%s'", f->path.c_str(),
                      title.c_str());
            std::lock_guard<std::mutex> lk(g_title_mu);
            g_titles[scope].titles[key] = title;
        }
        if (!title.empty() && title == model_name) {
            OBN_DEBUG("tunnel_upload: '%s' matched by 3MF title: %s",
                      model_name.c_str(), f->path.c_str());
            return f;
        }
    }
    return nullptr;
}

// A listing the budget left unfinished ends the pass, so a cached later one can't win.
const ModelFileEntry* match_model_by_title(
    const std::vector<std::pair<std::string, ListInfoOutcome>>& unmatched,
    const std::string& printer, const std::string& model_name,
    const TitleReader& read_title, const TileFetcher& fetch_tile,
    std::string* error)
{
    int         reads_left  = kMaxTitleReadsPerFetch;
    bool        tile_failed = false;
    std::string tile_failures;
    for (const auto& [storage, list] : unmatched) {
        bool transport = false;
        bool exhausted = false;
        const ModelFileEntry* hit = find_model_entry_by_title(
            list, storage, printer + "\x01" + storage, model_name, &reads_left,
            read_title, &transport, &exhausted);
        if (transport) {
            *error = "3MF title read failed";
            return nullptr;
        }
        if (exhausted) break;
        if (!hit) continue;
        if (fetch_tile(*hit, storage, &tile_failures)) return hit;
        tile_failed = true;
    }
    if (tile_failed) *error = "SUB_FILE thumbnail failed (" + tile_failures + ")";
    return nullptr;
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

    // Log the raw ability reply so `storage` vs `upload_storage` (the
    // writable subset we now prefer) is inspectable without decrypting
    // the TLS :6000 session in Wireshark.
    OBN_DEBUG("tunnel_upload: media-ability reply: %s", wire_json.c_str());

    std::string body = obn::tunnel_local::parse_ability_reply_to_ft_json(wire_json);
    if (body.empty()) {
        out.error = "bad ability reply";
        return out;
    }
    out.ok = true;
    out.json_body = std::move(body);
    return out;
}

DownloadOutcome Connection::download(const DownloadRequest& req, DownloadCallbacks cb)
{
    DownloadOutcome out;
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

    return run_download(session, ssl, &impl_->io_mu, seq, req, cb);
}

ModelThumbnailOutcome Connection::fetch_model_tile_thumbnail(
    const std::string& model_name, int plate_idx)
{
    ModelThumbnailOutcome out;
    // Listings without a file-name match, for the 3MF title pass.
    std::vector<std::pair<std::string, ListInfoOutcome>> unmatched;
    const auto next_wire = [this](std::uint32_t* seq, SSL** ssl,
                                  obn::tunnel_local::Session** session) {
        std::lock_guard<std::mutex> lk(impl_->io_mu);
        *seq     = impl_->wire_seq++;
        *ssl     = impl_->ssl;
        *session = impl_->session.get();
    };
    const auto fetch_tile = [&](const ModelFileEntry& hit,
                                const std::string&    list_storage,
                                std::string*          failures) {
        for (const auto& wire_storage : sub_file_storage_labels(list_storage)) {
            std::uint32_t seq = 0;
            SSL* ssl = nullptr;
            obn::tunnel_local::Session* session = nullptr;
            next_wire(&seq, &ssl, &session);

            SubFileRequest req;
            req.paths   = tile_thumbnail_sub_paths(hit.path, plate_idx);
            req.storage = wire_storage;
            const SubFileOutcome sf =
                run_sub_file(session, ssl, &impl_->io_mu, seq, req);
            if (!sf.ok || sf.data.empty() || !wire_chunk_is_image(sf.data)) {
                append_storage_failure(failures, wire_storage, sf.error);
                continue;
            }
            out.ok   = true;
            out.path = hit.path;
            out.data = sf.data;
            return true;
        }
        return false;
    };
    if (!is_connected()) {
        out.error = "not connected";
        return out;
    }
    if (model_name.empty()) {
        out.error = "missing model name";
        return out;
    }
    if (plate_idx < 1) plate_idx = 1;

    // A printer can refuse every listing, e.g. result 17 STORAGE_UNAVAILABLE
    // (research/09.05-ctrl.md §9.5.3); that must not read as a missing model.
    std::string list_failures;
    bool        any_list_ok = false;

    for (const auto& list_storage : model_list_storages()) {
        std::uint32_t seq = 0;
        SSL* ssl = nullptr;
        obn::tunnel_local::Session* session = nullptr;
        {
            std::lock_guard<std::mutex> lk(impl_->io_mu);
            seq = impl_->wire_seq++;
            ssl = impl_->ssl;
            session = impl_->session.get();
        }

        const ListInfoOutcome list =
            run_list_info(session, ssl, &impl_->io_mu, seq, list_storage);
        if (!list.ok) {
            append_storage_failure(&list_failures, list_storage, list.error);
            continue;
        }
        any_list_ok = true;

        const ModelFileEntry* hit = find_model_entry(list, model_name);
        if (!hit) {
            unmatched.emplace_back(list_storage, list);
            continue;
        }
        std::string sub_failures;
        if (fetch_tile(*hit, list_storage, &sub_failures)) return out;
        out.error = "SUB_FILE thumbnail failed (" + sub_failures + ")";
        return out;
    }
    if (!unmatched.empty()) {
        // A print started on the printer reports its 3MF title, not the file name.
        const TitleReader read_title = [&](const std::string& path,
                                           const std::string& storage) {
            TitleRead r;
            bool transient = false;
            const bool fd_ok = obn::os::socket_valid(impl_->fd);
            if (fd_ok) obn::tls::set_socket_io_timeout(impl_->fd, kTitleReadPollMs);
            for (const auto& label : sub_file_storage_labels(storage)) {
                std::uint32_t seq = 0;
                SSL* ssl = nullptr;
                obn::tunnel_local::Session* session = nullptr;
                next_wire(&seq, &ssl, &session);
                const SubFileOutcome sf = run_sub_file_data(
                    session, ssl, &impl_->io_mu, seq, path + "#3D/3dmodel.model",
                    label, kMaxModelXmlBytes);
                if (sf.ok) {
                    r.answered = true;
                    r.title    = model_title_from_3dmodel(
                        std::string(sf.data.begin(), sf.data.end()));
                    transient  = false;
                    break;
                }
                if (sf.wire_result == 0) {  // no complete reply
                    r = TitleRead{};
                    r.timed_out = sf.timed_out;
                    transient = false;
                    break;
                }
                // A transient refusal stays uncached unless another label answers.
                if (!title_refusal_is_final(sf.wire_result)) transient = true;
                r.answered = true;
            }
            if (transient) r = TitleRead{};
            if (fd_ok) obn::tls::clear_socket_io_timeout(impl_->fd);
            return r;
        };
        const std::string printer =
            impl_->params.dev_id.empty() ? impl_->params.dev_ip : impl_->params.dev_id;
        std::string title_error;
        if (match_model_by_title(unmatched, printer, model_name, read_title,
                                 fetch_tile, &title_error)) {
            return out;
        }
        if (!title_error.empty()) {
            out.error = title_error;
            return out;
        }
    }

    if (!any_list_ok && !list_failures.empty()) {
        out.error = "LIST_INFO failed (" + list_failures + ")";
    } else if (!list_failures.empty()) {
        out.error = "model not in LIST_INFO (failed: " + list_failures + ")";
    } else {
        out.error = "model not in LIST_INFO";
    }
    return out;
}

int upload_file(const ConnectParams& connect,
                const UploadRequest& upload,
                UploadCallbacks cb,
                UploadOutcome* out,
                int err_code_on_failure)
{
    if (out) *out = {};

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

#ifdef OBN_TESTING
// Title fallback hooks, driven by a scripted title reader and tile fetcher.
using TestFiles = std::vector<std::tuple<std::string, std::string, std::int64_t>>;
using TestRead  = std::function<std::pair<bool, std::string>(const std::string&,
                                                             const std::string&)>;

namespace {
ListInfoOutcome test_listing(const TestFiles& files)
{
    ListInfoOutcome list;
    list.ok = true;
    for (const auto& f : files) {
        list.files.push_back({std::get<0>(f), std::get<1>(f), std::get<2>(f)});
    }
    return list;
}

// {false, "timeout"}: no complete reply by the deadline; other {false, ...}: none.
TitleReader test_reader(const TestRead& read)
{
    return [read](const std::string& path, const std::string& storage) {
        const auto r = read(path, storage);
        if (!r.first) return TitleRead{false, {}, r.second == "timeout"};
        return TitleRead{true, r.second};
    };
}
} // namespace

std::string test_model_title_from_3dmodel(const std::string& xml)
{
    return model_title_from_3dmodel(xml);
}

bool test_title_refusal_is_final(int result)
{
    return title_refusal_is_final(result);
}

std::string test_find_model_entry_by_title(const TestFiles& files,
                                           const std::string& list_storage,
                                           const std::string& scope,
                                           const std::string& model_name,
                                           int* reads_left, const TestRead& read,
                                           bool* transport)
{
    const ListInfoOutcome list = test_listing(files);
    bool exhausted = false;
    const ModelFileEntry* hit = find_model_entry_by_title(
        list, list_storage, scope, model_name, reads_left, test_reader(read),
        transport, &exhausted);
    return hit ? hit->path : std::string{};
}

std::string test_match_model_by_title(
    const std::vector<std::pair<std::string, TestFiles>>& listings,
    const std::string& printer, const std::string& model_name,
    const TestRead& read,
    const std::function<bool(const std::string&, const std::string&,
                             std::string*)>& tile,
    std::string* error)
{
    std::vector<std::pair<std::string, ListInfoOutcome>> unmatched;
    for (const auto& l : listings) {
        unmatched.emplace_back(l.first, test_listing(l.second));
    }
    const ModelFileEntry* hit = match_model_by_title(
        unmatched, printer, model_name, test_reader(read),
        [&tile](const ModelFileEntry& f, const std::string& storage,
                std::string* failures) { return tile(f.path, storage, failures); },
        error);
    return hit ? hit->path : std::string{};
}

void test_clear_title_cache()
{
    std::lock_guard<std::mutex> lk(g_title_mu);
    g_titles.clear();
}

std::size_t test_title_cache_size(const std::string& scope)
{
    std::lock_guard<std::mutex> lk(g_title_mu);
    const auto it = g_titles.find(scope);
    return it == g_titles.end() ? 0 : it->second.titles.size();
}
#endif

} // namespace obn::tunnel_upload
