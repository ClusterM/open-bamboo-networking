#include "obn/tunnel_upload.hpp"

#include "obn/json_lite.hpp"

#include "obn/bambu_networking.hpp"
#include "obn/lan_tls.hpp"
#include "obn/log.hpp"
#include "obn/net_compat.hpp"
#include "obn/tls_dial.hpp"
#include "obn/tunnel_local.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <cstring>
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
};

bool wire_chunk_is_image(const std::vector<std::uint8_t>& chunk)
{
    if (chunk.size() >= 8 &&
        std::memcmp(chunk.data(), "\x89PNG\r\n\x1a\n", 8) == 0) {
        return true;
    }
    return chunk.size() >= 2 && chunk[0] == 0xff && chunk[1] == 0xd8;
}

SubFileOutcome run_sub_file(obn::tunnel_local::Session* session,
                            SSL* ssl, std::mutex* io_mu, std::uint32_t seq,
                            const SubFileRequest& req)
{
    SubFileOutcome out;
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
            if (!chunk.empty() && wire_chunk_is_image(chunk)) {
                out.data = chunk;
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
    if (!is_connected()) {
        out.error = "not connected";
        return out;
    }
    if (model_name.empty()) {
        out.error = "missing model name";
        return out;
    }
    if (plate_idx < 1) plate_idx = 1;

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
        if (!list.ok) continue;

        const ModelFileEntry* hit = find_model_entry(list, model_name);
        if (!hit) continue;

        for (const auto& wire_storage : sub_file_storage_labels(list_storage)) {
            {
                std::lock_guard<std::mutex> lk(impl_->io_mu);
                seq = impl_->wire_seq++;
                ssl = impl_->ssl;
                session = impl_->session.get();
            }

            SubFileRequest req;
            req.paths   = tile_thumbnail_sub_paths(hit->path, plate_idx);
            req.storage = wire_storage;
            const SubFileOutcome sf =
                run_sub_file(session, ssl, &impl_->io_mu, seq, req);
            if (!sf.ok || sf.data.empty() || !wire_chunk_is_image(sf.data)) {
                continue;
            }
            out.ok   = true;
            out.path = hit->path;
            out.data = sf.data;
            return out;
        }
        out.error = "SUB_FILE thumbnail failed";
        return out;
    }

    out.error = "model not in LIST_INFO";
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

} // namespace obn::tunnel_upload
