#pragma once

// Shared TLS :6000 connect + chunked FILE_UPLOAD (cmd_type=5) pipeline.
// Used by ft_* ABI (Send-to-Printer) and LAN print jobs (start_local_print).

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace obn::tunnel_upload {

struct ConnectParams {
    std::string dev_ip;
    std::string dev_id;   // TLS SNI / CN check (serial)
    int         port = 6000;
    std::string username{"bblp"};
    std::string password;
    std::string client_id;  // random UUID when empty
    std::string client_ver; // OBN_VERSION_STRING when empty
};

struct UploadRequest {
    std::string local_path;
    std::string dest_storage;  // "emmc" / "udisk"
    std::string dest_name;
};

struct UploadCallbacks {
    std::function<bool()>     cancelled;  // true => abort
    std::function<void(int)>  progress;   // 0..100, optional
};

struct UploadOutcome {
    bool          ok = false;
    std::uint64_t bytes = 0;
    std::string   md5_lower;
    int           wire_result = 0;
    std::string   error;
    std::string   json_body;  // media ability reply array
};

class Connection {
public:
    Connection();
    ~Connection();

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    // TLS dial + BambuTunnelLocal handshake. Returns 0 on success.
    int connect(const ConnectParams& p, std::string* err_out = nullptr);
    void disconnect();
    bool is_connected() const;

    UploadOutcome upload(const UploadRequest& req, UploadCallbacks cb = {});

    // cmd_type=7 media ability; returns JSON array string on success.
    UploadOutcome query_media_ability();

    std::uint32_t next_wire_seq();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Connect, upload, disconnect. Returns 0 on success or a BAMBU_NETWORK_ERR_* code.
int upload_file(const ConnectParams& connect,
                const UploadRequest& upload,
                UploadCallbacks cb,
                UploadOutcome* out,
                int err_code_on_failure);

ConnectParams connect_params_from_print(const std::string& dev_ip,
                                        const std::string& dev_id,
                                        const std::string& password);

} // namespace obn::tunnel_upload
