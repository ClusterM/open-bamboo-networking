// In-process mock servers mimicking a real Bambu Lab printer's LAN endpoints,
// captured from a live H2D. Two servers are provided:
//
//   lanmock::FtpsMock       - implicit FTPS (vsFTPd 3.0.5), TLS on control +
//                             PASV/EPSV data channel, records STOR uploads.
//   lanmock::MqttBrokerMock - plaintext MQTT 3.1.1 broker, records PUBLISH
//                             and SUBSCRIBE traffic.
//
// Socket/threading style mirrors tests/wire_compliance_test.cpp MockServer:
// a background acceptor thread on a blocking loop, bind 127.0.0.1:0, a
// stop flag + closed listen fd for shutdown, mutex-guarded record vectors.
//
// Header-only; OpenSSL + POSIX sockets + std only.

#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cctype>
#include <cerrno>
#include <functional>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace lanmock {

// ---------------------------------------------------------------------------
// One-time OpenSSL init (safe if two mock instances exist).
// ---------------------------------------------------------------------------
inline void ensure_ssl_init() {
    static std::atomic<bool> done{false};
    static std::mutex m;
    if (done.load()) return;
    std::lock_guard<std::mutex> lk(m);
    if (done.load()) return;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    done.store(true);
}

// ---------------------------------------------------------------------------
// Generate a fresh self-signed RSA-2048 cert + key (CN=127.0.0.1, 10y validity)
// for the mock TLS endpoints. Returns false on any OpenSSL error. The same
// keypair doubles as the test slicer signing key and the seeded printer pubkey,
// so cert and key must match -- generating them here keeps that guaranteed and
// avoids an opaque baked-in PEM blob.
// ---------------------------------------------------------------------------
inline bool make_self_signed(std::string& cert_pem, std::string& key_pem) {
    ensure_ssl_init();
    cert_pem.clear();
    key_pem.clear();

    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    if (!pkey) return false;
    X509* x = X509_new();
    if (!x) { EVP_PKEY_free(pkey); return false; }

    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 3650);
    X509_set_pubkey(x, pkey);
    X509_NAME* nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("127.0.0.1"),
                               -1, -1, 0);
    X509_set_issuer_name(x, nm);   // self-signed: issuer == subject
    bool ok = X509_sign(x, pkey, EVP_sha256()) != 0;

    auto dump = [](std::string& out, const std::function<int(BIO*)>& write) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) return false;
        bool w = write(bio) != 0;
        if (w) {
            char* p = nullptr;
            long n = BIO_get_mem_data(bio, &p);
            out.assign(p, static_cast<size_t>(n));
        }
        BIO_free(bio);
        return w;
    };
    ok = ok && dump(key_pem, [&](BIO* b) {
        return PEM_write_bio_PrivateKey(b, pkey, nullptr, nullptr, 0, nullptr,
                                        nullptr);
    });
    ok = ok && dump(cert_pem, [&](BIO* b) { return PEM_write_bio_X509(b, x); });

    X509_free(x);
    EVP_PKEY_free(pkey);
    return ok;
}

// ---------------------------------------------------------------------------
// Small socket helpers.
// ---------------------------------------------------------------------------
inline int make_listener(int& out_port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (::bind(fd, (sockaddr*)&a, sizeof a) < 0) { ::close(fd); return -1; }
    socklen_t len = sizeof a;
    ::getsockname(fd, (sockaddr*)&a, &len);
    out_port = ntohs(a.sin_port);
    if (::listen(fd, 16) < 0) { ::close(fd); return -1; }
    return fd;
}

// Blocking read of a single CRLF-terminated line from a plaintext socket.
// Returns false on EOF/error before any data.
inline bool recv_line_plain(int fd, std::string& line) {
    line.clear();
    char ch;
    while (true) {
        ssize_t n = ::recv(fd, &ch, 1, 0);
        if (n <= 0) return !line.empty();
        if (ch == '\n') {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            return true;
        }
        line.push_back(ch);
    }
}

// Blocking read of a single CRLF-terminated line from a TLS socket.
inline bool recv_line_ssl(SSL* ssl, std::string& line) {
    line.clear();
    char ch;
    while (true) {
        int n = SSL_read(ssl, &ch, 1);
        if (n <= 0) return !line.empty();
        if (ch == '\n') {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            return true;
        }
        line.push_back(ch);
    }
}

inline void send_ssl_str(SSL* ssl, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        int n = SSL_write(ssl, s.data() + off, (int)(s.size() - off));
        if (n <= 0) return;
        off += (size_t)n;
    }
}

inline void send_all_plain(int fd, const uint8_t* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::send(fd, data + off, len - off, 0);
        if (n <= 0) return;
        off += (size_t)n;
    }
}

// ---------------------------------------------------------------------------
// CLASS 1: FtpsMock - implicit FTPS control channel + TLS data channel.
// ---------------------------------------------------------------------------
class FtpsMock {
public:
    struct Stor {
        std::string path;
        size_t bytes;
        std::string md5_hex;
    };

    FtpsMock(const std::string& cert_pem_path, const std::string& key_pem_path) {
        ensure_ssl_init();
        ctx_ = SSL_CTX_new(TLS_server_method());
        if (ctx_) {
            SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
            // The FTPS data channel is write-only for STOR: the client never
            // reads it, so any post-handshake TLS 1.3 NewSessionTicket we emit
            // sits unread in the client's buffer and its close() becomes an RST
            // that truncates our read. Disable session tickets so the upload
            // always ends with a clean close_notify.
            SSL_CTX_set_num_tickets(ctx_, 0);
            SSL_CTX_set_options(ctx_, SSL_OP_NO_TICKET);
            if (SSL_CTX_use_certificate_file(ctx_, cert_pem_path.c_str(), SSL_FILETYPE_PEM) <= 0)
                std::fprintf(stderr, "FtpsMock: failed to load cert %s\n", cert_pem_path.c_str());
            if (SSL_CTX_use_PrivateKey_file(ctx_, key_pem_path.c_str(), SSL_FILETYPE_PEM) <= 0)
                std::fprintf(stderr, "FtpsMock: failed to load key %s\n", key_pem_path.c_str());
        }
        fd_ = make_listener(port_);
        if (fd_ >= 0) {
            timeval tv{0, 200000};
            ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            th_ = std::thread([this] { loop(); });
        }
    }

    ~FtpsMock() {
        stop_ = true;
        if (fd_ >= 0) ::shutdown(fd_, SHUT_RDWR);
        if (th_.joinable()) th_.join();
        {
            std::lock_guard<std::mutex> lk(workers_mu_);
            for (auto& t : workers_) if (t.joinable()) t.join();
        }
        if (fd_ >= 0) ::close(fd_);
        if (ctx_) SSL_CTX_free(ctx_);
    }

    int port() const { return port_; }

    std::vector<Stor> stors() const {
        std::lock_guard<std::mutex> lk(mu_);
        return stors_;
    }

    // Directory-listing support (LIST/MLSD/NLST). The reply defaults to a small
    // vsFTPd-style listing; override with set_listing(). list_count() reports how
    // many LIST-family commands were served.
    int  list_count() const { return list_count_.load(); }
    void set_listing(std::string l) { std::lock_guard<std::mutex> lk(mu_); listing_ = std::move(l); }

private:
    void loop() {
        while (!stop_) {
            int c = ::accept(fd_, nullptr, nullptr);
            if (c < 0) continue;
            std::lock_guard<std::mutex> lk(workers_mu_);
            workers_.emplace_back([this, c] { handle_control(c); });
        }
    }

    void handle_control(int c) {
        SSL* ssl = SSL_new(ctx_);
        if (!ssl) { ::close(c); return; }
        SSL_set_fd(ssl, c);
        if (SSL_accept(ssl) <= 0) {
            std::fprintf(stderr, "FtpsMock: control SSL_accept failed\n");
            SSL_free(ssl);
            ::close(c);
            return;
        }

        bool prot_private = false;
        int data_listen_fd = -1;
        int data_listen_port = 0;

        send_ssl_str(ssl, "220 (vsFTPd 3.0.5)\r\n");

        std::string line;
        while (recv_line_ssl(ssl, line)) {
            std::string verb, arg;
            {
                size_t sp = line.find(' ');
                if (sp == std::string::npos) { verb = line; }
                else { verb = line.substr(0, sp); arg = line.substr(sp + 1); }
            }
            std::string uv = upper(verb);

            if (uv == "USER") {
                send_ssl_str(ssl, "331 Please specify the password.\r\n");
            } else if (uv == "PASS") {
                send_ssl_str(ssl, "230 Login successful.\r\n");
            } else if (uv == "PBSZ") {
                send_ssl_str(ssl, "200 PBSZ set to 0.\r\n");
            } else if (uv == "PROT") {
                prot_private = true;
                send_ssl_str(ssl, "200 PROT now Private.\r\n");
            } else if (uv == "PWD" || uv == "XPWD") {
                send_ssl_str(ssl, "257 \"/\" is the current directory\r\n");
            } else if (uv == "TYPE") {
                send_ssl_str(ssl, "200 Switching to Binary mode.\r\n");
            } else if (uv == "CWD") {
                send_ssl_str(ssl, "250 Directory successfully changed.\r\n");
            } else if (uv == "SIZE") {
                send_ssl_str(ssl, "213 0\r\n");
            } else if (uv == "PASV") {
                close_data_listener(data_listen_fd);
                data_listen_fd = make_listener(data_listen_port);
                if (data_listen_fd < 0) {
                    send_ssl_str(ssl, "425 Can't open data connection.\r\n");
                } else {
                    int p1 = (data_listen_port >> 8) & 0xff;
                    int p2 = data_listen_port & 0xff;
                    char buf[96];
                    std::snprintf(buf, sizeof buf,
                                  "227 Entering Passive Mode (127,0,0,1,%d,%d)\r\n", p1, p2);
                    send_ssl_str(ssl, buf);
                }
            } else if (uv == "EPSV") {
                close_data_listener(data_listen_fd);
                data_listen_fd = make_listener(data_listen_port);
                if (data_listen_fd < 0) {
                    send_ssl_str(ssl, "425 Can't open data connection.\r\n");
                } else {
                    char buf[96];
                    std::snprintf(buf, sizeof buf,
                                  "229 Entering Extended Passive Mode (|||%d|)\r\n",
                                  data_listen_port);
                    send_ssl_str(ssl, buf);
                }
            } else if (uv == "STOR") {
                send_ssl_str(ssl, "150 Ok to send data.\r\n");
                handle_stor(arg, data_listen_fd, prot_private);
                close_data_listener(data_listen_fd);
                send_ssl_str(ssl, "226 Transfer complete.\r\n");
            } else if (uv == "LIST" || uv == "NLST" || uv == "MLSD") {
                send_ssl_str(ssl, "150 Here comes the directory listing.\r\n");
                handle_list(data_listen_fd, prot_private);
                close_data_listener(data_listen_fd);
                send_ssl_str(ssl, "226 Directory send OK.\r\n");
            } else if (uv == "DELE") {
                send_ssl_str(ssl, "250 Delete operation successful.\r\n");
            } else if (uv == "QUIT") {
                send_ssl_str(ssl, "221 Goodbye.\r\n");
                break;
            } else {
                // MDTM / FEAT / OPTS / NOOP / anything else: be permissive.
                send_ssl_str(ssl, "200 Command okay.\r\n");
            }
        }

        close_data_listener(data_listen_fd);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ::close(c);
    }

    void handle_stor(const std::string& name, int data_listen_fd, bool prot_private) {
        if (data_listen_fd < 0) return;
        int dc = ::accept(data_listen_fd, nullptr, nullptr);
        if (dc < 0) {
            std::fprintf(stderr, "FtpsMock: data accept failed\n");
            return;
        }
        // The accepted data socket inherits the listener's SO_RCVTIMEO on Linux;
        // clear it so SSL_read blocks until the real EOF and never truncates a
        // multi-record upload mid-transfer.
        struct timeval no_to{0, 0};
        ::setsockopt(dc, SOL_SOCKET, SO_RCVTIMEO, &no_to, sizeof no_to);

        EVP_MD_CTX* md = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md, EVP_md5(), nullptr);
        size_t total = 0;

        SSL* dssl = nullptr;
        if (prot_private) {
            dssl = SSL_new(ctx_);
            if (dssl) {
                SSL_set_fd(dssl, dc);
                if (SSL_accept(dssl) <= 0) {
                    std::fprintf(stderr, "FtpsMock: data SSL_accept failed\n");
                    SSL_free(dssl);
                    dssl = nullptr;
                    EVP_MD_CTX_free(md);
                    ::close(dc);
                    return;
                }
            }
        }

        char buf[16384];
        int idle = 0;
        while (true) {
            int n;
            if (dssl) n = SSL_read(dssl, buf, sizeof buf);
            else      n = (int)::recv(dc, buf, sizeof buf, 0);
            if (n <= 0) {
                // A recv timeout (SO_RCVTIMEO inherited from the listener) shows up
                // as SSL_ERROR_SYSCALL/EAGAIN or a bare EAGAIN — that is "no data
                // yet", NOT end of file. Only a clean close (ZERO_RETURN / 0-length
                // recv) ends the upload. Bound the idle spins so a genuinely dead
                // peer can't hang the mock.
                int err = dssl ? SSL_get_error(dssl, n) : 0;
                bool again = (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                          || ((err == SSL_ERROR_SYSCALL || !dssl)
                              && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR));
                if (again && ++idle < 500) continue;   // ~ up to seconds of stalls
                if (n < 0 && err != SSL_ERROR_ZERO_RETURN)
                    std::fprintf(stderr, "FtpsMock: data read abnormal end ssl_err=%d errno=%d(%s) after %zu bytes\n",
                                 err, errno, std::strerror(errno), total);
                break;
            }
            idle = 0;
            EVP_DigestUpdate(md, buf, (size_t)n);
            total += (size_t)n;
        }

        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int dlen = 0;
        EVP_DigestFinal_ex(md, digest, &dlen);
        EVP_MD_CTX_free(md);

        if (dssl) { SSL_shutdown(dssl); SSL_free(dssl); }
        ::close(dc);

        std::string hex = to_hex(digest, dlen);
        std::lock_guard<std::mutex> lk(mu_);
        stors_.push_back(Stor{name, total, hex});
    }

    // Serve the canned directory listing on the PASV data channel (mirrors
    // handle_stor but writes instead of reads).
    void handle_list(int data_listen_fd, bool prot_private) {
        ++list_count_;
        if (data_listen_fd < 0) return;
        int dc = ::accept(data_listen_fd, nullptr, nullptr);
        if (dc < 0) return;
        SSL* dssl = nullptr;
        if (prot_private) {
            dssl = SSL_new(ctx_);
            if (dssl) {
                SSL_set_fd(dssl, dc);
                if (SSL_accept(dssl) <= 0) { SSL_free(dssl); ::close(dc); return; }
            }
        }
        std::string body;
        { std::lock_guard<std::mutex> lk(mu_); body = listing_; }
        if (dssl) SSL_write(dssl, body.data(), (int)body.size());
        else      ::send(dc, body.data(), body.size(), 0);
        if (dssl) { SSL_shutdown(dssl); SSL_free(dssl); }
        ::close(dc);
    }

    static void close_data_listener(int& fd) {
        if (fd >= 0) { ::close(fd); fd = -1; }
    }

    static std::string upper(const std::string& s) {
        std::string o = s;
        for (char& c : o) c = (char)::toupper((unsigned char)c);
        return o;
    }

    static std::string to_hex(const unsigned char* p, unsigned int n) {
        static const char* hx = "0123456789abcdef";
        std::string s;
        s.reserve(n * 2);
        for (unsigned int i = 0; i < n; ++i) {
            s.push_back(hx[(p[i] >> 4) & 0xf]);
            s.push_back(hx[p[i] & 0xf]);
        }
        return s;
    }

    int fd_{-1};
    int port_{0};
    SSL_CTX* ctx_{nullptr};
    std::thread th_;
    std::atomic<bool> stop_{false};
    std::atomic<int>  list_count_{0};
    // Default directory listing (vsFTPd style) served for LIST; overridable.
    std::string listing_ =
        "-rwxr-xr-x    1 1002     1002       825312 Jul 14 09:38 3DBenchy.gcode.3mf\r\n"
        "-rwxr-xr-x    1 1002     1002       961941 Jul 12 12:51 BENCHY.gcode.3mf\r\n"
        "-rwxr-xr-x    1 1002     1002        71521 Jul 03 12:21 Hinge.gcode.3mf\r\n";
    mutable std::mutex mu_;
    std::vector<Stor> stors_;
    std::mutex workers_mu_;
    std::vector<std::thread> workers_;
};

// ---------------------------------------------------------------------------
// CLASS 1b: NativeTunnelMock - the printer's native :6000 TLS CTRL endpoint
// (BambuTunnelLocal / PrinterFileSystem). libBambuSource's Bambu_Open dials
// this port and Bambu_StartStreamEx(0x3001) runs the framed login/setup
// handshake before the file-browser CTRL channel is usable. We answer only
// the handshake: LOGIN -> login-ack, SETUP -> setup-reply(result:0). Once the
// session is Ready the OSS serves LIST over FTPS (force_ftps), so this mock
// just holds the TLS session open afterwards.
//
// Wire frame: 16-byte header [payload_len u32-LE][magic u32-LE][seq u32-LE]
// [4 bytes zero] followed by payload_len bytes. Magics mirror tunnel_local.
// ---------------------------------------------------------------------------
class NativeTunnelMock {
public:
    static constexpr uint32_t kMagicLoginClient = 0x0101013Fu;
    static constexpr uint32_t kMagicLoginServer = 0x0001013Fu;
    static constexpr uint32_t kMagicCtrlClient  = 0x0102013Fu;
    static constexpr uint32_t kMagicCtrlServer  = 0x0002013Fu;

    NativeTunnelMock(const std::string& cert_pem_path, const std::string& key_pem_path) {
        ensure_ssl_init();
        ctx_ = SSL_CTX_new(TLS_server_method());
        if (ctx_) {
            SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
            SSL_CTX_set_num_tickets(ctx_, 0);
            SSL_CTX_set_options(ctx_, SSL_OP_NO_TICKET);
            if (SSL_CTX_use_certificate_file(ctx_, cert_pem_path.c_str(), SSL_FILETYPE_PEM) <= 0)
                std::fprintf(stderr, "NativeTunnelMock: failed to load cert %s\n", cert_pem_path.c_str());
            if (SSL_CTX_use_PrivateKey_file(ctx_, key_pem_path.c_str(), SSL_FILETYPE_PEM) <= 0)
                std::fprintf(stderr, "NativeTunnelMock: failed to load key %s\n", key_pem_path.c_str());
        }
        fd_ = make_listener(port_);
        if (fd_ >= 0) {
            timeval tv{0, 200000};
            ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            th_ = std::thread([this] { loop(); });
        }
    }

    ~NativeTunnelMock() {
        stop_ = true;
        if (fd_ >= 0) ::shutdown(fd_, SHUT_RDWR);
        if (th_.joinable()) th_.join();
        {
            std::lock_guard<std::mutex> lk(workers_mu_);
            for (auto& t : workers_) if (t.joinable()) t.join();
        }
        if (fd_ >= 0) ::close(fd_);
        if (ctx_) SSL_CTX_free(ctx_);
    }

    int port() const { return port_; }
    bool handshake_ok() const { return handshakes_.load() > 0; }

private:
    void loop() {
        while (!stop_) {
            int c = ::accept(fd_, nullptr, nullptr);
            if (c < 0) continue;
            std::lock_guard<std::mutex> lk(workers_mu_);
            workers_.emplace_back([this, c] { handle(c); });
        }
    }

    // The accepted socket inherits the listener's 200ms SO_RCVTIMEO, so a read
    // with no data pending returns SSL_ERROR_SYSCALL/EAGAIN. Treat that (and
    // WANT_READ/WRITE) as "retry" while the mock is running, so a slow peer
    // doesn't abort the handshake and teardown can still interrupt a wait.
    bool read_retryable(SSL* ssl, int r) {
        int e = SSL_get_error(ssl, r);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return true;
        if (e == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK))
            return true;
        return false;
    }

    // Read exactly n bytes from the TLS socket into out; false on EOF/error.
    bool ssl_read_exact(SSL* ssl, uint8_t* out, size_t n) {
        size_t off = 0;
        while (off < n) {
            if (stop_) return false;
            int r = SSL_read(ssl, out + off, (int)(n - off));
            if (r <= 0) {
                if (read_retryable(ssl, r)) continue;
                return false;
            }
            off += (size_t)r;
        }
        return true;
    }

    // Read one framed message; returns false on EOF/error.
    bool read_frame(SSL* ssl, uint32_t& magic, std::string& payload) {
        uint8_t hdr[16];
        if (!ssl_read_exact(ssl, hdr, 16)) return false;
        uint32_t plen = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
                        ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
        magic = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8) |
                ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 24);
        payload.assign(plen, '\0');
        if (plen && !ssl_read_exact(ssl, (uint8_t*)payload.data(), plen)) return false;
        return true;
    }

    void write_frame(SSL* ssl, uint32_t magic, const std::string& payload) {
        uint8_t hdr[16] = {0};
        uint32_t plen = (uint32_t)payload.size();
        hdr[0] = plen & 0xff;  hdr[1] = (plen >> 8) & 0xff;
        hdr[2] = (plen >> 16) & 0xff; hdr[3] = (plen >> 24) & 0xff;
        hdr[4] = magic & 0xff; hdr[5] = (magic >> 8) & 0xff;
        hdr[6] = (magic >> 16) & 0xff; hdr[7] = (magic >> 24) & 0xff;
        // seq (bytes 8-11) and reserved (12-15) stay zero.
        int w = SSL_write(ssl, hdr, 16);
        if (w <= 0) return;
        if (!payload.empty()) send_ssl_str(ssl, payload);
    }

    void handle(int c) {
        SSL* ssl = SSL_new(ctx_);
        if (!ssl) { ::close(c); return; }
        SSL_set_fd(ssl, c);
        if (SSL_accept(ssl) <= 0) {
            std::fprintf(stderr, "NativeTunnelMock: SSL_accept failed\n");
            SSL_free(ssl); ::close(c); return;
        }

        uint32_t magic = 0;
        std::string payload;
        // Phase 1: LOGIN (user/access-code, 16 bytes) -> login-ack.
        if (read_frame(ssl, magic, payload) && magic == kMagicLoginClient) {
            write_frame(ssl, kMagicLoginServer, "");
            // Phase 2: SETUP (ctrl json) -> setup reply with result:0.
            if (read_frame(ssl, magic, payload) && magic == kMagicCtrlClient) {
                write_frame(ssl, kMagicCtrlServer,
                            "{\"mtype\":12291,\"result\":0}");
                handshakes_.fetch_add(1);
            }
        }

        // Session is Ready; the OSS now serves the file browser over FTPS and
        // sends nothing further here. Hold the socket open until teardown so
        // the client's TLS session stays valid.
        uint8_t drain[512];
        while (!stop_) {
            int r = SSL_read(ssl, drain, sizeof drain);
            if (r <= 0) {
                if (read_retryable(ssl, r)) continue;
                break;  // clean close_notify or hard error
            }
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ::close(c);
    }

    int fd_{-1};
    int port_{0};
    SSL_CTX* ctx_{nullptr};
    std::thread th_;
    std::atomic<bool> stop_{false};
    std::atomic<int>  handshakes_{0};
    std::mutex workers_mu_;
    std::vector<std::thread> workers_;
};

// ---------------------------------------------------------------------------
// CLASS 2: MqttBrokerMock - plaintext MQTT 3.1.1 broker.
// ---------------------------------------------------------------------------
class MqttBrokerMock {
public:
    struct Pub {
        std::string topic;
        std::string payload;
    };

    MqttBrokerMock() {
        fd_ = make_listener(port_);
        if (fd_ >= 0) {
            timeval tv{0, 200000};
            ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            th_ = std::thread([this] { loop(); });
        }
    }

    ~MqttBrokerMock() {
        stop_ = true;
        if (fd_ >= 0) ::shutdown(fd_, SHUT_RDWR);
        if (th_.joinable()) th_.join();
        {
            std::lock_guard<std::mutex> lk(workers_mu_);
            for (auto& t : workers_) if (t.joinable()) t.join();
        }
        if (fd_ >= 0) ::close(fd_);
    }

    int port() const { return port_; }

    std::vector<Pub> pubs() const {
        std::lock_guard<std::mutex> lk(mu_);
        return pubs_;
    }

    std::vector<std::string> subscriptions() const {
        std::lock_guard<std::mutex> lk(mu_);
        return subs_;
    }

    bool got_connect() const { return got_connect_.load(); }

private:
    void loop() {
        while (!stop_) {
            int c = ::accept(fd_, nullptr, nullptr);
            if (c < 0) continue;
            std::lock_guard<std::mutex> lk(workers_mu_);
            workers_.emplace_back([this, c] { handle_conn(c); });
        }
    }

    void handle_conn(int c) {
        std::string buf;
        while (!stop_) {
            char tmp[4096];
            ssize_t n = ::recv(c, tmp, sizeof tmp, 0);
            if (n <= 0) {
                // treat as closed; but honor recv timeout by retrying while open
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if (stop_) break;
                    continue;
                }
                break;
            }
            buf.append(tmp, (size_t)n);

            // Parse as many complete packets as are buffered.
            while (true) {
                if (buf.size() < 2) break;
                uint8_t byte0 = (uint8_t)buf[0];

                size_t rem_len = 0;
                int rem_bytes = 0;
                bool have_len = decode_remaining_length(buf, 1, rem_len, rem_bytes);
                if (!have_len) break;  // need more bytes for the length field

                size_t header_len = 1 + (size_t)rem_bytes;
                size_t total_len = header_len + rem_len;
                if (buf.size() < total_len) break;  // full packet not yet buffered

                const uint8_t* vh = (const uint8_t*)buf.data() + header_len;
                if (!handle_packet(c, byte0, vh, rem_len)) {
                    // DISCONNECT or fatal
                    ::close(c);
                    return;
                }
                buf.erase(0, total_len);
            }
        }
        ::close(c);
    }

    // Returns false if the connection should be closed (DISCONNECT).
    bool handle_packet(int c, uint8_t byte0, const uint8_t* vh, size_t rem_len) {
        uint8_t type = (byte0 >> 4) & 0x0f;
        uint8_t flags = byte0 & 0x0f;

        switch (type) {
            case 1: {  // CONNECT
                got_connect_.store(true);
                uint8_t connack[4] = {0x20, 0x02, 0x00, 0x00};
                send_all_plain(c, connack, sizeof connack);
                return true;
            }
            case 8: {  // SUBSCRIBE
                if (rem_len < 2) return true;
                uint16_t pid = (uint16_t)((vh[0] << 8) | vh[1]);
                size_t off = 2;
                std::vector<std::string> topics;
                while (off + 2 <= rem_len) {
                    uint16_t tlen = (uint16_t)((vh[off] << 8) | vh[off + 1]);
                    off += 2;
                    if (off + tlen > rem_len) break;
                    topics.emplace_back((const char*)vh + off, tlen);
                    off += tlen;
                    if (off >= rem_len) break;  // missing QoS byte, tolerate
                    off += 1;                   // requested QoS byte
                }
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    for (auto& t : topics) subs_.push_back(t);
                }
                // SUBACK: pid (2) + one return code per topic.
                std::vector<uint8_t> pkt;
                size_t body = 2 + topics.size();
                pkt.push_back(0x90);
                encode_remaining_length(pkt, body);
                pkt.push_back((uint8_t)(pid >> 8));
                pkt.push_back((uint8_t)(pid & 0xff));
                for (size_t i = 0; i < topics.size(); ++i) pkt.push_back(0x00);
                send_all_plain(c, pkt.data(), pkt.size());
                return true;
            }
            case 3: {  // PUBLISH
                uint8_t qos = (flags >> 1) & 0x03;
                if (rem_len < 2) return true;
                uint16_t tlen = (uint16_t)((vh[0] << 8) | vh[1]);
                size_t off = 2;
                if (off + tlen > rem_len) return true;
                std::string topic((const char*)vh + off, tlen);
                off += tlen;
                uint16_t pid = 0;
                if (qos > 0) {
                    if (off + 2 > rem_len) return true;
                    pid = (uint16_t)((vh[off] << 8) | vh[off + 1]);
                    off += 2;
                }
                std::string payload;
                if (off <= rem_len) payload.assign((const char*)vh + off, rem_len - off);
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    pubs_.push_back(Pub{topic, payload});
                }
                if (qos == 1) {
                    uint8_t puback[4] = {0x40, 0x02,
                                         (uint8_t)(pid >> 8), (uint8_t)(pid & 0xff)};
                    send_all_plain(c, puback, sizeof puback);
                }
                return true;
            }
            case 12: {  // PINGREQ
                uint8_t pingresp[2] = {0xD0, 0x00};
                send_all_plain(c, pingresp, sizeof pingresp);
                return true;
            }
            case 14:  // DISCONNECT
                return false;
            default:
                // Unknown/unsupported: bytes already consumed by caller.
                return true;
        }
    }

    // Decode MQTT variable-length remaining length starting at offset `start`.
    // Returns false if more bytes are required. On success sets value + count.
    static bool decode_remaining_length(const std::string& buf, size_t start,
                                        size_t& value, int& nbytes) {
        value = 0;
        int multiplier = 1;
        size_t i = start;
        nbytes = 0;
        for (int b = 0; b < 4; ++b) {
            if (i >= buf.size()) return false;
            uint8_t enc = (uint8_t)buf[i++];
            value += (size_t)(enc & 0x7f) * (size_t)multiplier;
            nbytes++;
            if ((enc & 0x80) == 0) return true;
            multiplier *= 128;
        }
        return true;  // malformed >4 bytes; treat as complete
    }

    static void encode_remaining_length(std::vector<uint8_t>& out, size_t value) {
        do {
            uint8_t enc = (uint8_t)(value & 0x7f);
            value >>= 7;
            if (value > 0) enc |= 0x80;
            out.push_back(enc);
        } while (value > 0);
    }

    int fd_{-1};
    int port_{0};
    std::thread th_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> got_connect_{false};
    mutable std::mutex mu_;
    std::vector<Pub> pubs_;
    std::vector<std::string> subs_;
    std::mutex workers_mu_;
    std::vector<std::thread> workers_;
};

}  // namespace lanmock
