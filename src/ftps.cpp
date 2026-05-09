#include "obn/ftps.hpp"

#include "ftps_parse.hpp"
#include "obn/log.hpp"
#include "obn/os_compat.hpp"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/socket.h>
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace obn::ftps {

namespace {

using obn::os::socket_t;
using obn::os::kInvalidSocket;

// OpenSSL one-time init - shared across ftps/cert_store/mqtt_client. The
// global libssl setup they all do is idempotent, but we lock anyway to
// stay defensive in case OpenSSL ever becomes sensitive to concurrent
// library init again.
std::once_flag g_openssl_once;

void init_openssl_once()
{
    std::call_once(g_openssl_once, [] {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    });
}

std::string openssl_last_error()
{
    unsigned long e = ERR_peek_last_error();
    if (!e) return "unknown";
    char buf[256]{};
    ERR_error_string_n(e, buf, sizeof(buf));
    ERR_clear_error();
    return buf;
}

int wait_fd(socket_t fd, short events, int timeout_ms)
{
    return obn::os::poll_one(fd, events, timeout_ms);
}

socket_t connect_tcp(const std::string& host, int port, int timeout_ms, std::string& err)
{
    obn::os::winsock_init_once();
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* ai = nullptr;
    int rv = ::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &ai);
    if (rv != 0 || !ai) {
        err = std::string{"getaddrinfo: "} + ::gai_strerror(rv);
        return kInvalidSocket;
    }

    socket_t fd = kInvalidSocket;
    for (addrinfo* a = ai; a; a = a->ai_next) {
        fd = static_cast<socket_t>(::socket(a->ai_family, a->ai_socktype, a->ai_protocol));
        if (!obn::os::socket_valid(fd)) { fd = kInvalidSocket; continue; }
        if (obn::os::set_nonblocking(fd) < 0) { obn::os::close_socket(fd); fd = kInvalidSocket; continue; }

        int rc = ::connect(static_cast<int>(fd), a->ai_addr,
                           static_cast<int>(a->ai_addrlen));
        if (rc == 0) break;
        int last_err = obn::os::last_socket_error();
        if (obn::os::socket_in_progress(last_err)) {
            if (wait_fd(fd, POLLOUT, timeout_ms) > 0) {
                int soerr = 0;
#if defined(_WIN32)
                int slen = sizeof(soerr);
                if (::getsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_ERROR,
                                 reinterpret_cast<char*>(&soerr), &slen) == 0 && soerr == 0) break;
#else
                socklen_t slen = sizeof(soerr);
                if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0 && soerr == 0) break;
#endif
                err = std::string{"connect: "} + std::strerror(soerr ? soerr : last_err);
            } else {
                err = "connect: timeout";
            }
        } else {
            err = std::string{"connect: "} + std::strerror(last_err);
        }
        obn::os::close_socket(fd);
        fd = kInvalidSocket;
    }
    ::freeaddrinfo(ai);

    if (!obn::os::socket_valid(fd) && err.empty()) err = "connect failed";
    int yes = 1;
    if (obn::os::socket_valid(fd)) {
        ::setsockopt(static_cast<int>(fd), IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&yes), sizeof(yes));
    }
    return fd;
}

// Drives SSL_connect / SSL_write / SSL_read until it stops returning
// WANT_READ/WANT_WRITE, bounded by timeout_ms.
int drive_ssl(SSL* ssl, socket_t fd, int (*op)(SSL*), int timeout_ms)
{
    for (;;) {
        int r = op(ssl);
        if (r > 0) return r;
        int err = SSL_get_error(ssl, r);
        short ev = 0;
        if (err == SSL_ERROR_WANT_READ)  ev = POLLIN;
        else if (err == SSL_ERROR_WANT_WRITE) ev = POLLOUT;
        else return -1;
        int pr = wait_fd(fd, ev, timeout_ms);
        if (pr <= 0) return -1;
    }
}

bool ssl_write_all(SSL* ssl, socket_t fd, const void* buf, std::size_t len, int timeout_ms)
{
    const char* p   = static_cast<const char*>(buf);
    std::size_t off = 0;
    while (off < len) {
        int r = SSL_write(ssl, p + off, static_cast<int>(len - off));
        if (r > 0) { off += r; continue; }
        int err = SSL_get_error(ssl, r);
        short ev = 0;
        if (err == SSL_ERROR_WANT_READ) ev = POLLIN;
        else if (err == SSL_ERROR_WANT_WRITE) ev = POLLOUT;
        else return false;
        if (wait_fd(fd, ev, timeout_ms) <= 0) return false;
    }
    return true;
}

int ssl_read_some(SSL* ssl, socket_t fd, void* buf, std::size_t max_len, int timeout_ms)
{
    for (;;) {
        int r = SSL_read(ssl, buf, static_cast<int>(max_len));
        if (r > 0) return r;
        int err = SSL_get_error(ssl, r);
        if (err == SSL_ERROR_ZERO_RETURN) return 0;
        short ev = 0;
        if (err == SSL_ERROR_WANT_READ) ev = POLLIN;
        else if (err == SSL_ERROR_WANT_WRITE) ev = POLLOUT;
        else return -1;
        if (wait_fd(fd, ev, timeout_ms) <= 0) return -1;
    }
}

} // namespace

// -------------------------------------------------------------------
// Impl
// -------------------------------------------------------------------

struct Client::Impl {
    SSL_CTX* ctx        = nullptr;
    SSL*     ctrl_ssl   = nullptr;
    socket_t ctrl_fd    = kInvalidSocket;
    std::string host;
    int      control_timeout_ms = 10000;
    int      data_timeout_ms    = 60000;

    // Line-oriented read buffer for the control channel.
    std::string ctrl_buf;

    ~Impl()
    {
        if (ctrl_ssl) { SSL_shutdown(ctrl_ssl); SSL_free(ctrl_ssl); ctrl_ssl = nullptr; }
        if (obn::os::socket_valid(ctrl_fd)) {
            obn::os::close_socket(ctrl_fd);
            ctrl_fd = kInvalidSocket;
        }
        if (ctx) { SSL_CTX_free(ctx); ctx = nullptr; }
    }

    // Reads one CRLF-terminated line (without the CRLF) from the control
    // channel. Returns empty string + *ok=false on timeout/error.
    std::string read_line(bool* ok)
    {
        while (true) {
            auto nl = ctrl_buf.find('\n');
            if (nl != std::string::npos) {
                std::string line = ctrl_buf.substr(0, nl);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                ctrl_buf.erase(0, nl + 1);
                *ok = true;
                return line;
            }
            char tmp[512];
            int n = ssl_read_some(ctrl_ssl, ctrl_fd, tmp, sizeof(tmp), control_timeout_ms);
            if (n <= 0) { *ok = false; return {}; }
            ctrl_buf.append(tmp, tmp + n);
        }
    }

    // Reads a complete multiline FTP reply. Returns numeric reply code,
    // accumulated text in *body, or -1 on error.
    int read_reply(std::string* body)
    {
        int         code        = -1;
        std::string accumulated;
        for (;;) {
            bool ok = false;
            std::string line = read_line(&ok);
            if (!ok) return -1;
            if (!accumulated.empty()) accumulated += '\n';
            accumulated += line;
            // Multi-line continuation is "NNN-..." and terminated by a
            // final line starting with the same "NNN ".
            if (line.size() >= 4 && std::isdigit(static_cast<unsigned char>(line[0]))
                && std::isdigit(static_cast<unsigned char>(line[1]))
                && std::isdigit(static_cast<unsigned char>(line[2]))) {
                int this_code = std::atoi(line.substr(0, 3).c_str());
                if (line[3] == ' ') {
                    code = this_code;
                    break;
                }
                // '-' => continuation
            }
        }
        if (body) *body = std::move(accumulated);
        return code;
    }

    // Sends "CMD\r\n" and reads the reply. Returns reply code (or -1 on
    // IO error). Logs the exchange at DEBUG.
    int send_cmd(const std::string& cmd, std::string* reply_body = nullptr, bool redact = false)
    {
        std::string wire = cmd + "\r\n";
        OBN_DEBUG("ftps ctrl > %s", redact ? "<redacted>" : cmd.c_str());
        if (!ssl_write_all(ctrl_ssl, ctrl_fd, wire.data(), wire.size(), control_timeout_ms)) {
            OBN_WARN("ftps: write %s failed: %s", cmd.c_str(), openssl_last_error().c_str());
            return -1;
        }
        std::string body;
        int code = read_reply(&body);
        if (code < 0) {
            OBN_WARN("ftps: read reply for %s failed", cmd.c_str());
            return -1;
        }
        OBN_DEBUG("ftps ctrl < %d %s", code, body.c_str());
        if (reply_body) *reply_body = std::move(body);
        return code;
    }
};

Client::Client() : p_(std::make_unique<Impl>()) { init_openssl_once(); }
Client::~Client() { quit(); }

std::string Client::connect(const ConnectConfig& cfg)
{
    p_->control_timeout_ms = cfg.control_timeout_s * 1000;
    p_->data_timeout_ms    = cfg.data_timeout_s * 1000;
    p_->host               = cfg.host;

    std::string err;
    socket_t fd = connect_tcp(cfg.host, cfg.port, p_->control_timeout_ms, err);
    if (!obn::os::socket_valid(fd)) return "tcp: " + err;
    p_->ctrl_fd = fd;

    p_->ctx = SSL_CTX_new(TLS_client_method());
    if (!p_->ctx) return "SSL_CTX_new: " + openssl_last_error();
    SSL_CTX_set_options(p_->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    // Bambu's firmware presents TLS 1.2-era ciphers; leave defaults.
    // Printer cert has no matching SAN for the IP, so we always skip
    // hostname verification. Chain verification is enabled only if a CA
    // bundle was provided.
    if (!cfg.ca_file.empty()) {
        if (SSL_CTX_load_verify_locations(p_->ctx, cfg.ca_file.c_str(), nullptr) != 1) {
            OBN_WARN("ftps: load_verify_locations(%s) failed: %s (falling back to no-verify)",
                     cfg.ca_file.c_str(), openssl_last_error().c_str());
            SSL_CTX_set_verify(p_->ctx, SSL_VERIFY_NONE, nullptr);
        } else {
            SSL_CTX_set_verify(p_->ctx, SSL_VERIFY_PEER, nullptr);
        }
    } else {
        SSL_CTX_set_verify(p_->ctx, SSL_VERIFY_NONE, nullptr);
    }
    // Bambu firmware uses X25519 + session tickets and is happy with TLS
    // session reuse; we don't need to opt-in explicitly.
    SSL_CTX_set_session_cache_mode(p_->ctx, SSL_SESS_CACHE_CLIENT);

    p_->ctrl_ssl = SSL_new(p_->ctx);
    if (!p_->ctrl_ssl) return "SSL_new: " + openssl_last_error();
    SSL_set_fd(p_->ctrl_ssl, static_cast<int>(fd));
    SSL_set_tlsext_host_name(p_->ctrl_ssl, cfg.host.c_str());
    if (drive_ssl(p_->ctrl_ssl, fd, SSL_connect, p_->control_timeout_ms) <= 0) {
        return "TLS handshake: " + openssl_last_error();
    }

    // Bambu firmware sends the 220 banner as the first thing after the
    // TLS handshake.
    std::string banner;
    int code = p_->read_reply(&banner);
    if (code != 220) return "no 220 banner (got " + std::to_string(code) + "): " + banner;
    OBN_DEBUG("ftps: banner <%s>", banner.c_str());

    code = p_->send_cmd("USER " + cfg.username);
    if (code != 331 && code != 230) return "USER rejected: code=" + std::to_string(code);
    if (code == 331) {
        code = p_->send_cmd("PASS " + cfg.password, nullptr, /*redact=*/true);
        if (code != 230) return "PASS rejected: code=" + std::to_string(code);
    }
    code = p_->send_cmd("TYPE I");
    if (code != 200) return "TYPE I rejected: code=" + std::to_string(code);
    code = p_->send_cmd("PBSZ 0");
    if (code != 200) return "PBSZ rejected: code=" + std::to_string(code);
    code = p_->send_cmd("PROT P");
    if (code != 200) return "PROT P rejected: code=" + std::to_string(code);
    OBN_INFO("ftps: logged in to %s as %s", cfg.host.c_str(), cfg.username.c_str());
    return {};
}

// Opens a PASV data connection as a plain TCP socket. vsftpd (which
// Bambu's firmware runs) delays its half of the TLS handshake until
// *after* the client issues STOR/LIST and the 150 reply is sent, so we
// have to interleave: PASV -> data TCP -> command -> 150 -> data TLS
// handshake -> transfer.
static socket_t open_data_tcp(Client::Impl& p, const std::string& host, std::string& err)
{
    std::string body;
    int code = p.send_cmd("PASV", &body);
    if (code != 227) {
        err = "PASV rejected: code=" + std::to_string(code);
        return kInvalidSocket;
    }
    auto lp = body.find('(');
    auto rp = body.find(')');
    if (lp == std::string::npos || rp == std::string::npos || rp <= lp) {
        err = "PASV bad body: " + body;
        return kInvalidSocket;
    }
    std::string addr = body.substr(lp + 1, rp - lp - 1);
    int h1, h2, h3, h4, p1, p2;
    if (std::sscanf(addr.c_str(), "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2) != 6) {
        err = "PASV parse: " + addr;
        return kInvalidSocket;
    }
    int data_port = p1 * 256 + p2;
    OBN_DEBUG("ftps: PASV -> %d.%d.%d.%d:%d (reconnecting to control host %s)",
              h1, h2, h3, h4, data_port, host.c_str());

    std::string connect_err;
    socket_t fd = connect_tcp(host, data_port, p.control_timeout_ms, connect_err);
    if (!obn::os::socket_valid(fd)) err = "data tcp: " + connect_err;
    return fd;
}

// Performs the delayed TLS handshake on a data socket after the server
// accepted the STOR/LIST (150). Caller owns the returned SSL*.
static SSL* wrap_data_tls(Client::Impl& p, SSL* ctrl_ssl, socket_t fd,
                          const std::string& host, std::string& err)
{
    SSL* data_ssl = SSL_new(p.ctx);
    if (!data_ssl) { err = "data SSL_new"; return nullptr; }
    SSL_set_fd(data_ssl, static_cast<int>(fd));
    SSL_set_tlsext_host_name(data_ssl, host.c_str());
    // Reuse the control channel's TLS session. Some FTPS servers
    // (pureftpd when hardened, newer vsftpd builds with
    // require_ssl_reuse=YES) refuse data channels that don't share the
    // session. Bambu's vsftpd doesn't hit that path today but mirroring
    // bambulabs_api's behaviour makes us more portable across firmwares.
    if (SSL_SESSION* sess = SSL_get1_session(ctrl_ssl)) {
        SSL_set_session(data_ssl, sess);
        SSL_SESSION_free(sess);
    }
    if (drive_ssl(data_ssl, fd, SSL_connect, p.data_timeout_ms) <= 0) {
        err = "data TLS handshake: " + openssl_last_error();
        SSL_free(data_ssl);
        return nullptr;
    }
    return data_ssl;
}

std::string Client::stor(const std::string& local_path,
                         const std::string& remote_path,
                         ProgressFn         progress)
{
    std::ifstream f(local_path, std::ios::binary | std::ios::ate);
    if (!f) return "open " + local_path + ": " + std::strerror(errno);
    std::uint64_t total = static_cast<std::uint64_t>(f.tellg());
    f.seekg(0, std::ios::beg);

    std::string err;
    socket_t data_fd = open_data_tcp(*p_, p_->host, err);
    if (!obn::os::socket_valid(data_fd)) return err;

    // Printer must reply 150 "Opening BINARY connection" before it
    // expects TLS handshake on the data socket.
    int code = p_->send_cmd("STOR " + remote_path);
    if (code != 150 && code != 125) {
        obn::os::close_socket(data_fd);
        return "STOR rejected: code=" + std::to_string(code);
    }

    SSL* data_ssl = wrap_data_tls(*p_, p_->ctrl_ssl, data_fd, p_->host, err);
    if (!data_ssl) { obn::os::close_socket(data_fd); return err; }

    std::vector<char>  buf(64 * 1024);
    std::uint64_t      sent = 0;
    auto               last_progress = -1LL;
    while (true) {
        f.read(buf.data(), buf.size());
        std::streamsize n = f.gcount();
        if (n <= 0) break;
        if (!ssl_write_all(data_ssl, data_fd, buf.data(), static_cast<std::size_t>(n),
                           p_->data_timeout_ms))
        {
            SSL_shutdown(data_ssl);
            SSL_free(data_ssl);
            obn::os::close_socket(data_fd);
            return "data write: " + openssl_last_error();
        }
        sent += static_cast<std::uint64_t>(n);
        if (progress) {
            long long pct = total > 0 ? static_cast<long long>(sent * 100 / total) : -1;
            // Throttle progress callbacks to whole-percent transitions;
            // Studio's update loop uses this to redraw the progress bar.
            if (pct != last_progress) {
                last_progress = pct;
                if (!progress(sent, total)) {
                    SSL_shutdown(data_ssl);
                    SSL_free(data_ssl);
                    obn::os::close_socket(data_fd);
                    return "upload cancelled";
                }
            }
        }
    }

    // Close the data channel politely. SSL_shutdown() may return 0 which
    // is fine (remote hasn't sent close_notify yet). Some printers block
    // on the final 226 until the data socket is fully closed, so we do
    // it before reading the reply.
    SSL_shutdown(data_ssl);
    SSL_free(data_ssl);
    obn::os::close_socket(data_fd);

    std::string body;
    int done = p_->read_reply(&body);
    if (done != 226 && done != 250) return "STOR finish code=" + std::to_string(done) + ": " + body;
    OBN_INFO("ftps: STOR %s ok (%llu bytes)", remote_path.c_str(),
             static_cast<unsigned long long>(sent));
    if (progress) progress(sent, total);
    return {};
}

std::string Client::list(const std::string& path, std::string& err_out)
{
    std::string err;
    socket_t data_fd = open_data_tcp(*p_, p_->host, err);
    if (!obn::os::socket_valid(data_fd)) { err_out = err; return {}; }

    int code = p_->send_cmd(path.empty() ? "LIST" : "LIST " + path);
    if (code != 150 && code != 125) {
        obn::os::close_socket(data_fd);
        err_out = "LIST rejected: code=" + std::to_string(code);
        return {};
    }

    SSL* data_ssl = wrap_data_tls(*p_, p_->ctrl_ssl, data_fd, p_->host, err);
    if (!data_ssl) { obn::os::close_socket(data_fd); err_out = err; return {}; }

    std::string body;
    char buf[1024];
    while (true) {
        int n = ssl_read_some(data_ssl, data_fd, buf, sizeof(buf), p_->data_timeout_ms);
        if (n <= 0) break;
        body.append(buf, buf + n);
    }
    SSL_shutdown(data_ssl);
    SSL_free(data_ssl);
    obn::os::close_socket(data_fd);

    int done = p_->read_reply(nullptr);
    if (done != 226 && done != 250) {
        err_out = "LIST finish code=" + std::to_string(done);
        return {};
    }
    err_out.clear();
    return body;
}

std::string Client::dele(const std::string& remote_path)
{
    int code = p_->send_cmd("DELE " + remote_path);
    if (code != 250 && code != 200) return "DELE code=" + std::to_string(code);
    return {};
}

std::string Client::size(const std::string& remote_path,
                         std::uint64_t* size_out)
{
    if (size_out) *size_out = 0;
    std::string body;
    int code = p_->send_cmd("SIZE " + remote_path, &body);
    if (code != 213) return "SIZE code=" + std::to_string(code);
    // Reply is "213 <bytes>"; strip the code and any leading whitespace.
    const char* s = body.c_str();
    while (*s && !std::isdigit(static_cast<unsigned char>(*s))) ++s;
    // skip the 213 prefix
    while (*s && std::isdigit(static_cast<unsigned char>(*s))) ++s;
    while (*s == ' ' || *s == '\t') ++s;
    char* end = nullptr;
    unsigned long long v = std::strtoull(s, &end, 10);
    if (end == s) return "SIZE parse: " + body;
    if (size_out) *size_out = v;
    return {};
}

std::string Client::retr(const std::string& remote_path, DataSinkFn sink)
{
    std::string err;
    socket_t data_fd = open_data_tcp(*p_, p_->host, err);
    if (!obn::os::socket_valid(data_fd)) return err;

    int code = p_->send_cmd("RETR " + remote_path);
    if (code != 150 && code != 125) {
        obn::os::close_socket(data_fd);
        return "RETR rejected: code=" + std::to_string(code);
    }
    SSL* data_ssl = wrap_data_tls(*p_, p_->ctrl_ssl, data_fd, p_->host, err);
    if (!data_ssl) { obn::os::close_socket(data_fd); return err; }

    char buf[64 * 1024];
    bool aborted = false;
    while (true) {
        int n = ssl_read_some(data_ssl, data_fd, buf, sizeof(buf), p_->data_timeout_ms);
        if (n < 0) {
            err = "data read: " + openssl_last_error();
            aborted = true;
            break;
        }
        if (n == 0) break;
        if (sink && !sink(buf, static_cast<std::size_t>(n))) {
            err = "download cancelled";
            aborted = true;
            break;
        }
    }
    SSL_shutdown(data_ssl);
    SSL_free(data_ssl);
    obn::os::close_socket(data_fd);

    std::string body;
    int done = p_->read_reply(&body);
    if (aborted) return err;
    if (done != 226 && done != 250) return "RETR finish code=" + std::to_string(done) + ": " + body;
    return {};
}

namespace {
using obn::ftps::detail::parse_ls_line;
} // namespace

std::string Client::list_entries(const std::string& path,
                                 std::vector<Entry>* entries)
{
    if (entries) entries->clear();

    // Bambu firmware (across O1S/X1/P1/P2S/A1 and their FTP daemons)
    // does not advertise MLSD in FEAT and rejects it with 500 Unknown
    // command. Don't bother trying -- just issue LIST. parse_ls_line
    // recovers size / name / is_dir / mtime from the `ls -l` output.
    std::string err;
    socket_t data_fd = open_data_tcp(*p_, p_->host, err);
    if (!obn::os::socket_valid(data_fd)) return err;

    int code = p_->send_cmd(path.empty() ? "LIST" : "LIST " + path);
    if (code != 150 && code != 125) {
        obn::os::close_socket(data_fd);
        return "LIST rejected: code=" + std::to_string(code);
    }
    SSL* data_ssl = wrap_data_tls(*p_, p_->ctrl_ssl, data_fd, p_->host, err);
    if (!data_ssl) { obn::os::close_socket(data_fd); return err; }
    std::string body;
    char buf[1024];
    while (true) {
        int n = ssl_read_some(data_ssl, data_fd, buf, sizeof(buf), p_->data_timeout_ms);
        if (n <= 0) break;
        body.append(buf, buf + n);
    }
    SSL_shutdown(data_ssl);
    SSL_free(data_ssl);
    obn::os::close_socket(data_fd);
    int done = p_->read_reply(nullptr);
    if (done != 226 && done != 250) return "LIST finish code=" + std::to_string(done);

    std::size_t i = 0;
    std::size_t without_mtime_ls = 0;
    while (i < body.size()) {
        auto nl = body.find('\n', i);
        std::string line = body.substr(i, (nl == std::string::npos ? body.size() : nl) - i);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        i = (nl == std::string::npos) ? body.size() : (nl + 1);
        if (line.empty()) continue;
        Entry e;
        parse_ls_line(line, &e);
        if (e.name.empty() || e.name == "." || e.name == "..") continue;
        if (e.mtime == 0) ++without_mtime_ls;
        if (entries) entries->push_back(std::move(e));
    }
    if (entries)
        OBN_DEBUG("ftps: LIST %s -> %zu entries (%zu without parsable date)",
                  path.c_str(), entries->size(), without_mtime_ls);
    return {};
}

std::string Client::cwd(const std::string& path)
{
    int code = p_->send_cmd("CWD " + path);
    // 250 is the usual success reply. Some firmwares answer 200 here.
    if (code == 250 || code == 200) return {};
    return "CWD " + path + " code=" + std::to_string(code);
}

void Client::quit()
{
    if (!p_) return;
    if (p_->ctrl_ssl) {
        // Best-effort: send QUIT if the channel is still usable, then
        // shutdown TLS.
        if (obn::os::socket_valid(p_->ctrl_fd)) {
            std::string wire = "QUIT\r\n";
            ssl_write_all(p_->ctrl_ssl, p_->ctrl_fd, wire.data(), wire.size(), 1000);
            // Drain the 221 reply if it arrives promptly.
            std::string body;
            p_->read_reply(&body);
        }
        SSL_shutdown(p_->ctrl_ssl);
        SSL_free(p_->ctrl_ssl);
        p_->ctrl_ssl = nullptr;
    }
    if (obn::os::socket_valid(p_->ctrl_fd)) {
        obn::os::close_socket(p_->ctrl_fd);
        p_->ctrl_fd = kInvalidSocket;
    }
    if (p_->ctx) { SSL_CTX_free(p_->ctx); p_->ctx = nullptr; }
}

} // namespace obn::ftps
