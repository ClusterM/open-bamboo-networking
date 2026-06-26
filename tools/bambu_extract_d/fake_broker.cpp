#include "fake_broker.h"
#include "connect_redirect_embed.h"  // connect_redirect_embed_so + _len
#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

std::string write_connect_redirect_memfd(int* out_fd) {
    *out_fd = -1;
    if (connect_redirect_embed_so_len == 0) return {};
    int fd = memfd_create("bambu_cr", 0);  // no MFD_CLOEXEC — daemon must inherit
    if (fd < 0) return {};
    size_t total = 0;
    while (total < connect_redirect_embed_so_len) {
        ssize_t n = write(fd,
            (const char*)connect_redirect_embed_so + total,
            connect_redirect_embed_so_len - total);
        if (n <= 0) { close(fd); return {}; }
        total += (size_t)n;
    }
    *out_fd = fd;
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    return std::string(path);
}

// ---------------------------------------------------------------------------
// FakePrinterBroker implementation
// ---------------------------------------------------------------------------

bool FakePrinterBroker::start(const std::string& target_dev_id) {
    dev_id = target_dev_id;
    if (!gen_ctx()) return false;

    connect_redirect_so_path = write_connect_redirect_memfd(&connect_redirect_fd);
    if (connect_redirect_so_path.empty())
        LOG_W("connect_redirect shim unavailable (stub embed?) — TLS may fail");

    if (!try_bind(8883)) {
        int free_port = find_free_port();
        if (free_port <= 0) return false;
        if (!try_bind(free_port)) return false;
        std::fprintf(stderr,
            "[fake-printer] port 8883 busy — redirecting via LD_PRELOAD shim to %d\n",
            free_port);
    }
    if (listen(srv_fd, 4) < 0) {
        close(srv_fd); srv_fd = -1; return false;
    }
    thr = std::thread([this]{ accept_loop(); });
    {
        std::unique_lock<std::mutex> lk(mu);
        cv.wait_for(lk, std::chrono::seconds(1), [this]{ return ready; });
    }
    return ready;
}

void FakePrinterBroker::stop() {
    if (srv_fd >= 0) { shutdown(srv_fd, SHUT_RDWR); close(srv_fd); srv_fd = -1; }
    if (thr.joinable()) thr.join();
    if (ctx) { SSL_CTX_free(ctx); ctx = nullptr; }
    if (connect_redirect_fd >= 0) {
        close(connect_redirect_fd);
        connect_redirect_fd = -1;
    }
}

FakePrinterBroker::~FakePrinterBroker() { stop(); }

int FakePrinterBroker::find_free_port() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    sa.sin_port = 0;
    if (bind(fd, (sockaddr*)&sa, sizeof(sa)) < 0) { close(fd); return -1; }
    socklen_t len = sizeof(sa);
    getsockname(fd, (sockaddr*)&sa, &len);
    int p = ntohs(sa.sin_port);
    close(fd);
    return p;
}

bool FakePrinterBroker::try_bind(int p) {
    if (srv_fd >= 0) { close(srv_fd); srv_fd = -1; }
    srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) return false;
    int yes = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    sa.sin_port = htons((uint16_t)p);
    if (bind(srv_fd, (sockaddr*)&sa, sizeof(sa)) < 0) {
        close(srv_fd); srv_fd = -1; return false;
    }
    port = p;
    return true;
}

bool FakePrinterBroker::gen_ctx() {
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return false;

    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    if (!pkey) return false;

    X509* cert = X509_new();
    if (!cert) { EVP_PKEY_free(pkey); return false; }
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 3600);
    X509_set_pubkey(cert, pkey);
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char*)"bambu-fake-printer", -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509_sign(cert, pkey, EVP_sha256());

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    char* data = nullptr;
    long data_len = BIO_get_mem_data(bio, &data);
    printer_cert_pem = std::string(data, (size_t)data_len);
    BIO_free(bio);

    if (SSL_CTX_use_certificate(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        X509_free(cert); EVP_PKEY_free(pkey); return false;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return true;
}

std::vector<uint8_t> FakePrinterBroker::encode_remaining(uint32_t n) {
    std::vector<uint8_t> out;
    do {
        uint8_t b = n & 0x7f; n >>= 7;
        out.push_back(n ? (b | 0x80) : b);
    } while (n);
    return out;
}

bool FakePrinterBroker::ssl_write_all(SSL* ssl, const void* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        int w = SSL_write(ssl, (const char*)buf + off, (int)(n - off));
        if (w <= 0) return false;
        off += (size_t)w;
    }
    return true;
}

bool FakePrinterBroker::ssl_read_exact(SSL* ssl, void* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        int r = SSL_read(ssl, (char*)buf + off, (int)(n - off));
        if (r <= 0) return false;
        off += (size_t)r;
    }
    return true;
}

uint8_t FakePrinterBroker::read_packet(SSL* ssl, std::vector<uint8_t>& body) {
    uint8_t hdr;
    if (!ssl_read_exact(ssl, &hdr, 1)) return 0;
    uint32_t rem = 0; int shift = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t b;
        if (!ssl_read_exact(ssl, &b, 1)) return 0;
        rem |= (uint32_t)(b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    body.resize(rem);
    if (rem > 0 && !ssl_read_exact(ssl, body.data(), rem)) return 0;
    return hdr;
}

bool FakePrinterBroker::mqtt_publish(SSL* ssl, const std::string& topic,
                                     const std::string& payload) {
    uint16_t tlen = (uint16_t)topic.size();
    uint32_t rem = 2 + tlen + payload.size();
    std::vector<uint8_t> pkt;
    pkt.push_back(0x30);
    for (uint8_t b : encode_remaining(rem)) pkt.push_back(b);
    pkt.push_back((uint8_t)(tlen >> 8));
    pkt.push_back((uint8_t)(tlen & 0xff));
    for (char c : topic) pkt.push_back((uint8_t)c);
    for (char c : payload) pkt.push_back((uint8_t)c);
    return ssl_write_all(ssl, pkt.data(), pkt.size());
}

void FakePrinterBroker::handle_client(SSL* ssl) {
    std::string security_topic = "device/" + dev_id + "/security";
    bool conn_sent = false;
    while (true) {
        std::vector<uint8_t> body;
        uint8_t hdr = read_packet(ssl, body);
        if (!hdr) break;
        uint8_t type = hdr >> 4;
        if (type == 1) {  // CONNECT
            uint8_t connack[4] = {0x20, 0x02, 0x00, 0x00};
            ssl_write_all(ssl, connack, 4);
            conn_sent = true;
            std::fprintf(stderr, "[fake-printer] MQTT CONNECT accepted\n");
            std::fflush(stderr);
        } else if (type == 8 && conn_sent) {  // SUBSCRIBE
            if (body.size() >= 2) {
                uint16_t pid = ((uint16_t)body[0] << 8) | body[1];
                uint8_t suback[5] = {0x90, 0x03,
                    (uint8_t)(pid >> 8), (uint8_t)(pid & 0xff), 0x00};
                ssl_write_all(ssl, suback, 5);
            }
        } else if (type == 3 && conn_sent) {  // PUBLISH from daemon
            if (body.size() < 2) continue;
            uint16_t tlen = ((uint16_t)body[0] << 8) | body[1];
            if (2 + tlen > body.size()) continue;
            std::string topic(body.begin() + 2, body.begin() + 2 + tlen);
            if (topic == security_topic && !cert_sent) {
                std::string pem_json;
                pem_json.reserve(printer_cert_pem.size() + 64);
                for (char c : printer_cert_pem) {
                    if (c == '\n') { pem_json += "\\n"; }
                    else if (c == '"') { pem_json += "\\\""; }
                    else { pem_json += c; }
                }
                std::string cr_payload =
                    "{\"cert_report\":{\"command\":\"cert_report\","
                    "\"dev_id\":\"" + dev_id + "\","
                    "\"printer_cert\":\"" + pem_json + "\"}}";
                if (mqtt_publish(ssl, security_topic, cr_payload)) {
                    std::fprintf(stderr,
                        "[fake-printer] cert_report injected (%zu bytes)\n",
                        cr_payload.size());
                    std::fflush(stderr);
                    cert_sent = true;
                    std::lock_guard<std::mutex> lk(mu);
                    cv.notify_all();
                }
            }
            if ((hdr & 0x06) == 0x02 && body.size() >= (size_t)(2 + tlen + 2)) {
                uint16_t pid = ((uint16_t)body[2+tlen] << 8) | body[3+tlen];
                uint8_t puback[4] = {0x40, 0x02,
                    (uint8_t)(pid >> 8), (uint8_t)(pid & 0xff)};
                ssl_write_all(ssl, puback, 4);
            }
        } else if (type == 12) {  // PINGREQ
            uint8_t pingresp[2] = {0xd0, 0x00};
            ssl_write_all(ssl, pingresp, 2);
        } else if (type == 14) {  // DISCONNECT
            break;
        }
    }
}

void FakePrinterBroker::accept_loop() {
    {
        std::lock_guard<std::mutex> lk(mu);
        ready = true;
    }
    cv.notify_all();
    while (srv_fd >= 0) {
        struct sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        int fd = accept(srv_fd, (sockaddr*)&peer, &plen);
        if (fd < 0) break;
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        if (SSL_accept(ssl) == 1) {
            std::fprintf(stderr, "[fake-printer] TLS accepted from %s\n",
                         inet_ntoa(peer.sin_addr));
            std::fflush(stderr);
            handle_client(ssl);
        } else {
            unsigned long e = ERR_get_error();
            char ebuf[256];
            ERR_error_string_n(e, ebuf, sizeof(ebuf));
            std::fprintf(stderr, "[fake-printer] TLS handshake failed: %s\n", ebuf);
            std::fflush(stderr);
        }
        SSL_free(ssl);
        close(fd);
    }
}

bool fake_broker_wait_cert(FakePrinterBroker& b, int timeout_ms) {
    std::unique_lock<std::mutex> lk(b.mu);
    return b.cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                         [&b]{ return b.cert_sent; });
}
