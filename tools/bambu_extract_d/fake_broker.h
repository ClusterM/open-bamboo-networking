#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <openssl/ssl.h>
#include "logging.h"

// Free function — writes the connect-redirect shim to a memfd.
// connect_redirect_embed.h included only in fake_broker.cpp.
std::string write_connect_redirect_memfd(int* out_fd);

// Fake TLS MQTT broker that mimics a Bambu printer.
struct FakePrinterBroker {
    std::string dev_id;
    int         port         = 8883;
    bool        ready        = false;
    bool        cert_sent    = false;
    std::string connect_redirect_so_path;
    int         connect_redirect_fd = -1;
    std::mutex  mu;
    std::condition_variable cv;
    std::thread  thr;
    SSL_CTX*     ctx     = nullptr;
    int          srv_fd  = -1;
    std::string  printer_cert_pem;

    bool start(const std::string& target_dev_id);
    void stop();
    ~FakePrinterBroker();

private:
    static int find_free_port();
    bool try_bind(int p);
    bool gen_ctx();
    static std::vector<uint8_t> encode_remaining(uint32_t n);
    static bool ssl_write_all(SSL* ssl, const void* buf, size_t n);
    static bool ssl_read_exact(SSL* ssl, void* buf, size_t n);
    static uint8_t read_packet(SSL* ssl, std::vector<uint8_t>& body);
    bool mqtt_publish(SSL* ssl, const std::string& topic, const std::string& payload);
    void handle_client(SSL* ssl);
    void accept_loop();
};

bool fake_broker_wait_cert(FakePrinterBroker& b, int timeout_ms);
