// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 bambu-network-oss contributors.
//
// MiniMqttBroker — single-connection, MQTT-3.1.1, plaintext TCP test
// fixture. Implements the subset of the spec our LanMqttSession +
// CloudMqttSession actually exercise: CONNECT/CONNACK, SUBSCRIBE/SUBACK,
// UNSUBSCRIBE/UNSUBACK, PUBLISH/PUBACK, PINGREQ/PINGRESP, DISCONNECT.
//
// Why an in-process mini-broker rather than a real mosquitto:
//   The build host has libmosquitto + mosquitto-clients but NOT the
//   mosquitto broker (`apt: mosquitto`). Spec forbids adding it as a
//   runtime dep. An in-process broker is also faster + deterministic for
//   tests. The real broker is what the LAN mosquitto fixture mocks: same
//   wire bytes, smaller surface.
//
// Threading: one accept thread, one I/O thread per accepted connection.
// All API surface is documented; callers wait on listening_ before
// connecting clients.

#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace bnet_test {

// Single PUBLISH (sent by the SUT to us).
struct CapturedPublish {
    std::string topic;
    std::string payload;
    int         qos = 0;
};

class MiniMqttBroker {
public:
    MiniMqttBroker() = default;
    ~MiniMqttBroker() { stop(); }

    // Bind on 127.0.0.1:0, return assigned port, or 0 on failure.
    std::uint16_t start();
    void          stop();

    // Block (up to timeout_ms) until at least n PUBLISHes have been
    // captured. Returns the count actually captured (>= 0). Spurious
    // wakeup safe.
    std::size_t wait_for_publishes(std::size_t n, int timeout_ms);

    // Block until at least one subscribe has been accepted.
    bool wait_for_subscribe(int timeout_ms);

    // Block until at least one connection has authed (CONNACK sent).
    bool wait_for_connect(int timeout_ms);

    // Snapshot captures so far. Thread-safe.
    std::vector<CapturedPublish> publishes() const;
    std::vector<std::string>     subscribes() const;

    // Send a synthetic PUBLISH from the broker to the connected client.
    // Used by the test to simulate a `cert_report` arriving on the
    // security topic. Returns false if no client connected.
    bool publish_to_client(const std::string& topic,
                           const std::string& payload,
                           int qos = 0);

private:
    void accept_loop();
    void client_loop(int fd);

    bool read_packet(int fd, std::uint8_t& type, std::vector<std::uint8_t>& body);
    bool write_all(int fd, const void* buf, std::size_t n);
    static std::vector<std::uint8_t>
        encode_remaining_length(std::uint32_t len);

    void handle_connect(int fd, const std::vector<std::uint8_t>& body);
    void handle_subscribe(int fd, const std::vector<std::uint8_t>& body);
    void handle_unsubscribe(int fd, const std::vector<std::uint8_t>& body);
    void handle_publish(int fd, std::uint8_t flags,
                        const std::vector<std::uint8_t>& body);
    void handle_pingreq(int fd);

    int                  listen_fd_ = -1;
    std::uint16_t        port_ = 0;
    std::thread          accept_thread_;
    std::atomic<bool>    stop_{false};

    mutable std::mutex          mu_;
    std::condition_variable     cv_;
    bool                        connected_ = false;
    int                         client_fd_ = -1;
    std::vector<CapturedPublish> publishes_;
    std::vector<std::string>     subs_;
};

}  // namespace bnet_test
