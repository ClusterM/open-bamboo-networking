// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 bambu-network-oss contributors.

#include "mqtt_mini_broker.hpp"

#include <chrono>
#include <cstdio>

namespace bnet_test {

std::uint16_t MiniMqttBroker::start() {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) return 0;
    int yes = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in a{};
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port        = 0;
    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        return 0;
    }
    socklen_t alen = sizeof(a);
    ::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&a), &alen);
    port_ = ntohs(a.sin_port);
    if (::listen(listen_fd_, 4) < 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        return 0;
    }
    accept_thread_ = std::thread(&MiniMqttBroker::accept_loop, this);
    return port_;
}

void MiniMqttBroker::stop() {
    if (stop_.exchange(true)) return;
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (client_fd_ >= 0) {
            ::shutdown(client_fd_, SHUT_RDWR);
            ::close(client_fd_);
            client_fd_ = -1;
        }
    }
    if (accept_thread_.joinable()) accept_thread_.join();
}

void MiniMqttBroker::accept_loop() {
    while (!stop_.load()) {
        sockaddr_in peer{};
        socklen_t   plen = sizeof(peer);
        int fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&peer), &plen);
        if (fd < 0) {
            if (stop_.load()) return;
            continue;
        }
        std::thread([this, fd]() { client_loop(fd); }).detach();
    }
}

std::vector<std::uint8_t>
MiniMqttBroker::encode_remaining_length(std::uint32_t len) {
    std::vector<std::uint8_t> out;
    do {
        std::uint8_t digit = len & 0x7f;
        len >>= 7;
        if (len > 0) digit |= 0x80;
        out.push_back(digit);
    } while (len > 0);
    return out;
}

bool MiniMqttBroker::write_all(int fd, const void* buf, std::size_t n) {
    const std::uint8_t* p = static_cast<const std::uint8_t*>(buf);
    while (n > 0) {
        ssize_t w = ::send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0) return false;
        p += w;
        n -= static_cast<std::size_t>(w);
    }
    return true;
}

bool MiniMqttBroker::read_packet(int fd, std::uint8_t& type,
                                 std::vector<std::uint8_t>& body) {
    std::uint8_t hdr;
    ssize_t r = ::recv(fd, &hdr, 1, 0);
    if (r != 1) return false;
    type = hdr;
    // Variable-length remaining-length.
    std::uint32_t mul = 1;
    std::uint32_t len = 0;
    for (int i = 0; i < 4; ++i) {
        std::uint8_t d;
        r = ::recv(fd, &d, 1, 0);
        if (r != 1) return false;
        len += (d & 0x7f) * mul;
        if ((d & 0x80) == 0) break;
        mul *= 128;
    }
    body.resize(len);
    std::size_t got = 0;
    while (got < len) {
        r = ::recv(fd, body.data() + got, len - got, 0);
        if (r <= 0) return false;
        got += static_cast<std::size_t>(r);
    }
    return true;
}

void MiniMqttBroker::handle_connect(int fd,
                                    const std::vector<std::uint8_t>& /*body*/) {
    // Reply CONNACK: 0x20 0x02 0x00 0x00 (sp=0, ret=0)
    std::uint8_t pkt[] = {0x20, 0x02, 0x00, 0x00};
    write_all(fd, pkt, sizeof(pkt));
    std::lock_guard<std::mutex> lk(mu_);
    connected_ = true;
    cv_.notify_all();
}

void MiniMqttBroker::handle_subscribe(int fd,
                                      const std::vector<std::uint8_t>& body) {
    // Variable header: PacketId (2 B). Payload: pairs of (topic, qos).
    if (body.size() < 2) return;
    std::uint16_t pid = (body[0] << 8) | body[1];
    std::size_t off = 2;
    std::vector<std::uint8_t> return_codes;
    while (off + 2 <= body.size()) {
        std::uint16_t tl = (body[off] << 8) | body[off + 1];
        off += 2;
        if (off + tl > body.size()) break;
        std::string topic(reinterpret_cast<const char*>(body.data() + off), tl);
        off += tl;
        if (off >= body.size()) break;
        std::uint8_t qos = body[off++];
        return_codes.push_back(qos);
        {
            std::lock_guard<std::mutex> lk(mu_);
            subs_.push_back(topic);
        }
    }
    // SUBACK: type 0x90, remaining = 2 (pid) + N (codes)
    std::vector<std::uint8_t> pkt;
    pkt.push_back(0x90);
    auto rl = encode_remaining_length(2 + return_codes.size());
    pkt.insert(pkt.end(), rl.begin(), rl.end());
    pkt.push_back(pid >> 8);
    pkt.push_back(pid & 0xff);
    pkt.insert(pkt.end(), return_codes.begin(), return_codes.end());
    write_all(fd, pkt.data(), pkt.size());
    cv_.notify_all();
}

void MiniMqttBroker::handle_unsubscribe(int fd,
                                        const std::vector<std::uint8_t>& body) {
    if (body.size() < 2) return;
    std::uint16_t pid = (body[0] << 8) | body[1];
    // UNSUBACK: type 0xb0, len 2, pid.
    std::uint8_t pkt[4] = {0xb0, 0x02,
                           static_cast<std::uint8_t>(pid >> 8),
                           static_cast<std::uint8_t>(pid & 0xff)};
    write_all(fd, pkt, sizeof(pkt));
}

void MiniMqttBroker::handle_publish(int fd, std::uint8_t flags,
                                    const std::vector<std::uint8_t>& body) {
    int qos = (flags >> 1) & 0x03;
    // Variable header: topic (UTF-8 with 2 B length) [+ pid if qos > 0]
    if (body.size() < 2) return;
    std::uint16_t tl = (body[0] << 8) | body[1];
    if (body.size() < 2u + tl) return;
    std::string topic(reinterpret_cast<const char*>(body.data() + 2), tl);
    std::size_t off = 2u + tl;
    std::uint16_t pid = 0;
    if (qos > 0) {
        if (body.size() < off + 2) return;
        pid = (body[off] << 8) | body[off + 1];
        off += 2;
    }
    std::string payload(reinterpret_cast<const char*>(body.data() + off),
                        body.size() - off);
    {
        std::lock_guard<std::mutex> lk(mu_);
        publishes_.push_back({topic, payload, qos});
    }
    cv_.notify_all();
    if (qos == 1) {
        // PUBACK 0x40 0x02 pid_hi pid_lo
        std::uint8_t pkt[4] = {0x40, 0x02,
                               static_cast<std::uint8_t>(pid >> 8),
                               static_cast<std::uint8_t>(pid & 0xff)};
        write_all(fd, pkt, sizeof(pkt));
    }
}

void MiniMqttBroker::handle_pingreq(int fd) {
    std::uint8_t pkt[2] = {0xd0, 0x00};
    write_all(fd, pkt, sizeof(pkt));
}

void MiniMqttBroker::client_loop(int fd) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        client_fd_ = fd;
    }
    while (!stop_.load()) {
        std::uint8_t hdr;
        std::vector<std::uint8_t> body;
        if (!read_packet(fd, hdr, body)) break;
        std::uint8_t type  = hdr >> 4;
        std::uint8_t flags = hdr & 0x0f;
        switch (type) {
        case 1:  handle_connect(fd, body); break;       // CONNECT
        case 3:  handle_publish(fd, flags, body); break;// PUBLISH
        case 8:  handle_subscribe(fd, body); break;     // SUBSCRIBE
        case 10: handle_unsubscribe(fd, body); break;   // UNSUBSCRIBE
        case 12: handle_pingreq(fd); break;             // PINGREQ
        case 14: /* DISCONNECT */ goto done;
        default: break;
        }
    }
done:
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (client_fd_ == fd) client_fd_ = -1;
    }
    ::close(fd);
}

bool MiniMqttBroker::publish_to_client(const std::string& topic,
                                       const std::string& payload,
                                       int qos) {
    int fd;
    {
        std::lock_guard<std::mutex> lk(mu_);
        fd = client_fd_;
    }
    if (fd < 0) return false;

    std::vector<std::uint8_t> body;
    body.push_back(topic.size() >> 8);
    body.push_back(topic.size() & 0xff);
    body.insert(body.end(), topic.begin(), topic.end());
    std::uint16_t pid = 1;
    if (qos > 0) {
        body.push_back(pid >> 8);
        body.push_back(pid & 0xff);
    }
    body.insert(body.end(), payload.begin(), payload.end());

    std::vector<std::uint8_t> pkt;
    pkt.push_back(0x30 | ((qos & 0x3) << 1));
    auto rl = encode_remaining_length(body.size());
    pkt.insert(pkt.end(), rl.begin(), rl.end());
    pkt.insert(pkt.end(), body.begin(), body.end());
    return write_all(fd, pkt.data(), pkt.size());
}

std::size_t MiniMqttBroker::wait_for_publishes(std::size_t n, int timeout_ms) {
    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                 [&] { return publishes_.size() >= n || stop_.load(); });
    return publishes_.size();
}

bool MiniMqttBroker::wait_for_subscribe(int timeout_ms) {
    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                 [&] { return !subs_.empty() || stop_.load(); });
    return !subs_.empty();
}

bool MiniMqttBroker::wait_for_connect(int timeout_ms) {
    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                 [&] { return connected_ || stop_.load(); });
    return connected_;
}

std::vector<CapturedPublish> MiniMqttBroker::publishes() const {
    std::lock_guard<std::mutex> lk(mu_);
    return publishes_;
}

std::vector<std::string> MiniMqttBroker::subscribes() const {
    std::lock_guard<std::mutex> lk(mu_);
    return subs_;
}

}  // namespace bnet_test
