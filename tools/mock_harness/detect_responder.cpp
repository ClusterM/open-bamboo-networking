// detect_responder -- clean-room :3000 login/detect sidecar for the
// openbu-mock harness (plan 04-02, decision D-01).
//
// Clean-room per D-01 - sources: research/08.06-bind.md 8.6.2 + obn::lan_bind_tcp codec
//
// Wire facts, all from research/08.06-bind.md section 8.6.2: stock opens a
// plaintext TCP connection to dev_ip:3000, sends one framed request
//     A5 A5 | uint16_le total_len | UTF-8 JSON | A7 A7
//     {"login":{"command":"detect","sequence_id":"20000"}}
// expects a single framed reply whose "login" object carries command, id,
// model, name, version, bind, connect (sequence_id echoed as a JSON number
// in the captured reply dialect), then closes. Our own
// obn::lan_bind_tcp::encode_frame / drain_frames perform all framing -- no
// framing byte is written by hand here ("Don't Hand-Roll", plan 04-02) and
// nothing from the openbu-mock source was read.
//
// The reply must satisfy our stock-equivalent parser in
// src/lan_bind_tcp.cpp:326-339: field reads as listed above and a hard
// failure on an empty id -- hence --id is required below.

#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "obn/json_lite.hpp"
#include "obn/lan_bind_tcp.hpp"

namespace {

struct Options {
    std::string bind       = "0.0.0.0:3000";
    std::string id;
    std::string model      = "C12";       // P1S model code (research 8.6.2 reply dialect)
    std::string name;
    std::string version    = "01.09.01.00";
    std::string bind_state = "free";      // OQ5 provisional default
    std::string connect    = "lan";       // OQ5 provisional default
    long long   seq        = 20000;       // JSON number, per the captured reply
};

void usage(std::FILE* out)
{
    std::fprintf(out,
        "usage: detect_responder [options]\n"
        "  --bind ADDR:PORT     listen address (default 0.0.0.0:3000)\n"
        "  --id ID              printer serial; required, stock hard-fails on empty id\n"
        "  --model MODEL        model code (default C12)\n"
        "  --name NAME          device name\n"
        "  --version VERSION    firmware version (default 01.09.01.00)\n"
        "  --bind-state STATE   reply bind field (default free)\n"
        "  --connect MODE       reply connect field (default lan)\n"
        "  --seq N              reply sequence_id as JSON number (default 20000)\n"
        "  --help               show this help\n");
}

bool split_host_port(const std::string& spec, std::string& host, int& port)
{
    const auto pos = spec.rfind(':');
    if (pos == std::string::npos || pos == 0 || pos + 1 >= spec.size()) return false;
    host = spec.substr(0, pos);
    char* end = nullptr;
    const long p = std::strtol(spec.c_str() + pos + 1, &end, 10);
    if (!end || *end != '\0' || p <= 0 || p > 65535) return false;
    port = static_cast<int>(p);
    return true;
}

// Serve exactly one TCP session: read until obn::lan_bind_tcp::drain_frames
// yields a payload (~2 s deadline), reply with one framed detect answer if
// the request command is "detect", then the caller closes the socket.
// Non-detect or malformed input closes without any reply.
void serve_one(int cfd, const Options& opt)
{
    std::string buf;
    std::vector<std::string> payloads;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline) {
        struct pollfd pfd;
        pfd.fd = cfd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        const int pr = ::poll(&pfd, 1, 200);
        if (pr < 0) break;
        if (pr == 0) continue;
        char tmp[4096];
        const ssize_t n = ::recv(cfd, tmp, sizeof(tmp), 0);
        if (n <= 0) break;
        buf.append(tmp, static_cast<size_t>(n));
        payloads = obn::lan_bind_tcp::drain_frames(buf);
        if (!payloads.empty()) break;
    }
    if (payloads.empty()) return;

    const std::string& payload = payloads.front();
    std::string perr;
    auto root = obn::json::parse(payload, &perr);
    if (!root) return;
    const auto& login = root->find("login");
    if (!login.is_object()) return;
    if (login.find("command").as_string() != "detect") return;

    obn::json::Object reply;
    reply.emplace("command", obn::json::Value("detect"));
    reply.emplace("bind", obn::json::Value(opt.bind_state));
    reply.emplace("connect", obn::json::Value(opt.connect));
    reply.emplace("dev_cap", obn::json::Value(1.0));
    reply.emplace("id", obn::json::Value(opt.id));
    reply.emplace("model", obn::json::Value(opt.model));
    reply.emplace("name", obn::json::Value(opt.name));
    reply.emplace("sequence_id",
                  obn::json::Value(static_cast<double>(opt.seq)));
    reply.emplace("version", obn::json::Value(opt.version));
    obn::json::Object outer;
    outer.emplace("login", obn::json::Value(std::move(reply)));

    const std::string frame = obn::lan_bind_tcp::encode_frame(
        obn::json::Value(std::move(outer)).dump());
    if (frame.empty()) return;
    size_t off = 0;
    while (off < frame.size()) {
        const ssize_t n = ::send(cfd, frame.data() + off, frame.size() - off, 0);
        if (n <= 0) return;
        off += static_cast<size_t>(n);
    }
    std::printf("detect: served id=%s\n", opt.id.c_str());
    std::fflush(stdout);
}

} // namespace

int main(int argc, char** argv)
{
    Options opt;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](const char* flag) -> const char* {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "detect_responder: %s needs a value\n", flag);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--help" || a == "-h") {
            usage(stdout);
            return 0;
        } else if (a == "--bind") {
            opt.bind = next("--bind");
        } else if (a == "--id") {
            opt.id = next("--id");
        } else if (a == "--model") {
            opt.model = next("--model");
        } else if (a == "--name") {
            opt.name = next("--name");
        } else if (a == "--version") {
            opt.version = next("--version");
        } else if (a == "--bind-state") {
            opt.bind_state = next("--bind-state");
        } else if (a == "--connect") {
            opt.connect = next("--connect");
        } else if (a == "--seq") {
            char* end = nullptr;
            const long long v = std::strtoll(next("--seq"), &end, 10);
            if (!end || *end != '\0') {
                std::fprintf(stderr, "detect_responder: --seq must be an integer\n");
                return 2;
            }
            opt.seq = v;
        } else {
            std::fprintf(stderr, "detect_responder: unknown flag %s\n", a.c_str());
            usage(stderr);
            return 2;
        }
    }
    if (opt.id.empty()) {
        // src/lan_bind_tcp.cpp:335-339 -- our client hard-fails on empty id,
        // so a responder without one would be useless by construction.
        std::fprintf(stderr,
                     "detect_responder: --id is required (stock hard-fails on "
                     "an empty detect id)\n");
        return 2;
    }

    std::string host;
    int port = 0;
    if (!split_host_port(opt.bind, host, port)) {
        std::fprintf(stderr, "detect_responder: --bind must be ADDR:PORT (got %s)\n",
                     opt.bind.c_str());
        return 2;
    }

    const int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        std::perror("detect_responder: socket");
        return 1;
    }
    int yes = 1;
    ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(static_cast<uint16_t>(port));
    if (::inet_pton(AF_INET, host.c_str(), &sa.sin_addr) != 1) {
        std::fprintf(stderr, "detect_responder: bad IPv4 address %s\n", host.c_str());
        ::close(lfd);
        return 2;
    }
    if (::bind(lfd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) != 0) {
        std::perror("detect_responder: bind");
        ::close(lfd);
        return 1;
    }
    if (::listen(lfd, 8) != 0) {
        std::perror("detect_responder: listen");
        ::close(lfd);
        return 1;
    }
    std::printf("detect_responder: listening on %s id=%s bind=%s connect=%s\n",
                opt.bind.c_str(), opt.id.c_str(), opt.bind_state.c_str(),
                opt.connect.c_str());
    std::fflush(stdout);

    // The loop serves repeated connections -- stock retries after a miss.
    for (;;) {
        const int cfd = ::accept(lfd, nullptr, nullptr);
        if (cfd < 0) continue;
        serve_one(cfd, opt);
        ::close(cfd);
    }
}
