#include "obn/lan_bind_tcp.hpp"

#include "obn/bambu_networking.hpp"
#include "obn/config.hpp"
#include "obn/json_lite.hpp"
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
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#endif

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace obn::lan_bind_tcp {
namespace {

constexpr uint8_t kMagicHead0 = 0xA5;
constexpr uint8_t kMagicHead1 = 0xA5;
constexpr uint8_t kMagicTail0 = 0xA7;
constexpr uint8_t kMagicTail1 = 0xA7;
constexpr uint16_t kMinFrame  = 6;

using clock    = std::chrono::steady_clock;
using socket_t = obn::os::socket_t;

socket_t connect_tcp(const std::string& host, int port, int timeout_ms)
{
    obn::os::winsock_init_once();

    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;
    addrinfo* res     = nullptr;
    char port_buf[16];
    std::snprintf(port_buf, sizeof(port_buf), "%d", port);
    int gai = ::getaddrinfo(host.c_str(), port_buf, &hints, &res);
    if (gai != 0 || !res) {
        OBN_WARN("lan_bind_tcp: getaddrinfo(%s): %s",
                 host.c_str(), ::gai_strerror(gai));
        return obn::os::kInvalidSocket;
    }

    socket_t fd = obn::os::kInvalidSocket;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = static_cast<socket_t>(
            ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
        if (!obn::os::socket_valid(fd)) continue;
        if (obn::os::set_nonblocking(fd) != 0) {
            obn::os::close_socket(fd);
            fd = obn::os::kInvalidSocket;
            continue;
        }
        int rc = ::connect(static_cast<int>(fd), ai->ai_addr,
                           static_cast<int>(ai->ai_addrlen));
        if (rc == 0) break;
        int err = obn::os::last_socket_error();
        if (!obn::os::socket_in_progress(err)) {
            obn::os::close_socket(fd);
            fd = obn::os::kInvalidSocket;
            continue;
        }
        short revents = 0;
        int w = obn::os::poll_one(fd, POLLOUT, timeout_ms, &revents);
        if (w <= 0) {
            obn::os::close_socket(fd);
            fd = obn::os::kInvalidSocket;
            continue;
        }
        int soerr = 0;
#ifdef _WIN32
        int slen = sizeof(soerr);
#else
        socklen_t slen = sizeof(soerr);
#endif
        if (::getsockopt(static_cast<int>(fd), SOL_SOCKET, SO_ERROR,
                         reinterpret_cast<char*>(&soerr), &slen) != 0 ||
            soerr != 0) {
            obn::os::close_socket(fd);
            fd = obn::os::kInvalidSocket;
            continue;
        }
        break;
    }
    ::freeaddrinfo(res);
    return fd;
}

bool send_all(socket_t fd, const std::string& data, int timeout_ms)
{
    size_t off = 0;
    auto deadline = clock::now() + std::chrono::milliseconds(timeout_ms);
    while (off < data.size()) {
        int left = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - clock::now())
                .count());
        if (left <= 0) return false;
        short revents = 0;
        int w = obn::os::poll_one(fd, POLLOUT, left, &revents);
        if (w <= 0) return false;
#ifdef _WIN32
        int n = ::send(static_cast<SOCKET>(fd), data.data() + off,
                       static_cast<int>(data.size() - off), 0);
#else
        ssize_t n = ::send(fd, data.data() + off, data.size() - off, 0);
#endif
        if (n < 0) {
            int e = obn::os::last_socket_error();
            if (obn::os::socket_in_progress(e) || e == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

bool recv_some(socket_t fd, std::string& buf, int timeout_ms)
{
    short revents = 0;
    int w = obn::os::poll_one(fd, POLLIN, timeout_ms, &revents);
    if (w <= 0) return false;
    char tmp[4096];
#ifdef _WIN32
    int n = ::recv(static_cast<SOCKET>(fd), tmp, sizeof(tmp), 0);
#else
    ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
#endif
    if (n <= 0) return false;
    buf.append(tmp, static_cast<size_t>(n));
    return true;
}

LoginReport parse_login_report(const std::string& json)
{
    LoginReport r;
    std::string perr;
    auto root = obn::json::parse(json, &perr);
    if (!root) return r;
    const auto& login = root->find("login");
    if (!login.is_object()) return r;
    if (login.find("command").as_string() != "login_report") return r;
    r.status = login.find("status").as_string();
    r.ticket = login.find("ticket").as_string();
    r.reason = login.find("reason").as_string();
    if (!r.reason.empty() && r.reason.front() == '{') {
        auto rr = obn::json::parse(r.reason, &perr);
        if (rr) {
            auto ec = rr->find("err_code");
            if (!ec.is_null()) {
                if (ec.is_number()) {
                    r.err_code     = static_cast<int>(ec.as_int());
                    r.has_err_code = true;
                } else if (ec.is_string()) {
                    try {
                        r.err_code     = std::stoi(ec.as_string());
                        r.has_err_code = true;
                    } catch (...) {
                    }
                }
            }
        }
    }
    return r;
}

std::string build_login_json(const std::string& timezone,
                             bool               improved,
                             const std::string& region,
                             const std::string& country_code)
{
    const auto& cfg = obn::config::current();
    std::string api  = obn::config::cloud_api_host_for(cfg, region);
    std::string mqtt = obn::config::cloud_mqtt_host_for(cfg, region);
    std::string web  = obn::config::cloud_web_host_for(cfg, region);
    std::string base_domain = web;
    if (base_domain.rfind("https://", 0) == 0) base_domain = base_domain.substr(8);
    else if (base_domain.rfind("http://", 0) == 0) base_domain = base_domain.substr(7);
    while (!base_domain.empty() && base_domain.back() == '/') base_domain.pop_back();

    std::string cc = country_code.empty()
                         ? (region == "CN" ? "CN" : "US")
                         : country_code;
    if (api.empty() || api.back() != '/') api.push_back('/');

    std::ostringstream os;
    os << "{\"login\":{"
       << "\"command\":\"login\","
       << "\"sequence_id\":\"20001\","
       << "\"apix\":" << obn::json::escape(api) << ','
       << "\"base_domain\":" << obn::json::escape(base_domain) << ','
       << "\"iot\":" << obn::json::escape(api + "v1") << ','
       << "\"emqx\":" << obn::json::escape("ssl://" + mqtt + ":8883") << ','
       << "\"environment\":\"\","
       << "\"timezone\":" << obn::json::escape(timezone) << ','
       << "\"e-improved\":" << (improved ? "true" : "false") << ','
       << "\"tutk\":" << obn::json::escape(cc) << ','
       << "\"wifi\":" << obn::json::escape(cc)
       << "}}";
    return os.str();
}

} // namespace

std::string encode_frame(const std::string& json)
{
    const size_t total = 2 + 2 + json.size() + 2;
    if (total > 0xFFFF) return {};
    std::string out;
    out.resize(total);
    out[0] = static_cast<char>(kMagicHead0);
    out[1] = static_cast<char>(kMagicHead1);
    const uint16_t len = static_cast<uint16_t>(total);
    out[2] = static_cast<char>(len & 0xFF);
    out[3] = static_cast<char>((len >> 8) & 0xFF);
    if (!json.empty())
        std::memcpy(&out[4], json.data(), json.size());
    out[total - 2] = static_cast<char>(kMagicTail0);
    out[total - 1] = static_cast<char>(kMagicTail1);
    return out;
}

std::vector<std::string> drain_frames(std::string& buf)
{
    std::vector<std::string> out;
    while (true) {
        auto i = buf.find(std::string("\xa5\xa5", 2));
        if (i == std::string::npos) {
            buf.clear();
            break;
        }
        if (i > 0) buf.erase(0, i);
        if (buf.size() < 4) break;
        const uint16_t total =
            static_cast<uint8_t>(buf[2]) |
            (static_cast<uint16_t>(static_cast<uint8_t>(buf[3])) << 8);
        if (total < kMinFrame) {
            buf.erase(0, 2);
            continue;
        }
        if (buf.size() < total) break;
        if (static_cast<uint8_t>(buf[total - 2]) != kMagicTail0 ||
            static_cast<uint8_t>(buf[total - 1]) != kMagicTail1) {
            buf.erase(0, 2);
            continue;
        }
        out.emplace_back(buf.data() + 4, total - 6);
        buf.erase(0, total);
    }
    return out;
}

int detect(const std::string& dev_ip, BBL::detectResult& out, int timeout_ms)
{
    out = BBL::detectResult{};
    if (dev_ip.empty()) return BAMBU_NETWORK_ERR_BIND_SOCKET_CONNECT_FAILED;

    auto fd = connect_tcp(dev_ip, 3000, timeout_ms);
    if (!obn::os::socket_valid(fd)) {
        OBN_WARN("bind_detect: connect %s:3000 failed", dev_ip.c_str());
        out.result_msg = "socket connect failed";
        return BAMBU_NETWORK_ERR_BIND_SOCKET_CONNECT_FAILED;
    }

    const std::string req =
        encode_frame(R"({"login":{"command":"detect","sequence_id":"20000"}})");
    if (req.empty() || !send_all(fd, req, timeout_ms)) {
        obn::os::close_socket(fd);
        out.result_msg = "publish login request failed";
        return BAMBU_NETWORK_ERR_BIND_PUBLISH_LOGIN_REQUEST;
    }

    std::string buf;
    auto deadline = clock::now() + std::chrono::milliseconds(timeout_ms);
    while (clock::now() < deadline) {
        int left = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - clock::now())
                .count());
        if (left <= 0) break;
        if (!recv_some(fd, buf, left)) {
            if (buf.empty()) continue;
        }
        for (const auto& payload : drain_frames(buf)) {
            std::string perr;
            auto root = obn::json::parse(payload, &perr);
            if (!root) continue;
            const auto& login = root->find("login");
            if (!login.is_object()) continue;
            const std::string cmd = login.find("command").as_string();
            if (cmd == "login_report") {
                // P1 firmware in LAN-only mode rejects the detect probe with a
                // login_report FAILURE instead of the identity reply (OBN #38).
                LoginReport rep = parse_login_report(payload);
                if (rep.status != "FAILURE") continue;
                obn::os::close_socket(fd);
                OBN_WARN("bind_detect: %s refused detect: %s",
                         dev_ip.c_str(),
                         obn::log::redact(rep.reason, 160).c_str());
                out.result_msg = "login report failed";
                return rep.has_err_code
                           ? BAMBU_NETWORK_ERR_BIND_ECODE_LOGIN_REPORT_FAILED
                           : BAMBU_NETWORK_ERR_BIND_PARSE_LOGIN_REPORT_FAILED;
            }
            if (cmd != "detect") continue;

            out.command      = "detect";
            out.result_msg   = "success";
            out.dev_id       = login.find("id").as_string();
            out.model_id     = login.find("model").as_string();
            out.dev_name     = login.find("name").as_string();
            out.version      = login.find("version").as_string();
            out.bind_state   = login.find("bind").as_string();
            out.connect_type = login.find("connect").as_string();
            obn::os::close_socket(fd);
            if (out.dev_id.empty()) {
                OBN_WARN("bind_detect: empty id from %s", dev_ip.c_str());
                out.result_msg = "parse login report failed";
                return BAMBU_NETWORK_ERR_BIND_PARSE_LOGIN_REPORT_FAILED;
            }
            OBN_INFO("bind_detect %s -> id=%s bind=%s connect=%s",
                     dev_ip.c_str(),
                     out.dev_id.c_str(),
                     out.bind_state.c_str(),
                     out.connect_type.c_str());
            return BAMBU_NETWORK_SUCCESS;
        }
    }
    obn::os::close_socket(fd);
    OBN_WARN("bind_detect: timeout waiting for detect reply from %s",
             dev_ip.c_str());
    out.result_msg = "receive login report timeout";
    return BAMBU_NETWORK_ERR_BIND_RECEIVE_LOGIN_REPORT_TIMEOUT;
}

int login_bind_session(const std::string&                           dev_ip,
                       const std::string&                           timezone,
                       bool                                         improved,
                       const std::string&                           region,
                       const std::string&                           country_code,
                       const std::function<int(const std::string&)>& cloud_fn,
                       std::string&                                 fail_info,
                       int*                                         fail_err_code,
                       int                                          timeout_ms)
{
    fail_info.clear();
    if (fail_err_code) *fail_err_code = 0;
    if (dev_ip.empty()) return BAMBU_NETWORK_ERR_BIND_SOCKET_CONNECT_FAILED;

    auto fd = connect_tcp(dev_ip, 3000, std::min(timeout_ms, 5000));
    if (!obn::os::socket_valid(fd)) {
        fail_info = "tcp connect failed";
        return BAMBU_NETWORK_ERR_BIND_SOCKET_CONNECT_FAILED;
    }

    const std::string login_json =
        build_login_json(timezone, improved, region, country_code);
    const std::string frame = encode_frame(login_json);
    if (frame.empty() || !send_all(fd, frame, 5000)) {
        obn::os::close_socket(fd);
        fail_info = "publish login failed";
        return BAMBU_NETWORK_ERR_BIND_PUBLISH_LOGIN_REQUEST;
    }
    OBN_INFO("bind login published to %s:3000", dev_ip.c_str());

    std::string buf;
    std::string ticket;
    bool        saw_success = false;
    bool        cloud_done  = false;
    int         cloud_rc    = BAMBU_NETWORK_ERR_BIND_FAILED;
    auto        deadline =
        clock::now() + std::chrono::milliseconds(timeout_ms);

    while (clock::now() < deadline) {
        int left = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - clock::now())
                .count());
        if (left <= 0) break;
        (void)recv_some(fd, buf, std::min(left, 500));
        for (const auto& payload : drain_frames(buf)) {
            LoginReport rep = parse_login_report(payload);
            if (rep.status.empty()) continue;
            OBN_INFO("bind login_report status=%s ticket=%s reason=%s",
                     rep.status.c_str(),
                     rep.ticket.c_str(),
                     obn::log::redact(rep.reason, 120).c_str());

            if (rep.status == "FAILURE") {
                fail_info = rep.reason.empty() ? "login_report FAILURE"
                                               : rep.reason;
                if (fail_err_code && rep.has_err_code)
                    *fail_err_code = rep.err_code;
                obn::os::close_socket(fd);
                return rep.has_err_code
                           ? BAMBU_NETWORK_ERR_BIND_ECODE_LOGIN_REPORT_FAILED
                           : BAMBU_NETWORK_ERR_BIND_PARSE_LOGIN_REPORT_FAILED;
            }
            if (rep.status == "wait_auth" && !rep.ticket.empty() &&
                ticket.empty()) {
                ticket = rep.ticket;
            }
            if (rep.status == "SUCCESS") saw_success = true;
        }

        if (!ticket.empty() && !cloud_done && cloud_fn) {
            cloud_rc   = cloud_fn(ticket);
            cloud_done = true;
            if (cloud_rc != BAMBU_NETWORK_SUCCESS) {
                obn::os::close_socket(fd);
                fail_info = "cloud ticket validate failed";
                return cloud_rc;
            }
        }

        if (cloud_done && saw_success) {
            obn::os::close_socket(fd);
            return BAMBU_NETWORK_SUCCESS;
        }
        if (cloud_done && !ticket.empty()) {
            auto rest = deadline - clock::now();
            if (rest < std::chrono::milliseconds(800)) {
                obn::os::close_socket(fd);
                return BAMBU_NETWORK_SUCCESS;
            }
        }
    }

    obn::os::close_socket(fd);
    if (ticket.empty()) {
        fail_info = "timeout waiting for wait_auth ticket";
        return BAMBU_NETWORK_ERR_BIND_GET_PRINTER_TICKET_TIMEOUT;
    }
    if (!cloud_done) {
        fail_info = "timeout before cloud ticket POST";
        return BAMBU_NETWORK_ERR_BIND_GET_CLOUD_TICKET_TIMEOUT;
    }
    return BAMBU_NETWORK_SUCCESS;
}

} // namespace obn::lan_bind_tcp
