#pragma once

// Plaintext TCP :3000 bind protocol used by stock bind_detect / account
// bind (research/08.06-bind.md). Frame:
//   A5 A5 | uint16_le total_len | UTF-8 JSON | A7 A7
// where total_len includes both magic pairs and the length field.

#include <functional>
#include <string>
#include <vector>

#include "obn/bambu_networking.hpp"

namespace obn::lan_bind_tcp {

struct LoginReport {
    std::string status; // wait_auth | SUCCESS | FAILURE
    std::string ticket;
    std::string reason; // raw reason string (may be JSON)
    int         err_code     = 0;
    bool        has_err_code = false;
};

// Encode JSON into a wire frame.
std::string encode_frame(const std::string& json);

// Parse one or more frames from a buffer; consumes complete frames and
// leaves any trailing partial bytes in `buf`. Returns JSON payloads.
std::vector<std::string> drain_frames(std::string& buf);

// TCP detect → fill Studio detectResult. Returns 0 or BAMBU_NETWORK_ERR_BIND_*;
// the ABI layer narrows those to the -1/-2/-3 space Studio understands.
int detect(const std::string& dev_ip,
           BBL::detectResult& out,
           int                timeout_ms = 5000);

// Full LAN side of account bind on one TCP session: publish login, wait for
// wait_auth+ticket, invoke cloud_fn(ticket) (GET+POST my/ticket), then wait
// for SUCCESS (or accept after cloud ok). On FAILURE fills fail_info /
// fail_err_code for Studio HMS paths (-1040/-1080).
int login_bind_session(const std::string&                           dev_ip,
                       const std::string&                           timezone,
                       bool                                         improved,
                       const std::string&                           region,
                       const std::string&                           country_code,
                       const std::function<int(const std::string&)>& cloud_fn,
                       std::string&                                 fail_info,
                       int*                                         fail_err_code,
                       int                                          timeout_ms = 20000);

} // namespace obn::lan_bind_tcp
