#pragma once

// High-level wrappers for Bambu's cloud auth endpoints.
//
// Studio drives the interactive sign-in through its own wxWebView /
// system-browser flow and hands the resulting tokens back via
// `bambu_network_change_user` (see Agent::apply_login_info). On our
// side we only need:
//   * a ticket->token exchange (for the "system browser" callback),
//   * a refresh_token rotation (to keep the session alive), and
//   * a profile fetch (uid / nickname / avatar).
// The global host is `api.bambulab.com`, with a CN mirror at
// `api.bambulab.cn`.

#include <cstdint>
#include <string>
#include <vector>

namespace obn::cloud {

struct AuthResult {
    bool        ok           = false;
    long        http_status  = 0;
    std::string raw_body;       // server response body (verbatim); we keep it so
                                // Studio-side code that expects the JSON shape
                                // of "login_info" gets the real thing.
    std::string access_token;
    std::string refresh_token;
    long        expires_in         = 0; // seconds until access_token dies, as reported
    long        refresh_expires_in = 0; // seconds until refresh_token dies, as reported
    std::string login_type;      // "", "verifyCode", "tfa"
    std::string tfa_key;         // present when login_type == "tfa"
    std::string error_message;   // human-readable; populated on !ok
};

struct ProfileResult {
    bool        ok           = false;
    long        http_status  = 0;
    std::string raw_body;
    std::string user_id;
    std::string user_name;
    std::string nick_name;
    std::string avatar;
    std::string account;    // email
    std::string error_message;
};

// Endpoint host helpers. `region` is "CN" or anything else (global).
//   api_host  -> REST API base, e.g. "https://api.bambulab.com" (no slash).
//   web_host  -> portal base Studio injects into wxWebView, e.g.
//                "https://bambulab.com/" (WITH trailing slash). Studio
//                concatenates different suffixes onto this base
//                ("/sign-in", "api/sign-in/ticket?..." without a leading
//                slash, "/<lang>/sign-in"). The trailing slash on our side
//                is mandatory - otherwise "host + api/..." produces
//                "bambulab.comapi/..." and DNS fails.
std::string api_host(const std::string& region);
std::string web_host(const std::string& region);

// Ticket-exchange: the "system browser" / wxWebView login lands on the
// local HTTP server Studio stands up and hands us a short-lived
// `ticket`. We POST it to /v1/user-service/user/ticket/<TICKET> (the
// body is ignored) and the server replies with accessToken /
// refreshToken. On success the populated AuthResult's raw_body is the
// JSON Studio feeds back into `bambu_network_change_user`.
AuthResult login_with_ticket(const std::string& region,
                             const std::string& ticket);

AuthResult refresh_token(const std::string& region,
                         const std::string& refresh_token);

ProfileResult get_profile(const std::string& region,
                          const std::string& access_token);

} // namespace obn::cloud
