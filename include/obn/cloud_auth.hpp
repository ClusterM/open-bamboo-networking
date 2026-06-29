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
//
// Token persistence:
//   SessionData holds tokens with absolute expiry timestamps.
//   save_session() writes atomically (write-temp + rename) with mode 0600
//   to $XDG_CONFIG_HOME/BambuStudio/session.json (or ~/.config/BambuStudio/).
//   load_and_refresh_if_needed() is the one-call startup helper: reads the
//   file, refreshes the access token if it is within slack_seconds of
//   expiry, and saves the updated tokens back before returning.

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
    long        expires_in   = 0; // seconds until access_token dies, as reported
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

// ---- Session persistence ------------------------------------------------

// Persistent session data: tokens paired with absolute epoch-second expiry
// timestamps. Can be serialised to / deserialised from a JSON file on disk.
struct SessionData {
    std::string access_token;
    std::string refresh_token;
    int64_t     access_expires_at  = 0;   // epoch seconds; 0 = unknown
    int64_t     refresh_expires_at = 0;   // epoch seconds; 0 = unknown (assume valid)
    std::string user_id;
    std::string region;
    std::string user_email;

    // True iff both tokens are non-empty (does NOT check expiry).
    bool has_tokens() const noexcept
    {
        return !access_token.empty() && !refresh_token.empty();
    }

    // True iff the access token has at least slack_seconds remaining.
    // When access_expires_at == 0 (unknown) returns false — callers will
    // then try a refresh to be safe.
    bool access_valid(int slack_seconds = 60) const noexcept;

    // True iff the refresh token still has time.
    // When refresh_expires_at == 0 (unknown) returns true — we assume the
    // refresh token is long-lived and still usable.
    bool refresh_valid(int slack_seconds = 60) const noexcept;
};

// Default file path used by save_session() / load_session() when no
// explicit path is supplied:
//   $XDG_CONFIG_HOME/BambuStudio/session.json
//   or ~/.config/BambuStudio/session.json
std::string default_session_path();

// Promote a login / refresh AuthResult into a SessionData, computing
// access_expires_at from the current wall clock and the server-reported
// expires_in.  refresh_expires_at is left at 0 (unknown) because
// AuthResult does not carry it.
SessionData session_from_auth(const AuthResult& r,
                              const std::string& region,
                              const std::string& user_id,
                              const std::string& user_email = {});

// Persist data to disk with an atomic write (write to <path>.tmp, rename)
// and force permissions to 0600 on POSIX.  Creates the parent directory
// if missing.  Returns true on success.
bool save_session(const SessionData& data, const std::string& path = {});

// Read a session from disk.  On any error (file absent, parse failure)
// returns a SessionData with empty tokens — callers should check
// has_tokens().
SessionData load_session(const std::string& path = {});

// All-in-one startup helper:
//   1. load_session(path)
//   2. If access_valid(slack_seconds) → return as-is.
//   3. Else if refresh_valid(slack_seconds) → refresh_token HTTP call,
//      save the updated tokens back to disk, return updated SessionData.
//   4. Otherwise → return SessionData{} with empty tokens.
SessionData load_and_refresh_if_needed(const std::string& path = {},
                                       int slack_seconds = 60);

} // namespace obn::cloud
