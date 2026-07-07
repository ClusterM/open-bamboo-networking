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
//   save_session() writes atomically (write-temp + rename) with mode 0600.
//   Path priority: obn.conf session_path > config_dir/session.json.
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
    bool        firmware_beta_open = false; // setting.isFirmwareBetaOpen
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
// explicit path is supplied: obn.conf session_path, or
// config_dir/session.json when empty.
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
// NOT YET WIRED - the following struct and function document the cloud MQTT
// mTLS certificate endpoint. The implementation in cloud_auth.cpp is gated
// with #if 0. See agent.cpp install_device_cert for the integration plan.
//
// Result of fetching the cloud MQTT client certificate for a device.
// The cert chain contains three PEM blocks: device leaf, per-device
// intermediate CA named "{dev_uid}.bambulab.com", and the root CA.
// The private key is AES-256-CBC encrypted; the caller must decrypt it
// with the same aes256_key passed to fetch_device_cert().
struct DeviceCertResult {
    bool        ok          = false;
    long        http_status = 0;
    std::string raw_body;
    std::string cert;          // PEM chain: device leaf + intermediate + root
    std::string crl;           // PEM CRL from crl[0] array entry, valid ~30 days from issue
    std::string key;           // AES-256-CBC encrypted private key, base64-encoded
    std::string error_message;
};

// Fetch the cloud MQTT mTLS client certificate for a device.
//
// `application_token` - session-scoped token generated by the stock plugin and
// stored in BambuNetworkEngine.conf. It rotates between login sessions and is
// distinct from the printer dev_id. Derivation from the stock binary is not
// yet confirmed; pass the value retrieved from the active session config.
//
// `aes256_key` - caller-generated random 32-byte key, base64url-encoded.
// The server uses it to encrypt the returned private key. The caller must
// base64url-decode this key and use AES-256-CBC to decrypt
// DeviceCertResult::key before the private key can be used with mosquitto.
DeviceCertResult fetch_device_cert(const std::string& region,
                                   const std::string& access_token,
                                   const std::string& application_token,
                                   const std::string& aes256_key);

} // namespace obn::cloud
