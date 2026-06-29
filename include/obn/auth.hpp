#pragma once

// Persistence layer for the cloud user session.
//
// Bambu Studio itself keeps the logged-in state in-memory and expects
// the plugin to remember tokens across restarts. We stash them in
// `<config_dir>/obn.auth.json` with user-only permissions (0600).
//
// The struct is a flat view of everything we need later to talk to the
// cloud: the refresh token, a valid access token with its expiry, and
// the basic profile data Studio asks us for via
// `bambu_network_get_user_{id,name,avatar,nickanme}`.

#include "obn/cloud_auth.hpp"

#include <chrono>
#include <mutex>
#include <optional>
#include <string>

namespace obn::auth {

struct Session {
    std::string region       = "GLOBAL";
    std::string account;           // email used to log in
    std::string access_token;
    std::string refresh_token;
    std::chrono::system_clock::time_point expires_at;

    std::string user_id;           // uid as string
    std::string user_name;
    std::string nick_name;
    std::string avatar;
    bool firmware_beta_open = false; // from GET /v1/user-service/my/profile setting.isFirmwareBetaOpen

    bool logged_in() const { return !access_token.empty() && !user_id.empty(); }
};

class Store {
public:
    // `path` is usually `<config_dir>/obn.auth.json`. Empty path disables
    // disk persistence (useful for tests).
    explicit Store(std::string path);

    // Load from disk if possible. Safe to call before any mutators.
    void load();

    // Replace the whole session. Persists to disk.
    void set(Session s);

    // Update the tokens (and expires_at) in-place; other fields untouched.
    void update_tokens(const std::string& access,
                       const std::string& refresh,
                       std::chrono::seconds lifetime);

    // Update profile fields; tokens untouched.
    void update_profile(const std::string& user_id,
                        const std::string& user_name,
                        const std::string& nick_name,
                        const std::string& avatar);

    // Update the firmware beta flag independently of other profile fields.
    void update_firmware_beta(bool open);

    // Read a copy of the current session.
    Session snapshot() const;

    // Wipe everything and delete the file.
    void clear();

    // Best-effort "do we need to refresh?" check with a grace period.
    bool needs_refresh(std::chrono::seconds margin = std::chrono::minutes(10)) const;

private:
    void persist_locked() const;
    void load_locked();

    std::string          path_;
    mutable std::mutex   mu_;
    Session              s_;
};

} // namespace obn::auth
