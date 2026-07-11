#pragma once

// Long-lived cloud MQTT client used to talk to Bambu's message broker at
// us.mqtt.bambulab.com:8883 (or cn.mqtt.bambulab.com for the CN region).
//
// Scope:
//   * One connection per logged-in user, authenticated as
//         u_{USER_ID} / {ACCESS_TOKEN}
//     (see OpenBambuAPI/mqtt.md).
//   * Owns the set of subscribed device topics, which grows/shrinks via
//     add_subscribe()/del_subscribe() as Studio's UI opens/closes
//     devices. Re-applies the subscription set on every reconnect so
//     messages keep flowing after transient network drops.
//   * Publishes Studio's request payloads verbatim to
//     device/{dev_id}/request.
//
// Thread model is identical to LanSession: mosquitto's network loop
// runs on its own thread and invokes our callbacks from there. The
// caller is responsible for trampolining those into the UI thread via
// Agent::queue_on_main_ where needed.

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace obn {
namespace mqtt { class Client; }

class CloudSession {
public:
    // Studio expects the same three callback shapes the LAN path uses.
    // on_connected() follows the BBL::ConnectStatus contract (Ok=0,
    // Failed=1, Lost=2). on_message() delivers the raw JSON payload
    // already keyed by dev_id parsed out of the topic.
    using ConnectedCb = std::function<void(int status, int reason_code,
                                           std::string msg)>;
    using MessageCb   = std::function<void(std::string dev_id, std::string json)>;
    using SubscribeFailedCb = std::function<void(std::string dev_id)>;

    CloudSession();
    ~CloudSession();

    CloudSession(const CloudSession&)            = delete;
    CloudSession& operator=(const CloudSession&) = delete;

    // Parameters are captured so the session can reconnect by itself:
    //   region       "GLOBAL" (us.mqtt.bambulab.com) or "CN"
    //   user_id      stringified user id, prefixed with "u_" in username
    //   access_token bearer token from login/refresh
    //   ca_file      optional PEM bundle override; empty -> system trust
    void configure(std::string region,
                   std::string user_id,
                   std::string access_token,
                   std::string ca_file = {});

    // Kick off the connection. Returns BAMBU_NETWORK_* code reflecting
    // mosquitto_connect_async; later connection success/failure is
    // reported through the ConnectedCb.
    int start(ConnectedCb on_connected,
              MessageCb   on_message,
              SubscribeFailedCb on_subscribe_failed = {});

    // Tear the session down. Blocks until the network thread has
    // stopped. Safe to call repeatedly.
    void stop();

    // Add / remove device subscriptions. Works whether or not we're
    // currently connected: on reconnect the full set is re-applied.
    int add_subscribe(const std::vector<std::string>& dev_ids);
    int del_subscribe(const std::vector<std::string>& dev_ids);

    // Publish to device/{dev_id}/request. Returns BAMBU_NETWORK_*.
    int publish(const std::string& dev_id,
                const std::string& json_str,
                int qos);

    bool is_connected() const { return connected_.load(std::memory_order_acquire); }

private:
    std::string report_topic_(const std::string& dev_id) const;
    std::string request_topic_(const std::string& dev_id) const;

    std::string mqtt_host_() const;
    // Called under mu_ after every successful CONNACK: iterates subscribed_,
    // issues SUBSCRIBE for each dev_id that is not yet in active_, and
    // populates active_ on success.
    void apply_subscriptions_locked_();

    mutable std::mutex mu_;
    std::string        region_;
    std::string        user_id_;
    std::string        access_token_;
    std::string        ca_file_;
    std::set<std::string> subscribed_; // the desired set; re-applied on connect.
    std::set<std::string> active_;     // what we've actually issued SUBSCRIBEs for.

    std::unique_ptr<mqtt::Client> client_;
    ConnectedCb                   on_connected_;
    MessageCb                     on_message_;
    SubscribeFailedCb             on_subscribe_failed_;

    std::atomic<bool> connected_{false};
    std::atomic<bool> started_{false};
};

} // namespace obn
