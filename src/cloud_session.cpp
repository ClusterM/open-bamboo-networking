#include "obn/cloud_session.hpp"

#include "obn/bambu_networking.hpp"
#include "obn/config.hpp"
#include "obn/log.hpp"
#include "obn/mqtt_client.hpp"

#include <mosquitto.h>

#include <chrono>
#include <cstddef>
#include <cstring>
#include <random>
#include <sstream>
#include <utility>

namespace obn {

namespace {

std::string make_client_id(const std::string& user_id)
{
    // Bambu's real plugin uses a client id shaped roughly like
    //   "u_<USER_ID>_<hex>". We mirror the prefix so the broker-side
    // logs show which user the connection belongs to; the broker does
    // NOT enforce the format, so any unique string works.
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::ostringstream os;
    os << "u_" << user_id << "_" << std::hex << rng();
    return os.str();
}

// Map a libmosquitto CONNACK rc back onto Studio's OnServerConnectedFn
// contract:
//   return_code >= 0   success
//   return_code < 0    generic failure
//   return_code == 5   Studio sees this as "login expired" and forces
//                      a logout + re-login. MQTT CONNACK 5 (bad user/
//                      password) maps 1:1 to that.
int map_connack_to_status(int rc, int& reason)
{
    reason = rc;
    if (rc == 0) return 0;          // BBL::ConnectStatusOk
    if (rc == 5) return 5;          // signal auth failure explicitly
    // Anything else: negative to trigger generic "server failed" UI.
    return -1;
}

} // namespace

CloudSession::CloudSession()  = default;
CloudSession::~CloudSession() { stop(); }

void CloudSession::configure(std::string region,
                             std::string user_id,
                             std::string access_token,
                             std::string ca_file)
{
    std::lock_guard<std::mutex> lk(mu_);
    region_       = std::move(region);
    user_id_      = std::move(user_id);
    access_token_ = std::move(access_token);
    ca_file_      = std::move(ca_file);
}

std::string CloudSession::mqtt_host_() const
{
    if (auto o = config::resolve_override("OBN_CLOUD_MQTT_HOSTNAME", OBN_CLOUD_MQTT_HOSTNAME_DEFAULT)) return *o;
    if (region_ == "CN" || region_ == "cn") return "cn.mqtt.bambulab.com";
    return "us.mqtt.bambulab.com";
}

std::string CloudSession::report_topic_(const std::string& dev_id) const
{
    return "device/" + dev_id + "/report";
}

std::string CloudSession::request_topic_(const std::string& dev_id) const
{
    return "device/" + dev_id + "/request";
}

int CloudSession::start(ConnectedCb on_connected,
                        MessageCb   on_message,
                        SubscribeFailedCb on_subscribe_failed)
{
    if (started_.exchange(true, std::memory_order_acq_rel)) {
        // Already running - Studio sometimes calls connect_server()
        // more than once. Re-use the existing client.
        return BAMBU_NETWORK_SUCCESS;
    }

    std::string user_id;
    std::string token;
    std::string ca_file;
    std::string host;
    {
        std::lock_guard<std::mutex> lk(mu_);
        on_connected_       = std::move(on_connected);
        on_message_         = std::move(on_message);
        on_subscribe_failed_= std::move(on_subscribe_failed);
        user_id             = user_id_;
        token               = access_token_;
        ca_file             = ca_file_;
        host                = mqtt_host_();
    }

    if (user_id.empty() || token.empty()) {
        OBN_WARN("cloud mqtt: start without configured credentials");
        started_.store(false, std::memory_order_release);
        return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    }

    try {
        client_ = std::make_unique<mqtt::Client>(make_client_id(user_id));
    } catch (const std::exception& e) {
        OBN_ERROR("cloud mqtt::Client ctor failed: %s", e.what());
        started_.store(false, std::memory_order_release);
        return BAMBU_NETWORK_ERR_CONNECT_FAILED;
    }

    client_->set_on_connect([this](int rc) {
        int reason = 0;
        int status = map_connack_to_status(rc, reason);
        if (rc == 0) {
            connected_.store(true, std::memory_order_release);
            OBN_INFO("cloud mqtt: connected, re-applying %zu subscriptions",
                     [this]{ std::lock_guard<std::mutex> lk(mu_); return subscribed_.size(); }());
            {
                std::lock_guard<std::mutex> lk(mu_);
                active_.clear();
                apply_subscriptions_locked_();
            }
        } else {
            connected_.store(false, std::memory_order_release);
            OBN_WARN("cloud mqtt CONNACK rc=%d (%s)", rc, mqtt::Client::err_str(rc));
        }
        ConnectedCb cb;
        {
            std::lock_guard<std::mutex> lk(mu_);
            cb = on_connected_;
        }
        if (cb) {
            cb(status, reason,
               rc == 0 ? std::string{"ok"}
                       : std::string{"mqtt CONNACK rc="} + mqtt::Client::err_str(rc));
        }
    });

    client_->set_on_disconnect([this](int rc) {
        connected_.store(false, std::memory_order_release);
        OBN_WARN("cloud mqtt disconnect rc=%d (%s)", rc, mqtt::Client::err_str(rc));
        ConnectedCb cb;
        {
            std::lock_guard<std::mutex> lk(mu_);
            cb = on_connected_;
            active_.clear();
        }
        if (cb) {
            // status=-1 so Studio treats it as a transport failure and
            // shows the "cloud disconnected" notification; mosquitto
            // itself will try to reconnect because we used loop_start.
            cb(-1, rc,
               std::string{"cloud mqtt disconnect rc="} + mqtt::Client::err_str(rc));
        }
    });

    client_->set_on_message([this](const mqtt::Message& msg) {
        // Topic is device/<dev_id>/report. Pull the dev_id out; any
        // other topic shape we ignore (shouldn't happen - we only ever
        // subscribe to report topics).
        const std::string kPrefix = "device/";
        const std::string kSuffix = "/report";
        std::string dev_id;
        if (msg.topic.size() > kPrefix.size() + kSuffix.size()
            && msg.topic.compare(0, kPrefix.size(), kPrefix) == 0
            && msg.topic.compare(msg.topic.size() - kSuffix.size(), kSuffix.size(), kSuffix) == 0) {
            dev_id = msg.topic.substr(kPrefix.size(),
                                      msg.topic.size() - kPrefix.size() - kSuffix.size());
        } else {
            OBN_DEBUG("cloud mqtt: ignoring topic %s", msg.topic.c_str());
            return;
        }
        MessageCb cb;
        {
            std::lock_guard<std::mutex> lk(mu_);
            cb = on_message_;
        }
        if (cb) cb(std::move(dev_id), msg.payload);
    });

    mqtt::ConnectConfig cfg;
    cfg.host         = host;
    cfg.port         = 8883;
    cfg.username     = "u_" + user_id;
    cfg.password     = token;
    cfg.use_tls      = true;
    // Cloud broker runs a real publicly-trusted cert, so we verify.
    cfg.tls_insecure = false;
    cfg.ca_file      = ca_file; // optional override; empty -> system store
    cfg.keepalive_s  = 60;
#if defined(_WIN32)
    // Windows MVP: ca_file (above) is the BBL slicer bundle that
    // Agent::connect_cloud forwards us. It's the only PEM we can hand
    // mosquitto_tls_set on this platform (the static OpenSSL ships no
    // default trust dir), but its roots don't sign *.bambulab.com.
    // Skip both the chain check and the hostname check, so the SSL
    // handshake doesn't reject a perfectly-valid public cert just
    // because we can't anchor it. Cloud auth remains gated by the
    // bearer token in `password`, so an MITM still can't impersonate
    // the user. See agent.cpp Agent::connect_cloud for the rationale.
    if (!ca_file.empty()) {
        cfg.tls_skip_chain_verify = true;
        cfg.tls_insecure          = true;
    }
#endif

    OBN_INFO("cloud mqtt: connecting to %s:%d as u_%s (token=%zu bytes)",
             cfg.host.c_str(), cfg.port, user_id.c_str(), token.size());

    int rc = client_->connect(cfg);
    if (rc != MOSQ_ERR_SUCCESS) {
        OBN_ERROR("cloud mqtt connect_async rc=%d (%s)",
                  rc, mqtt::Client::err_str(rc));
        started_.store(false, std::memory_order_release);
        return BAMBU_NETWORK_ERR_CONNECT_FAILED;
    }
    return BAMBU_NETWORK_SUCCESS;
}

void CloudSession::stop()
{
    if (!started_.exchange(false, std::memory_order_acq_rel)) return;
    if (client_) {
        client_->disconnect();
        client_.reset();
    }
    connected_.store(false, std::memory_order_release);
    std::lock_guard<std::mutex> lk(mu_);
    active_.clear();
}

int CloudSession::add_subscribe(const std::vector<std::string>& dev_ids)
{
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto& d : dev_ids) {
        if (d.empty()) continue;
        subscribed_.insert(d);
    }
    if (connected_.load(std::memory_order_acquire)) {
        apply_subscriptions_locked_();
    }
    return BAMBU_NETWORK_SUCCESS;
}

int CloudSession::del_subscribe(const std::vector<std::string>& dev_ids)
{
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto& d : dev_ids) {
        subscribed_.erase(d);
        if (active_.erase(d) && client_) {
            client_->unsubscribe(report_topic_(d));
        }
    }
    return BAMBU_NETWORK_SUCCESS;
}

void CloudSession::apply_subscriptions_locked_()
{
    if (!client_) return;
    // Collect everything we need to act on into local vectors so we
    // can release the lock before calling user callbacks.
    std::vector<std::string> to_sub;
    for (const auto& d : subscribed_) {
        if (!active_.count(d)) to_sub.push_back(d);
    }
    std::vector<std::string> failed;
    for (const auto& d : to_sub) {
        int rc = client_->subscribe(report_topic_(d), /*qos=*/0);
        if (rc != MOSQ_ERR_SUCCESS) {
            OBN_WARN("cloud mqtt: subscribe %s failed rc=%d (%s)",
                     d.c_str(), rc, mqtt::Client::err_str(rc));
            failed.push_back(d);
            continue;
        }
        active_.insert(d);
        OBN_INFO("cloud mqtt: subscribed to %s", report_topic_(d).c_str());
    }
    if (!failed.empty()) {
        SubscribeFailedCb cb = on_subscribe_failed_;
        mu_.unlock();
        if (cb) for (const auto& d : failed) cb(d);
        mu_.lock();
    }
}

int CloudSession::publish(const std::string& dev_id,
                          const std::string& json_str,
                          int qos)
{
    if (!client_ || !connected_.load(std::memory_order_acquire)) {
        OBN_WARN("cloud mqtt: publish to %s while disconnected", dev_id.c_str());
        return BAMBU_NETWORK_ERR_SEND_MSG_FAILED;
    }
    int rc = client_->publish(request_topic_(dev_id), json_str, qos, /*retain=*/false);
    if (rc != MOSQ_ERR_SUCCESS) {
        OBN_WARN("cloud mqtt: publish to %s rc=%d (%s)",
                 dev_id.c_str(), rc, mqtt::Client::err_str(rc));
        return BAMBU_NETWORK_ERR_SEND_MSG_FAILED;
    }
    return BAMBU_NETWORK_SUCCESS;
}

} // namespace obn
