#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/lan_tls.hpp"
#include "obn/log.hpp"
#include "obn/mqtt_client.hpp"

#include <mosquitto.h>

#include <chrono>
#include <cstdio>
#include <random>
#include <sstream>

namespace obn {

namespace {

// Bambu printers accept any MQTT client ID but Studio itself uses something
// like "bblp/<rand>". We mirror that so logs on the printer side look
// familiar.
std::string make_client_id()
{
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::ostringstream                  oss;
    oss << "obn-" << std::hex << rng() << "-" << std::chrono::steady_clock::now().time_since_epoch().count();
    return oss.str();
}

int map_mqtt_err(int rc)
{
    return rc == MOSQ_ERR_SUCCESS ? BAMBU_NETWORK_SUCCESS
                                  : BAMBU_NETWORK_ERR_CONNECT_FAILED;
}

} // namespace

LanSession::LanSession(std::string dev_id,
                       std::string dev_ip,
                       std::string username,
                       std::string password,
                       bool        use_ssl,
                       std::string ca_file)
    : dev_id_(std::move(dev_id))
    , dev_ip_(std::move(dev_ip))
    , username_(std::move(username))
    , password_(std::move(password))
    , use_ssl_(use_ssl)
    , ca_file_(std::move(ca_file))
{
}

LanSession::~LanSession()
{
    disconnect();
}

std::string LanSession::report_topic_() const
{
    return "device/" + dev_id_ + "/report";
}

std::string LanSession::request_topic_() const
{
    return "device/" + dev_id_ + "/request";
}

int LanSession::start(ConnectedCb on_connected, MessageCb on_message)
{
    on_connected_ = std::move(on_connected);
    on_message_   = std::move(on_message);

    OBN_INFO("LanSession start dev=%s ip=%s user=%s ssl=%d",
             dev_id_.c_str(), dev_ip_.c_str(), username_.c_str(), use_ssl_);

    try {
        client_ = std::make_unique<mqtt::Client>(make_client_id());
    } catch (const std::exception& e) {
        OBN_ERROR("LanSession mqtt::Client ctor failed: %s", e.what());
        return BAMBU_NETWORK_ERR_CONNECT_FAILED;
    } catch (...) {
        OBN_ERROR("LanSession mqtt::Client ctor failed: unknown");
        return BAMBU_NETWORK_ERR_CONNECT_FAILED;
    }

    client_->set_on_connect([this](int rc) {
        if (rc == 0) {
            // Subscribe to the printer's report topic as soon as we are
            // connected; the printer answers LAN command requests by pushing
            // status updates to this topic.
            OBN_INFO("LanSession connected, subscribing to %s", report_topic_().c_str());
            client_->subscribe(report_topic_(), 0);
            if (on_connected_) on_connected_(BBL::ConnectStatusOk, {});
        } else {
            OBN_WARN("LanSession mqtt connect failed rc=%d (%s)",
                     rc, obn::mqtt::Client::connack_str(rc));
            if (on_connected_)
                on_connected_(BBL::ConnectStatusFailed,
                              std::string("mqtt connect rc=")
                                  + obn::mqtt::Client::connack_str(rc));
        }
    });

    client_->set_on_disconnect([this](int rc) {
        OBN_INFO("LanSession disconnect rc=%d (%s)", rc, mqtt::Client::err_str(rc));
        if (on_connected_) {
            on_connected_(rc == 0 ? BBL::ConnectStatusOk : BBL::ConnectStatusLost,
                          std::string("mqtt disconnect rc=") + mqtt::Client::err_str(rc));
        }
    });

    client_->set_on_message([this](const mqtt::Message& msg) {
        OBN_DEBUG("LanSession msg dev=%s bytes=%zu",
                  dev_id_.c_str(), msg.payload.size());
        if (on_message_) on_message_(dev_id_, msg.payload);
    });

    if (!use_ssl_) {
        OBN_DEBUG("LanSession: use_ssl=false, connecting plain on port 1883");
    }

    mqtt::ConnectConfig cfg;
    cfg.host                = dev_ip_;
    cfg.port                = use_ssl_ ? 8883 : 1883;
    cfg.username            = username_;
    cfg.password            = password_;
    cfg.use_tls             = use_ssl_;
    cfg.ca_file             = ca_file_;
    cfg.tls_verify_hostname = dev_id_;
    cfg.tls_insecure        = !obn::lan_tls::verify_enabled();
    cfg.keepalive_s         = 60;

    if (use_ssl_ && obn::lan_tls::verify_enabled()) {
        if (ca_file_.empty()) {
            OBN_ERROR("LanSession: TLS verify enabled but printer.cer missing");
            return BAMBU_NETWORK_ERR_CONNECT_FAILED;
        }
        if (dev_id_.empty()) {
            OBN_ERROR("LanSession: TLS verify enabled but dev_id empty");
            return BAMBU_NETWORK_ERR_CONNECT_FAILED;
        }
    }

    OBN_INFO("LanSession tls=%d ca_file=%s verify_host=%s insecure=%d",
             use_ssl_ ? 1 : 0,
             ca_file_.empty() ? "<none>" : ca_file_.c_str(),
             dev_id_.c_str(),
             cfg.tls_insecure ? 1 : 0);

    int rc = client_->connect(cfg);
    if (rc != 0) {
        OBN_ERROR("mqtt connect to %s:%d failed rc=%d (%s)",
                  cfg.host.c_str(), cfg.port, rc, mqtt::Client::err_str(rc));
    }
    return map_mqtt_err(rc);
}

int LanSession::publish_json(const std::string& json_str, int qos)
{
    if (!client_) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    int rc = client_->publish(request_topic_(), json_str, qos, /*retain=*/false);
    return rc == MOSQ_ERR_SUCCESS ? BAMBU_NETWORK_SUCCESS : BAMBU_NETWORK_ERR_SEND_MSG_FAILED;
}

bool LanSession::is_connected() const
{
    return client_ && client_->is_connected();
}

int LanSession::disconnect()
{
    if (client_) {
        client_->disconnect();
        client_.reset();
    }
    return BAMBU_NETWORK_SUCCESS;
}

} // namespace obn
