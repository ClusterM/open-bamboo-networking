#include "obn/mqtt_client.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <stdexcept>

#include <mosquitto.h>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#endif

#include "obn/log.hpp"
#include "obn/lan_tls.hpp"
#include "obn/lan_tls_env.hpp"

extern "C" int mosquitto_tls_verify_hostname_set(struct mosquitto* mosq, const char* hostname);

namespace obn::mqtt {

namespace {

std::once_flag g_init_once;

void final_cleanup()
{
    ::mosquitto_lib_cleanup();
}

} // namespace

void global_init()
{
    std::call_once(g_init_once, []() {
        ::mosquitto_lib_init();
        std::atexit(&final_cleanup);
    });
}

void global_cleanup()
{
    // Intentionally a no-op. The mosquitto library stays initialised for the
    // lifetime of the loaded plugin; the matching mosquitto_lib_cleanup()
}

const char* Client::err_str(int rc)
{
    return ::mosquitto_strerror(rc);
}

namespace {

const char* connack_reason(int rc)
{
    switch (rc) {
    case 0: return "accepted";
    case 1: return "unacceptable protocol version";
    case 2: return "identifier rejected";
    case 3: return "server unavailable";
    case 4: return "bad username or password";
    case 5: return "not authorized";
    default: return "unknown connack code";
    }
}

} // namespace

const char* Client::connack_str(int rc)
{
    return connack_reason(rc);
}

std::string Client::detailed_err(int rc, int wsa_err)
{
    std::string s = ::mosquitto_strerror(rc);
#if defined(_WIN32)
    if (rc == MOSQ_ERR_ERRNO) {
        if (wsa_err == 0) {
            // Best-effort fallback: many call sites can't easily snapshot
            // WSAGetLastError() at the exact failure point, so we read
            // whatever the current value is and tag it as "(latest)".
            wsa_err = ::WSAGetLastError();
        }
        char buf[256] = {};
        DWORD len = ::FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            static_cast<DWORD>(wsa_err),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            buf, sizeof(buf) - 1, nullptr);
        // Strip trailing CRLF FormatMessage likes to add.
        while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n'
                           || buf[len - 1] == ' ' || buf[len - 1] == '.')) {
            buf[--len] = '\0';
        }
        s += " [WSA=" + std::to_string(wsa_err) + ": "
             + (len > 0 ? buf : "<unknown>") + "]";
    }
#else
    (void)wsa_err;
#endif
    return s;
}

Client::Client(std::string client_id)
    : client_id_(std::move(client_id))
{
    global_init();
    mosq_ = ::mosquitto_new(client_id_.empty() ? nullptr : client_id_.c_str(),
                            /*clean_session=*/true,
                            /*obj=*/this);
    if (!mosq_) {
        global_cleanup();
        throw std::runtime_error("mosquitto_new failed");
    }

    ::mosquitto_connect_callback_set(mosq_, &Client::s_on_connect);
    ::mosquitto_disconnect_callback_set(mosq_, &Client::s_on_disconnect);
    ::mosquitto_message_callback_set(mosq_, &Client::s_on_message);
}

namespace {

void remove_trust_bundle_file(const std::string& path)
{
    if (path.empty()) return;
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

} // namespace

Client::~Client()
{
    remove_trust_bundle_file(merged_trust_path_);
    merged_trust_path_.clear();
    if (mosq_) {
        // Normally disconnect() already ran (loop_started_ == false) and this
        // is a plain destroy. If not, shut down gracefully too so we don't
        // leave a ghost session on the printer (see disconnect()).
        if (loop_started_.exchange(false, std::memory_order_acq_rel)) {
            ::mosquitto_disconnect(mosq_);
            ::mosquitto_loop_stop(mosq_, /*force=*/false);
        }
        ::mosquitto_destroy(mosq_);
        mosq_ = nullptr;
    }
    global_cleanup();
}

void Client::set_on_connect(OnConnectCb cb)
{
    std::lock_guard<std::mutex> lk(mu_);
    on_connect_ = std::move(cb);
}

void Client::set_on_disconnect(OnDisconnectCb cb)
{
    std::lock_guard<std::mutex> lk(mu_);
    on_disconnect_ = std::move(cb);
}

void Client::set_on_message(OnMessageCb cb)
{
    std::lock_guard<std::mutex> lk(mu_);
    on_message_ = std::move(cb);
}

int Client::connect(const ConnectConfig& cfg)
{
    if (!mosq_) return MOSQ_ERR_INVAL;

    OBN_DEBUG("mqtt connect host=%s port=%d tls=%d insecure=%d client_id=%s user=%s",
              cfg.host.c_str(), cfg.port, cfg.use_tls, cfg.tls_insecure,
              client_id_.c_str(), cfg.username.c_str());

    if (!cfg.username.empty() || !cfg.password.empty()) {
        int rc = ::mosquitto_username_pw_set(mosq_,
            cfg.username.empty() ? nullptr : cfg.username.c_str(),
            cfg.password.empty() ? nullptr : cfg.password.c_str());
        if (rc != MOSQ_ERR_SUCCESS) {
            OBN_ERROR("mqtt username_pw_set rc=%d (%s)", rc, err_str(rc));
            return rc;
        }
    }

    if (cfg.use_tls) {
        // LAN (serial hostname verify) vs cloud (public CA / system store).
        const bool lan_hostname_verify = !cfg.tls_verify_hostname.empty();
        const bool skip_verify =
            cfg.tls_insecure
            || (lan_hostname_verify && !obn::lan_tls::verify_enabled());

        if (lan_hostname_verify && !skip_verify) {
            int rc = ::mosquitto_tls_verify_hostname_set(mosq_,
                cfg.tls_verify_hostname.c_str());
            if (rc != MOSQ_ERR_SUCCESS) {
                OBN_ERROR("mqtt tls_verify_hostname_set rc=%d (%s)", rc, err_str(rc));
                return rc;
            }
        }

        const char* cafile = nullptr;
        const char* capath = nullptr;
        bool        verify_peer = false;
        std::string trust_bundle;
        if (!cfg.ca_file.empty()) {
            trust_bundle = cfg.ca_file;
            if (lan_hostname_verify && !skip_verify) {
                if (const char* peer = obn::lan_tls::peer_cert_path_for_ip(cfg.host.c_str())) {
                    trust_bundle = obn::lan_tls::merged_trust_bundle_path(
                        cfg.ca_file, peer);
                }
            }
            if (trust_bundle != cfg.ca_file) {
                remove_trust_bundle_file(merged_trust_path_);
                merged_trust_path_ = trust_bundle;
            }
            cafile      = trust_bundle.c_str();
            verify_peer = !cfg.tls_skip_chain_verify && !skip_verify;
            OBN_DEBUG("mqtt using ca bundle %s (verify_peer=%d, skip_chain=%d, insecure=%d)",
                      cafile, verify_peer ? 1 : 0,
                      cfg.tls_skip_chain_verify ? 1 : 0,
                      skip_verify ? 1 : 0);
        } else if (lan_hostname_verify && !skip_verify) {
            OBN_ERROR("mqtt LAN TLS verify enabled but ca_file is empty");
            return MOSQ_ERR_TLS;
        } else {
#if defined(_WIN32)
            // Windows has no canonical /etc/ssl trust dir and OpenSSL static
            // builds shipped via vcpkg don't carry a default cert store.
            // Probing /etc/ssl/* and handing nonexistent paths to mosquitto
            // makes net__tls_load_ca() fail later, so just leave both
            // cafile and capath null and ask mosquitto to use whatever the
            // OS exposes via OPENSSL_init_crypto's default verify paths.
            // Caller-driven verification stays governed by tls_insecure.
            cafile = nullptr;
            capath = nullptr;
            verify_peer = !cfg.tls_insecure;
            OBN_DEBUG("mqtt no ca_file on Windows; using openssl default verify paths "
                      "(verify_peer=%d, tls_insecure=%d)",
                      verify_peer ? 1 : 0, cfg.tls_insecure ? 1 : 0);
#else
            static const char* kCaCandidates[] = {
                "/etc/ssl/certs/ca-certificates.crt",        // Debian, Ubuntu
                "/etc/pki/tls/certs/ca-bundle.crt",          // Fedora, RHEL
                "/etc/ssl/ca-bundle.pem",                    // openSUSE
                "/etc/ssl/cert.pem",                         // Alpine, macOS
            };
            for (const char* p : kCaCandidates) {
                FILE* f = std::fopen(p, "rb");
                if (f) { std::fclose(f); cafile = p; break; }
            }
            capath      = cafile ? nullptr : "/etc/ssl/certs";
            verify_peer = !cfg.tls_insecure;
#endif
        }
        int rc = ::mosquitto_tls_set(mosq_, cafile, capath, nullptr, nullptr, nullptr);
        if (rc != MOSQ_ERR_SUCCESS) {
            OBN_ERROR("mqtt tls_set rc=%d (%s) cafile=%s capath=%s",
                      rc, err_str(rc),
                      cafile ? cafile : "(null)",
                      capath ? capath : "(null)");
            return rc;
        }
        // SSL_VERIFY_PEER (1) vs SSL_VERIFY_NONE (0).
        rc = ::mosquitto_tls_opts_set(mosq_, verify_peer ? 1 : 0, nullptr, nullptr);
        if (rc != MOSQ_ERR_SUCCESS) {
            OBN_ERROR("mqtt tls_opts_set rc=%d (%s)", rc, err_str(rc));
            return rc;
        }
        if (skip_verify) {
            rc = ::mosquitto_tls_insecure_set(mosq_, true);
            if (rc != MOSQ_ERR_SUCCESS) {
                OBN_ERROR("mqtt tls_insecure_set rc=%d (%s)", rc, err_str(rc));
                return rc;
            }
        }
    }

    // Let the loop thread (started below) keep retrying with exponential
    // backoff (2s..30s) instead of making a single attempt. A transient TCP
    // timeout — e.g. a P1-series printer that briefly refuses :8883 while it
    // reaps a stale MQTT session — then self-heals without Studio having to
    // drive a manual reconnect (GitHub issues #34, #38).
    ::mosquitto_reconnect_delay_set(mosq_, /*reconnect_delay=*/2,
                                    /*reconnect_delay_max=*/30,
                                    /*reconnect_exponential_backoff=*/true);

    // mosquitto_connect_async only kicks off a non-blocking connect; the real
    // work (TCP + TLS handshake + CONNECT/CONNACK) runs on the loop thread.
    //
    // We deliberately do NOT fall back to the synchronous mosquitto_connect:
    // it blocks the calling Studio ABI/UI thread for the full TCP timeout
    // (~21s on Windows) and, on failure, mosquitto runs getpeername() on the
    // already-closed socket — which clobbers the real error with a misleading
    // WSAENOTSOCK ("not a socket" / "Bad file descriptor"). A failed async
    // attempt is not fatal: mosquitto_loop_forever() (run by loop_start) sees
    // MOSQ_ERR_NO_CONN / MOSQ_ERR_ERRNO and reconnects on its own.
    int rc = ::mosquitto_connect_async(mosq_,
                                       cfg.host.c_str(),
                                       cfg.port,
                                       cfg.keepalive_s);
    if (rc != MOSQ_ERR_SUCCESS) {
        // INVAL/NOMEM are our own programming/allocation errors and won't fix
        // themselves, so don't spin up a loop thread for them. Anything else
        // (notably MOSQ_ERR_ERRNO from a transient TCP failure) is handed to
        // the loop thread's reconnect logic.
        if (rc == MOSQ_ERR_INVAL || rc == MOSQ_ERR_NOMEM) {
#if defined(_WIN32)
            int wsa = (rc == MOSQ_ERR_ERRNO) ? ::WSAGetLastError() : 0;
            OBN_ERROR("mqtt connect_async rc=%d (%s)", rc, detailed_err(rc, wsa).c_str());
#else
            OBN_ERROR("mqtt connect_async rc=%d (%s)", rc, err_str(rc));
#endif
            return rc;
        }
        OBN_INFO("mqtt connect_async rc=%d (%s); loop will reconnect in background",
                 rc, err_str(rc));
    }

    rc = ::mosquitto_loop_start(mosq_);
    if (rc != MOSQ_ERR_SUCCESS) {
#if defined(_WIN32)
        int wsa = (rc == MOSQ_ERR_ERRNO) ? ::WSAGetLastError() : 0;
        OBN_ERROR("mqtt loop_start rc=%d (%s)", rc, detailed_err(rc, wsa).c_str());
#else
        OBN_ERROR("mqtt loop_start rc=%d (%s)", rc, err_str(rc));
#endif
        return rc;
    }
    loop_started_.store(true, std::memory_order_release);
    return MOSQ_ERR_SUCCESS;
}

int Client::subscribe(const std::string& topic, int qos)
{
    if (!mosq_) return MOSQ_ERR_INVAL;
    return ::mosquitto_subscribe(mosq_, nullptr, topic.c_str(), qos);
}

int Client::unsubscribe(const std::string& topic)
{
    if (!mosq_) return MOSQ_ERR_INVAL;
    return ::mosquitto_unsubscribe(mosq_, nullptr, topic.c_str());
}

int Client::publish(const std::string& topic, const std::string& payload, int qos, bool retain)
{
    if (!mosq_) return MOSQ_ERR_INVAL;
    // Symmetric to s_on_message: log every outgoing publish under TRACE.
    // Lets `OBN_LOG_LEVEL=trace` capture both directions of the MQTT
    // conversation in one log file, without rebuilding the plugin or
    // standing up a real MITM. Stays cheap when TRACE is disabled
    // because the macro short-circuits before formatting.
    OBN_DEBUG("mqtt publish topic=%s bytes=%zu qos=%d retain=%d",
              topic.c_str(), payload.size(), qos, retain ? 1 : 0);
    OBN_TRACE("mqtt publish payload=%.*s",
              static_cast<int>(payload.size()), payload.data());
    return ::mosquitto_publish(mosq_,
                               nullptr,
                               topic.c_str(),
                               static_cast<int>(payload.size()),
                               payload.data(),
                               qos,
                               retain);
}

void Client::disconnect()
{
    if (!mosq_) return;
    // Request a clean MQTT DISCONNECT so the broker frees the session right
    // away. This matters on P1-series printers, which accept only a very small
    // number of concurrent LAN MQTT sessions: a half-open ghost session (left
    // behind when a forced thread cancel drops the DISCONNECT packet) blocks
    // the next connect until the firmware reaps it ~1 keepalive later, which
    // surfaces as "connection failed, works on the second try" (issues #34, #38).
    ::mosquitto_disconnect(mosq_);
    if (loop_started_.exchange(false, std::memory_order_acq_rel)) {
        // force=false: mosquitto_disconnect() set the request-disconnect flag,
        // so the loop thread flushes the DISCONNECT, closes the socket and
        // exits on its own; loop_stop then joins it. (force=true would
        // pthread_cancel the thread mid-write and drop the DISCONNECT.)
        ::mosquitto_loop_stop(mosq_, /*force=*/false);
    }
    remove_trust_bundle_file(merged_trust_path_);
    merged_trust_path_.clear();
}

void Client::s_on_connect(::mosquitto* /*m*/, void* obj, int rc)
{
    auto* self = static_cast<Client*>(obj);
    if (!self) return;
    self->connected_.store(rc == 0, std::memory_order_release);
    OBN_INFO("mqtt connect callback rc=%d (%s)", rc, connack_str(rc));
    OnConnectCb cb;
    {
        std::lock_guard<std::mutex> lk(self->mu_);
        cb = self->on_connect_;
    }
    if (cb) cb(rc);
}

void Client::s_on_disconnect(::mosquitto* /*m*/, void* obj, int rc)
{
    auto* self = static_cast<Client*>(obj);
    if (!self) return;
    self->connected_.store(false, std::memory_order_release);
    OBN_INFO("mqtt disconnect callback rc=%d (%s)", rc, err_str(rc));
    OnDisconnectCb cb;
    {
        std::lock_guard<std::mutex> lk(self->mu_);
        cb = self->on_disconnect_;
    }
    if (cb) cb(rc);
}

void Client::s_on_message(::mosquitto* /*m*/, void* obj, const ::mosquitto_message* msg)
{
    auto* self = static_cast<Client*>(obj);
    if (!self || !msg) return;
    OBN_DEBUG("mqtt msg topic=%s bytes=%d qos=%d", msg->topic, msg->payloadlen, msg->qos);
    if (msg->payload && msg->payloadlen > 0) {
        OBN_TRACE("mqtt msg payload=%.*s",
            msg->payloadlen, static_cast<const char*>(msg->payload));
    }
    OnMessageCb cb;
    {
        std::lock_guard<std::mutex> lk(self->mu_);
        cb = self->on_message_;
    }
    if (!cb) return;
    Message m;
    m.topic  = msg->topic ? msg->topic : std::string{};
    if (msg->payload && msg->payloadlen > 0) {
        m.payload.assign(static_cast<const char*>(msg->payload),
                         static_cast<std::size_t>(msg->payloadlen));
    }
    m.qos    = msg->qos;
    m.retain = msg->retain;
    cb(m);
}

} // namespace obn::mqtt
