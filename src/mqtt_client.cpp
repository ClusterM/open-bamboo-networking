#include "obn/mqtt_client.hpp"

#include <atomic>
#include <cstdio>
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

namespace obn::mqtt {

namespace {

std::mutex       g_init_mu;
int              g_init_refcount = 0;

} // namespace

void global_init()
{
    std::lock_guard<std::mutex> lk(g_init_mu);
    if (g_init_refcount++ == 0) {
        ::mosquitto_lib_init();
    }
}

void global_cleanup()
{
    std::lock_guard<std::mutex> lk(g_init_mu);
    if (--g_init_refcount == 0) {
        ::mosquitto_lib_cleanup();
    }
}

const char* Client::err_str(int rc)
{
    return ::mosquitto_strerror(rc);
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

Client::~Client()
{
    if (mosq_) {
        if (loop_started_.load(std::memory_order_acquire)) {
            ::mosquitto_disconnect(mosq_);
            ::mosquitto_loop_stop(mosq_, /*force=*/true);
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
        // Three TLS modes, decided by what the caller has supplied:
        //   1. ca_file provided -> chain verification against that bundle;
        //      hostname check still skipped because the printer's cert CN is
        //      its serial number, not the IP we connect by.
        //   2. no ca_file, tls_insecure=true -> accept anything; fall back to
        //      the distro trust store just because libmosquitto requires us
        //      to hand it *some* CA path.
        //   3. no ca_file, tls_insecure=false -> distro trust store with full
        //      verification. Unlikely to work for LAN but left as an option
        //      for future cloud use.
        const char* cafile = nullptr;
        const char* capath = nullptr;
        bool        verify_peer = false;
        if (!cfg.ca_file.empty()) {
            cafile      = cfg.ca_file.c_str();
            // skip_chain_verify wins over verify_peer: when caller has
            // told us the supplied cafile is just a placeholder to keep
            // mosquitto_tls_set happy (e.g. cloud-on-Windows with the
            // BBL cert that won't actually validate *.bambulab.com),
            // we must NOT ask SSL_VERIFY_PEER or the handshake fails.
            verify_peer = !cfg.tls_skip_chain_verify;
            OBN_DEBUG("mqtt using ca bundle %s (verify_peer=%d, skip_chain=%d)",
                      cafile, verify_peer ? 1 : 0,
                      cfg.tls_skip_chain_verify ? 1 : 0);
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
        if (cfg.tls_insecure) {
            rc = ::mosquitto_tls_insecure_set(mosq_, true);
            if (rc != MOSQ_ERR_SUCCESS) {
                OBN_ERROR("mqtt tls_insecure_set rc=%d (%s)", rc, err_str(rc));
                return rc;
            }
        }
    }

    int rc = ::mosquitto_connect_async(mosq_,
                                       cfg.host.c_str(),
                                       cfg.port,
                                       cfg.keepalive_s);
#if defined(_WIN32)
    // Snapshot WSAGetLastError() the instant connect_async returns: any
    // logging/formatting we do on the way to OBN_ERROR can clobber it
    // (FormatMessage, snprintf-via-CRT, syscalls in obn::os::localtime_safe,
    // etc. each involve Winsock-adjacent state). Without this snapshot
    // mosquitto_strerror(MOSQ_ERR_ERRNO) collapses to "No error" because
    // it hands errno=0 to strerror.
    int wsa_after_async = (rc == MOSQ_ERR_ERRNO) ? ::WSAGetLastError() : 0;
#else
    int wsa_after_async = 0;
#endif
    if (rc != MOSQ_ERR_SUCCESS) {
        OBN_ERROR("mqtt connect_async rc=%d (%s)",
                  rc, detailed_err(rc, wsa_after_async).c_str());

#if defined(_WIN32)
        // Last-ditch fallback: when connect_async dies inside libmosquitto's
        // non-blocking connect path (e.g. the well-known v2.0.x cycle where
        // net__try_connect_tcp's WINDOWS_SET_ERRNO sees an errno value that
        // doesn't match COMPAT_EWOULDBLOCK), the synchronous mosquitto_connect
        // takes a different code branch (blocking connect, sets non-blocking
        // *after*) and routinely succeeds where async did not. Try that
        // exactly once, also still backed by mosquitto_loop_start() for the
        // network thread.
        if (rc == MOSQ_ERR_ERRNO) {
            OBN_WARN("mqtt connect_async failed with WSA=%d; retrying with "
                     "synchronous mosquitto_connect", wsa_after_async);
            int rc_sync = ::mosquitto_connect(mosq_,
                                              cfg.host.c_str(),
                                              cfg.port,
                                              cfg.keepalive_s);
            int wsa_after_sync = (rc_sync == MOSQ_ERR_ERRNO)
                                 ? ::WSAGetLastError() : 0;
            if (rc_sync == MOSQ_ERR_SUCCESS) {
                OBN_INFO("mqtt sync connect succeeded after async failure");
                rc = MOSQ_ERR_SUCCESS;
            } else {
                OBN_ERROR("mqtt sync connect rc=%d (%s)",
                          rc_sync,
                          detailed_err(rc_sync, wsa_after_sync).c_str());
                return rc_sync;
            }
        } else {
            return rc;
        }
#else
        return rc;
#endif
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
    ::mosquitto_disconnect(mosq_);
    if (loop_started_.exchange(false, std::memory_order_acq_rel)) {
        ::mosquitto_loop_stop(mosq_, /*force=*/false);
    }
}

void Client::s_on_connect(::mosquitto* /*m*/, void* obj, int rc)
{
    auto* self = static_cast<Client*>(obj);
    if (!self) return;
    self->connected_.store(rc == 0, std::memory_order_release);
    OBN_INFO("mqtt connect callback rc=%d (%s)", rc, err_str(rc));
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
