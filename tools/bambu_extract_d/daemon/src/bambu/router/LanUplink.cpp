#include "LanUplink.hpp"

#include "../BambuNetworkingPluginHandle.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Slic3r {
namespace bambu {
namespace router {

namespace {

bool print_bypass_enabled() {
    const char* env = std::getenv("BBL_BRIDGE_ENABLE_PRINT_BYPASS");
    return env && *env && std::strcmp(env, "0") != 0;
}

bool payload_top_level_key_is(const std::string& json, const char* key) {

    size_t i = 0;
    while (i < json.size() &&
           (json[i] == ' ' || json[i] == '\t' ||
            json[i] == '\n' || json[i] == '\r')) ++i;
    if (i >= json.size() || json[i] != '{') return false;
    ++i;
    while (i < json.size() &&
           (json[i] == ' ' || json[i] == '\t' ||
            json[i] == '\n' || json[i] == '\r')) ++i;
    if (i >= json.size() || json[i] != '"') return false;
    ++i;
    const size_t klen = std::strlen(key);
    if (i + klen >= json.size()) return false;
    if (std::memcmp(json.data() + i, key, klen) != 0) return false;
    if (json[i + klen] != '"') return false;
    return true;
}

bool payload_is_print_control(const std::string& json) {
    return payload_top_level_key_is(json, "print");
}

bool payload_is_tier2_no_envelope(const std::string& json) {
    return payload_top_level_key_is(json, "camera") ||
           payload_top_level_key_is(json, "xcam")   ||
           payload_top_level_key_is(json, "system");
}

std::string resolve_helper_path_once() {
    static std::string cached;
    static std::once_flag flag;
    std::call_once(flag, []{

        if (const char* env = std::getenv("BBL_BRIDGE_RAW_MQTT_HELPER");
            env && *env) {
            struct stat st;
            if (::stat(env, &st) == 0) { cached = env; return; }
        }

        char buf[4096] = {0};
        ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (n > 0) {
            std::string exe(buf, buf + n);

            auto slash = exe.find_last_of('/');
            std::string dir = (slash == std::string::npos)
                ? std::string(".") : exe.substr(0, slash);

            const std::vector<std::string> candidates = {
                dir + "/../../src/bambu/router/raw_mqtt_publish.py",
                dir + "/../../../src/bambu/router/raw_mqtt_publish.py",
                dir + "/raw_mqtt_publish.py",
            };
            for (const auto& p : candidates) {
                struct stat st;
                if (::stat(p.c_str(), &st) == 0) { cached = p; return; }
            }
        }

        const char* canonical =
            "/home/danielwoz/BambuStudio-bridge/src/bambu/router/"
            "raw_mqtt_publish.py";
        struct stat st;
        if (::stat(canonical, &st) == 0) { cached = canonical; return; }
        cached.clear();
    });
    return cached;
}

std::string write_tmp_payload(const std::vector<uint8_t>& payload,
                              const std::string& dev_id) {
    char tmpl[] = "/tmp/bblbridge_print_XXXXXX";
    int fd = ::mkstemp(tmpl);
    if (fd < 0) {
        std::fprintf(stderr,
            "[print-via-cert/diag dev=%s] mkstemp failed: %s\n",
            dev_id.c_str(), std::strerror(errno));
        return {};
    }
    size_t off = 0;
    while (off < payload.size()) {
        ssize_t w = ::write(fd, payload.data() + off, payload.size() - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            ::close(fd); ::unlink(tmpl);
            return {};
        }
        off += static_cast<size_t>(w);
    }
    ::close(fd);
    return std::string(tmpl);
}

std::string make_client_id() {
    static std::mt19937 s_rng{std::random_device{}()};
    static std::mutex   s_mu;
    static std::atomic<unsigned> s_counter{0};
    char buf[64];
    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto sec = std::chrono::duration_cast<std::chrono::seconds>(now).count();
    unsigned r;
    {
        std::lock_guard<std::mutex> lk(s_mu);
        r = std::uniform_int_distribution<unsigned>(0, 0xFFFF)(s_rng);
    }
    unsigned c = ++s_counter;
    std::snprintf(buf, sizeof(buf), "bridge:%lld:%04x%04x",
                  static_cast<long long>(sec), r, c & 0xFFFF);
    return buf;
}

int spawn_raw_mqtt_helper(const std::string& helper_path,
                          const std::string& printer_ip,
                          uint16_t           printer_port,
                          const std::string& cert_path,
                          const std::string& key_path,
                          const std::string& access_code,
                          const std::string& client_id,
                          const std::string& topic,
                          uint8_t            qos,
                          const std::string& payload_file,
                          const std::string& dev_id) {

    std::string port_s = std::to_string(printer_port);
    std::string qos_s  = std::to_string(static_cast<int>(qos));

    std::vector<const char*> argv = {
        "python3", helper_path.c_str(),
        "--ip",          printer_ip.c_str(),
        "--port",        port_s.c_str(),
        "--cert",        cert_path.c_str(),
        "--key",         key_path.c_str(),
        "--user",        "bblp",
        "--pass",        access_code.c_str(),
        "--client-id",   client_id.c_str(),
        "--topic",       topic.c_str(),
        "--qos",         qos_s.c_str(),
        "--payload-file",payload_file.c_str(),
        nullptr,
    };

    pid_t pid = ::fork();
    if (pid < 0) {
        std::fprintf(stderr,
            "[print-via-cert/diag dev=%s] fork failed: %s\n",
            dev_id.c_str(), std::strerror(errno));
        return -1;
    }
    if (pid == 0) {

        int devnull = ::open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDIN_FILENO);
            if (devnull > 2) ::close(devnull);
        }
        ::execvp("python3", const_cast<char* const*>(argv.data()));

        std::fprintf(stderr,
            "[print-via-cert/diag dev=%s] execvp python3 failed: %s\n",
            dev_id.c_str(), std::strerror(errno));
        std::_Exit(127);
    }

    int status = 0;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(15);
    while (true) {
        pid_t r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid) break;
        if (r < 0) {
            if (errno == EINTR) continue;
            std::fprintf(stderr,
                "[print-via-cert/diag dev=%s] waitpid failed: %s\n",
                dev_id.c_str(), std::strerror(errno));
            return -2;
        }

        if (std::chrono::steady_clock::now() >= deadline) {
            std::fprintf(stderr,
                "[print-via-cert/diag dev=%s] helper timeout — killing pid=%d\n",
                dev_id.c_str(), pid);
            ::kill(pid, SIGKILL);
            ::waitpid(pid, &status, 0);
            return -3;
        }
        ::usleep(20 * 1000);
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return -100 - WTERMSIG(status);
    return -200;
}

}

struct LanUplink::Impl {
    struct DeviceState {
        LanUplinkConfig                                cfg;

        std::unordered_map<std::string, int> topic_refs;
    };

    struct Subscriber {
        uint64_t                            session_id;
        server::IUplink::DownstreamPublisher publisher;
    };

    struct RetainedMsg {
        std::string          topic;
        std::vector<uint8_t> payload;
        uint8_t              qos;
    };
    static constexpr size_t kRetainedCap = 2;

    std::shared_ptr<BambuNetworkingPluginHandle>                  handle;

    std::shared_ptr<EncMsgEnvelope>                               enc_msg;
    mutable std::mutex                                            mu;
    std::unordered_map<std::string, std::unique_ptr<DeviceState>> devices;
    std::unordered_map<std::string, std::vector<Subscriber>>      downstreams;
    std::unordered_map<std::string, std::vector<RetainedMsg>>     retained;

    std::string                                                   current_connected_dev_id;

    std::thread                                                   resign_thread;
    std::atomic<bool>                                             resign_stop{false};

    std::thread                                                   gcode_cmd_thread;
    std::atomic<bool>                                             gcode_cmd_stop{false};

    DeviceState* find_locked(const std::string& dev_id) {
        auto it = devices.find(dev_id);
        return it == devices.end() ? nullptr : it->second.get();
    }
};

LanUplink::LanUplink()  : m_impl(std::make_unique<Impl>()) {}

LanUplink::~LanUplink() {

    m_impl->resign_stop.store(true);
    if (m_impl->resign_thread.joinable()) m_impl->resign_thread.join();

    m_impl->gcode_cmd_stop.store(true);
    if (m_impl->gcode_cmd_thread.joinable()) m_impl->gcode_cmd_thread.join();

    std::shared_ptr<BambuNetworkingPluginHandle> h;
    std::vector<std::string> dev_ids;
    bool we_were_connected = false;
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        h = m_impl->handle;
        for (auto& kv : m_impl->devices) dev_ids.push_back(kv.first);
        we_were_connected = !m_impl->current_connected_dev_id.empty();
    }
    if (h) {
        for (const auto& d : dev_ids) h->unregister_local_message_receiver(d);
        if (we_were_connected) h->disconnect_printer();
    }
}

void LanUplink::attach_plugin(std::shared_ptr<BambuNetworkingPluginHandle> handle) {

    std::vector<std::string> dev_ids;
    std::shared_ptr<BambuNetworkingPluginHandle> old;
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        old = m_impl->handle;
        m_impl->handle = handle;
        for (auto& kv : m_impl->devices) dev_ids.push_back(kv.first);
    }
    if (old) {
        for (const auto& d : dev_ids) old->unregister_local_message_receiver(d);
    }
    if (handle) {
        Impl* impl = m_impl.get();
        for (const auto& dev_id : dev_ids) {
            handle->register_local_message_receiver(dev_id,
                [impl, dev_id](std::string topic,
                               std::vector<uint8_t> payload,
                               uint8_t qos) {
                std::vector<server::IUplink::DownstreamPublisher> cbs;
                {
                    std::lock_guard<std::mutex> lk(impl->mu);
                    auto it = impl->downstreams.find(dev_id);
                    if (it != impl->downstreams.end()) {
                        cbs.reserve(it->second.size());
                        for (auto& s : it->second) cbs.push_back(s.publisher);
                    }
                    auto& ring = impl->retained[dev_id];
                    ring.push_back({topic, payload, qos});
                    if (ring.size() > Impl::kRetainedCap) {
                        ring.erase(ring.begin(),
                                   ring.begin() + (ring.size() - Impl::kRetainedCap));
                    }
                }
                for (auto& cb : cbs) {
                    if (cb) cb(topic, payload, qos);
                }
            });
        }
    }
}

std::shared_ptr<BambuNetworkingPluginHandle> LanUplink::plugin_handle() const {
    std::lock_guard<std::mutex> lk(m_impl->mu);
    return m_impl->handle;
}

void LanUplink::attach_enc_msg_envelope(std::shared_ptr<EncMsgEnvelope> envelope) {
    std::lock_guard<std::mutex> lk(m_impl->mu);
    m_impl->enc_msg = std::move(envelope);
}

std::shared_ptr<EncMsgEnvelope> LanUplink::enc_msg_envelope() const {
    std::lock_guard<std::mutex> lk(m_impl->mu);
    return m_impl->enc_msg;
}

void LanUplink::add_device(LanUplinkConfig cfg) {
    const std::string dev_id     = cfg.dev_id;
    const std::string dev_ip     = cfg.printer_ip;
    const std::string access     = cfg.access_code;
    const bool        use_ssl    = cfg.use_ssl;
    std::fprintf(stderr,
        "[lan-uplink] add_device dev=%s ip=%s ssl=%d ac_len=%zu\n",
        dev_id.c_str(), dev_ip.c_str(), use_ssl ? 1 : 0, access.size());
    std::fflush(stderr);

    std::shared_ptr<BambuNetworkingPluginHandle> h;
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        auto state = std::make_unique<Impl::DeviceState>();
        state->cfg = std::move(cfg);
        m_impl->devices[dev_id] = std::move(state);
        h = m_impl->handle;
    }

    if (!h) return;

    Impl* impl = m_impl.get();
    h->register_local_message_receiver(dev_id,
        [impl, dev_id](std::string topic,
                       std::vector<uint8_t> payload,
                       uint8_t qos) {
        std::vector<server::IUplink::DownstreamPublisher> cbs;
        size_t subscriber_count = 0;
        {
            std::lock_guard<std::mutex> lk(impl->mu);
            auto it = impl->downstreams.find(dev_id);
            if (it != impl->downstreams.end()) {
                subscriber_count = it->second.size();
                cbs.reserve(subscriber_count);
                for (auto& s : it->second) cbs.push_back(s.publisher);
            }
            auto& ring = impl->retained[dev_id];
            ring.push_back({topic, payload, qos});
            if (ring.size() > Impl::kRetainedCap) {
                ring.erase(ring.begin(),
                           ring.begin() + (ring.size() - Impl::kRetainedCap));
            }
        }
        std::fprintf(stderr,
            "[lan-uplink] receiver dev=%s topic=%s bytes=%zu qos=%u subscribers=%zu\n",
            dev_id.c_str(), topic.c_str(), payload.size(), unsigned(qos),
            subscriber_count);
        std::fflush(stderr);
        for (auto& cb : cbs) {
            if (cb) cb(topic, payload, qos);
        }
    });

    int rc = h->connect_printer(dev_id, dev_ip, "bblp", access, use_ssl);
    std::fprintf(stderr,
        "[lan-uplink] add_device dev=%s connect_printer rc=%d\n",
        dev_id.c_str(), rc);
    std::fflush(stderr);
    if (rc == 0) {
        {
            std::lock_guard<std::mutex> lk(m_impl->mu);
            m_impl->current_connected_dev_id = dev_id;
        }

        h->set_user_selected_machine(dev_id);
        h->install_device_cert(dev_id, false);
        std::fprintf(stderr,
            "[lan-uplink] add_device dev=%s armed enc_msg gate "
            "(set_user_selected_machine + install_device_cert)\n",
            dev_id.c_str());
        std::fflush(stderr);

        if (const char* ms = std::getenv("BAMBU_BRIDGE_RESIGN_MS")) {
            long period = std::atol(ms);
            if (period > 0 && !m_impl->resign_thread.joinable()) {
                auto* impl = m_impl.get();
                std::string d = dev_id;
                impl->resign_thread = std::thread([impl, h, d, period]() {
                    std::fprintf(stderr,
                        "[lan-uplink] resign pulse started dev=%s period=%ldms\n",
                        d.c_str(), period);
                    std::fflush(stderr);
                    while (!impl->resign_stop.load()) {

                        h->set_user_selected_machine(d);
                        h->install_device_cert(d, false);
                        for (long slept = 0; slept < period &&
                             !impl->resign_stop.load(); slept += 50)
                            std::this_thread::sleep_for(
                                std::chrono::milliseconds(50));
                    }
                });
            }
        }

        if (const char* ms = std::getenv("BAMBU_BRIDGE_GCODE_CMD_MS")) {
            long period = std::atol(ms);
            if (period > 0 && !m_impl->gcode_cmd_thread.joinable()) {
                auto* impl = m_impl.get();
                std::string d = dev_id;
                impl->gcode_cmd_thread = std::thread([impl, h, d, period]() {
                    std::fprintf(stderr,
                        "[lan-uplink] gcode-cmd pulse started dev=%s "
                        "period=%ldms (print.command=gcode_file, NON-EXISTENT "
                        "file, no print start)\n",
                        d.c_str(), period);
                    std::fflush(stderr);

                    unsigned long seq = 100000;
                    std::mt19937_64 rng(
                        std::chrono::steady_clock::now()
                            .time_since_epoch().count());

                    const bool diag =
                        std::getenv("BAMBU_BRIDGE_GCODE_CMD_DIAG") != nullptr;
                    while (!impl->gcode_cmd_stop.load()) {
                        unsigned long long r = rng();
                        char namebuf[64];
                        std::snprintf(namebuf, sizeof(namebuf),
                            "bridge_nonexistent_%016llx.gcode.3mf", r);
                        std::string fname = namebuf;

                        std::string gcode_file_json =
                            std::string("{\"print\":{")
                          + "\"command\":\"gcode_file\","
                          + "\"sequence_id\":\"" + std::to_string(seq++) + "\","
                          + "\"param\":\"Metadata/plate_1.gcode\","
                          + "\"url\":\"file:///mnt/sdcard/cache/" + fname + "\","
                          + "\"md5\":\"00000000000000000000000000000000\","
                          + "\"subtask_name\":\"" + fname + "\","
                          + "\"project_id\":\"0\","
                          + "\"profile_id\":\"0\","
                          + "\"task_id\":\"0\","
                          + "\"subtask_id\":\"0\","
                          + "\"plate_idx\":1,"
                          + "\"use_ams\":false,"
                          + "\"timelapse\":false,"
                          + "\"bed_leveling\":false,"
                          + "\"flow_cali\":false,"
                          + "\"vibration_cali\":false,"
                          + "\"layer_inspect\":false"
                          + "}}";
                        int rc = h->send_message_to_printer(d, gcode_file_json, 0);
                        std::fprintf(stderr,
                            "[lan-uplink] gcode-cmd pulse dev=%s file=%s "
                            "send_message_to_printer rc=%d\n",
                            d.c_str(), fname.c_str(), rc);
                        std::fflush(stderr);

                        if (diag) {

                            std::string gcode_line_json =
                                std::string("{\"print\":{")
                              + "\"command\":\"gcode_line\","
                              + "\"sequence_id\":\"" + std::to_string(seq++) + "\","
                              + "\"param\":\"M105\\n\""
                              + "}}";
                            int rc2 = h->send_message_to_printer(d, gcode_line_json, 0);
                            std::fprintf(stderr,
                                "[lan-uplink] gcode-cmd DIAG dev=%s cmd=gcode_line(M105) "
                                "send_message_to_printer rc=%d\n", d.c_str(), rc2);
                            std::fflush(stderr);

                            std::string pushall_json =
                                std::string("{\"pushing\":{")
                              + "\"command\":\"pushall\","
                              + "\"sequence_id\":\"" + std::to_string(seq++) + "\","
                              + "\"version\":1,\"push_target\":1"
                              + "}}";
                            int rc3 = h->send_message_to_printer(d, pushall_json, 0);
                            std::fprintf(stderr,
                                "[lan-uplink] gcode-cmd DIAG dev=%s cmd=pushing.pushall "
                                "send_message_to_printer rc=%d\n", d.c_str(), rc3);
                            std::fflush(stderr);
                        }

                        for (long slept = 0; slept < period &&
                             !impl->gcode_cmd_stop.load(); slept += 50)
                            std::this_thread::sleep_for(
                                std::chrono::milliseconds(50));
                    }
                });
            }
        }
    }
}

void LanUplink::remove_device(const std::string& dev_id) {
    std::shared_ptr<BambuNetworkingPluginHandle> h;
    bool was_current = false;
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        auto it = m_impl->devices.find(dev_id);
        if (it == m_impl->devices.end()) return;
        m_impl->devices.erase(it);
        m_impl->downstreams.erase(dev_id);
        m_impl->retained.erase(dev_id);
        if (m_impl->current_connected_dev_id == dev_id) {
            m_impl->current_connected_dev_id.clear();
            was_current = true;
        }
        h = m_impl->handle;
    }
    if (h) {
        h->unregister_local_message_receiver(dev_id);

        if (was_current) h->disconnect_printer();
    }
}

bool LanUplink::is_connected(const std::string& dev_id) const {
    std::shared_ptr<BambuNetworkingPluginHandle> h;
    bool current_match = false;
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        if (m_impl->devices.count(dev_id) == 0) return false;
        h = m_impl->handle;
        current_match = (m_impl->current_connected_dev_id == dev_id);
    }
    if (!h || !current_match) return false;
    return h->is_local_connected();
}

void LanUplink::on_subscribe(const std::string& dev_id, std::string topic) {

    std::shared_ptr<BambuNetworkingPluginHandle> h;
    bool need_swap = false;
    bool found = false;
    std::string dev_ip;
    std::string access_code;
    bool use_ssl = true;
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        auto* d = m_impl->find_locked(dev_id);
        found = (d != nullptr);
        if (d) {
            ++d->topic_refs[topic];
            if (m_impl->current_connected_dev_id != dev_id) {
                need_swap   = true;
                dev_ip      = d->cfg.printer_ip;
                access_code = d->cfg.access_code;
                use_ssl     = d->cfg.use_ssl;
                h           = m_impl->handle;
            }
        }
    }
    if (!found) return;
    if (need_swap && h) {
        std::fprintf(stderr,
            "[lan-uplink] SWAP active dev → %s (ip=%s) on slicer subscribe %s\n",
            dev_id.c_str(), dev_ip.c_str(), topic.c_str());
        std::fflush(stderr);
        int rc = h->connect_printer(dev_id, dev_ip, "bblp", access_code, use_ssl);
        if (rc == 0) {
            std::lock_guard<std::mutex> lk(m_impl->mu);
            m_impl->current_connected_dev_id = dev_id;
        } else {
            std::fprintf(stderr,
                "[lan-uplink] SWAP failed rc=%d for dev=%s\n", rc, dev_id.c_str());
            std::fflush(stderr);
        }
    }
}

void LanUplink::on_publish(const std::string& dev_id, std::string topic,
                           std::vector<uint8_t> payload, uint8_t qos) {
    (void)topic;
    std::shared_ptr<BambuNetworkingPluginHandle> h;
    bool have_device = false;
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        auto it = m_impl->devices.find(dev_id);
        have_device = (it != m_impl->devices.end());
        h   = m_impl->handle;
    }
    if (!have_device) {
        std::fprintf(stderr,
            "[lan-uplink] on_publish DROP dev=%s have_dev=0 bytes=%zu\n",
            dev_id.c_str(), payload.size());
        std::fflush(stderr);
        return;
    }
    std::string json(payload.begin(), payload.end());

#if 0
    auto publish_via_cert = [&](const std::string& label) -> bool {
        const std::string helper = resolve_helper_path_once();
        if (helper.empty()) {
            std::fprintf(stderr,
                "[%s dev=%s] helper script not found "
                "(set BBL_BRIDGE_RAW_MQTT_HELPER); falling back to plugin\n",
                label.c_str(), dev_id.c_str());
            std::fflush(stderr);
            return false;
        }
        const std::string tmpfile = write_tmp_payload(payload, dev_id);
        if (tmpfile.empty()) {
            std::fprintf(stderr,
                "[%s dev=%s] tmp file write failed; falling back\n",
                label.c_str(), dev_id.c_str());
            std::fflush(stderr);
            return false;
        }
        const std::string client_id  = make_client_id();
        const std::string topic_real =
            std::string("device/") + dev_id + "/request";
        int rc = spawn_raw_mqtt_helper(
            helper,
            cfg.printer_ip,
             8883,
            cfg.mtls_cert_path,
            cfg.mtls_key_path,
            cfg.access_code,
            client_id,
            topic_real,
            qos,
            tmpfile,
            dev_id);
        ::unlink(tmpfile.c_str());
        std::fprintf(stderr,
            "[%s] dev=%s topic=%s qos=%u bytes=%zu rc=%d\n",
            label.c_str(),
            dev_id.c_str(), topic_real.c_str(),
            unsigned(qos), payload.size(), rc);
        std::fflush(stderr);
        return true;
    };

    if (is_tier2 && have_cert) {
        if (publish_via_cert("tier2-via-cert")) return;

    }

    if (is_print && have_cert && print_bypass_enabled()) {

        bool wrap_ok = true;
        if (enc) {
            try {
                const size_t in_sz = json.size();
                std::string env = enc->wrap(json);
                json = std::move(env);
                payload.assign(json.begin(), json.end());
                std::fprintf(stderr,
                    "[lan-uplink] enc_msg wrap dev=%s in=%zuB out=%zuB\n",
                    dev_id.c_str(), in_sz, payload.size());
                std::fflush(stderr);
            } catch (const std::exception& ex) {
                std::fprintf(stderr,
                    "[lan-uplink] enc_msg wrap FAILED dev=%s: %s; "
                    "falling back to plugin path\n",
                    dev_id.c_str(), ex.what());
                std::fflush(stderr);
                wrap_ok = false;
            }
        }
        if (!wrap_ok) {

        } else {
        const std::string helper = resolve_helper_path_once();
        if (helper.empty()) {
            std::fprintf(stderr,
                "[print-via-cert/diag dev=%s] helper script not found "
                "(set BBL_BRIDGE_RAW_MQTT_HELPER); falling back to plugin\n",
                dev_id.c_str());
            std::fflush(stderr);
        } else {

            const std::string tmpfile = write_tmp_payload(payload, dev_id);
            if (tmpfile.empty()) {
                std::fprintf(stderr,
                    "[print-via-cert/diag dev=%s] tmp file write failed; falling back\n",
                    dev_id.c_str());
                std::fflush(stderr);
            } else {
                const std::string client_id = make_client_id();
                const std::string topic_real =
                    std::string("device/") + dev_id + "/request";
                int rc = spawn_raw_mqtt_helper(
                    helper,
                    cfg.printer_ip,
                     8883,
                    cfg.mtls_cert_path,
                    cfg.mtls_key_path,
                    cfg.access_code,
                    client_id,
                    topic_real,
                    qos,
                    tmpfile,
                    dev_id);
                ::unlink(tmpfile.c_str());
                std::fprintf(stderr,
                    "[print-via-cert/diag] dev=%s topic=%s qos=%u bytes=%zu rc=%d\n",
                    dev_id.c_str(), topic_real.c_str(),
                    unsigned(qos), payload.size(), rc);
                std::fflush(stderr);
                return;
            }
        }
        }
    }
#endif

    if (!h) {
        std::fprintf(stderr,
            "[lan-uplink] on_publish DROP dev=%s handle=null bytes=%zu\n",
            dev_id.c_str(), payload.size());
        std::fflush(stderr);
        return;
    }

    int rc = h->send_message_to_printer(dev_id, json, static_cast<int>(qos));
    std::fprintf(stderr,
        "[lan-uplink] on_publish dev=%s bytes=%zu qos=%u send_message_to_printer rc=%d\n",
        dev_id.c_str(), payload.size(), unsigned(qos), rc);
    std::fflush(stderr);
}

void LanUplink::on_unsubscribe(const std::string& dev_id, std::string topic) {
    std::lock_guard<std::mutex> lk(m_impl->mu);
    auto* d = m_impl->find_locked(dev_id);
    if (!d) return;
    auto it = d->topic_refs.find(topic);
    if (it == d->topic_refs.end()) return;
    if (--it->second <= 0) {
        d->topic_refs.erase(it);
    }
}

void LanUplink::on_disconnect(const std::string& dev_id) {

    (void)dev_id;
}

void LanUplink::attach_downstream(const std::string& dev_id,
                                  uint64_t            session_id,
                                  DownstreamPublisher publisher) {
    std::vector<Impl::RetainedMsg> replay;
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        if (!publisher) {
            auto it = m_impl->downstreams.find(dev_id);
            if (it != m_impl->downstreams.end()) {
                auto& vec = it->second;
                vec.erase(std::remove_if(vec.begin(), vec.end(),
                              [&](const Impl::Subscriber& s) {
                                  return s.session_id == session_id;
                              }),
                          vec.end());
                if (vec.empty()) m_impl->downstreams.erase(it);
            }
            return;
        }
        auto& vec = m_impl->downstreams[dev_id];
        bool replaced = false;
        for (auto& s : vec) {
            if (s.session_id == session_id) {
                s.publisher = publisher;
                replaced = true;
                break;
            }
        }
        if (!replaced) vec.push_back({session_id, publisher});
        auto rit = m_impl->retained.find(dev_id);
        if (rit != m_impl->retained.end()) replay = rit->second;
    }
    for (auto& m : replay) {
        publisher(m.topic, m.payload, m.qos);
    }
}

void LanUplink::detach_downstream(const std::string& dev_id,
                                  uint64_t            session_id) {
    std::lock_guard<std::mutex> lk(m_impl->mu);
    auto it = m_impl->downstreams.find(dev_id);
    if (it == m_impl->downstreams.end()) return;
    auto& vec = it->second;
    vec.erase(std::remove_if(vec.begin(), vec.end(),
                  [&](const Impl::Subscriber& s) {
                      return s.session_id == session_id;
                  }),
              vec.end());
    if (vec.empty()) m_impl->downstreams.erase(it);
}

void LanUplink::attach_downstream(const std::string& dev_id,
                                  DownstreamPublisher publisher) {
    std::fprintf(stderr,
        "[lan-uplink] WARN: deprecated 2-arg attach_downstream(dev=%s) — "
        "caller should use the (dev_id, session_id, publisher) overload\n",
        dev_id.c_str());
    std::fflush(stderr);
    if (publisher) {
        attach_downstream(dev_id, 0, std::move(publisher));
    } else {
        detach_downstream(dev_id, 0);
    }
}

}
}
}
