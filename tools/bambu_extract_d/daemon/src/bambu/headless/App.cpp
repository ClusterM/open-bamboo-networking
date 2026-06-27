#include "App.hpp"

#include "../BambuNetworkingPluginHandle.hpp"
#include "../router/LanUplink.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>

namespace Slic3r {
namespace bambu {
namespace headless {

static std::pair<std::string, std::string>
resolve_mtls_paths(const std::string& dev_id) {
    std::string dir = "/tmp/bbl_capture/mtls.fresh/paired";
    if (const char* env = std::getenv("BBL_BRIDGE_MTLS_DIR");
        env && *env) {
        dir = env;
    }

    std::string cert_env_key = "BBL_BRIDGE_MTLS_CERT_" + dev_id;
    std::string key_env_key  = "BBL_BRIDGE_MTLS_KEY_"  + dev_id;
    const char* ec = std::getenv(cert_env_key.c_str());
    const char* ek = std::getenv(key_env_key.c_str());
    if (ec && *ec && ek && *ek) {
        struct stat st;
        if (::stat(ec, &st) == 0 && ::stat(ek, &st) == 0) {
            return {ec, ek};
        }
    }

    DIR* d = ::opendir(dir.c_str());
    if (!d) return {{}, {}};
    std::string cert_path, key_path;
    const std::string chain_suffix = "_" + dev_id + "_chain.pem";
    const std::string key_suffix   = "_" + dev_id + "_key.pem";
    while (struct dirent* e = ::readdir(d)) {
        std::string name = e->d_name;
        auto ends_with = [&](const std::string& suf) {
            return name.size() >= suf.size() &&
                   name.compare(name.size() - suf.size(),
                                suf.size(), suf) == 0;
        };
        if (cert_path.empty() && ends_with(chain_suffix)) {
            cert_path = dir + "/" + name;
        } else if (key_path.empty() && ends_with(key_suffix)) {
            key_path = dir + "/" + name;
        }
        if (!cert_path.empty() && !key_path.empty()) break;
    }
    ::closedir(d);
    return {cert_path, key_path};
}

static std::string detect_primary_lan_ip() {
    struct ifaddrs* ifa_list = nullptr;
    if (::getifaddrs(&ifa_list) != 0) return {};
    std::string best;
    for (auto* ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if ((ifa->ifa_flags & IFF_UP) == 0)        continue;
        if ((ifa->ifa_flags & IFF_LOOPBACK) != 0)  continue;
        auto* in = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
        char buf[INET_ADDRSTRLEN] = {0};
        if (!::inet_ntop(AF_INET, &in->sin_addr, buf, sizeof(buf))) continue;
        std::string ip = buf;

        const std::string ifname = ifa->ifa_name ? ifa->ifa_name : "";
        if (ifname.rfind("docker", 0) == 0)  continue;
        if (ifname.rfind("br-",    0) == 0)  continue;
        if (ifname.rfind("virbr",  0) == 0)  continue;
        if (ifname.rfind("veth",   0) == 0)  continue;
        best = ip;
        break;
    }
    ::freeifaddrs(ifa_list);
    return best;
}

static const char* const kVirtualSerialPrefix = "FFFF";

static std::string mangle_serial(const std::string& real_sn) {
    constexpr std::size_t kPrefixLen = 4;
    if (real_sn.size() <= kPrefixLen) {

        return std::string(kVirtualSerialPrefix) + real_sn;
    }
    return std::string(kVirtualSerialPrefix) +
           real_sn.substr(kPrefixLen);
}

static std::string default_port_map_path() {
    if (const char* p = std::getenv("BAMBU_BRIDGE_PORT_MAP_FILE"); p && *p)
        return p;
    std::string base;
    if (const char* x = std::getenv("XDG_CONFIG_HOME"); x && *x) {
        base = x;
    } else if (const char* h = std::getenv("HOME"); h && *h) {
        base = std::string(h) + "/.config";
    } else {
        base = "/tmp";
    }
    return base + "/bambu-bridge/port-map";
}

static void load_port_map(const std::string& path,
                          std::map<std::string, std::size_t>& out) {
    std::ifstream in(path);
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {

        if (line.empty() || line[0] == '#') continue;
        std::istringstream iss(line);
        std::string dev_id;
        std::size_t offset = 0;
        if (iss >> dev_id >> offset) out[dev_id] = offset;
    }
}

static bool save_port_map(const std::string& path,
                          const std::map<std::string, std::size_t>& m) {

    const std::size_t slash = path.find_last_of('/');
    if (slash != std::string::npos && slash > 0) {
        const std::string dir = path.substr(0, slash);
        std::string acc;
        for (std::size_t i = 0; i <= dir.size(); ++i) {
            if (i == dir.size() || dir[i] == '/') {
                if (!acc.empty() && acc != "/") {

                    ::mkdir(acc.c_str(), 0755);
                }
            }
            if (i < dir.size()) acc.push_back(dir[i]);
        }
    }
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            std::fprintf(stderr,
                "[bambu] port-map save FAILED: cannot open %s for write\n",
                tmp.c_str());
            return false;
        }
        out << "# bambu-bridge port-map (dev_id offset) — managed automatically\n";
        for (const auto& kv : m) out << kv.first << ' ' << kv.second << '\n';
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::fprintf(stderr,
            "[bambu] port-map save FAILED: rename %s -> %s errno=%d\n",
            tmp.c_str(), path.c_str(), errno);
        return false;
    }
    return true;
}

App::App(AppConfig cfg) : m_cfg(std::move(cfg)) {}

App::~App() {
    shutdown();
    if (m_poll_thread.joinable()) m_poll_thread.join();
    if (m_gcode_pulse_thread.joinable()) m_gcode_pulse_thread.join();
    if (m_print3mf_thread.joinable()) m_print3mf_thread.join();
    teardown();
}

void App::set_plugin_handle_for_test(
    std::shared_ptr<BambuNetworkingPluginHandle> handle) {
    m_plugin          = std::move(handle);
    m_plugin_injected = (m_plugin != nullptr);
}

void App::set_bambu_source_handle_for_test(
    std::shared_ptr<BambuSourceHandle> handle) {
    m_bambu_source          = std::move(handle);
    m_bambu_source_injected = (m_bambu_source != nullptr);
}

void App::attach_storage_delegate(
    StorageDelegate                         delegate,
    std::function<void(const std::string&)> release_cb) {

    m_storage_delegate   = std::move(delegate);
    m_storage_release_cb = std::move(release_cb);
}

void App::set_camera_url_resolver(CameraUrlResolver fn) {

    m_camera_url_resolver = fn;
}

uint16_t App::mqtt_port_for_dev_id(const std::string& dev_id) const {
    std::lock_guard<std::mutex> lk(m_devices_mu);

    auto it = m_devices.find(dev_id);
    if (it != m_devices.end()) return it->second.mqtt_port;

    if (dev_id.size() > 4 &&
        dev_id.compare(0, 4, kVirtualSerialPrefix) == 0) {
        const std::string tail = dev_id.substr(4);
        for (const auto& kv : m_devices) {
            const std::string& real = kv.first;
            if (real.size() >= tail.size() &&
                real.compare(real.size() - tail.size(),
                             tail.size(), tail) == 0) {
                return kv.second.mqtt_port;
            }
        }
    }
    return 0;
}

App::RealDeviceInfo
App::lookup_real_device(const std::string& dev_id) const {
    RealDeviceInfo out;
    std::lock_guard<std::mutex> lk(m_devices_mu);

    auto it = m_devices.find(dev_id);
    if (it != m_devices.end()) {
        out.real_dev_id = it->first;
        out.lan_ip      = it->second.lan_ip;
        return out;
    }

    if (dev_id.size() > 4 &&
        dev_id.compare(0, 4, kVirtualSerialPrefix) == 0) {
        const std::string tail = dev_id.substr(4);
        for (const auto& kv : m_devices) {
            const std::string& real = kv.first;
            if (real.size() >= tail.size() &&
                real.compare(real.size() - tail.size(),
                             tail.size(), tail) == 0) {
                out.real_dev_id = real;
                out.lan_ip      = kv.second.lan_ip;
                return out;
            }
        }
    }
    return out;
}

bool App::initialise() {
    if (m_initialised.load()) return true;

    if (!m_plugin_injected && !m_cfg.host_drives_inventory) {
        PluginHandleConfig hcfg;
        hcfg.plugin_path        = m_cfg.plugin_path;
        hcfg.config_dir         = m_cfg.config_dir;
        hcfg.country_code       = m_cfg.country_code;
        hcfg.extra_http_headers = m_cfg.http_extra_headers;
        hcfg.cert_dir           = m_cfg.cert_dir;
        hcfg.cert_file          = m_cfg.cert_file;
        m_plugin = std::make_shared<BambuNetworkingPluginHandle>(hcfg);
        if (!m_plugin->init()) {
            m_plugin.reset();
            return false;
        }
    } else if (m_plugin_injected) {
    } else {
    }

    m_lan_uplink = std::make_shared<router::LanUplink>();
    m_lan_uplink->attach_plugin(m_plugin);

    m_initialised.store(true);
    return true;
}

void App::teardown() {
    if (!m_initialised.load() && !m_plugin) return;

    std::vector<std::string> dev_ids;
    {
        std::lock_guard<std::mutex> lk(m_devices_mu);
        dev_ids.reserve(m_devices.size());
        for (const auto& kv : m_devices) dev_ids.push_back(kv.first);
    }
    for (const auto& d : dev_ids) {
        std::lock_guard<std::mutex> lk(m_devices_mu);
        remove_device_locked(d);
    }

    m_lan_uplink.reset();

    m_plugin.reset();

    m_initialised.store(false);
}

void App::reconcile_once() {

    if (m_cfg.printer_source) {
        std::vector<VirtualPrinter> printers;
        try {
            printers = m_cfg.printer_source();
        } catch (const std::exception& ex) {
            return;
        }
        set_virtual_printers(std::move(printers));
        expire_stale_lan_ips();
        return;
    }

    expire_stale_lan_ips();
}

void App::expire_stale_lan_ips() {
    std::lock_guard<std::mutex> lk(m_devices_mu);
    const auto now = std::chrono::steady_clock::now();
    for (auto& kv : m_devices) {
        auto& s = kv.second;
        if (s.lan_ip.empty()) continue;

        if (s.lan_ip_last_seen.time_since_epoch().count() == 0) continue;
        if (now - s.lan_ip_last_seen <= m_cfg.lan_ip_stale_after)
            continue;
        s.lan_ip.clear();
        s.lan_ip_last_seen = {};
    }
}

void App::set_virtual_printers(std::vector<VirtualPrinter> printers) {

    {
        std::string ids;
        for (const auto& p : printers) {
            if (!ids.empty()) ids += ",";
            ids += p.dev_id;
        }
        std::fprintf(stderr,
            "[bambu] set_virtual_printers count=%zu ids=[%s]\n",
            printers.size(), ids.c_str());
        std::fflush(stderr);
    }

    if (const char* env = std::getenv("BAMBU_BRIDGE_PRINTER_ORDER"); env && *env) {
        std::vector<std::string> want;
        const std::string s = env;
        size_t pos = 0;
        while (pos <= s.size()) {
            const size_t comma = s.find(',', pos);
            const size_t end = (comma == std::string::npos) ? s.size() : comma;
            if (end > pos) want.emplace_back(s.substr(pos, end - pos));
            if (comma == std::string::npos) break;
            pos = comma + 1;
        }
        std::stable_sort(printers.begin(), printers.end(),
            [&want](const VirtualPrinter& a, const VirtualPrinter& b) {
                const auto ia = std::find(want.begin(), want.end(), a.dev_id);
                const auto ib = std::find(want.begin(), want.end(), b.dev_id);
                return ia < ib;
            });
    }

    std::vector<std::string> env_keep_order;
    if (const char* env = std::getenv("BAMBU_BRIDGE_TARGET_DEV"); env && *env) {
        const std::string s = env;
        size_t pos = 0;
        while (pos <= s.size()) {
            const size_t comma = s.find(',', pos);
            const size_t end = (comma == std::string::npos) ? s.size() : comma;
            if (end > pos) env_keep_order.emplace_back(s.substr(pos, end - pos));
            if (comma == std::string::npos) break;
            pos = comma + 1;
        }
        printers.erase(
            std::remove_if(printers.begin(), printers.end(),
                [&env_keep_order](const VirtualPrinter& p) {
                    return std::find(env_keep_order.begin(), env_keep_order.end(), p.dev_id) == env_keep_order.end();
                }),
            printers.end());
    }

    std::lock_guard<std::mutex> lk(m_devices_mu);

    if (!m_port_map_loaded) {

        m_port_map_path = !m_cfg.config_dir.empty()
            ? (m_cfg.config_dir + "/port-map")
            : default_port_map_path();
        load_port_map(m_port_map_path, m_pinned_offset);
        bool changed = false;
        if (m_pinned_offset.empty() && !env_keep_order.empty()) {

            for (std::size_t i = 0; i < env_keep_order.size(); ++i) {
                m_pinned_offset.emplace(env_keep_order[i], i);
            }
            changed = true;
        } else if (!env_keep_order.empty()) {

            std::size_t max_offset = 0;
            bool any = false;
            for (const auto& kv : m_pinned_offset) {
                if (!any || kv.second > max_offset) { max_offset = kv.second; any = true; }
            }
            std::size_t next = any ? max_offset + 1 : 0;
            for (const auto& dev : env_keep_order) {
                if (m_pinned_offset.find(dev) == m_pinned_offset.end()) {
                    m_pinned_offset.emplace(dev, next++);
                    changed = true;
                }
            }
        }
        if (changed) {
            save_port_map(m_port_map_path, m_pinned_offset);
        }

        std::size_t max_offset = 0;
        bool any = false;
        for (const auto& kv : m_pinned_offset) {
            if (!any || kv.second > max_offset) { max_offset = kv.second; any = true; }
        }
        m_next_index = any ? max_offset + 1 : 0;
        std::fprintf(stderr,
            "[bambu] port-map %s loaded=%zu next_index=%zu\n",
            m_port_map_path.c_str(), m_pinned_offset.size(), m_next_index);
        std::fflush(stderr);
        m_port_map_loaded = true;
    }

    for (const auto& p : printers) {
        if (p.dev_id.empty()) continue;
        auto it = m_devices.find(p.dev_id);
        if (it == m_devices.end()) {
            add_device_locked(p);
        } else {
            if (!p.lan_ip.empty()) {
                if (it->second.lan_ip != p.lan_ip)
                    update_lan_ip_locked(it->second, p.lan_ip);

                it->second.lan_ip_last_seen =
                    std::chrono::steady_clock::now();
            }

            if (!p.firmware.empty() &&
                it->second.firmware_ver != p.firmware) {
                it->second.firmware_ver = p.firmware;
            }

            if (it->second.camera_url != p.camera_url) {
                it->second.camera_url = p.camera_url;
            }
        }
    }
    std::vector<std::string> doomed;
    for (const auto& kv : m_devices) {
        const auto& tracked = kv.first;
        auto hit = std::find_if(printers.begin(), printers.end(),
            [&](const VirtualPrinter& p) { return p.dev_id == tracked; });
        if (hit == printers.end()) doomed.push_back(tracked);
    }
    for (const auto& d : doomed) remove_device_locked(d);
}

void App::add_device_locked(const VirtualPrinter& vp) {
    const std::string& dev_id      = vp.dev_id;
    const std::string& lan_ip      = vp.lan_ip;
    const std::string& access_code = vp.access_code;

    DeviceState state;
    state.dev_id       = dev_id;
    state.lan_ip       = lan_ip;
    state.firmware_ver = vp.firmware;
    state.camera_url   = vp.camera_url;
    state.model        = vp.model;

    if (!lan_ip.empty())
        state.lan_ip_last_seen = std::chrono::steady_clock::now();
    state.access_code = access_code;

    if (auto it = m_pinned_offset.find(dev_id); it != m_pinned_offset.end()) {
        state.index = it->second;
    } else {
        state.index = m_next_index++;
        m_pinned_offset[dev_id] = state.index;
        if (!m_port_map_path.empty())
            save_port_map(m_port_map_path, m_pinned_offset);
        std::fprintf(stderr,
            "[bambu] port-map pinned new dev=%s offset=%zu (persisted)\n",
            dev_id.c_str(), state.index);
        std::fflush(stderr);
    }
    state.mqtt_port   = static_cast<uint16_t>(m_cfg.mqtt_port_base + state.index);
    state.ftps_port   = static_cast<uint16_t>(m_cfg.ftps_port_base + state.index);
    state.rtsp_port   = static_cast<uint16_t>(m_cfg.rtsp_port_base + state.index);
    state.vtun_port   = static_cast<uint16_t>(m_cfg.vtun_port_base + state.index);

    if (m_lan_uplink) {
        if (!lan_ip.empty()) {
            router::LanUplinkConfig u;
            u.dev_id      = dev_id;
            u.printer_ip  = lan_ip;
            u.access_code = access_code;

            auto mtls = resolve_mtls_paths(dev_id);
            u.mtls_cert_path = mtls.first;
            u.mtls_key_path  = mtls.second;
            if (!u.mtls_cert_path.empty()) {
                std::fprintf(stderr,
                    "[bambu] dev=%s mtls cert=%s key=%s\n",
                    dev_id.c_str(),
                    u.mtls_cert_path.c_str(),
                    u.mtls_key_path.c_str());
                std::fflush(stderr);
            } else {
                std::fprintf(stderr,
                    "[bambu] dev=%s NO mtls cert found in "
                    "/tmp/bbl_capture/mtls.fresh/paired — print.* publishes "
                    "will fall back to plugin (and likely drop)\n",
                    dev_id.c_str());
                std::fflush(stderr);
            }
            m_lan_uplink->add_device(u);
        }
    }

    m_devices.emplace(dev_id, std::move(state));
}

void App::update_lan_ip_locked(DeviceState&       state,
                                     const std::string& lan_ip) {

    state.lan_ip = lan_ip;

    if (!m_lan_uplink) return;

    if (!lan_ip.empty()) {
        router::LanUplinkConfig u;
        u.dev_id      = state.dev_id;
        u.printer_ip  = lan_ip;
        u.access_code = state.access_code;
        auto mtls = resolve_mtls_paths(state.dev_id);
        u.mtls_cert_path = mtls.first;
        u.mtls_key_path  = mtls.second;
        m_lan_uplink->add_device(u);
    }
}

void App::remove_device_locked(const std::string& dev_id) {
    auto it = m_devices.find(dev_id);
    if (it == m_devices.end()) return;

    if (m_lan_uplink) m_lan_uplink->remove_device(dev_id);

    if (m_storage_release_cb) {
        m_storage_release_cb(dev_id);
    }

    m_devices.erase(it);
}

bool App::poll_inventory_once() {
    if (!m_initialised.load()) {
        if (!initialise()) return false;
    }
    reconcile_once();
    return true;
}

void App::poll_loop() {
    while (!m_stop.load()) {
        reconcile_once();
        std::unique_lock<std::mutex> lk(m_stop_mu);
        m_stop_cv.wait_for(lk, m_cfg.inventory_poll,
                           [&] { return m_stop.load(); });
    }
}

int App::run() {
    if (!initialise()) return 1;

    m_stop.store(false);
    m_poll_thread = std::thread(&App::poll_loop, this);

    {
        std::unique_lock<std::mutex> lk(m_stop_mu);
        m_stop_cv.wait(lk, [&] { return m_stop.load(); });
    }
    if (m_poll_thread.joinable()) m_poll_thread.join();

    teardown();
    return 0;
}

void App::shutdown() {
    {
        std::lock_guard<std::mutex> lk(m_stop_mu);
        m_stop.store(true);
    }
    m_stop_cv.notify_all();
}

std::vector<App::DeviceBinding> App::device_bindings() const {
    std::vector<DeviceBinding> out;
    std::lock_guard<std::mutex> lk(m_devices_mu);
    out.reserve(m_devices.size());
    for (const auto& kv : m_devices) {
        DeviceBinding b;
        b.dev_id    = kv.second.dev_id;
        b.lan_ip    = kv.second.lan_ip;
        b.mqtt_port = kv.second.mqtt_port;
        b.ftps_port = kv.second.ftps_port;
        b.rtsp_port = kv.second.rtsp_port;
        b.vtun_port = kv.second.vtun_port;
        out.push_back(std::move(b));
    }
    return out;
}

bool App::mtls_info_for(const std::string& dev_id, MtlsInfo& out) const {
    {
        std::lock_guard<std::mutex> lk(m_devices_mu);
        auto it = m_devices.find(dev_id);
        if (it == m_devices.end()) return false;
        out.lan_ip      = it->second.lan_ip;
        out.access_code = it->second.access_code;
    }

    auto paths = resolve_mtls_paths(dev_id);
    out.cert_path = paths.first;
    out.key_path  = paths.second;
    return !out.cert_path.empty() && !out.key_path.empty();
}

}
}
}
