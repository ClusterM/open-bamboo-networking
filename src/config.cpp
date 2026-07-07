#include "obn/config.hpp"
#include "obn/lan_tls.hpp"
#include "obn_conf_default.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>

namespace obn::config {
namespace {

std::mutex  g_mu;
Settings    g_current;
std::string g_config_dir;

constexpr const char* kDefaultGlobalApi  = "https://api.bambulab.com";
constexpr const char* kDefaultGlobalWeb  = "https://bambulab.com";
constexpr const char* kDefaultGlobalMqtt = "us.mqtt.bambulab.com";
constexpr const char* kDefaultCnApi      = "https://api.bambulab.cn";
constexpr const char* kDefaultCnWeb      = "https://bambulab.cn";
constexpr const char* kDefaultCnMqtt     = "cn.mqtt.bambulab.com";

bool is_cn_region(const std::string& region)
{
    return region == "CN" || region == "cn";
}

const char* pick_or_default(const std::string& configured, const char* fallback)
{
    return configured.empty() ? fallback : configured.c_str();
}

std::string trim(const std::string& s)
{
    std::size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    std::size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string to_lower(const std::string& s)
{
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return r;
}

bool parse_line(const std::string& line, std::string& key, std::string& val)
{
    key.clear();
    val.clear();
    if (line.empty() || line[0] == '#') return false;
    const auto eq = line.find('=');
    if (eq == std::string::npos || eq == 0) return false;
    key = trim(line.substr(0, eq));
    val = trim(line.substr(eq + 1));
    return !key.empty();
}

void apply_key(Settings& out, const std::string& key, const std::string& val)
{
    if      (key == "log_level")      out.log_level = val;
    else if (key == "log_stderr")     out.log_stderr = val;
    else if (key == "log_to_file")    out.log_to_file = val;
    else if (key == "log_file")       out.log_file = val;
    else if (key == "cloud_global_api_host")  out.cloud_global_api_host = val;
    else if (key == "cloud_global_web_host")  out.cloud_global_web_host = val;
    else if (key == "cloud_global_mqtt_host") out.cloud_global_mqtt_host = val;
    else if (key == "cloud_cn_api_host")      out.cloud_cn_api_host = val;
    else if (key == "cloud_cn_web_host")      out.cloud_cn_web_host = val;
    else if (key == "cloud_cn_mqtt_host")     out.cloud_cn_mqtt_host = val;
    else if (key == "lan_tls_skip_verify")      out.lan_tls_skip_verify = truthy(val);
    else if (key == "cloud_mqtt_port") {
        int p = std::atoi(val.c_str());
        if (p > 0 && p <= 65535) out.cloud_mqtt_port = p;
    }
    else if (key == "block_cloud")              out.block_cloud = truthy(val);
    else if (key == "force_timelapse_external")  out.force_timelapse_external = truthy(val);
    else if (key == "force_ftps")                out.force_ftps = truthy(val);
    else if (key == "disable_camera_preview")      out.disable_camera_preview = truthy(val);
    else if (key == "mqtt_keep_connection")        out.mqtt_keep_connection = truthy(val);
    else if (key == "override_lan_ip")            out.override_lan_ip = truthy(val);
    else if (key == "patch_mqtt_home_flag")        out.patch_mqtt_home_flag = truthy(val);
    else if (key == "patch_mqtt_ipcam_file")       out.patch_mqtt_ipcam_file = truthy(val);
    else if (key == "patch_mqtt_internal_storage") out.patch_mqtt_internal_storage = truthy(val);
    else if (key == "slicer_key_pem")               out.slicer_key_pem = val;
    else if (key == "slicer_cert_id")              out.slicer_cert_id = val;
    else if (key == "session_path")                out.session_path = val;
    else if (key == "bambusource_log_level")       out.bambusource_log_level = val;
    else if (key == "bambusource_log_stderr")     out.bambusource_log_stderr = val;
    else if (key == "bambusource_log_to_file")   out.bambusource_log_to_file = val;
    else if (key == "bambusource_log_file")       out.bambusource_log_file = val;
}

Settings parse_file(const std::filesystem::path& path)
{
    Settings out;
    std::ifstream in(path);
    if (!in) return out;
    std::string line;
    while (std::getline(in, line)) {
        std::string key, val;
        if (!parse_line(line, key, val)) continue;
        apply_key(out, key, val);
    }
    return out;
}

bool write_default_template(const std::filesystem::path& path)
{
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);

    const std::filesystem::path tmp = path.string() + ".tmp";
    std::ofstream f(tmp, std::ios::binary);
    if (!f) return false;

    f << kDefaultTemplate;

    if (!f) {
        f.close();
        std::filesystem::remove(tmp, ec);
        return false;
    }
    f.close();

#if defined(_WIN32)
    std::filesystem::remove(path, ec);
#endif
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        return false;
    }
    return true;
}

std::filesystem::path config_path(const std::string& config_dir)
{
    std::string dir = config_dir;
    if (dir.empty()) return {};
    char last = dir.back();
    if (last != '/' && last != '\\') dir += '/';
    return std::filesystem::path(dir) / kConfigFileName;
}

} // namespace

bool truthy(const std::string& val, bool fallback)
{
    const std::string lc = to_lower(val);
    if (lc == "1" || lc == "true" || lc == "yes") return true;
    if (lc == "0" || lc == "false" || lc == "no") return false;
    return fallback;
}

Settings load_or_create(const std::string& config_dir)
{
    std::lock_guard<std::mutex> lk(g_mu);
    if (config_dir.empty()) return g_current;

    const auto path = config_path(config_dir);
    if (path.empty()) return g_current;

    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec))
        (void)write_default_template(path);

    g_config_dir = config_dir;
    g_current = parse_file(path);
    obn::lan_tls::propagate_cross_so_env(g_current);
    return g_current;
}

Settings load_if_exists(const std::string& config_dir)
{
    if (config_dir.empty()) return {};
    const auto path = config_path(config_dir);
    if (path.empty()) return {};
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) return {};
    return parse_file(path);
}

const Settings& current()
{
    std::lock_guard<std::mutex> lk(g_mu);
    return g_current;
}

const std::string& dir()
{
    std::lock_guard<std::mutex> lk(g_mu);
    return g_config_dir;
}

std::string cloud_api_host_for(const Settings& s, const std::string& region)
{
    if (is_cn_region(region))
        return pick_or_default(s.cloud_cn_api_host, kDefaultCnApi);
    return pick_or_default(s.cloud_global_api_host, kDefaultGlobalApi);
}

std::string cloud_web_host_for(const Settings& s, const std::string& region)
{
    if (is_cn_region(region))
        return pick_or_default(s.cloud_cn_web_host, kDefaultCnWeb);
    return pick_or_default(s.cloud_global_web_host, kDefaultGlobalWeb);
}

std::string cloud_mqtt_host_for(const Settings& s, const std::string& region)
{
    if (is_cn_region(region))
        return pick_or_default(s.cloud_cn_mqtt_host, kDefaultCnMqtt);
    return pick_or_default(s.cloud_global_mqtt_host, kDefaultGlobalMqtt);
}

} // namespace obn::config
