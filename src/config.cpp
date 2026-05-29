#include "obn/config.hpp"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>

namespace obn::config {
namespace {

std::mutex g_mu;
Settings   g_current;

std::string trim(const std::string& s)
{
    std::size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    std::size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
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
    if (key == "log_level") out.log_level = val;
    else if (key == "log_stderr") out.log_stderr = val;
    else if (key == "log_to_file") out.log_to_file = val;
    else if (key == "log_file") out.log_file = val;
    else if (key == "cloud_api_host") out.cloud_api_host = val;
    else if (key == "cloud_web_host") out.cloud_web_host = val;
    else if (key == "cloud_mqtt_host") out.cloud_mqtt_host = val;
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

    f << "# Open Bamboo Networking user settings\n"
      << "# Environment variables (OBN_LOG_*) override these values.\n"
      << "\n"
      << "# Logging\n"
      << "log_level = info\n"
      << "log_stderr = 1\n"
      << "log_to_file = 0\n"
      << "# log_file = /absolute/path/to/obn.log\n"
      << "\n"
      << "# Cloud endpoints (leave empty for production US/CN by country_code)\n"
      << "# Production global: https://api.bambulab.com / https://bambulab.com / us.mqtt.bambulab.com\n"
      << "# Production CN:      https://api.bambulab.cn / https://bambulab.cn / cn.mqtt.bambulab.com\n"
      << "# Dev/QA (Studio):    https://api-dev.bambulab.net / https://api-qa.bambulab.net / ...\n"
      << "# cloud_api_host = https://api.bambulab.com\n"
      << "# cloud_web_host = https://bambulab.com\n"
      << "# cloud_mqtt_host = us.mqtt.bambulab.com\n";

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

Settings load_or_create(const std::string& config_dir)
{
    std::lock_guard<std::mutex> lk(g_mu);
    if (config_dir.empty()) return g_current;

    const auto path = config_path(config_dir);
    if (path.empty()) return g_current;

    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec))
        (void)write_default_template(path);

    g_current = parse_file(path);
    return g_current;
}

const Settings& current()
{
    std::lock_guard<std::mutex> lk(g_mu);
    return g_current;
}

} // namespace obn::config
