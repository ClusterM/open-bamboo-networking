#include "obn/config.hpp"
#include "obn/log.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__          \
                      << " " << #cond << "\n";                          \
            return 1;                                                   \
        }                                                               \
    } while (0)

static fs::path make_temp_dir()
{
    const fs::path base = fs::temp_directory_path() / "obn-config-test";
    fs::create_directories(base);
    const fs::path dir = base / std::to_string(
        static_cast<unsigned long long>(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(dir);
    return dir;
}

static void write_conf(const fs::path& dir, const std::string& body)
{
    std::ofstream out(dir / obn::config::kConfigFileName);
    out << body;
}

static int test_parse_keys()
{
    const fs::path dir = make_temp_dir();
    write_conf(dir,
               "# comment\n"
               " log_level = debug \n"
               "cloud_global_api_host = https://api-dev.bambulab.net\n"
               "unknown_key = ignored\n");
    const auto cfg = obn::config::load_or_create(dir.string());
    CHECK(cfg.log_level == "debug");
    CHECK(cfg.cloud_global_api_host == "https://api-dev.bambulab.net");
    CHECK(cfg.log_stderr.empty());
    return 0;
}

static int test_create_template()
{
    const fs::path dir = make_temp_dir();
    const fs::path path = dir / obn::config::kConfigFileName;
    CHECK(!fs::exists(path));
    (void)obn::config::load_or_create(dir.string());
    CHECK(fs::exists(path));
    const auto first_size = fs::file_size(path);

    std::ifstream in(path);
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    CHECK(content.find("cloud_global_api_host = https://api.bambulab.com")
          != std::string::npos);
    CHECK(content.find("block_cloud = 1") != std::string::npos);

    write_conf(dir, "log_level = warn\n");
    (void)obn::config::load_or_create(dir.string());
    CHECK(obn::config::current().log_level == "warn");
    CHECK(fs::file_size(path) != first_size);
    return 0;
}

static int test_env_overrides_config()
{
    const fs::path dir = make_temp_dir();
    write_conf(dir, "log_level = trace\nlog_stderr = 0\n");
    (void)obn::config::load_or_create(dir.string());

#if defined(_WIN32)
    _putenv_s("OBN_LOG_LEVEL", "error");
    _putenv_s("OBN_LOG_STDERR", "1");
#else
    setenv("OBN_LOG_LEVEL", "error", 1);
    setenv("OBN_LOG_STDERR", "1", 1);
#endif

    obn::log::apply_config(obn::config::current());
    CHECK(obn::log::threshold() == obn::log::LVL_ERROR);

#if defined(_WIN32)
    _putenv_s("OBN_LOG_LEVEL", "");
    _putenv_s("OBN_LOG_STDERR", "");
#else
    unsetenv("OBN_LOG_LEVEL");
    unsetenv("OBN_LOG_STDERR");
#endif
    return 0;
}

static int test_cloud_api_override()
{
    const fs::path dir = make_temp_dir();
    write_conf(dir,
               "cloud_global_api_host = https://api-qa.bambulab.net\n"
               "cloud_cn_api_host = https://api-qa.bambulab.cn\n");
    (void)obn::config::load_or_create(dir.string());
    CHECK(obn::config::current().cloud_global_api_host == "https://api-qa.bambulab.net");
    CHECK(obn::config::current().cloud_cn_api_host == "https://api-qa.bambulab.cn");
    CHECK(obn::config::cloud_api_host_for(obn::config::current(), "US")
          == "https://api-qa.bambulab.net");
    CHECK(obn::config::cloud_api_host_for(obn::config::current(), "CN")
          == "https://api-qa.bambulab.cn");
    return 0;
}

static int test_cloud_regional_defaults()
{
    obn::config::Settings s{};
    CHECK(obn::config::cloud_api_host_for(s, "US") == "https://api.bambulab.com");
    CHECK(obn::config::cloud_web_host_for(s, "US") == "https://bambulab.com");
    CHECK(obn::config::cloud_mqtt_host_for(s, "US") == "us.mqtt.bambulab.com");
    CHECK(obn::config::cloud_api_host_for(s, "CN") == "https://api.bambulab.cn");
    CHECK(obn::config::cloud_web_host_for(s, "cn") == "https://bambulab.cn");
    CHECK(obn::config::cloud_mqtt_host_for(s, "CN") == "cn.mqtt.bambulab.com");
    return 0;
}

static int test_truthy()
{
    CHECK(obn::config::truthy("1") == true);
    CHECK(obn::config::truthy("0") == false);
    CHECK(obn::config::truthy("true") == true);
    CHECK(obn::config::truthy("false") == false);
    CHECK(obn::config::truthy("True") == true);
    CHECK(obn::config::truthy("FALSE") == false);
    CHECK(obn::config::truthy("yes") == true);
    CHECK(obn::config::truthy("no") == false);
    CHECK(obn::config::truthy("YES") == true);
    CHECK(obn::config::truthy("NO") == false);
    CHECK(obn::config::truthy("junk") == false);
    CHECK(obn::config::truthy("junk", true) == true);
    return 0;
}

static int test_new_keys()
{
    const fs::path dir = make_temp_dir();
    write_conf(dir,
               "lan_tls_skip_verify = yes\n"
               "cloud_mqtt_port = 1883\n"
               "block_cloud = false\n"
               "force_timelapse_external = 1\n"
               "force_ftps = 1\n"
               "disable_camera_preview = 1\n"
               "mqtt_keep_connection = yes\n"
               "patch_mqtt_home_flag = yes\n"
               "patch_mqtt_ipcam_file = true\n"
               "patch_mqtt_internal_storage = 1\n"
               "bambusource_log_level = debug\n"
               "bambusource_log_file = /tmp/bs.log\n");
    const auto cfg = obn::config::load_or_create(dir.string());
    CHECK(cfg.lan_tls_skip_verify == true);
    CHECK(cfg.cloud_mqtt_port == 1883);
    CHECK(cfg.block_cloud == false);
    CHECK(cfg.force_timelapse_external == true);
    CHECK(cfg.force_ftps == true);
    CHECK(cfg.disable_camera_preview == true);
    CHECK(cfg.mqtt_keep_connection == true);
    CHECK(cfg.patch_mqtt_home_flag == true);
    CHECK(cfg.patch_mqtt_ipcam_file == true);
    CHECK(cfg.patch_mqtt_internal_storage == true);
    CHECK(cfg.bambusource_log_level == "debug");
    CHECK(cfg.bambusource_log_file == "/tmp/bs.log");
    return 0;
}

static int test_new_keys_defaults()
{
    const fs::path dir = make_temp_dir();
    write_conf(dir, "log_level = info\n");
    const auto cfg = obn::config::load_or_create(dir.string());
    CHECK(cfg.lan_tls_skip_verify == false);
    CHECK(cfg.cloud_mqtt_port == 8883);
    CHECK(cfg.block_cloud == true);
    CHECK(cfg.force_timelapse_external == false);
    CHECK(cfg.force_ftps == false);
    CHECK(cfg.disable_camera_preview == false);
    CHECK(cfg.mqtt_keep_connection == true);
    CHECK(cfg.patch_mqtt_home_flag == false);
    CHECK(cfg.patch_mqtt_ipcam_file == false);
    CHECK(cfg.patch_mqtt_internal_storage == false);
    CHECK(cfg.bambusource_log_level.empty());
    CHECK(cfg.bambusource_log_file.empty());
    return 0;
}

static int test_load_if_exists()
{
    const fs::path dir = make_temp_dir();
    auto cfg = obn::config::load_if_exists(dir.string());
    CHECK(cfg.force_timelapse_external == false);
    CHECK(cfg.cloud_mqtt_port == 8883);

    write_conf(dir, "force_timelapse_external = 1\ncloud_mqtt_port = 9999\n");
    cfg = obn::config::load_if_exists(dir.string());
    CHECK(cfg.force_timelapse_external == true);
    CHECK(cfg.cloud_mqtt_port == 9999);
    return 0;
}

static int test_cloud_mqtt_port_bounds()
{
    const fs::path dir = make_temp_dir();
    write_conf(dir, "cloud_mqtt_port = 0\n");
    auto cfg = obn::config::load_or_create(dir.string());
    CHECK(cfg.cloud_mqtt_port == 8883);

    write_conf(dir, "cloud_mqtt_port = 99999\n");
    cfg = obn::config::load_or_create(dir.string());
    CHECK(cfg.cloud_mqtt_port == 8883);

    write_conf(dir, "cloud_mqtt_port = abc\n");
    cfg = obn::config::load_or_create(dir.string());
    CHECK(cfg.cloud_mqtt_port == 8883);
    return 0;
}

int main()
{
    if (test_parse_keys() != 0) return 1;
    if (test_create_template() != 0) return 1;
    if (test_env_overrides_config() != 0) return 1;
    if (test_cloud_api_override() != 0) return 1;
    if (test_cloud_regional_defaults() != 0) return 1;
    if (test_truthy() != 0) return 1;
    if (test_new_keys() != 0) return 1;
    if (test_new_keys_defaults() != 0) return 1;
    if (test_load_if_exists() != 0) return 1;
    if (test_cloud_mqtt_port_bounds() != 0) return 1;
    std::cout << "config_test: ok\n";
    return 0;
}
