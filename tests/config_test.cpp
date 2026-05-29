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
               "cloud_api_host = https://api-dev.bambulab.net\n"
               "unknown_key = ignored\n");
    const auto cfg = obn::config::load_or_create(dir.string());
    CHECK(cfg.log_level == "debug");
    CHECK(cfg.cloud_api_host == "https://api-dev.bambulab.net");
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
    write_conf(dir, "cloud_api_host = https://api-qa.bambulab.net\n");
    (void)obn::config::load_or_create(dir.string());
    CHECK(obn::config::current().cloud_api_host == "https://api-qa.bambulab.net");
    return 0;
}

int main()
{
    if (test_parse_keys() != 0) return 1;
    if (test_create_template() != 0) return 1;
    if (test_env_overrides_config() != 0) return 1;
    if (test_cloud_api_override() != 0) return 1;
    std::cout << "config_test: ok\n";
    return 0;
}
