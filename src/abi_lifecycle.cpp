#include <string>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/config.hpp"
#include "obn/log.hpp"

using obn::Agent;
using obn::as_agent;

// Studio sometimes accesses these as extern globals; define them here so the
// linker is happy if the headers are included via InitFTModule in-process.
std::string g_log_folder;
std::string g_log_start_time;

OBN_ABI void* bambu_network_create_agent(std::string log_dir)
{
    const auto cfg = obn::config::load_or_create(log_dir);
    obn::log::apply_config(cfg);
    // Optional file sink: OBN_LOG_TO_FILE=1 or log_to_file=1 in obn.conf
    // appends to <log_dir>/obn.log (same folder as Studio's logs).
    // Must run before the first OBN_* line.
    obn::log::configure_from_log_dir(log_dir);

    // MSVC's preprocessor (in /Zc:preprocessor-disabled mode, which is the
    // default for v142) refuses #ifdef directives inside macro arguments,
    // so resolve the version string before invoking OBN_INFO.
#ifdef OBN_VERSION_STRING
    constexpr const char* k_plugin_version = OBN_VERSION_STRING;
#else
    constexpr const char* k_plugin_version = "unknown";
#endif
    OBN_INFO("create_agent log_dir=%s  plugin_version=%s",
             log_dir.c_str(), k_plugin_version);
    try {
        return new Agent(std::move(log_dir));
    } catch (const std::exception& e) {
        OBN_ERROR("create_agent failed: %s", e.what());
        return nullptr;
    } catch (...) {
        OBN_ERROR("create_agent failed: unknown exception");
        return nullptr;
    }
}

OBN_ABI int bambu_network_destroy_agent(void* agent)
{
    OBN_INFO("destroy_agent %p", agent);
    delete as_agent(agent);
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_init_log(void* /*agent*/)
{
    OBN_DEBUG("init_log");
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_set_config_dir(void* agent, std::string config_dir)
{
    OBN_DEBUG("set_config_dir %s", config_dir.c_str());
    if (auto* a = as_agent(agent)) {
        a->set_config_dir(std::move(config_dir));
        return BAMBU_NETWORK_SUCCESS;
    }
    return BAMBU_NETWORK_ERR_INVALID_HANDLE;
}

OBN_ABI int bambu_network_set_cert_file(void* agent, std::string folder, std::string filename)
{
    OBN_DEBUG("set_cert_file folder=%s filename=%s", folder.c_str(), filename.c_str());
    if (auto* a = as_agent(agent)) {
        a->set_cert_file(std::move(folder), std::move(filename));
        return BAMBU_NETWORK_SUCCESS;
    }
    return BAMBU_NETWORK_ERR_INVALID_HANDLE;
}

OBN_ABI int bambu_network_set_country_code(void* agent, std::string country_code)
{
    OBN_DEBUG("set_country_code %s", country_code.c_str());
    if (auto* a = as_agent(agent)) {
        a->set_country_code(std::move(country_code));
        return BAMBU_NETWORK_SUCCESS;
    }
    return BAMBU_NETWORK_ERR_INVALID_HANDLE;
}

OBN_ABI int bambu_network_start(void* agent)
{
    OBN_INFO("start");
    // Studio's login flow only calls connect_server() after the privacy
    // policy check + EVT_USER_LOGIN_HANDLE round-trip finishes (see
    // GUI_App::on_user_login_handle). If the policy endpoint returns
    // empty resources for a cached sign-in, that cascade can silently
    // stall and we end up never kicking off cloud MQTT. Fire it off
    // here ourselves - start() is the very last call in the plugin
    // handshake, so all callbacks are already registered.
    if (auto* a = as_agent(agent); a && a->user_logged_in()) {
        OBN_INFO("start: user already logged in, auto-connecting cloud");
        a->connect_cloud();
    }
    return BAMBU_NETWORK_SUCCESS;
}
