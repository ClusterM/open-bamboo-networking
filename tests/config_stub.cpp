// Minimal stubs for obn::config — returns mutable Settings so that
// signing_test can inject key/cert paths without the full config chain.

#include "obn/config.hpp"

namespace obn::config {

static Settings  g_test_settings;
static std::string g_test_dir;

Settings& test_settings() { return g_test_settings; }
std::string& test_dir()   { return g_test_dir; }

const Settings& current() { return g_test_settings; }
const std::string& dir()  { return g_test_dir; }

} // namespace obn::config
