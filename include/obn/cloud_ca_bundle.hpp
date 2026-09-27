#pragma once

// A standard, Mozilla-derived root CA bundle (the same one curl.se
// publishes at https://curl.se/ca/cacert.pem, vendored at
// resources/cacert.pem and compiled in by cmake/EmbedCloudCaBundle.cmake).
//
// Why this exists: on Windows, vcpkg's static OpenSSL build ships no
// default trust store, so mosquitto has nothing to validate the cloud
// MQTT broker's certificate against unless we hand it a CA file
// explicitly. *.bambulab.com serves a normal, publicly-trusted
// DigiCert-issued certificate -- it needs an ordinary root bundle, not
// anything Bambu-specific -- so we ship one instead of skipping
// verification.

#include <string>

namespace obn::tls {

// PEM text of the vendored bundle, compiled in (see resources/cacert.pem).
extern const char* const kCloudCaBundlePem;

// Writes kCloudCaBundlePem to <config_dir>/obn_cloud_ca.pem (creating it, or
// overwriting it if the vendored bundle was updated by a newer build) and
// returns that path. Returns an empty string if config_dir is empty or the
// file could not be written, in which case the caller should fall back to
// whatever default trust source the platform provides.
std::string ensure_cloud_ca_bundle_file(const std::string& config_dir);

} // namespace obn::tls
