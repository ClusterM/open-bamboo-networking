#pragma once

#include <optional>
#include <string>

typedef struct ssl_ctx_st SSL_CTX;

namespace obn::config {
struct Settings;
}

namespace obn::lan_tls {

// True unless OBN_SKIP_TLS_VERIFY is 1/true/yes/y/t.
bool verify_enabled();

// In-memory registry (libbambu_networking). Each update syncs to process env
// and <config_dir>/obn.env for libBambuSource (separate dlopen).
void registry_set_config_dir(const std::string& dir);
void registry_set_ca_file(const std::string& path);
void registry_put_ip_serial(const std::string& ip, const std::string& serial);
// Snapshotted device leaf PEM (install_device_cert); trust anchor supplement.
void registry_set_peer_cert(const std::string& ip, const std::string& path);

std::string registry_ca_file();
std::optional<std::string> registry_lookup_serial(const std::string& ip);

// Load printer.cer (+ optional peer leaf), enable VERIFY_PEER + PARTIAL_CHAIN.
bool configure_lan_ssl_verify(SSL_CTX*           ctx,
                              const std::string& ca_file,
                              const std::string& peer_cert_file,
                              std::string*       err);

// Build a temp PEM file with ca_file + peer_cert (for mosquitto_tls_set).
// Returns ca_file when peer is empty or when merge/temp-file I/O fails.
std::string merged_trust_bundle_path(const std::string& ca_file,
                                     const std::string& peer_cert_file);

// Process env or <config_dir>/obn.env — IPC from libbambu_networking.
const char* resolve_lan_ca_file();

// Process env (OBN_LAN_TLS_PEER_<ip>) — IPC from libbambu_networking.
const char* resolve_lan_peer_cert(const char* ip, const char* serial);

// Mirror selected obn.conf flags for libBambuSource (separate dlopen): updates
// <config_dir>/obn.lan.tls.env when config_dir is known, plus process env.
void propagate_cross_so_env(const obn::config::Settings& cfg);

} // namespace obn::lan_tls
