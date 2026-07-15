#pragma once

#include <string>

// Forward-declaration matching <openssl/evp.h>; avoids pulling OpenSSL
// headers into every translation unit that includes this header.
typedef struct evp_pkey_st EVP_PKEY;

// Utility helpers for capturing and storing printer TLS certificates, used by
// Agent::install_device_cert() to mirror the behaviour of Bambu's own plugin
// which stashes each printer's self-signed server certificate in the user's
// Studio config dir.
namespace obn::cert_store {

// Builds "<config_dir>/certs/<dev_id>.pem". Does not touch the filesystem.
std::string device_cert_path(const std::string& config_dir, const std::string& dev_id);

// Ensures the parent directory of `file_path` exists (mkdir -p semantics).
// Returns true on success or if the directory already exists.
bool ensure_parent_dir(const std::string& file_path);

// Opens a short-lived TLS connection to `host:port`, captures the peer
// certificate leaf and writes it as PEM to `out_pem_path`. No chain
// verification is performed (TOFU bootstrap snapshot only).
// `tls_sni` is sent as SNI when non-empty (use dev_id/serial); otherwise `host`.
// On success also populates the in-memory pubkey cache via set_printer_pub_key.
bool capture_peer_cert_pem(const std::string& host,
                           int                port,
                           int                timeout_ms,
                           const std::string& out_pem_path,
                           const std::string& tls_sni = {});

// ---------------------------------------------------------------------------
// Thread-safe per-device RSA public-key cache.
//
// The authoritative source for a printer's public key is its device
// certificate, which the proprietary plugin obtains over MQTT via the
// `app_cert_install` command (command "app_cert" on the `security` topic) and
// stores per dev_id. Install that cert with set_printer_pub_key_from_cert_pem.
// This works for cloud and proxy (e.g. bambuddy) connections where the TLS
// endpoint is not the printer.
//
// As a fallback for LAN-direct connections (where the TLS peer *is* the
// printer), capture_peer_cert_pem also seeds this cache from the TLS leaf via
// set_printer_pub_key. That TOFU snapshot is NOT valid for cloud/proxy paths.
//
// Keys are kept in process memory so concurrent multi-printer publish paths
// can encrypt without a disk read or extra TLS handshake.
//
// Ownership: `get_printer_pub_key` returns a ref-bumped EVP_PKEY*; the
// caller is responsible for calling EVP_PKEY_free() when done.
// `set_printer_pub_key` refuses null and takes its own internal ref, so the
// caller may free its ref immediately after the call.
// `forget_printer` releases the cached ref and removes the entry — call on
// printer disconnect or session teardown.
// ---------------------------------------------------------------------------

// Returns the cached public key for dev_id (ref-bumped, caller must free),
// or nullptr when absent.
EVP_PKEY* get_printer_pub_key(const std::string& dev_id);

// Stores the printer's public key under dev_id. Refuses null pkey. Idempotent
// on re-capture (existing entry is kept; the printer key is stable).
void      set_printer_pub_key(const std::string& dev_id, EVP_PKEY* pkey);

// Installs the printer's public key from its device-certificate PEM (as
// obtained over MQTT via app_cert_install). This is the authoritative source
// and works for cloud/proxy connections. Replaces any existing entry for
// dev_id (e.g. a TLS-leaf TOFU fallback). Returns false on empty input or a
// PEM/cert parse failure.
bool      set_printer_pub_key_from_cert_pem(const std::string& dev_id,
                                            const std::string& cert_pem);

// Seeds the cache for dev_id from an on-disk device-certificate PEM file
// (e.g. the TLS-leaf snapshot at <config_dir>/certs/<dev_id>.pem), but only
// when no key is cached yet — an existing (authoritative app_cert_install)
// entry is left untouched. Use at LAN connect time so the field-encryption
// path has a key even when the cert was captured in a previous session and
// capture_peer_cert_pem is skipped. Returns true if a key is present for
// dev_id afterwards (already cached or freshly loaded); false on read/parse
// failure with an empty cache.
bool      prime_pub_key_from_cert_file(const std::string& dev_id,
                                       const std::string& pem_path);

// Removes and releases the cached key for dev_id. No-op if absent.
void      forget_printer(const std::string& dev_id);

} // namespace obn::cert_store
