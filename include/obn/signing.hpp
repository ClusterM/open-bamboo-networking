#pragma once

#include <string>

namespace obn::signing {

// Loads the RSA private key from key_pem_path and stores cert_id for use in
// signed envelopes. Thread-safe; may be called again to replace the key
// material (e.g. when the config directory changes). On failure the previous
// state is cleared so enabled() returns false.
//
// key_pem_path: path to an RSA private key in PEM format.
// cert_id:      the slicer's registered certificate ID string (not secret).
//
// Returns true if the key was loaded successfully.
bool init(const std::string& key_pem_path, const std::string& cert_id);

// True when init() succeeded and signing is active.
bool enabled();

// Returns a signed envelope JSON for {"print":{...}} payloads.
// All other message types pass through unchanged. When signing is not
// enabled, or on any crypto error, the original payload is returned as-is.
std::string sign_envelope(const std::string& payload_json);

// Signs raw bytes with the slicer key.
// Returns the base64-encoded RSA-PKCS#1 v1.5 + SHA-256 signature.
// Used to compute x-bbl-device-security-sign for REST requests.
// Throws std::runtime_error if no key is loaded; call enabled() first.
std::string sign_bytes(const std::string& data);

} // namespace obn::signing
