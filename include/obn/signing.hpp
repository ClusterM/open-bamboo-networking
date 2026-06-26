#pragma once

#include <string>

namespace obn::signing {

// Returns a signed envelope JSON for {"print":{...}} payloads.
// All other message types pass through unchanged.
// If printer_model is provided and identifies an H2D, nozzleId values in
// ams_mapping_info are flipped 0↔1 before signing.
std::string maybe_sign(const std::string& payload_json,
                       const std::string& printer_model = {});

// Signs raw bytes with the slicer key.
// Returns the base64-encoded RSA-PKCS#1 v1.5 + SHA-256 signature.
// Used to compute x-bbl-device-security-sign for REST requests.
std::string sign_bytes(const std::string& data);

} // namespace obn::signing
