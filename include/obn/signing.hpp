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

// Standard base64 encoding (RFC 4648, with padding).
std::string base64_encode(const unsigned char* data, std::size_t len);

// Returns the cert_id string used in envelope headers and REST auth headers.
// Priority: BBL_SLICER_CERT_ID env > slicer_cert_id.txt alongside the key file.
// Returns empty string if neither is configured.
const std::string& slicer_cert_id();

} // namespace obn::signing
