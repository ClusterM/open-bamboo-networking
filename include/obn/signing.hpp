#pragma once

#include <string>

// Forward-declaration matching <openssl/evp.h>; avoids pulling OpenSSL headers
// into every translation unit that includes this header.
typedef struct evp_pkey_st EVP_PKEY;

namespace obn::signing {

// Returns a signed envelope JSON for {"print":{...}} payloads.
// All other message types pass through unchanged.
//
// When `device_pub` is non-null, device-cert field encryption is applied to
// the `print` object *before* signing (so the signature covers the encrypted
// form that goes on the wire). Cleartext fields `url` and `param` are each
// REPLACED by `url_enc` / `param_enc` when present (stock sends only the
// encrypted field on the wire). Transforms are idempotent (skipped when the
// `_enc` field already exists) and no-ops when `device_pub` is null or
// encryption fails, in which case the cleartext field is kept (pure-LAN
// ftp:// path without a device key).
std::string maybe_sign(const std::string& payload_json,
                       EVP_PKEY* device_pub = nullptr);

// Blockwise RSA-PKCS#1 v1.5 encryption of `plaintext` under `pub`, returned as
// base64. The plaintext is split into <=245-byte chunks (the RSA-2048 PKCS#1
// v1.5 ceiling = keylen - 11), each chunk encrypts to one key-sized block, and
// the blocks are concatenated before base64. A short value yields a single
// 256-byte block; longer values (e.g. multi-line G-code) span several. Returns
// "" on failure, writing a reason to `err` when non-null. This is the
// `EncryptField` primitive shared by `url_enc` / `param_enc`.
std::string rsa_pkcs1v15_encrypt_b64(EVP_PKEY* pub, const std::string& plaintext,
                                     std::string* err = nullptr);

// Signs raw bytes with the slicer key.
// Returns the base64-encoded RSA-PKCS#1 v1.5 + SHA-256 signature.
std::string sign_bytes(const std::string& data);

// Computes the x-bbl-device-security-sign header value for cloud REST
// requests: a raw RSA PKCS#1 v1.5 signature (no hash) over the current Unix
// time in milliseconds, base64-encoded. Matches the proprietary plugin, which
// signs a fresh timestamp (not the request body) for replay protection.
// Returns "" when no slicer key is configured (the caller should omit the
// header rather than fail — it is only enforced on signed writes).
std::string device_security_sign();

// Standard base64 encoding (RFC 4648, with padding).
std::string base64_encode(const unsigned char* data, std::size_t len);

// Returns the cert_id string used in the MQTT envelope header.
// Priority: obn.conf slicer_cert_id > config_dir/slicer_cert_id.txt.
// Serialization is `serial + issuer` (no separator), matching the wire
// `header.cert_id`. Returns empty string if neither is configured.
const std::string& slicer_cert_id();

// Returns the value for the HTTP `x-bbl-app-certification-id` header used on
// secured-printer REST writes (e.g. POST /my/task). This is a DIFFERENT
// serialization from slicer_cert_id(): `issuer + ":" + serial.lower()`
// (per reverse-networking `6. HTTP.md`). Derived from the same stored
// cert_id by splitting the leading serial from the trailing issuer DN.
// Returns "" when the cert_id is unset or cannot be parsed.
const std::string& app_certification_id();

// PEM chain of the slicer (app) certificate matching slicer_key.pem, read
// from config_dir/slicer_cert.pem. Sent to the printer in the
// security.app_cert_install MQTT command. "" when the file is absent.
std::string slicer_cert_pem();

// PEM CRL entry accompanying the app certificate, read from
// config_dir/slicer_crl.pem. "" when the file is absent.
std::string slicer_crl_pem();

// True when slicer_key.pem + slicer_cert.pem are present (config paths or
// config_dir defaults) and the leaf certificate is currently within its
// notBefore/notAfter window. Gates fire-and-forget app_cert_install.
bool slicer_app_cert_usable();

} // namespace obn::signing
