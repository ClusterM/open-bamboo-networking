#pragma once
#include <cstdint>
#include <string>
#include <vector>

// ===========================================================================
// JSON envelope parsing + crypto helpers
// ===========================================================================
struct Envelope {
    std::string to_sign;
    std::string sig_b64;
    std::string cmd;  // optional, for error reporting
};

namespace mini_json {
void skip_ws(const std::string& s, size_t& i);
bool parse_string(const std::string& s, size_t& i, std::string& out);
bool skip_value(const std::string& s, size_t& i);
bool parse_envelope(const std::string& s, size_t& i, Envelope& env);
bool parse_envelopes(const std::string& s, std::vector<Envelope>& out);
}  // namespace mini_json

bool base64_decode(const std::string& in, std::vector<uint8_t>& out);
void pkcs1_v15_pad_sha256(const uint8_t hash[32], uint8_t out[256]);
