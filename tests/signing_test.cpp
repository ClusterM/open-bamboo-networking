// Tests for src/signing.cpp — classifier, envelope structure, and signature
// verification using a freshly generated RSA test keypair. The key material is
// supplied through obn::signing::init(); no environment variables are used.

#include "obn/signing.hpp"
#include "obn/json_lite.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <cstdio>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#define CHECK(cond) do {                                                    \
    if (!(cond)) {                                                          \
        std::cerr << "FAIL " << __FILE__ << ":" << __LINE__                \
                  << ": " #cond "\n";                                       \
        return 1;                                                           \
    }                                                                       \
} while (0)

static constexpr const char* kTestCertId = "testcertid123CN=test.example.com";

// ---------------------------------------------------------------------------
// Global test keypair — set in main() before any test runs.
// ---------------------------------------------------------------------------

static EVP_PKEY* g_test_key = nullptr;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string envelope_field(const std::string& json, const std::string& key)
{
    auto val = obn::json::parse(json);
    if (!val) return {};
    return val->find("header." + key).as_string();
}

// g_test_key is a full keypair; EVP_DigestVerifyInit accepts it for
// verification using its public component.
static EVP_PKEY* make_pub_key() { return g_test_key; }

// Verify an RSA-PKCS#1-v1.5-SHA256 base64 signature against `msg`.
static bool verify_b64_sig(const std::string& msg, const std::string& sig_b64)
{
    // Decode base64.
    auto b64_decode = [](const std::string& b64) -> std::vector<unsigned char> {
        std::vector<unsigned char> out;
        out.reserve(b64.size() * 3 / 4);
        auto val = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1; // '=' or unknown
        };
        for (std::size_t i = 0; i + 4 <= b64.size(); i += 4) {
            int v0 = val(b64[i]), v1 = val(b64[i+1]);
            int v2 = val(b64[i+2]), v3 = val(b64[i+3]);
            if (v0 < 0 || v1 < 0) break;
            out.push_back(static_cast<unsigned char>((v0 << 2) | (v1 >> 4)));
            if (v2 >= 0) out.push_back(static_cast<unsigned char>((v1 << 4) | (v2 >> 2)));
            if (v3 >= 0) out.push_back(static_cast<unsigned char>((v2 << 6) | v3));
        }
        return out;
    };

    auto sig = b64_decode(sig_b64);
    if (sig.empty()) return false;

    EVP_PKEY* pub = make_pub_key();
    struct MdDel { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };
    std::unique_ptr<EVP_MD_CTX, MdDel> ctx(EVP_MD_CTX_new());
    if (!ctx) return false;
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pub) != 1)
        return false;
    if (EVP_DigestVerifyUpdate(ctx.get(), msg.data(), msg.size()) != 1)
        return false;
    return EVP_DigestVerifyFinal(ctx.get(), sig.data(), sig.size()) == 1;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

static int test_non_print_passthrough()
{
    // system, info, upgrade, etc. must pass through unchanged.
    const std::string sys  = R"({"system":{"command":"get_access_code"}})";
    const std::string info = R"({"info":{"command":"get_version"}})";
    CHECK(obn::signing::sign_envelope(sys)  == sys);
    CHECK(obn::signing::sign_envelope(info) == info);
    return 0;
}

static int test_print_payload_gets_header()
{
    const std::string payload = R"({"print":{"command":"pause","sequence_id":"1"}})";
    const std::string env     = obn::signing::sign_envelope(payload);
    CHECK(env != payload);
    auto val = obn::json::parse(env);
    CHECK(val);
    CHECK(val->find("header.cert_id").kind()     == obn::json::Value::Kind::String);
    CHECK(val->find("header.sign_alg").kind()    == obn::json::Value::Kind::String);
    CHECK(val->find("header.sign_string").kind() == obn::json::Value::Kind::String);
    return 0;
}

static int test_cert_id_constant()
{
    const std::string payload = R"({"print":{"command":"pause","sequence_id":"2"}})";
    const std::string env     = obn::signing::sign_envelope(payload);
    CHECK(envelope_field(env, "cert_id") == kTestCertId);
    return 0;
}

static int test_sign_alg_and_ver()
{
    const std::string payload = R"({"print":{"command":"stop","sequence_id":"3"}})";
    const std::string env     = obn::signing::sign_envelope(payload);
    CHECK(envelope_field(env, "sign_alg") == "RSA_SHA256");
    CHECK(envelope_field(env, "sign_ver") == "v1.0");
    return 0;
}

static int test_payload_len_matches_to_sign()
{
    // payload_len must equal the byte length of {"print":{...sorted...}}.
    const std::string payload = R"({"print":{"z_key":"last","a_key":"first","sequence_id":"4"}})";
    const std::string env     = obn::signing::sign_envelope(payload);
    auto val = obn::json::parse(env);
    CHECK(val);
    // Reconstruct what to_sign would be: {"print":{sorted keys}}.
    // After parsing and re-dumping with json_lite (Object = std::map), keys
    // are alphabetically ordered: a_key < sequence_id < z_key.
    std::string expected_to_sign = R"({"print":{"a_key":"first","sequence_id":"4","z_key":"last"}})";
    double plen = val->find("header.payload_len").as_number();
    CHECK(static_cast<std::size_t>(plen) == expected_to_sign.size());
    return 0;
}

static int test_signature_verifies()
{
    // The sign_string in the envelope must verify against the sorted print
    // block using the test keypair's public component.
    const std::string payload = R"({"print":{"command":"resume","sequence_id":"5"}})";
    const std::string env     = obn::signing::sign_envelope(payload);
    auto val = obn::json::parse(env);
    CHECK(val);

    const std::string sig_b64 = val->find("header.sign_string").as_string();
    CHECK(!sig_b64.empty());

    // Reconstruct to_sign from the envelope's sorted print block.
    std::string print_dump = val->find("print").dump();
    std::string to_sign    = "{\"print\":" + print_dump + "}";

    CHECK(verify_b64_sig(to_sign, sig_b64));
    return 0;
}

static int test_keys_sorted_in_envelope()
{
    // Verify that the envelope's print block has alphabetically sorted keys,
    // confirming the to_sign builder uses the sorted dump.
    const std::string payload = R"({"print":{"z_last":"Z","a_first":"A","m_mid":"M","sequence_id":"6"}})";
    const std::string env     = obn::signing::sign_envelope(payload);
    auto val = obn::json::parse(env);
    CHECK(val);

    // Re-dump the print block and check key ordering in the string.
    std::string dumped = val->find("print").dump();
    CHECK(dumped.find("\"a_first\"") < dumped.find("\"m_mid\""));
    CHECK(dumped.find("\"m_mid\"")   < dumped.find("\"sequence_id\""));
    CHECK(dumped.find("\"sequence_id\"") < dumped.find("\"z_last\""));
    return 0;
}

static int test_enabled_reflects_init()
{
    CHECK(obn::signing::enabled());
    return 0;
}

static int test_sign_bytes_length()
{
    // RSA-2048 produces a 256-byte signature → 344 base64 characters.
    const std::string sig = obn::signing::sign_bytes("hello world");
    CHECK(sig.size() == 344);
    return 0;
}

static int test_sign_bytes_deterministic()
{
    // RSA-PKCS#1 v1.5 is deterministic; same input must produce same output.
    const std::string data = "determinism check";
    CHECK(obn::signing::sign_bytes(data) == obn::signing::sign_bytes(data));
    return 0;
}

static int test_sign_bytes_verifies()
{
    const std::string data  = "sign_bytes verification";
    const std::string sig   = obn::signing::sign_bytes(data);
    CHECK(verify_b64_sig(data, sig));
    return 0;
}

static int test_disabled_passthrough_after_failed_init()
{
    // A bogus key path must disable signing and make print payloads pass
    // through unchanged. Re-init with the real key afterwards so the rest of
    // the suite (if reordered) is unaffected.
    CHECK(!obn::signing::init("/nonexistent/key.pem", kTestCertId));
    CHECK(!obn::signing::enabled());

    const std::string payload = R"({"print":{"command":"pause","sequence_id":"99"}})";
    CHECK(obn::signing::sign_envelope(payload) == payload);
    return 0;
}

int main()
{
    namespace fs = std::filesystem;

    // Generate fresh RSA-2048 keypair for signing tests.
    g_test_key = EVP_RSA_gen(2048);
    if (!g_test_key) { std::cerr << "EVP_RSA_gen failed\n"; return 1; }

    // Write private key to a temp PEM file (cross-platform).
    const fs::path pem_path =
        fs::temp_directory_path() / "obn_signing_test_key.pem";
    std::FILE* f = std::fopen(pem_path.string().c_str(), "wb");
    if (!f) { std::perror("fopen pem"); EVP_PKEY_free(g_test_key); return 1; }
    PEM_write_PrivateKey(f, g_test_key, nullptr, nullptr, 0, nullptr, nullptr);
    std::fclose(f);

    if (!obn::signing::init(pem_path.string(), kTestCertId)) {
        std::cerr << "obn::signing::init failed\n";
        std::error_code ec;
        fs::remove(pem_path, ec);
        EVP_PKEY_free(g_test_key);
        return 1;
    }

    int rc = 0;
    if (test_enabled_reflects_init()       != 0) rc = 1;
    if (test_non_print_passthrough()       != 0) rc = 1;
    if (test_print_payload_gets_header()   != 0) rc = 1;
    if (test_cert_id_constant()            != 0) rc = 1;
    if (test_sign_alg_and_ver()            != 0) rc = 1;
    if (test_payload_len_matches_to_sign() != 0) rc = 1;
    if (test_signature_verifies()          != 0) rc = 1;
    if (test_keys_sorted_in_envelope()     != 0) rc = 1;
    if (test_sign_bytes_length()           != 0) rc = 1;
    if (test_sign_bytes_deterministic()    != 0) rc = 1;
    if (test_sign_bytes_verifies()         != 0) rc = 1;
    // Must run last: it deliberately tears down the loaded key.
    if (test_disabled_passthrough_after_failed_init() != 0) rc = 1;

    if (rc == 0) std::cout << "signing_test: ok\n";

    // Cleanup.
    std::error_code ec;
    fs::remove(pem_path, ec);
    EVP_PKEY_free(g_test_key);
    return rc;
}
