// Tests for src/signing.cpp — classifier, envelope structure, H2D inversion,
// and signature verification using a freshly generated RSA test keypair.

#include "obn/signing.hpp"
#include "obn/config.hpp"
#include "obn/json_lite.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

#define CHECK(cond) do {                                                    \
    if (!(cond)) {                                                          \
        std::cerr << "FAIL " << __FILE__ << ":" << __LINE__                \
                  << ": " #cond "\n";                                       \
        return 1;                                                           \
    }                                                                       \
} while (0)

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
    CHECK(obn::signing::maybe_sign(sys)  == sys);
    CHECK(obn::signing::maybe_sign(info) == info);
    return 0;
}

static int test_print_payload_gets_header()
{
    const std::string payload = R"({"print":{"command":"pause","sequence_id":"1"}})";
    const std::string env     = obn::signing::maybe_sign(payload);
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
    const std::string env     = obn::signing::maybe_sign(payload);
    CHECK(envelope_field(env, "cert_id") == "testcertid123CN=test.example.com");
    return 0;
}

static int test_sign_alg_and_ver()
{
    const std::string payload = R"({"print":{"command":"stop","sequence_id":"3"}})";
    const std::string env     = obn::signing::maybe_sign(payload);
    CHECK(envelope_field(env, "sign_alg") == "RSA_SHA256");
    CHECK(envelope_field(env, "sign_ver") == "v1.0");
    return 0;
}

static int test_payload_len_matches_to_sign()
{
    // payload_len must equal the byte length of {"print":{...sorted...}}.
    const std::string payload = R"({"print":{"z_key":"last","a_key":"first","sequence_id":"4"}})";
    const std::string env     = obn::signing::maybe_sign(payload);
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
    const std::string env     = obn::signing::maybe_sign(payload);
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
    const std::string env     = obn::signing::maybe_sign(payload);
    auto val = obn::json::parse(env);
    CHECK(val);

    // Re-dump the print block and check key ordering in the string.
    std::string dumped = val->find("print").dump();
    CHECK(dumped.find("\"a_first\"") < dumped.find("\"m_mid\""));
    CHECK(dumped.find("\"m_mid\"")   < dumped.find("\"sequence_id\""));
    CHECK(dumped.find("\"sequence_id\"") < dumped.find("\"z_last\""));
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

static int test_device_security_sign_is_raw_timestamp()
{
    // device_security_sign() must reproduce the proprietary plugin's scheme: a
    // RAW RSA PKCS#1 v1.5 signature over the current epoch-ms decimal string
    // (no SHA-256, no DigestInfo). Recovering it must yield exactly that
    // string — matching the real observed POST /my/task signature, which
    // recovered to the bare ms timestamp "1782788656000".
    const std::string sig_b64 = obn::signing::device_security_sign();
    CHECK(sig_b64.size() == 344);  // RSA-2048 -> 256 bytes -> 344 base64 chars

    std::vector<unsigned char> sig;
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    for (std::size_t i = 0; i + 4 <= sig_b64.size(); i += 4) {
        int v0 = val(sig_b64[i]),   v1 = val(sig_b64[i+1]);
        int v2 = val(sig_b64[i+2]), v3 = val(sig_b64[i+3]);
        if (v0 < 0 || v1 < 0) break;
        sig.push_back(static_cast<unsigned char>((v0 << 2) | (v1 >> 4)));
        if (v2 >= 0) sig.push_back(static_cast<unsigned char>((v1 << 4) | (v2 >> 2)));
        if (v3 >= 0) sig.push_back(static_cast<unsigned char>((v2 << 6) | v3));
    }
    CHECK(sig.size() == 256);

    // Raw PKCS#1 recover (no digest) with the test key's public component.
    struct CtxDel { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
    std::unique_ptr<EVP_PKEY_CTX, CtxDel> ctx(EVP_PKEY_CTX_new(g_test_key, nullptr));
    CHECK(ctx != nullptr);
    CHECK(EVP_PKEY_verify_recover_init(ctx.get()) == 1);
    CHECK(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) == 1);
    std::size_t rlen = 0;
    CHECK(EVP_PKEY_verify_recover(ctx.get(), nullptr, &rlen, sig.data(), sig.size()) == 1);
    std::vector<unsigned char> rec(rlen);
    CHECK(EVP_PKEY_verify_recover(ctx.get(), rec.data(), &rlen, sig.data(), sig.size()) == 1);
    rec.resize(rlen);
    const std::string msg(rec.begin(), rec.end());

    // The recovered message is the bare ms-timestamp string (same shape as the
    // real example), NOT a SHA-256 DigestInfo block.
    CHECK(msg.size() >= 12 && msg.size() <= 14);
    for (char c : msg) CHECK(c >= '0' && c <= '9');
    CHECK(std::stoll(msg) > 1700000000000LL);  // plausible recent epoch-ms
    return 0;
}

static int test_h2d_detection_noop_on_non_h2d()
{
    // A P2S printer should not have its payload altered.
    const std::string payload =
        R"({"print":{"command":"project_file","sequence_id":"7",)"
        R"("ams_mapping_info":[{"nozzleId":0},{"nozzleId":1}]}})";
    const std::string env_non_h2d = obn::signing::maybe_sign(payload, "3DPrinter-P2S");
    const std::string env_no_model = obn::signing::maybe_sign(payload);

    // Both should produce identical envelopes (no flip applied).
    CHECK(env_non_h2d == env_no_model);
    return 0;
}

static int test_h2d_nozzle_ids_flipped()
{
    // For an H2D printer, nozzleId 0 becomes 1 and vice versa before signing.
    const std::string payload =
        R"({"print":{"command":"project_file","sequence_id":"8",)"
        R"("ams_mapping_info":[{"nozzleId":0},{"nozzleId":1},{"nozzleId":0}]}})";

    const std::string env_h2d     = obn::signing::maybe_sign(payload, "3DPrinter-H2D");
    const std::string env_no_flip = obn::signing::maybe_sign(payload);

    // Envelopes must differ because the signed content differs.
    CHECK(env_h2d != env_no_flip);

    // The H2D envelope's print block should contain the flipped ids.
    auto val = obn::json::parse(env_h2d);
    CHECK(val);
    const auto& arr = val->find("print.ams_mapping_info").as_array();
    CHECK(arr.size() == 3);
    CHECK(static_cast<int>(arr[0].find("nozzleId").as_number()) == 1);
    CHECK(static_cast<int>(arr[1].find("nozzleId").as_number()) == 0);
    CHECK(static_cast<int>(arr[2].find("nozzleId").as_number()) == 1);
    return 0;
}

static int test_h2d_model_variants()
{
    // All three H2D model codes must trigger the inversion.
    const std::string payload =
        R"({"print":{"command":"project_file","sequence_id":"9",)"
        R"("ams_mapping_info":[{"nozzleId":0}]}})";
    const std::string baseline = obn::signing::maybe_sign(payload);

    for (const std::string& model : {"H2D", "O1D", "C16",
                                      "3DPrinter-H2D-xxx",
                                      "3DPrinter-O1D-xxx",
                                      "printer-c16-v2"}) {
        CHECK(obn::signing::maybe_sign(payload, model) != baseline);
    }
    return 0;
}

static int test_h2d_signature_verifies()
{
    // The H2D envelope's signature must verify against its (flipped) content.
    const std::string payload =
        R"({"print":{"command":"project_file","sequence_id":"10",)"
        R"("ams_mapping_info":[{"nozzleId":0},{"nozzleId":1}]}})";
    const std::string env = obn::signing::maybe_sign(payload, "H2D");
    auto val = obn::json::parse(env);
    CHECK(val);

    const std::string sig_b64  = val->find("header.sign_string").as_string();
    std::string print_dump     = val->find("print").dump();
    std::string to_sign        = "{\"print\":" + print_dump + "}";

    CHECK(verify_b64_sig(to_sign, sig_b64));
    return 0;
}

namespace obn::config {
    Settings& test_settings();
    std::string& test_dir();
}

int main()
{
    // Generate fresh RSA-2048 keypair for signing tests.
    g_test_key = EVP_RSA_gen(2048);
    if (!g_test_key) { std::cerr << "EVP_RSA_gen failed\n"; return 1; }

    // Write private key to a temp PEM file and point the config at it.
    char tmp_path[] = "/tmp/signing_test_XXXXXX";
    int fd = mkstemp(tmp_path);
    if (fd < 0) { std::cerr << "mkstemp failed\n"; EVP_PKEY_free(g_test_key); return 1; }
    close(fd);
    std::string pem_path = std::string(tmp_path) + ".pem";

    int pem_fd = open(pem_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    FILE* f = (pem_fd >= 0) ? fdopen(pem_fd, "w") : nullptr;
    if (!f) { perror("open pem"); EVP_PKEY_free(g_test_key); return 1; }
    PEM_write_PrivateKey(f, g_test_key, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);
    unlink(tmp_path);

    obn::config::test_settings().slicer_key_pem = pem_path;
    obn::config::test_settings().slicer_cert_id = "testcertid123CN=test.example.com";

    int rc = 0;
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
    if (test_device_security_sign_is_raw_timestamp() != 0) rc = 1;
    if (test_h2d_detection_noop_on_non_h2d() != 0) rc = 1;
    if (test_h2d_nozzle_ids_flipped()     != 0) rc = 1;
    if (test_h2d_model_variants()          != 0) rc = 1;
    if (test_h2d_signature_verifies()      != 0) rc = 1;

    if (rc == 0) std::cout << "signing_test: ok\n";

    // Cleanup.
    unlink(pem_path.c_str());
    EVP_PKEY_free(g_test_key);
    return rc;
}
