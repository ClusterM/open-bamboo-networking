// Classifies, signs, and wraps outbound MQTT payloads.
// Only {"print":{...}} messages receive an envelope; all others pass through.
// Envelope: {"header":{"cert_id":"...","payload_len":N,"sign_alg":"RSA_SHA256",
//            "sign_string":"...","sign_ver":"v1.0"},"print":{...sorted keys...}}
//
// Key material is supplied explicitly via init(); this module never reads
// environment variables or guesses filesystem locations. The caller (Agent)
// owns key discovery and decides where the PEM and cert_id come from.

#include "obn/signing.hpp"
#include "obn/json_lite.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace obn::signing {

namespace {

struct PkeyDel { void operator()(EVP_PKEY*   p) const { EVP_PKEY_free(p); } };
struct MdDel   { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };

static constexpr const char kSignAlg[] = "RSA_SHA256";
static constexpr const char kSignVer[] = "v1.0";

// Mutex-guarded signing state, populated by init(). Both the key and the
// cert_id are replaced atomically so sign_envelope()/sign_bytes() never see a
// half-initialised pair.
std::mutex                          g_mu;
std::unique_ptr<EVP_PKEY, PkeyDel>  g_pkey;
std::string                         g_cert_id;

std::unique_ptr<EVP_PKEY, PkeyDel> load_pkey(const std::string& path)
{
    if (path.empty()) return nullptr;
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return nullptr;
    EVP_PKEY* raw = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    std::fclose(f);
    return std::unique_ptr<EVP_PKEY, PkeyDel>(raw);
}

const char kB64Tbl[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const unsigned char* data, std::size_t len)
{
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (std::size_t i = 0; i < len; i += 3) {
        std::uint32_t w = static_cast<std::uint32_t>(data[i]) << 16;
        if (i + 1 < len) w |= static_cast<std::uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) w |= static_cast<std::uint32_t>(data[i + 2]);
        out.push_back(kB64Tbl[(w >> 18) & 63]);
        out.push_back(kB64Tbl[(w >> 12) & 63]);
        out.push_back(i + 1 < len ? kB64Tbl[(w >> 6) & 63] : '=');
        out.push_back(i + 2 < len ? kB64Tbl[w & 63] : '=');
    }
    return out;
}

// RSA-PKCS#1 v1.5 + SHA-256 over `data`, returned as base64.
// Throws std::runtime_error on any OpenSSL failure.
std::string rsa_sha256_sign_b64(EVP_PKEY* pkey,
                                const unsigned char* data, std::size_t len)
{
    if (!pkey) return {};
    std::unique_ptr<EVP_MD_CTX, MdDel> ctx(EVP_MD_CTX_new());
    if (!ctx) throw std::runtime_error("signing: EVP_MD_CTX_new failed");
    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey) != 1)
        throw std::runtime_error("signing: EVP_DigestSignInit failed");
    if (EVP_DigestSignUpdate(ctx.get(), data, len) != 1)
        throw std::runtime_error("signing: EVP_DigestSignUpdate failed");
    std::size_t siglen = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &siglen) != 1 || siglen == 0)
        throw std::runtime_error("signing: EVP_DigestSignFinal (size query) failed");
    std::vector<unsigned char> sig(siglen);
    if (EVP_DigestSignFinal(ctx.get(), sig.data(), &siglen) != 1)
        throw std::runtime_error("signing: EVP_DigestSignFinal failed");
    return base64_encode(sig.data(), siglen);
}

// Returns true if the payload's first JSON key is "print".
bool is_print_payload(const std::string& payload) noexcept
{
    const char* p   = payload.data();
    const char* end = p + payload.size();
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) ++p;
    if (p >= end || *p != '{') return false;
    ++p;
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) ++p;
    const char kKey[] = "\"print\"";
    if (p + 7 > end) return false;
    for (int i = 0; i < 7; ++i)
        if (p[i] != kKey[i]) return false;
    return true;
}

// Builds the to_sign string: {"print":{...sorted keys...}}
// Uses json_lite, whose Object type is std::map, so parse+dump already sorts.
std::string build_to_sign(const std::string& payload)
{
    auto root = obn::json::parse(payload);
    if (!root) return {};
    std::string print_dump;
    if (root->find("print").kind() == obn::json::Value::Kind::Object)
        print_dump = root->find("print").dump();
    if (print_dump.empty()) return {};
    return std::string("{\"print\":") + print_dump + '}';
}

// Escapes backslash and double-quote for embedding inside a JSON string
// literal whose surrounding quotes are managed by the caller.
std::string json_str_escape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\' || c == '"') out += '\\';
        out += c;
    }
    return out;
}

// Builds the complete signed envelope JSON string.
std::string build_envelope(const std::string& cert_id,
                           const std::string& to_sign,
                           const std::string& sig_b64,
                           const std::string& print_dump)
{
    std::string out;
    out.reserve(to_sign.size() + sig_b64.size() + 200);
    out += "{\"header\":{\"cert_id\":\"";
    out += json_str_escape(cert_id);
    out += "\",\"payload_len\":";
    out += std::to_string(to_sign.size());
    out += ",\"sign_alg\":\"";
    out += kSignAlg;
    out += "\",\"sign_string\":\"";
    out += json_str_escape(sig_b64);
    out += "\",\"sign_ver\":\"";
    out += kSignVer;
    out += "\"},\"print\":";
    out += print_dump;
    out += '}';
    return out;
}

} // namespace

bool init(const std::string& key_pem_path, const std::string& cert_id)
{
    auto pkey = load_pkey(key_pem_path);

    std::lock_guard<std::mutex> lk(g_mu);
    if (!pkey) {
        g_pkey.reset();
        g_cert_id.clear();
        return false;
    }
    g_pkey    = std::move(pkey);
    g_cert_id = cert_id;
    return true;
}

bool enabled()
{
    std::lock_guard<std::mutex> lk(g_mu);
    return g_pkey != nullptr;
}

std::string sign_envelope(const std::string& payload_json)
{
    if (!is_print_payload(payload_json)) return payload_json;

    const std::string to_sign = build_to_sign(payload_json);
    if (to_sign.empty()) return payload_json; // malformed; pass through

    // Extract the sorted print dump from to_sign to avoid re-parsing.
    // to_sign has the shape: {"print":<dump>}
    const std::string print_dump = to_sign.substr(9, to_sign.size() - 10);

    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_pkey) return payload_json;

    try {
        const std::string sig_b64 = rsa_sha256_sign_b64(
            g_pkey.get(),
            reinterpret_cast<const unsigned char*>(to_sign.data()),
            to_sign.size());
        return build_envelope(g_cert_id, to_sign, sig_b64, print_dump);
    } catch (const std::exception&) {
        // Never let a crypto failure crash the MQTT publish path; fall back
        // to the unsigned payload so the command still goes out.
        return payload_json;
    }
}

std::string sign_bytes(const std::string& data)
{
    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_pkey)
        throw std::runtime_error(
            "signing: no key loaded; call obn::signing::init() first");
    return rsa_sha256_sign_b64(
        g_pkey.get(),
        reinterpret_cast<const unsigned char*>(data.data()), data.size());
}

} // namespace obn::signing
