// Classifies, signs, and wraps outbound MQTT payloads.
// Only {"print":{...}} messages receive an envelope; all others pass through.
// Envelope: {"header":{"cert_id":"...","payload_len":N,"sign_alg":"RSA_SHA256",
//            "sign_string":"...","sign_ver":"v1.0"},"print":{...sorted keys...}}

#include "obn/signing.hpp"
#include "obn/config.hpp"
#include "obn/json_lite.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace obn::signing {

namespace {

struct PkeyDel { void operator()(EVP_PKEY*     p) const { EVP_PKEY_free(p); } };
struct MdDel   { void operator()(EVP_MD_CTX*   p) const { EVP_MD_CTX_free(p); } };
struct CtxDel  { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };

static constexpr const char kSignAlg[] = "RSA_SHA256";
static constexpr const char kSignVer[] = "v1.0";

// Resolve the key file path: obn.conf slicer_key_pem, or
// config_dir/slicer_key.pem when empty.
static std::string resolve_key_path()
{
    const auto& cfg = obn::config::current().slicer_key_pem;
    if (!cfg.empty()) return cfg;
    const auto& dir = obn::config::dir();
    if (dir.empty()) return {};
    return dir + "/slicer_key.pem";
}

// Read cert_id from slicer_cert_id.txt in config_dir.
static std::string load_cert_id_from_file()
{
    const auto& dir = obn::config::dir();
    if (dir.empty()) return {};
    std::string path = dir + "/slicer_cert_id.txt";
    std::FILE* f = std::fopen(path.c_str(), "r");
    if (!f) return {};
    char buf[256] = {};
    if (!std::fgets(buf, sizeof(buf), f)) buf[0] = '\0';
    std::fclose(f);
    std::string s(buf);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
        s.pop_back();
    return s;
}

} // namespace

// cert_id identifies the slicer's registered signing certificate on Bambu's
// backend. It is fixed for the life of a given RSA key pair and is not secret.
// Priority: obn.conf slicer_cert_id > config_dir/slicer_cert_id.txt
const std::string& slicer_cert_id()
{
    static const std::string id = []() -> std::string {
        const auto& cfg = obn::config::current().slicer_cert_id;
        if (!cfg.empty()) return cfg;
        std::string from_file = load_cert_id_from_file();
        if (!from_file.empty()) return from_file;
        return "";
    }();
    return id;
}

namespace {

static std::unique_ptr<EVP_PKEY, PkeyDel> load_pkey()
{
    std::string path = resolve_key_path();
    if (path.empty()) return nullptr;

    std::FILE* f = std::fopen(path.c_str(), "r");
    if (!f) return nullptr;

    EVP_PKEY* raw = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    std::fclose(f);

    return std::unique_ptr<EVP_PKEY, PkeyDel>(raw);
}

EVP_PKEY* slicer_pkey()
{
    static const std::unique_ptr<EVP_PKEY, PkeyDel> key = load_pkey();
    return key.get();
}


// RSA-PKCS#1 v1.5 + SHA-256 over `data`, returned as base64.
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

// Raw RSA PKCS#1 v1.5 signature over `data` — the data IS the signed message,
// NOT its hash. Unlike rsa_sha256_sign_b64, no digest is applied and no
// DigestInfo is prepended: the encoded block is 00 01 FF..FF 00 || data.
// Returned as base64.
std::string rsa_pkcs1_sign_raw_b64(EVP_PKEY* pkey,
                                   const unsigned char* data, std::size_t len)
{
    if (!pkey) return {};
    std::unique_ptr<EVP_PKEY_CTX, CtxDel> ctx(EVP_PKEY_CTX_new(pkey, nullptr));
    if (!ctx) throw std::runtime_error("signing: EVP_PKEY_CTX_new failed");
    if (EVP_PKEY_sign_init(ctx.get()) != 1)
        throw std::runtime_error("signing: EVP_PKEY_sign_init failed");
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) != 1)
        throw std::runtime_error("signing: set_rsa_padding failed");
    std::size_t siglen = 0;
    if (EVP_PKEY_sign(ctx.get(), nullptr, &siglen, data, len) != 1 || siglen == 0)
        throw std::runtime_error("signing: EVP_PKEY_sign (size query) failed");
    std::vector<unsigned char> sig(siglen);
    if (EVP_PKEY_sign(ctx.get(), sig.data(), &siglen, data, len) != 1)
        throw std::runtime_error("signing: EVP_PKEY_sign failed");
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

// Returns true when `model` identifies an H2D-family printer.
// Matches model codes H2D, O1D, and C16 case-insensitively.
bool is_h2d_printer(const std::string& model) noexcept
{
    if (model.empty()) return false;
    auto ci_has = [&](const char* tok, std::size_t tlen) noexcept {
        for (std::size_t i = 0; i + tlen <= model.size(); ++i) {
            bool ok = true;
            for (std::size_t j = 0; j < tlen && ok; ++j) {
                char a = model[i + j], b = tok[j];
                if (a >= 'a' && a <= 'z') a = static_cast<char>(a - 32);
                if (b >= 'a' && b <= 'z') b = static_cast<char>(b - 32);
                ok = (a == b);
            }
            if (ok) return true;
        }
        return false;
    };
    return ci_has("H2D", 3) || ci_has("O1D", 3) || ci_has("C16", 3);
}

// Flips nozzleId values 0↔1 within the ams_mapping_info array region.
// Only touches the array substring to avoid false positives elsewhere.
std::string flip_nozzle_ids(std::string json) noexcept
{
    const auto region_start = json.find("\"ams_mapping_info\":[");
    if (region_start == std::string::npos) return json;
    const auto arr_pos = json.find('[', region_start);
    if (arr_pos == std::string::npos) return json;

    // Walk brackets to find the matching ']'.
    int depth = 0;
    std::size_t arr_end = std::string::npos;
    for (std::size_t i = arr_pos; i < json.size(); ++i) {
        if      (json[i] == '[') ++depth;
        else if (json[i] == ']') { if (--depth == 0) { arr_end = i; break; } }
    }
    if (arr_end == std::string::npos) return json;

    // Three-step 0↔1 swap to avoid chain-replacement bugs.
    // Step 1: :0 → :2 (temp marker, never appears in the original)
    // Step 2: :1 → :0
    // Step 3: :2 → :1
    std::string sub = json.substr(arr_pos, arr_end - arr_pos + 1);
    struct Step { const char* from; char to; };
    for (auto [from, to] : {Step{"\"nozzleId\":0", '2'},
                             Step{"\"nozzleId\":1", '0'},
                             Step{"\"nozzleId\":2", '1'}}) {
        const std::size_t flen = std::char_traits<char>::length(from);
        std::size_t pos = 0;
        while ((pos = sub.find(from, pos)) != std::string::npos) {
            sub[pos + flen - 1] = to;
            pos += flen;
        }
    }
    json.replace(arr_pos, arr_end - arr_pos + 1, sub);
    return json;
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
static std::string json_str_escape(const std::string& s)
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
std::string build_envelope(const std::string& to_sign,
                           const std::string& sig_b64,
                           const std::string& print_dump)
{
    std::string out;
    out.reserve(to_sign.size() + sig_b64.size() + 200);
    out += "{\"header\":{\"cert_id\":\"";
    out += json_str_escape(slicer_cert_id());
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

std::string maybe_sign(const std::string& payload_json,
                       const std::string& printer_model)
{
    if (!is_print_payload(payload_json)) return payload_json;

    EVP_PKEY* pkey = slicer_pkey();
    if (!pkey) return payload_json;

    // Apply H2D nozzleId flip before signing so the signature covers
    // the on-wire shape the printer will receive.
    std::string working = printer_model.empty() || !is_h2d_printer(printer_model)
                          ? payload_json
                          : flip_nozzle_ids(payload_json);

    const std::string to_sign = build_to_sign(working);
    if (to_sign.empty()) return payload_json; // malformed; pass through

    // Extract the sorted print dump from to_sign to avoid re-parsing.
    // to_sign has the shape: {"print":<dump>}
    const std::string print_dump = to_sign.substr(9, to_sign.size() - 10);

    const std::string sig_b64 = rsa_sha256_sign_b64(
        pkey,
        reinterpret_cast<const unsigned char*>(to_sign.data()), to_sign.size());

    return build_envelope(to_sign, sig_b64, print_dump);
}

std::string sign_bytes(const std::string& data)
{
    EVP_PKEY* pkey = slicer_pkey();
    if (!pkey) {
        const auto& d = obn::config::dir();
        throw std::runtime_error(
            "signing: no key loaded; set slicer_key_pem in obn.conf "
            "or place slicer_key.pem in the config directory ("
            + (d.empty() ? "<not set>" : d) + ")");
    }
    return rsa_sha256_sign_b64(
        pkey,
        reinterpret_cast<const unsigned char*>(data.data()), data.size());
}

std::string device_security_sign()
{
    EVP_PKEY* pkey = slicer_pkey();
    // Degrade gracefully when no slicer key is configured (same as maybe_sign):
    // return empty so the caller omits the header rather than crashing the
    // cloud-connect/print path. The header is only enforced on signed writes.
    if (!pkey) return {};
    // The proprietary plugin signs the *current* time in milliseconds (as a
    // decimal string) with a raw RSA PKCS#1 v1.5 signature — no hash. The
    // cloud recovers the timestamp from the signature and checks it is recent
    // (replay protection).
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
    const std::string ts = std::to_string(ms);
    return rsa_pkcs1_sign_raw_b64(
        pkey,
        reinterpret_cast<const unsigned char*>(ts.data()), ts.size());
}

static constexpr char kB64Tbl[] =
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

} // namespace obn::signing
