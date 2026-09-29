#include "obn/openssl_host_check.hpp"

#include "obn/log.hpp"

#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#include <mutex>
#include <set>

#if defined(__linux__)
#  include <dlfcn.h>
#endif

namespace obn::openssl_host_check {

namespace {

#if defined(__linux__)
// Looked up by name rather than by address-of so that symbols missing from
// the OpenSSL we compiled against (or from an interposed older copy) are
// simply skipped. EVP_PKEY_new is the one that crashed in #110; the 3.x-only
// entries pin down which object is the real libcrypto.so.3.
constexpr const char* kCryptoProbes[] = {
    "OPENSSL_init_crypto",
    "OpenSSL_version_num",
    "EVP_PKEY_new",
    "EVP_PKEY_free",
    "EVP_PKEY_set_type",
    "EVP_PKEY_CTX_new_from_pkey",
    "EVP_KEYMGMT_get0_name",
    "EVP_MD_CTX_new",
    "OBJ_nid2sn",
    "X509_free",
    "ERR_peek_last_error",
};

constexpr const char* kSslProbes[] = {
    "OPENSSL_init_ssl",
    "TLS_client_method",
    "SSL_CTX_new",
    "SSL_CTX_new_ex",
    "SSL_new",
    "SSL_free",
};

// RTLD_DEFAULT walks the same global-then-local scope that libssl.so.3's own
// relocations use, so this is where libssl's EVP_* calls actually land.
template <std::size_t N>
std::string resolve_group(const char* const (&names)[N], Report& r)
{
    std::set<std::string> objects;
    std::string           first;
    for (const char* name : names) {
        void* addr = ::dlsym(RTLD_DEFAULT, name);
        if (!addr) continue;
        Dl_info info{};
        if (!::dladdr(addr, &info) || !info.dli_fname) continue;
        std::string obj = info.dli_fname;
        // dladdr may report an empty name for the main executable.
        if (obj.empty()) obj = "<main executable>";
        r.bindings.push_back({name, obj});
        objects.insert(obj);
        if (first.empty()) first = obj;
    }
    if (objects.size() > 1) {
        r.conflict = true;
        return {};
    }
    return first;
}
#endif

} // namespace

Report inspect()
{
    Report r;
    r.runtime_version = ::OpenSSL_version_num();
#if defined(__linux__)
    r.libcrypto = resolve_group(kCryptoProbes, r);
    r.libssl    = resolve_group(kSslProbes, r);
    if ((r.runtime_version >> 28) != (OPENSSL_VERSION_NUMBER >> 28))
        r.conflict = true;
#endif
    return r;
}

void log_once()
{
    static std::once_flag once;
    std::call_once(once, [] {
        const Report r = inspect();
        const char*  runtime = ::OpenSSL_version(OPENSSL_VERSION);
        if (!r.conflict) {
            OBN_INFO("openssl: %s (built against %s), libcrypto=%s libssl=%s",
                     runtime ? runtime : "?", OPENSSL_VERSION_TEXT,
                     r.libcrypto.empty() ? "?" : r.libcrypto.c_str(),
                     r.libssl.empty() ? "?" : r.libssl.c_str());
            return;
        }
        OBN_ERROR("openssl: CONFLICTING OpenSSL COPIES IN THIS PROCESS. The "
                  "slicer binary provides its own OpenSSL symbols that "
                  "override the libssl/libcrypto this plugin uses, so the "
                  "first TLS connection (printer, cloud) will most likely "
                  "crash the slicer. Rebuild the slicer against the system "
                  "OpenSSL (e.g. Bambu Studio deps with -DDEP_BUILD_OPENSSL=0), "
                  "see GitHub issue #110. Runtime: %s (0x%08lx), built "
                  "against: %s",
                  runtime ? runtime : "?", r.runtime_version,
                  OPENSSL_VERSION_TEXT);
        for (const Binding& b : r.bindings)
            OBN_ERROR("openssl:   %-28s -> %s", b.symbol.c_str(), b.object.c_str());
    });
}

} // namespace obn::openssl_host_check
