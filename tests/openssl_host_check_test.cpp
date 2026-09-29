// Tests for src/openssl_host_check.cpp.
//
// Built twice: once as a plain process (no conflict expected) and once with
// OBN_TEST_INTERPOSE, where the executable exports its own EVP_PKEY_new the
// way a slicer with a static OpenSSL does (GitHub issue #110).

#include "obn/openssl_host_check.hpp"

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <dlfcn.h>

#include <cstring>
#include <iostream>
#include <string>

#define CHECK(cond) do {                                                    \
    if (!(cond)) {                                                          \
        std::cerr << "FAIL " << __FILE__ << ":" << __LINE__                \
                  << ": " #cond "\n";                                       \
        return 1;                                                           \
    }                                                                       \
} while (0)

#ifdef OBN_TEST_INTERPOSE
// The project builds with -fvisibility=hidden; the override must be exported.
extern "C" __attribute__((visibility("default"))) EVP_PKEY* EVP_PKEY_new(void)
{
    using Fn = EVP_PKEY* (*)(void);
    static Fn real = reinterpret_cast<Fn>(::dlsym(RTLD_NEXT, "EVP_PKEY_new"));
    return real ? real() : nullptr;
}
#endif

static const obn::openssl_host_check::Binding*
find_binding(const obn::openssl_host_check::Report& r, const char* symbol)
{
    for (const auto& b : r.bindings)
        if (b.symbol == symbol) return &b;
    return nullptr;
}

int main()
{
    // Keeps libssl a real dependency under --as-needed, as it is in the plugin.
    CHECK(::OPENSSL_init_ssl(0, nullptr) == 1);

    const auto r = obn::openssl_host_check::inspect();
    for (const auto& b : r.bindings)
        std::cout << b.symbol << " -> " << b.object << "\n";

    const auto* pkey_new = find_binding(r, "EVP_PKEY_new");
    const auto* ctx_new  = find_binding(r, "SSL_CTX_new");
    CHECK(pkey_new != nullptr);
    CHECK(ctx_new != nullptr);
    CHECK(ctx_new->object.find("libssl") != std::string::npos);

#ifdef OBN_TEST_INTERPOSE
    CHECK(r.conflict);
    CHECK(r.libcrypto.empty());
    CHECK(pkey_new->object.find("libcrypto") == std::string::npos);
#else
    CHECK(!r.conflict);
    CHECK(r.libcrypto.find("libcrypto") != std::string::npos);
    CHECK(pkey_new->object == r.libcrypto);
#endif

    obn::openssl_host_check::log_once();
    std::cout << "OK\n";
    return 0;
}
