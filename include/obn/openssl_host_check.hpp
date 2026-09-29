#pragma once

#include <string>
#include <vector>

// Detects a host process that interposes its own copy of OpenSSL over the
// libssl/libcrypto the plugin was linked against.
//
// A slicer built with a static OpenSSL 1.1.x that ends up exporting some of
// those symbols (e.g. an AUR Bambu Studio build, GitHub issue #110) makes
// libssl.so.3 call into 1.1.x EVP_* code with 3.x structures; the first
// SSL_CTX_new then segfaults deep inside libcrypto. We cannot repair such a
// process, but we can say so in the log before it dies.
//
// Linux only. Windows binds DLL imports per module and macOS uses two-level
// namespaces, so neither can be interposed this way; there inspect() only
// reports the runtime version.

namespace obn::openssl_host_check {

struct Binding {
    std::string symbol;
    std::string object;  // path of the loaded object that defines it
};

struct Report {
    bool                 conflict = false;
    std::string          libcrypto;   // object all libcrypto probes resolve to, empty if mixed
    std::string          libssl;      // object all libssl probes resolve to, empty if mixed
    unsigned long        runtime_version = 0;  // OpenSSL_version_num() as bound
    std::vector<Binding> bindings;
};

Report inspect();

// Runs inspect() once per process and logs the result: one INFO line when
// the binding is consistent, a loud ERROR with every binding when it is not.
void log_once();

} // namespace obn::openssl_host_check
