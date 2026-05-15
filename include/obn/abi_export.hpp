#pragma once

// Mark a symbol as exported by the plugin. With -fvisibility=hidden the
// default ELF visibility is local; OBN_ABI exports the function under the
// plain C-linkage name (no C++ mangling) so Bambu Studio's dlsym() finds it.
#if defined(_WIN32)
#    define OBN_ABI extern "C" __declspec(dllexport)
#else
#    define OBN_ABI extern "C" __attribute__((visibility("default")))
#endif

// Studio dlopen()-loads the plugin and expects plain C symbol names, but
// several exports return/take C++ types (e.g. std::string). Clang warns that
// the return type is not C-compatible; the ABI is intentional (Itanium C++).
#if defined(__cplusplus) && defined(__clang__)
#    define OBN_IGNORE_RETURN_CXX_IN_EXTERN_C_BEGIN                       \
        _Pragma("clang diagnostic push")                                 \
        _Pragma("clang diagnostic ignored \"-Wreturn-type-c-linkage\"")
#    define OBN_IGNORE_RETURN_CXX_IN_EXTERN_C_END _Pragma("clang diagnostic pop")
#else
#    define OBN_IGNORE_RETURN_CXX_IN_EXTERN_C_BEGIN
#    define OBN_IGNORE_RETURN_CXX_IN_EXTERN_C_END
#endif
