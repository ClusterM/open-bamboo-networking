# Minimal static libcurl via FetchContent for embedding into
# libbambu_networking.dylib on macOS without a Homebrew libcurl.dylib
# runtime dependency (issue #60).
#
# Build with OpenSSL + system zlib only; disable every optional third-party
# feature (nghttp2 / brotli / zstd / libpsl / libssh2 / idn2 / ldap) so the
# archive has no transitive Homebrew NEEDED entries. OpenSSL must already
# be findable as OpenSSL::SSL / OpenSSL::Crypto (caller sets
# OPENSSL_USE_STATIC_LIBS + OPENSSL_ROOT_DIR before calling this).

function(obn_vendor_curl_setup)
    include(FetchContent)

    # FetchContent_Populate is deprecated (CMP0169 NEW)
    if(POLICY CMP0169)
        cmake_policy(SET CMP0169 OLD)
    endif()

    # CACHE+FORCE so curl's option() calls (CMP0077 OLD) cannot reset these.
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
    set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
    set(BUILD_STATIC_CURL OFF CACHE BOOL "" FORCE)
    set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
    set(CURL_ENABLE_EXPORT_TARGET OFF CACHE BOOL "" FORCE)
    set(CURL_DISABLE_INSTALL ON CACHE BOOL "" FORCE)

    set(CURL_USE_OPENSSL ON CACHE BOOL "" FORCE)
    set(CURL_ZLIB ON CACHE BOOL "" FORCE)
    set(USE_NGHTTP2 OFF CACHE BOOL "" FORCE)
    set(CURL_BROTLI OFF CACHE BOOL "" FORCE)
    set(CURL_ZSTD OFF CACHE BOOL "" FORCE)
    set(CURL_USE_LIBPSL OFF CACHE BOOL "" FORCE)
    set(CURL_USE_LIBSSH2 OFF CACHE BOOL "" FORCE)
    set(USE_LIBIDN2 OFF CACHE BOOL "" FORCE)
    set(CURL_DISABLE_LDAP ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_LDAPS ON CACHE BOOL "" FORCE)

    FetchContent_Declare(curl
        GIT_REPOSITORY https://github.com/curl/curl.git
        GIT_TAG ${OBN_CURL_GIT_TAG}
        GIT_SHALLOW TRUE
        GIT_PROGRESS TRUE
    )

    FetchContent_GetProperties(curl)
    if(NOT curl_POPULATED)
        FetchContent_Populate(curl)
    endif()

    set(_obn_saved_skip_install "${CMAKE_SKIP_INSTALL_RULES}")
    set(CMAKE_SKIP_INSTALL_RULES TRUE)
    add_subdirectory("${curl_SOURCE_DIR}" "${curl_BINARY_DIR}" EXCLUDE_FROM_ALL)
    set(CMAKE_SKIP_INSTALL_RULES "${_obn_saved_skip_install}")

    # Prefer the explicit static target; fall back to CURL::libcurl_static /
    # CURL::libcurl when present (curl CMake has renamed aliases across
    # releases).
    set(_obn_curl_target "")
    if(TARGET libcurl_static)
        set(_obn_curl_target libcurl_static)
    elseif(TARGET CURL::libcurl_static)
        set(_obn_curl_target CURL::libcurl_static)
    elseif(TARGET CURL::libcurl)
        set(_obn_curl_target CURL::libcurl)
    endif()
    if(NOT _obn_curl_target)
        message(FATAL_ERROR
            "obn: vendored curl (${OBN_CURL_GIT_TAG}) did not produce a "
            "static libcurl target (libcurl_static / CURL::libcurl_static)")
    endif()

    # We only embed the static archive; do not build unused shared libs.
    if(TARGET libcurl_shared)
        set_target_properties(libcurl_shared PROPERTIES EXCLUDE_FROM_ALL TRUE)
    endif()
    if(TARGET curl)
        set_target_properties(curl PROPERTIES EXCLUDE_FROM_ALL TRUE)
    endif()

    add_library(obn_vendor_curl_iface INTERFACE)
    target_link_libraries(obn_vendor_curl_iface INTERFACE "${_obn_curl_target}")
    # Static libcurl on Darwin needs these frameworks (resolver / proxy /
    # SCDynamicStore). Linking them here keeps consumers platform-free.
    if(APPLE)
        target_link_libraries(obn_vendor_curl_iface INTERFACE
            "-framework SystemConfiguration"
            "-framework CoreFoundation"
        )
    endif()
    # Match curl's own static-build define so headers do not emit
    # dllimport-style declarations on any platform.
    target_compile_definitions(obn_vendor_curl_iface INTERFACE CURL_STATICLIB)

    message(STATUS
        "obn: using vendored libcurl_static (${OBN_CURL_GIT_TAG}) via ${_obn_curl_target}")
endfunction()
