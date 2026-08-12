# Bundled libmosquitto (static + PIC) via FetchContent for embedding into
# libbambu_networking.so without a system libmosquitto.a.

function(obn_vendor_mosquitto_setup)
    find_package(Threads REQUIRED)
    include(FetchContent)

    # FetchContent_Populate is deprecated (CMP0169 NEW)
    if(POLICY CMP0169)
        cmake_policy(SET CMP0169 OLD)
    endif()

    include("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/VendorCJSON.cmake")
    obn_vendor_cjson_setup()

    # Upstream leaves WITH_ARGON2 undefined ("Disable until separate password
    # handling thread is implemented") but still links libmosquitto_common
    # against the SHARED IMPORTED target its own Findargon2.cmake creates, so
    # the plugin gets an unused libargon2 in its NEEDED list (a Homebrew dylib
    # on macOS). Shadow the module: no argon2 symbol is referenced either way.
    set(_obn_mosq_override_dir "${CMAKE_CURRENT_BINARY_DIR}/_obn_cmake_overrides")
    file(MAKE_DIRECTORY "${_obn_mosq_override_dir}")
    list(PREPEND CMAKE_MODULE_PATH "${_obn_mosq_override_dir}")
    file(WRITE "${_obn_mosq_override_dir}/Findargon2.cmake"
        "include_guard(GLOBAL)\n"
        "set(ARGON2_FOUND FALSE)\n"
        "set(argon2_FOUND FALSE)\n"
    )

    FetchContent_Declare(eclipse_mosquitto
        GIT_REPOSITORY https://github.com/eclipse/mosquitto.git
        GIT_TAG ${OBN_MOSQUITTO_GIT_TAG}
        GIT_SHALLOW TRUE
        GIT_PROGRESS TRUE
    )

    # CACHE+FORCE so mosquitto's option() calls (CMP0077 OLD) cannot reset these.
    set(WITH_BROKER OFF CACHE BOOL "" FORCE)
    set(WITH_APPS OFF CACHE BOOL "" FORCE)
    set(WITH_CLIENTS OFF CACHE BOOL "" FORCE)
    set(WITH_PLUGINS OFF CACHE BOOL "" FORCE)
    set(WITH_DOCS OFF CACHE BOOL "" FORCE)
    set(WITH_TESTS OFF CACHE BOOL "" FORCE)
    set(WITH_STATIC_LIBRARIES ON CACHE BOOL "" FORCE)
    set(WITH_PIC ON CACHE BOOL "" FORCE)
    set(WITH_LIB_CPP OFF CACHE BOOL "" FORCE)
    # Client-only embed: skip broker/apps features that pull extra deps on Windows
    # (LineEditing, libwebsockets, PThreads4W is still required via vcpkg pthreads).
    set(WITH_WEBSOCKETS OFF CACHE BOOL "" FORCE)
    set(WITH_CTRL_SHELL OFF CACHE BOOL "" FORCE)
    set(WITH_SRV OFF CACHE BOOL "" FORCE)
    set(INC_MEMTRACK OFF CACHE BOOL "" FORCE)

    # MakeAvailable = Populate + add_subdirectory; we patch sources first so
    # OpenSSL 3.5+ systems without openssl/engine.h still compile (issue #19).
    FetchContent_GetProperties(eclipse_mosquitto)
    if(NOT eclipse_mosquitto_POPULATED)
        FetchContent_Populate(eclipse_mosquitto)
        include("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/VendorMosquittoOpenSSL35Patch.cmake")
        obn_patch_mosquitto_openssl35_engine("${eclipse_mosquitto_SOURCE_DIR}")
        include("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/VendorMosquittoTlsVerifyHost.cmake")
        obn_patch_mosquitto_tls_verify_host("${eclipse_mosquitto_SOURCE_DIR}")
        include("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/VendorMosquittoEmbedPatch.cmake")
        obn_patch_mosquitto_common_object("${eclipse_mosquitto_SOURCE_DIR}")
    endif()

    set(_obn_saved_skip_install "${CMAKE_SKIP_INSTALL_RULES}")
    set(CMAKE_SKIP_INSTALL_RULES TRUE)
    add_subdirectory("${eclipse_mosquitto_SOURCE_DIR}" "${eclipse_mosquitto_BINARY_DIR}" EXCLUDE_FROM_ALL)
    set(CMAKE_SKIP_INSTALL_RULES "${_obn_saved_skip_install}")

    if(NOT TARGET libmosquitto_static)
        message(FATAL_ERROR
            "obn: bundled mosquitto did not produce target libmosquitto_static")
    endif()
    if(TARGET libmosquitto_common)
        target_compile_definitions(libmosquitto_common PRIVATE LIBMOSQUITTO_STATIC)
    endif()
    # Upstream sets full include paths for libmosquitto (shared), but the
    # static target misses libcommon/common, bundled deps (utlist.h), and
    # picohttpparser while still compiling sources that include those headers.
    target_include_directories(libmosquitto_static PRIVATE
        "${eclipse_mosquitto_SOURCE_DIR}/common"
        "${eclipse_mosquitto_SOURCE_DIR}/deps"
        "${eclipse_mosquitto_SOURCE_DIR}/deps/picohttpparser"
        "${eclipse_mosquitto_SOURCE_DIR}/libcommon"
    )

    add_library(obn_mosquitto_iface INTERFACE)
    target_include_directories(obn_mosquitto_iface INTERFACE
        "${eclipse_mosquitto_SOURCE_DIR}/include"
    )
    # Our sources include <mosquitto.h> but link libmosquitto_static. Without
    # LIBMOSQUITTO_STATIC, MSVC emits __declspec(dllimport) calls and the plugin
    # DLL gets an import table entry for libmosquitto.dll (LoadLibrary error 126).
    target_compile_definitions(obn_mosquitto_iface INTERFACE LIBMOSQUITTO_STATIC)
    target_link_libraries(obn_mosquitto_iface INTERFACE
        obn_vendor_cjson_iface
        libmosquitto_static
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
    )
    if(WIN32)
        # libmosquitto_static links PThreads4W privately; propagate so the
        # final bambu_networking.dll resolves pthread symbols at link time.
        if(TARGET PThreads4W::PThreads4W)
            target_link_libraries(obn_mosquitto_iface INTERFACE PThreads4W::PThreads4W)
        endif()
    endif()
    # We only embed the static archive; do not build the unused shared lib.
    if(TARGET libmosquitto)
        set_target_properties(libmosquitto PROPERTIES EXCLUDE_FROM_ALL TRUE)
    endif()
    if(UNIX AND NOT APPLE AND NOT ANDROID)
        find_library(_obn_vendor_librt NAMES rt)
        if(_obn_vendor_librt)
            target_link_libraries(obn_mosquitto_iface INTERFACE "${_obn_vendor_librt}")
        endif()
    endif()

    message(STATUS "obn: using vendored libmosquitto_static (${OBN_MOSQUITTO_GIT_TAG})")
endfunction()
