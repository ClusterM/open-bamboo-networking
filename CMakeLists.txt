cmake_minimum_required(VERSION 3.20)
project(open-bamboo-networking
    VERSION 0.1.0
    DESCRIPTION "Open Bamboo Networking — open-source replacement for Bambu Studio's bambu_networking plugin"
    LANGUAGES CXX
)

# Vendored mosquitto pulls cJSON via FetchContent; released cJSON tags still
# declare cmake_minimum_required(VERSION 3.0) or older. CMake 3.31+ rejects
# that unless we raise the policy floor (same effect as -DCMAKE_POLICY_VERSION_MINIMUM=3.5).
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.31")
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
endif()

# Which slicer this build targets. Drives the install layout (.so file
# name, OTA manifest presence, which conf file is patched). The plugin
# code itself does NOT change between clients -- the same C ABI is used.
set(OBN_CLIENT_TYPE "bambu_studio" CACHE STRING
    "Target slicer for install rules (bambu_studio | orca_slicer)")
set_property(CACHE OBN_CLIENT_TYPE PROPERTY STRINGS bambu_studio orca_slicer)
if(NOT OBN_CLIENT_TYPE MATCHES "^(bambu_studio|orca_slicer)$")
    message(FATAL_ERROR
        "OBN_CLIENT_TYPE must be 'bambu_studio' or 'orca_slicer' "
        "(got '${OBN_CLIENT_TYPE}').")
endif()

# The plugin's reported version must have the same first-8-char prefix as
# Bambu Studio's SLIC3R_VERSION (AppImage v02.05.02.51 expects prefix
# "02.05.02"; source builds from the main branch currently expect
# "02.05.03"). We deliberately refuse to pick a default: a stale hardcode
# silently breaks Studio's compatibility gate on the user's machine,
# which is a much worse failure mode than failing at configure time.
# The top-level ./configure wrapper auto-detects this from the installed
# BambuStudio.conf; bare `cmake -S . -B build` callers need to pass
# -DOBN_VERSION=... by hand.
set(OBN_VERSION "" CACHE STRING "Plugin version reported via bambu_network_get_version()")
if(NOT OBN_VERSION)
    message(FATAL_ERROR
        "OBN_VERSION is not set. Run ./configure (it auto-detects from "
        "BambuStudio.conf) or pass -DOBN_VERSION=MAJOR.MINOR.PATCH.99 to cmake."
    )
endif()

set(OBN_CLOUD_API_URL      "" CACHE STRING "Override cloud REST API base URL (e.g. https://api.example.com).")
set(OBN_CLOUD_WEB_URL      "" CACHE STRING "Override cloud web portal base URL, trailing slash required (e.g. https://example.com/).")
set(OBN_CLOUD_MQTT_HOSTNAME "" CACHE STRING "Override cloud MQTT broker hostname (no scheme, no port).")
if(OBN_CLOUD_API_URL OR OBN_CLOUD_WEB_URL OR OBN_CLOUD_MQTT_HOSTNAME)
    message(STATUS "obn: cloud endpoint overrides")
    if(OBN_CLOUD_API_URL)
        message(STATUS "  api  = ${OBN_CLOUD_API_URL}")
    endif()
    if(OBN_CLOUD_WEB_URL)
        message(STATUS "  web  = ${OBN_CLOUD_WEB_URL}")
    endif()
    if(OBN_CLOUD_MQTT_HOSTNAME)
        message(STATUS "  mqtt = ${OBN_CLOUD_MQTT_HOSTNAME}")
    endif()
endif()
# First three dotted components of OBN_VERSION (MM.mm.pp from MM.mm.pp.rr)
# as a single preprocessor integer 0xMMmmpp for #if ABI_VERSION in
# include/obn/bambu_networking.hpp (matches Studio's 8-char prefix gate).
if(NOT OBN_VERSION MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
    message(FATAL_ERROR
        "OBN_VERSION must look like MM.mm.pp.rr with decimal components (got '${OBN_VERSION}').")
endif()
function(_obn_dec_string_to_int s outvar)
    string(REGEX REPLACE "^0+" "" _t "${s}")
    if(_t STREQUAL "")
        set(_t "0")
    endif()
    math(EXPR _n "${_t}")
    set(${outvar} "${_n}" PARENT_SCOPE)
endfunction()
function(_obn_byte_to_hex2 b outvar)
    set(_digits "0123456789abcdef")
    math(EXPR _hi "${b} / 16")
    math(EXPR _lo "${b} % 16")
    string(SUBSTRING "${_digits}" ${_hi} 1 _h1)
    string(SUBSTRING "${_digits}" ${_lo} 1 _h2)
    set(${outvar} "${_h1}${_h2}" PARENT_SCOPE)
endfunction()
_obn_dec_string_to_int("${CMAKE_MATCH_1}" _obn_b0)
_obn_dec_string_to_int("${CMAKE_MATCH_2}" _obn_b1)
_obn_dec_string_to_int("${CMAKE_MATCH_3}" _obn_b2)
foreach(_obn_x IN ITEMS ${_obn_b0} ${_obn_b1} ${_obn_b2})
    if(_obn_x GREATER 255)
        message(FATAL_ERROR
            "OBN_VERSION component out of 0..255 range after parsing '${OBN_VERSION}'.")
    endif()
endforeach()
_obn_byte_to_hex2(${_obn_b0} _obn_h0)
_obn_byte_to_hex2(${_obn_b1} _obn_h1)
_obn_byte_to_hex2(${_obn_b2} _obn_h2)
set(OBN_ABI_VERSION_HEX "0x${_obn_h0}${_obn_h1}${_obn_h2}")
message(STATUS "obn: ABI_VERSION=${OBN_ABI_VERSION_HEX} (from OBN_VERSION=${OBN_VERSION})")

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/ObnGitInfo.cmake")
obn_detect_git_info(OBN_GIT_COMMIT OBN_GIT_DIRTY)
if(OBN_GIT_COMMIT)
    if(OBN_GIT_DIRTY)
        message(STATUS "obn: git commit=${OBN_GIT_COMMIT} (dirty)")
    else()
        message(STATUS "obn: git commit=${OBN_GIT_COMMIT}")
    endif()
else()
    message(STATUS "obn: git commit unavailable (git not found or not a checkout)")
endif()

# Per-client install settings: file name of the .so, OTA manifest layout,
# which conf file the post-install patch script targets, recommended
# default prefix, etc. Populates OBN_CLIENT_* variables in this scope.
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/Clients.cmake")
obn_resolve_client("${OBN_CLIENT_TYPE}")
if(WIN32)
    message(STATUS "obn: client=${OBN_CLIENT_TYPE} plugin=${OBN_CLIENT_PLUGIN_NAME}.dll")
elseif(APPLE)
    message(STATUS "obn: client=${OBN_CLIENT_TYPE} plugin=lib${OBN_CLIENT_PLUGIN_NAME}.dylib")
else()
    message(STATUS "obn: client=${OBN_CLIENT_TYPE} plugin=lib${OBN_CLIENT_PLUGIN_NAME}.so")
endif()

# Default install location: the per-client config dir.
# Honoured only when the user did not pass -DCMAKE_INSTALL_PREFIX (the
# CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT flag is unset by CMake the
# moment it picks up an explicit value, including ones cached from a
# previous configure). The top-level ./configure / configure.ps1 wrapper
# independently computes the same default and passes it via
# -DCMAKE_INSTALL_PREFIX, so this branch only fires for callers that
# invoke cmake directly. Linux native config dir, macOS Library/Application
# Support, Windows %APPDATA%\<client>.
if(NOT CMAKE_CROSSCOMPILING
   AND CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT
   AND NOT OBN_CLIENT_DEFAULT_PREFIX STREQUAL "")
    set(CMAKE_INSTALL_PREFIX "${OBN_CLIENT_DEFAULT_PREFIX}"
        CACHE PATH "Install prefix (plugins/ under it)" FORCE)
endif()

# When ON, the ft_* C ABI used by Studio's "Send to Printer" dialog and
# the Print job's eMMC pre-flight speaks native BambuTunnelLocal (TLS :6000),
# same as stock libbambu_networking.so.
#
# Non-stock paths gated by OBN_ENABLE_WORKAROUNDS (see README):
#   - push_status home_flag / ipcam.file rewrites (Studio UI on P2S)
#   - in-print Device-panel cover (get_subtask_info + cover_cache)
#   - start_sdcard_print over LAN MQTT instead of signed cloud REST
option(OBN_ENABLE_WORKAROUNDS "Enable non-stock workaround paths (see README)" ON)

# When ON, 'cmake --install' (and therefore 'make install') will also
# edit the slicer's conf file so it trusts this plugin:
#   bambu_studio -> ~/.config/BambuStudio/BambuStudio.conf
#                   ("installed_networking"="1", "update_network_plugin"="false")
#   orca_slicer  -> ~/.config/OrcaSlicer/OrcaSlicer.conf (or the Flatpak
#                   path) -- "installed_networking"="true",
#                   "network_plugin_version"="<OBN_VERSION>",
#                   "network_plugin_remind_later"="true", and our version
#                   is stripped from "network_plugin_skipped_versions".
# The patch edits "${CMAKE_INSTALL_PREFIX}/<conf file>". Disable with
# -DOBN_PATCH_CLIENT_CONF=OFF or ./configure --no-conf-patch (e.g. staging).
# A backup file (*.obn-bak) is written whenever the file actually changes.
#
# OBN_PATCH_STUDIO_CONF is kept as a backward-compat alias -- existing
# CMake caches set the old name and we want them to keep working.
option(OBN_PATCH_CLIENT_CONF
    "Edit the slicer's conf file after install" ON)
if(DEFINED OBN_PATCH_STUDIO_CONF AND NOT DEFINED CACHE{OBN_PATCH_CLIENT_CONF})
    set(OBN_PATCH_CLIENT_CONF "${OBN_PATCH_STUDIO_CONF}" CACHE BOOL
        "Edit the slicer's conf file after install" FORCE)
endif()

# Bundled libmosquitto (static + PIC) via FetchContent — always embedded in
# libbambu_networking.so. Requires Git and uthash headers at configure time.
set(OBN_MOSQUITTO_GIT_TAG "v2.1.2"
    CACHE STRING "Git tag for eclipse/mosquitto (FetchContent)")
set(OBN_CJSON_GIT_TAG "v1.7.18"
    CACHE STRING "Git tag for DaveGamble/cJSON (FetchContent)")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
    # Match the Bambu Studio toolchain (Visual Studio 2019, MSVC STL). The ABI
    # crosses the DLL boundary as std::string / std::map / std::function, so
    # we must use exactly the same STL Studio is built with -- compiling with
    # MinGW or any libstdc++ flavour will hand Studio mangled types it cannot
    # consume. _CRT_SECURE_NO_WARNINGS silences the deprecation noise around
    # POSIX-style I/O we still use through portable wrappers; NOMINMAX +
    # WIN32_LEAN_AND_MEAN keep <windows.h> from clobbering std::min/max and
    # pulling in the rarely-used GDI/RPC headers.
    add_compile_options(/W3 /utf-8 /permissive- /Zc:__cplusplus)
    # /wd4100: unreferenced formal parameter (intentional in many ABI stubs).
    # /wd4101: unreferenced local variable.
    # /wd4244 /wd4267: integer narrowing in stdlib/curl call sites we cannot
    #                  fix from here.
    # /wd4190: extern "C" function returning std::string. This is the whole
    #          point of the plugin ABI: Bambu Studio is built with the same
    #          MSVC STL and unmangles the type identically. The warning fires
    #          all over abi_user.cpp / abi_presets.cpp / abi_http.cpp.
    add_compile_options(/wd4100 /wd4101 /wd4244 /wd4267 /wd4190)
    add_compile_definitions(
        _CRT_SECURE_NO_WARNINGS
        _WINSOCK_DEPRECATED_NO_WARNINGS
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _WIN32_WINNT=0x0601
    )
else()
    # Bambu Studio's Linux build is compiled against libstdc++ new C++11 ABI;
    # match it so std::string layout lines up across the boundary.
    add_compile_definitions(_GLIBCXX_USE_CXX11_ABI=1)
    add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-unused-variable)
    # Clang/AppleClang always; GNU only since GCC 8 (older toolchains reject the flag).
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang" OR
            (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
                CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "8"))
        add_compile_options(-Wno-unused-lambda-capture)
    endif()
    # Hide every symbol by default, explicitly export only the ABI functions
    # via __attribute__((visibility("default"))) (see include/obn/abi_export.hpp).
    add_compile_options(
        -fvisibility=hidden
        $<$<COMPILE_LANGUAGE:CXX>:-fvisibility-inlines-hidden>
    )
endif()

# --------------------------------------------------------------------------
# libbambu_networking.so  (main plugin)
# --------------------------------------------------------------------------

# Dependency resolution:
#   - Linux/macOS: pkg-config for libcurl; OpenSSL/zlib via CMake.
#   - Windows: vcpkg manifest for curl/openssl/zlib; mosquitto is always
#     vendored via FetchContent (same as Linux).
if(WIN32)
    find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)
    find_package(ZLIB REQUIRED)
    find_package(CURL CONFIG REQUIRED)
else()
    find_package(PkgConfig REQUIRED)
    find_package(OpenSSL COMPONENTS SSL REQUIRED)
    find_package(ZLIB REQUIRED)
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/VendorMosquitto.cmake")
obn_vendor_mosquitto_setup()

# CURL imported target: PkgConfig::CURL on POSIX, CURL::libcurl on Windows
# (vcpkg's CURLConfig.cmake exports that name). We expose a unified alias
# so the per-target target_link_libraries calls below stay platform-free.
add_library(obn_curl_iface INTERFACE)
if(WIN32)
    target_link_libraries(obn_curl_iface INTERFACE CURL::libcurl)
else()
    pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
    target_link_libraries(obn_curl_iface INTERFACE PkgConfig::CURL)
endif()
# zlib is shared between BambuSource (FTPS fallback: client-side ZIP
# extract for file-browser thumbnails) and other zlib users in the tree.

add_library(bambu_networking SHARED
    src/abi_meta.cpp
    src/abi_lifecycle.cpp
    src/abi_callbacks.cpp
    src/abi_cloud.cpp
    src/abi_lan.cpp
    src/abi_user.cpp
    src/abi_bind.cpp
    src/abi_print.cpp
    src/abi_presets.cpp
    src/abi_http.cpp
    src/abi_filament.cpp
    src/abi_camera.cpp
    src/abi_makerworld.cpp
    src/abi_track.cpp
    src/abi_ft.cpp
    src/agent.cpp
    src/auth.cpp
    src/cert_store.cpp
    src/cloud_auth.cpp
    src/bind_cloud.cpp
    src/cloud_filament.cpp
    src/cloud_presets.cpp
    src/cloud_print.cpp
    src/cloud_session.cpp
    src/cover_cache.cpp
    src/cover_server.cpp
    src/ftps.cpp
    src/http_client.cpp
    src/json_lite.cpp
    src/print_params_ftp_prefs.cpp
    src/lan_session.cpp
    src/lan_tls.cpp
    src/log.cpp
    src/plugin_load_banner.cpp
    src/mqtt_client.cpp
    src/os_compat.cpp
    src/print_job.cpp
    src/print_job_naming.cpp
    src/ssdp.cpp
    src/tunnel_local.cpp
    src/tunnel_upload.cpp
    src/tls_dial.cpp
)

target_include_directories(bambu_networking PRIVATE include)
set(_obn_git_compile_defs "")
if(OBN_GIT_COMMIT)
    list(APPEND _obn_git_compile_defs OBN_GIT_COMMIT="${OBN_GIT_COMMIT}")
    if(OBN_GIT_DIRTY)
        list(APPEND _obn_git_compile_defs OBN_GIT_DIRTY=1)
    endif()
endif()

target_compile_definitions(bambu_networking PRIVATE
    OBN_VERSION_STRING="${OBN_VERSION}"
    ABI_VERSION=${OBN_ABI_VERSION_HEX}
    OBN_ENABLE_WORKAROUNDS=$<BOOL:${OBN_ENABLE_WORKAROUNDS}>
    OBN_CLOUD_API_URL_DEFAULT="${OBN_CLOUD_API_URL}"
    OBN_CLOUD_WEB_URL_DEFAULT="${OBN_CLOUD_WEB_URL}"
    OBN_CLOUD_MQTT_HOSTNAME_DEFAULT="${OBN_CLOUD_MQTT_HOSTNAME}"
    ${_obn_git_compile_defs}
)
target_link_libraries(bambu_networking PRIVATE
    obn_mosquitto_iface
    obn_curl_iface
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
)

if(WIN32)
    # Winsock2 + the typical curl/openssl Windows transitive deps. vcpkg's
    # static triplet exports these in the curl/openssl link line, but the
    # plugin itself also calls Winsock directly (sockets, WSAPoll) through
    # src/os_compat.cpp.
    target_link_libraries(bambu_networking PRIVATE
        ws2_32 crypt32 secur32 bcrypt iphlpapi)
endif()

# Output filename:
#   POSIX  -> libbambu_networking.so / libbambu_networking.dylib
#   Windows -> bambu_networking.dll  (no "lib" prefix; matches what
#              NetworkAgent::initialize_network_module hard-codes).
if(WIN32)
    set_target_properties(bambu_networking PROPERTIES
        OUTPUT_NAME "bambu_networking"
        PREFIX      ""
    )
else()
    set_target_properties(bambu_networking PROPERTIES
        OUTPUT_NAME "bambu_networking"
        PREFIX      "lib"
    )
endif()

# --------------------------------------------------------------------------
# libBambuSource.so  (camera tunnel + PrinterFileSystem CTRL bridge;
# consumed by Studio's gstbambusrc element on Linux/Windows and by
# wxMediaCtrl2.mm on macOS).
# --------------------------------------------------------------------------

# RTSPS livestream (X1/P1S/P2S/N7) is handled by a custom RTSP/RTSPS
# client (stubs/rtsp_client.cpp) plus an Annex-B passthrough worker
# (stubs/rtsp_passthrough.cpp). We do NOT decode or transcode H.264
# in-process: gstbambusrc.c (vendored verbatim by both Bambu Studio
# and Orca Slicer on Linux) hands whatever Bambu_ReadSample returns
# straight at h264parse + avdec_h264 / openh264dec, so the slicer
# already pulls H.264 decoders into the process. Doing it again here
# would only add an in-process libavcodec dependency that neither
# Studio (decoder-only bundle) nor Orca (no bundle at all) can
# satisfy.
#
# Historic context: we used to have OBN_VIDEO_BACKEND=ffmpeg|gstreamer
# selecting an in-process H.264 -> MJPEG transcoder. Both were dropped
# once we realised gstbambusrc was already doing the decode for us:
# the ffmpeg path failed inside Orca because libavcodec wasn't loaded;
# the gstreamer path always aborted with a libjpeg ABI clash inside
# Studio's AppImage.

# BambuSource ships the PrinterFileSystem CTRL passthrough (:6000) AND
# the RTSP/RTSPS Annex-B H.264 passthrough used by the live view, so it
# needs json + tunnel_local + log from the core tree. Compile them in
# directly instead of linking against libbambu_networking to keep the
# shared-object self-contained (Studio dlopens BambuSource *before* it
# loads the network plugin).
#
# Single source list shared by Linux/macOS/Windows: the porting of
# BambuSource.cpp / rtsp_client.cpp / tls_socket.cpp through obn::os_compat
# means the Windows build now exercises the same code path as Linux for
# the C ABI half (file browser, MJPEG framing, RTSPS passthrough). The
# camera-tab side on Windows additionally needs a DirectShow source filter
# (stubs/dshow_filter.cpp) registered for the bambu: URL scheme; that is
# Phase B and lives inside the same DLL.
set(_obn_bambusource_sources
    stubs/BambuSource.cpp
    stubs/source_log.cpp
    stubs/tls_socket.cpp
    stubs/rtsp_client.cpp
    stubs/rtsp_passthrough.cpp
    src/json_lite.cpp
    src/tunnel_local.cpp
    src/tls_dial.cpp
    src/lan_tls.cpp
    src/log.cpp
    src/os_compat.cpp
)
if(WIN32)
    list(APPEND _obn_bambusource_sources
        stubs/dshow_filter.cpp
        # .def file lists the COM in-proc-server entry points
        # (DllGetClassObject etc.) since they cannot use
        # __declspec(dllexport) without clashing with <objbase.h>'s
        # prototypes. Bambu_* exports stay on __declspec(dllexport).
        stubs/BambuSource.def
    )
endif()

add_library(BambuSource SHARED ${_obn_bambusource_sources})
target_include_directories(BambuSource PRIVATE include stubs)
if(WIN32)
    set_target_properties(BambuSource PROPERTIES OUTPUT_NAME "BambuSource" PREFIX "")
    target_link_libraries(BambuSource PRIVATE
        OpenSSL::SSL OpenSSL::Crypto
        ws2_32 crypt32 secur32 bcrypt iphlpapi
        strmiids ole32 oleaut32 uuid
        advapi32 shell32 user32
    )
else()
    set_target_properties(BambuSource PROPERTIES OUTPUT_NAME "BambuSource" PREFIX "lib")
    target_link_libraries(BambuSource PRIVATE
        OpenSSL::SSL OpenSSL::Crypto
    )
endif()

# RTSPS is handled by stubs/rtsp_client.cpp + stubs/rtsp_passthrough.cpp,
# both of which only need OpenSSL (already linked above) and the C++
# stdlib. There is no in-process libavcodec dependency: gstbambusrc on
# the slicer side is the H.264 decoder.

# --------------------------------------------------------------------------
# liblive555.so  (stub; used by the real BambuSource internally)
# --------------------------------------------------------------------------

add_library(live555 SHARED stubs/live555.cpp)
if(WIN32)
    set_target_properties(live555 PROPERTIES OUTPUT_NAME "live555" PREFIX "")
else()
    set_target_properties(live555 PROPERTIES OUTPUT_NAME "live555" PREFIX "lib")
endif()

# --------------------------------------------------------------------------
# install (copies into <prefix>/plugins/)
# --------------------------------------------------------------------------

# A brand-new slicer profile may not have created plugins/ (or, for
# Studio, ota/plugins/) yet -- the slicer often creates them only after
# its first official plugin download. cmake --install would then fail
# copying into a missing parent. Create the dirs explicitly before any
# install(TARGETS|FILES) into them. Use \${CMAKE_INSTALL_PREFIX} so the
# path is resolved at install time (honours cmake --install --prefix).
if(OBN_CLIENT_INSTALL_OTA)
    install(CODE "
        file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/plugins\")
        file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${OBN_CLIENT_OTA_SUBPATH}\")
    ")
else()
    install(CODE "
        file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/plugins\")
    ")
endif()

# BambuSource always ships under its stock name -- both slicers dlopen
# it by fixed file name. The main plugin .so/.dll file differs by client:
#   bambu_studio -> libbambu_networking.so / bambu_networking.dll  (fixed)
#   orca_slicer  -> libbambu_networking_<VER>.so / bambu_networking_<VER>.dll
#                   (Orca dlopens that exact name, including the version)
# On Windows DLLs go to RUNTIME; on POSIX shared libraries go to LIBRARY.
install(TARGETS BambuSource
    LIBRARY DESTINATION plugins
    RUNTIME DESTINATION plugins
)

# liblive555 is trickier. On Linux both slicers ship it as part of their
# own plugin bundle and nothing in the camera path of *this* port calls
# into it -- our stub exists only to satisfy a "file exists" check in
# PresetUpdater on Studio, so the OTA-update banner stays quiet. On
# Windows OrcaSlicer ships a real ~4.4 MB live555.dll alongside its
# DirectShow filter; replacing it with our 10 kB stub breaks unrelated
# Orca code paths that load it lazily. The rule below is: only install
# the stub if there is no existing live555 at the target, or the existing
# one looks like a previous obn stub (small file, < 64 kB). Real
# vendor-supplied live555 builds are at least ~4 MB on every platform we
# have seen, so the heuristic is safe.
if(WIN32)
    set(_obn_live555_dst_name "live555.dll")
elseif(APPLE)
    set(_obn_live555_dst_name "liblive555.dylib")
else()
    set(_obn_live555_dst_name "liblive555.so")
endif()
install(CODE "
    set(_src \"$<TARGET_FILE:live555>\")
    set(_dst \"\${CMAKE_INSTALL_PREFIX}/plugins/${_obn_live555_dst_name}\")
    set(_install_stub TRUE)
    if(EXISTS \"\${_dst}\")
        file(SIZE \"\${_dst}\" _existing_size)
        if(_existing_size GREATER 65536)
            message(STATUS
                \"obn: keeping existing live555 (\${_existing_size} bytes) at \${_dst}; \"
                \"looks like the slicer's vendor build, not our stub\")
            set(_install_stub FALSE)
        endif()
    endif()
    if(_install_stub)
        message(STATUS \"obn: installing live555 stub to \${_dst}\")
        file(INSTALL \"\${_src}\" DESTINATION \"\${CMAKE_INSTALL_PREFIX}/plugins\")
    endif()
")

# DirectShow Source Filter registration: BambuSource.dll exports
# DllRegisterServer / DllUnregisterServer (HKCU only, no admin needed)
# so wxMediaCtrl2 can find our CLSID for the bambu: URL scheme. Default
# ON for Windows; pass -DOBN_REGISTER_DSHOW_FILTER=OFF (or
# -RegisterDShowFilter:$false in configure.ps1) to skip if the user
# wants to register manually.
if(WIN32)
    option(OBN_REGISTER_DSHOW_FILTER
           "After install, run regsvr32 on BambuSource.dll" ON)
    if(OBN_REGISTER_DSHOW_FILTER)
        install(CODE [[
            set(_obn_dll "${CMAKE_INSTALL_PREFIX}/plugins/BambuSource.dll")
            execute_process(
                COMMAND regsvr32.exe /s "${_obn_dll}"
                RESULT_VARIABLE _obn_rc
            )
            if(NOT _obn_rc EQUAL 0)
                message(WARNING
                    "obn: regsvr32 failed (rc=${_obn_rc}); register manually:\n"
                    "  regsvr32 /s \"${_obn_dll}\"")
            else()
                message(STATUS
                    "obn: registered BambuSource DirectShow filter (HKCU)")
            endif()
        ]])
    endif()
endif()
if(WIN32)
    set(_obn_plugin_artefact "${OBN_CLIENT_PLUGIN_NAME}.dll")
elseif(APPLE)
    set(_obn_plugin_artefact "lib${OBN_CLIENT_PLUGIN_NAME}.dylib")
else()
    set(_obn_plugin_artefact "lib${OBN_CLIENT_PLUGIN_NAME}.so")
endif()

if(OBN_CLIENT_PLUGIN_NAME STREQUAL "bambu_networking")
    install(TARGETS bambu_networking
        LIBRARY DESTINATION plugins
        RUNTIME DESTINATION plugins
    )
else()
    install(FILES $<TARGET_FILE:bambu_networking>
        DESTINATION plugins
        RENAME "${_obn_plugin_artefact}")
endif()

# Studio's PresetUpdater expects this JSON to declare the cached version
# in <data_dir>/ota/plugins/; we ship the same file so the updater trusts
# our installation. Orca does NOT use this file as a persistent manifest
# (PresetUpdater drops it as a transient OTA artefact and deletes it
# after the update flow finishes), so for orca_slicer we skip it
# entirely -- shipping it would accumulate stale state in the user's
# data dir for no benefit.
if(OBN_CLIENT_INSTALL_OTA)
    configure_file(packaging/network_plugins.json.in
        ${CMAKE_CURRENT_BINARY_DIR}/network_plugins.json @ONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/network_plugins.json
        DESTINATION "${OBN_CLIENT_OTA_SUBPATH}")
endif()

# First-time slicer configuration: see the OBN_PATCH_CLIENT_CONF docstring
# at the top of this file for what each client needs flipped. The patch
# script template is per-client (cmake/patch_<client>_conf.cmake.in);
# configure_file() expands @OBN_*@ variables into a runnable .cmake we
# pass to install(SCRIPT). install(SCRIPT) executes at `make install`
# time inside a CMake script-mode interpreter, so the file is allowed
# to use string(JSON), file(READ/WRITE), foreach, etc. just like a
# regular CMakeLists.
if(OBN_PATCH_CLIENT_CONF AND (UNIX OR WIN32))
    set(_obn_patch_out
        "${CMAKE_CURRENT_BINARY_DIR}/patch_${OBN_CLIENT_TYPE}_conf.cmake")
    configure_file("${OBN_CLIENT_CONF_PATCH_SCRIPT}"
        "${_obn_patch_out}" @ONLY)
    install(SCRIPT "${_obn_patch_out}")
endif()

# --------------------------------------------------------------------------
# tests (compiled only if BUILD_TESTING is on)
# --------------------------------------------------------------------------

option(OBN_BUILD_TESTS "Build smoke tests" OFF)
if(OBN_BUILD_TESTS)
    enable_testing()
    # probe_plugin is cross-platform: dlopen/dlsym on POSIX,
    # LoadLibrary/GetProcAddress on Windows. It also exercises
    # bambu_network_create_agent so the heap and std::string ABI
    # contracts get validated end-to-end without depending on Studio.
    add_executable(probe_plugin tests/probe_plugin.cpp)
    target_include_directories(probe_plugin PRIVATE include)
    if(NOT WIN32)
        target_link_libraries(probe_plugin PRIVATE dl)
    endif()
    add_test(NAME plugin_symbols
        COMMAND probe_plugin $<TARGET_FILE:bambu_networking>)
endif()
if(OBN_BUILD_TESTS AND NOT WIN32)

    # Live test: skipped unless OBN_PRINTER_IP etc. are exported when ctest
    # runs. Links against the same library as the plugin so it can exercise
    # obn::Agent directly.
    add_executable(ssdp_listener_test tests/ssdp_listener_test.cpp
        src/log.cpp
        src/os_compat.cpp
        src/ssdp.cpp)
    target_include_directories(ssdp_listener_test PRIVATE include)

    add_executable(ftps_live_test tests/ftps_live_test.cpp
        src/ftps.cpp
        src/lan_tls.cpp
        src/log.cpp
        src/os_compat.cpp)
    target_include_directories(ftps_live_test PRIVATE include)
    target_link_libraries(ftps_live_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)

    # Hermetic unit test for src/ftps_parse.hpp. Exercises the `ls -l`
    # parser that populates Entry::mtime -- a regression there causes
    # every file in Studio's storage tab to show up as 1970 (Bambu
    # firmware has no MLSD, so LIST is the only thing we have).
    add_executable(ftps_parse_test tests/ftps_parse_test.cpp
        src/os_compat.cpp)
    target_include_directories(ftps_parse_test PRIVATE include src)
    add_test(NAME ftps_parse COMMAND ftps_parse_test)

    add_executable(remote_name_test tests/remote_name_test.cpp
        src/print_job_naming.cpp)
    target_include_directories(remote_name_test PRIVATE include)
    target_compile_definitions(remote_name_test PRIVATE
        ABI_VERSION=${OBN_ABI_VERSION_HEX})
    add_test(NAME remote_name COMMAND remote_name_test)

    add_executable(print_url_test tests/print_url_test.cpp
        src/print_job_naming.cpp)
    target_include_directories(print_url_test PRIVATE include)
    target_compile_definitions(print_url_test PRIVATE
        ABI_VERSION=${OBN_ABI_VERSION_HEX})
    add_test(NAME print_url COMMAND print_url_test)

    add_executable(tunnel_local_test tests/tunnel_local_test.cpp
        src/tunnel_local.cpp
        src/tls_dial.cpp
        src/lan_tls.cpp
        src/json_lite.cpp
        src/log.cpp
        src/os_compat.cpp)
    target_include_directories(tunnel_local_test PRIVATE include stubs)
    target_link_libraries(tunnel_local_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    add_test(NAME tunnel_local COMMAND tunnel_local_test)

    add_executable(lan_live_test tests/lan_live_test.cpp
        src/agent.cpp
        src/auth.cpp
        src/cert_store.cpp
        src/cloud_auth.cpp
        src/cloud_presets.cpp
        src/cloud_session.cpp
        src/cover_cache.cpp
        src/cover_server.cpp
        src/ftps.cpp
        src/http_client.cpp
        src/json_lite.cpp
        src/lan_session.cpp
        src/lan_tls.cpp
        src/log.cpp
        src/mqtt_client.cpp
        src/print_params_ftp_prefs.cpp
        src/os_compat.cpp
        src/ssdp.cpp
        src/tls_dial.cpp
        src/tunnel_local.cpp
        src/tunnel_upload.cpp)
    target_include_directories(lan_live_test PRIVATE include)
    target_compile_definitions(lan_live_test PRIVATE
        OBN_VERSION_STRING="${OBN_VERSION}"
        ABI_VERSION=${OBN_ABI_VERSION_HEX}
    )
    target_link_libraries(lan_live_test PRIVATE
        obn_mosquitto_iface
        obn_curl_iface
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
    )
    add_test(NAME lan_live COMMAND lan_live_test)
endif()
