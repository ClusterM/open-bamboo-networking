cmake_minimum_required(VERSION 3.20)
project(open-bambu-networking
    VERSION 0.1.0
    DESCRIPTION "Open-source replacement for Bambu Studio's bambu_networking plugin"
    LANGUAGES CXX
)

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

# Per-client install settings: file name of the .so, OTA manifest layout,
# which conf file the post-install patch script targets, recommended
# default prefix, etc. Populates OBN_CLIENT_* variables in this scope.
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/Clients.cmake")
obn_resolve_client("${OBN_CLIENT_TYPE}")
message(STATUS "obn: client=${OBN_CLIENT_TYPE} plugin=lib${OBN_CLIENT_PLUGIN_NAME}.so")

# Default install location: the per-client config dir on Linux. Honoured
# only when the user did not pass -DCMAKE_INSTALL_PREFIX (the
# CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT flag is unset by CMake the
# moment it picks up an explicit value, including ones cached from a
# previous configure). The top-level ./configure wrapper independently
# computes the same default and passes it via -DCMAKE_INSTALL_PREFIX,
# so this branch only fires for callers that invoke cmake directly.
if(UNIX AND NOT APPLE AND NOT CMAKE_CROSSCOMPILING
   AND CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT
   AND NOT OBN_CLIENT_DEFAULT_PREFIX STREQUAL "")
    set(CMAKE_INSTALL_PREFIX "${OBN_CLIENT_DEFAULT_PREFIX}"
        CACHE PATH "Install prefix (plugins/ under it)" FORCE)
endif()

# When ON, the ft_* C ABI used by Studio's "Send to Printer" dialog and
# the Print job's eMMC pre-flight speaks a real transport instead of
# reporting an immediate I/O error. The transport is FTPS (same one we
# use for LAN print uploads), not the proprietary port-6000 tunnel, so
# only `bambu:///local/*` URLs are served; TUTK/Agora URLs still get
# FT_EIO. With this OFF, every ft_* entry point is a polite-failure
# stub and Studio falls back to its internal FTP path (our
# start_send_gcode_to_sdcard / start_local_print entry points). Both
# modes produce the same file in the same place on the printer; the
# FTPS fastpath gives the more native dialog sequence (ability probe
# / storage picker / percent progress).
option(OBN_FT_FTPS_FASTPATH "Serve ft_* ABI calls over FTPS for LAN URLs" ON)

# Toggles every non-stock behaviour in the plugin. With this ON the plugin
# makes choices the original bambu_networking.so never would in order to
# get Developer-Mode LAN printers (most notably the P2S, which has a USB
# stick in place of an SD card) fully functional in Studio. With this
# OFF the plugin stays a strict drop-in: the same MQTT/HTTP/FTPS/MJPEG
# paths the stock plugin uses, and nothing else. Features that only exist
# via a workaround disappear cleanly (no partial UI, no runtime errors):
#   - push_status `home_flag` SDCARD-bits rewrite (P2S reports NO_SDCARD)
#   - push_status `ipcam.file` block injection (unblocks MediaFilePanel on P2S)
#   - `start_sdcard_print` routed over LAN MQTT instead of the cloud API
#   - RTSPS camera transcode to MJPEG inside libBambuSource
#     (stock pipes H.264 straight to Studio's gstbambusrc)
#   - PrinterFileSystem CTRL bridge served from a worker thread over FTPS
#     (stock speaks a proprietary port-6000 CTRL protocol)
# See "What works" and "Workaround reference" in README.md.
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
# The patch only runs when the install prefix is a default config dir
# for the selected --client-type; if you installed into a staging tree
# with --prefix=..., the per-user config is untouched regardless of
# this flag. A backup file (*.obn-bak) is written whenever the file
# actually changes.
#
# OBN_PATCH_STUDIO_CONF is kept as a backward-compat alias -- existing
# CMake caches set the old name and we want them to keep working.
option(OBN_PATCH_CLIENT_CONF
    "Edit the slicer's conf file after install" ON)
if(DEFINED OBN_PATCH_STUDIO_CONF AND NOT DEFINED CACHE{OBN_PATCH_CLIENT_CONF})
    set(OBN_PATCH_CLIENT_CONF "${OBN_PATCH_STUDIO_CONF}" CACHE BOOL
        "Edit the slicer's conf file after install" FORCE)
endif()

# When ON, pkg-config resolves libmosquitto with --static (Libs.private,
# transitive deps). Ignored when OBN_VENDOR_MOSQUITTO is ON.
option(OBN_STATIC_MOSQUITTO "Link libmosquitto via pkg-config --static" OFF)

# Fetch and build eclipse/mosquitto as a static PIC library — no libmosquitto-dev
# or libmosquitto.a on the host. Requires Git and network at configure time.
option(OBN_VENDOR_MOSQUITTO "Bundle libmosquitto via FetchContent (static PIC)" OFF)
set(OBN_MOSQUITTO_GIT_TAG "v2.1.2"
    CACHE STRING "Git tag for eclipse/mosquitto when OBN_VENDOR_MOSQUITTO is ON")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
# Bambu Studio is built against libstdc++ new C++11 ABI; match it.
add_compile_definitions(_GLIBCXX_USE_CXX11_ABI=1)

add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-unused-variable)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Hide every symbol by default, explicitly export only the ABI functions via
# __attribute__((visibility("default"))). Keeps the library slim and avoids
# name clashes with Studio's own symbols.
add_compile_options(
    -fvisibility=hidden
    $<$<COMPILE_LANGUAGE:CXX>:-fvisibility-inlines-hidden>
)

# --------------------------------------------------------------------------
# libbambu_networking.so  (main plugin)
# --------------------------------------------------------------------------

find_package(PkgConfig REQUIRED)
find_package(OpenSSL COMPONENTS SSL REQUIRED)

if(OBN_VENDOR_MOSQUITTO AND OBN_STATIC_MOSQUITTO)
    message(WARNING
        "OBN_VENDOR_MOSQUITTO and OBN_STATIC_MOSQUITTO are both ON — "
        "using the bundled mosquitto build; system static libmosquitto (pkg-config) is ignored.")
endif()

if(OBN_VENDOR_MOSQUITTO)
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/VendorMosquitto.cmake")
    obn_vendor_mosquitto_setup()
elseif(OBN_STATIC_MOSQUITTO)
    pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)
    set(_obn_prev_lib_suffix "${CMAKE_FIND_LIBRARY_SUFFIXES}")
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    find_library(MOSQUITTO_STATIC_ARCHIVE NAMES mosquitto
        PATHS ${MOSQUITTO_LIBRARY_DIRS}
        NO_DEFAULT_PATH)
    if(NOT MOSQUITTO_STATIC_ARCHIVE)
        find_library(MOSQUITTO_STATIC_ARCHIVE NAMES mosquitto)
    endif()
    set(CMAKE_FIND_LIBRARY_SUFFIXES "${_obn_prev_lib_suffix}")
    if(NOT MOSQUITTO_STATIC_ARCHIVE OR NOT MOSQUITTO_STATIC_ARCHIVE MATCHES "\\.a$")
        message(FATAL_ERROR
            "OBN_STATIC_MOSQUITTO is ON but libmosquitto.a was not found "
            "(resolved '${MOSQUITTO_STATIC_ARCHIVE}'). Many distros ship only "
            "the shared library in libmosquitto-dev — build mosquitto with "
            "BUILD_SHARED_LIBS=OFF or pass -DOBN_STATIC_MOSQUITTO=OFF.")
    endif()
    execute_process(
        COMMAND "${PKG_CONFIG_EXECUTABLE}" --static --libs libmosquitto
        OUTPUT_VARIABLE _obn_mosq_ldflags
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE _obn_mosq_ld_rc)
    if(NOT _obn_mosq_ld_rc EQUAL 0)
        message(FATAL_ERROR "pkg-config --static --libs libmosquitto failed (code ${_obn_mosq_ld_rc})")
    endif()
    string(REGEX REPLACE "-lmosquitto(\\s|$)" "${MOSQUITTO_STATIC_ARCHIVE}\\1"
        _obn_mosq_ldflags "${_obn_mosq_ldflags}")
    separate_arguments(_obn_mosq_link UNIX_COMMAND "${_obn_mosq_ldflags}")
    message(STATUS "obn: linking libmosquitto statically (${MOSQUITTO_STATIC_ARCHIVE})")
else()
    pkg_check_modules(MOSQUITTO REQUIRED IMPORTED_TARGET libmosquitto)
endif()

if(NOT OBN_VENDOR_MOSQUITTO)
    add_library(obn_mosquitto_iface INTERFACE)
    if(OBN_STATIC_MOSQUITTO)
        target_include_directories(obn_mosquitto_iface INTERFACE ${MOSQUITTO_INCLUDE_DIRS})
        target_link_libraries(obn_mosquitto_iface INTERFACE ${_obn_mosq_link})
    else()
        target_link_libraries(obn_mosquitto_iface INTERFACE PkgConfig::MOSQUITTO)
    endif()
endif()

pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
# zlib is shared between bambu_networking (cover_cache: unpacks
# Metadata/plate_N.png out of /cache/<name>.3mf to show it as the
# printing-task thumbnail) and BambuSource (same unpack, but for the
# file browser).
find_package(ZLIB REQUIRED)

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
    src/lan_session.cpp
    src/log.cpp
    src/mqtt_client.cpp
    src/print_job.cpp
    src/ssdp.cpp
    src/zip_reader.cpp
)

target_include_directories(bambu_networking PRIVATE include)
target_compile_definitions(bambu_networking PRIVATE
    OBN_VERSION_STRING="${OBN_VERSION}"
    ABI_VERSION=${OBN_ABI_VERSION_HEX}
    OBN_FT_FTPS_FASTPATH=$<BOOL:${OBN_FT_FTPS_FASTPATH}>
    OBN_ENABLE_WORKAROUNDS=$<BOOL:${OBN_ENABLE_WORKAROUNDS}>
)
target_link_libraries(bambu_networking PRIVATE
    obn_mosquitto_iface
    PkgConfig::CURL
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
)

# No "lib" prefix rename: output is literally "libbambu_networking.so"
set_target_properties(bambu_networking PROPERTIES
    OUTPUT_NAME "bambu_networking"
    PREFIX      "lib"
)

# --------------------------------------------------------------------------
# libBambuSource.so  (camera tunnel + PrinterFileSystem CTRL bridge;
# consumed by Studio's gstbambusrc element on Linux/Windows and by
# wxMediaCtrl2.mm on macOS).
# --------------------------------------------------------------------------

# Picks the RTSPS backend used to demux H.264 + transcode to MJPEG:
#   ffmpeg - in-process RTSP/RTSPS client (custom, stubs/rtsp_client.cpp)
#            + libavcodec H.264 decode + libswscale + stb_image_write
#            baseline JPEG encode. NO libavformat dependency, and no
#            libavcodec encoder dependency (Studio's bundled libavcodec
#            ships decoder-only, so avcodec_find_encoder returns NULL
#            in-process). libav* symbols are resolved via
#            dlsym(RTLD_DEFAULT, ...) against whatever Studio's bundle
#            has already loaded -- guaranteed ABI match against the
#            AppImage's bundled libav minor. Default; smallest runtime
#            footprint; works on macOS too.
#   none   - no RTSPS support; only the MJPG path (port 6000) and the
#            file-browser CTRL bridge work. Useful for small builds
#            that don't ship live view.
#
# A GStreamer backend used to live here (rtspsrc -> jpegenc pipeline)
# but was removed once the FFmpeg one stabilised: it always aborted
# inside Studio's AppImage with a libjpeg ABI clash we could not fix
# from outside Studio's bundle, and the FFmpeg path turned out to work
# everywhere we tried it.
set(OBN_VIDEO_BACKEND "ffmpeg" CACHE STRING
    "RTSPS video backend for libBambuSource (ffmpeg | none)")
set_property(CACHE OBN_VIDEO_BACKEND PROPERTY STRINGS ffmpeg none)
if(NOT OBN_VIDEO_BACKEND MATCHES "^(ffmpeg|none)$")
    message(FATAL_ERROR
        "OBN_VIDEO_BACKEND must be 'ffmpeg' or 'none' "
        "(got '${OBN_VIDEO_BACKEND}').")
endif()
message(STATUS "obn: video backend = ${OBN_VIDEO_BACKEND}")

# zlib is pulled in for the Metadata/plate_*.png unpacker used by
# PrinterFileSystem to serve 3mf thumbnails directly from FTPS.
find_package(ZLIB REQUIRED)

# Image decode/encode for the thumbnail letterbox path AND for the
# RTSPS pipeline's JPEG re-encode are both handled by the vendored
# stb_image / stb_image_write headers under stubs/third_party/. We
# deliberately do *not* link libpng / libjpeg into BambuSource: see
# stubs/image_io.hpp for why (libjpeg-turbo ABI tag mismatch with
# Studio's bundled GStreamer plugins inside the same process; even
# though we no longer use GStreamer ourselves, Studio still loads
# its own copy and aborts if its libjpeg sees ours), and the comment
# block in stubs/BambuSource.cpp around
# `using DecodedRGBA = obn::image::DecodedRGBA;`.

# BambuSource ships the PrinterFileSystem CTRL bridge (FTPS-backed file
# browser for X1/P1S/P2S/A-series in LAN mode), so it needs ftps + json +
# log from the core tree. Compile them in directly instead of linking
# against libbambu_networking to keep the shared-object self-contained
# (Studio dlopens BambuSource *before* it loads the network plugin).
set(_obn_bambusource_sources
    stubs/BambuSource.cpp
    stubs/image_io.cpp
    stubs/source_log.cpp
    stubs/tls_socket.cpp
    src/ftps.cpp
    src/json_lite.cpp
    src/log.cpp
    src/zip_reader.cpp
)

# stb_image_write triggers -Wmissing-field-initializers on the
# stbi__write_context partial brace initialiser. It is upstream code
# we do not want to patch; isolate the warning suppression to the
# translation unit that includes the stb implementations.
set_source_files_properties(stubs/image_io.cpp PROPERTIES
    COMPILE_FLAGS "-Wno-missing-field-initializers")
if(OBN_VIDEO_BACKEND STREQUAL "ffmpeg")
    # The FFmpeg backend is now a custom RTSP/RTSPS client (rtsp_client)
    # plus H.264 decode + libswscale + baseline JPEG encode (h264_decoder
    # routes the decoded RGB through obn::image::encode_jpeg / stb).
    # libavcodec / libavutil / libswscale are resolved through ffmpeg_dyn
    # (dlsym against whatever Studio's bundle has loaded -- see
    # stubs/ffmpeg_dyn.hpp). Two FFmpeg things we deliberately do *not*
    # depend on:
    #   * libavformat -- replaced by our own RTSP client. The ABI clash
    #     that motivated all the dlmopen / namespace work was a
    #     libavutil-vs-libavformat version mismatch we side-step by not
    #     depending on libavformat anymore.
    #   * the libavcodec MJPEG encoder -- Studio's libavcodec ships
    #     decoder-only (avcodec_find_encoder returns NULL), so we use
    #     stb_image_write instead. Its only dependency is image_io.cpp,
    #     which is already in the source list above.
    list(APPEND _obn_bambusource_sources
        stubs/video_pipeline_libav.cpp
        stubs/rtsp_client.cpp
        stubs/h264_decoder.cpp
        stubs/ffmpeg_dyn.cpp)
else()
    list(APPEND _obn_bambusource_sources stubs/video_pipeline_none.cpp)
endif()

# macOS specifically: Studio's wxMediaCtrl2.mm dlsym's an Objective-C
# class `BambuPlayer` out of libBambuSource.dylib for the camera
# widget. Without it the camera widget sits in MEDIASTATE_LOADING
# forever (see stubs/BambuPlayer.mm for the full story). The
# Objective-C class also pulls in a small MJPG reader (port-6000
# protocol, see stubs/mjpg_reader.cpp) so the BambuPlayer doesn't
# have to share the C-ABI tunnel state inside BambuSource.cpp.
if(APPLE)
    enable_language(OBJCXX)
    list(APPEND _obn_bambusource_sources
        stubs/BambuPlayer.mm
        stubs/mjpg_reader.cpp
    )
endif()

add_library(BambuSource SHARED ${_obn_bambusource_sources})
target_include_directories(BambuSource PRIVATE include stubs)
target_compile_definitions(BambuSource PRIVATE
    OBN_ENABLE_WORKAROUNDS=$<BOOL:${OBN_ENABLE_WORKAROUNDS}>
)
set_target_properties(BambuSource PROPERTIES OUTPUT_NAME "BambuSource" PREFIX "lib")
target_link_libraries(BambuSource PRIVATE
    OpenSSL::SSL OpenSSL::Crypto
    ZLIB::ZLIB
)

if(APPLE)
    # ARC for the Objective-C class so we don't have to track retains
    # by hand. The OrcaSlicer caller is non-ARC and explicitly invokes
    # -dealloc; that interplay is documented in stubs/BambuPlayer.mm.
    set_source_files_properties(stubs/BambuPlayer.mm PROPERTIES
        COMPILE_FLAGS "-fobjc-arc")
    # Cocoa view + AVSampleBufferDisplayLayer + CGImage / ImageIO are
    # the bare-minimum frameworks for the rendering path.
    target_link_libraries(BambuSource PRIVATE
        "-framework Foundation"
        "-framework QuartzCore"
        "-framework AppKit"
        "-framework AVFoundation"
        "-framework CoreMedia"
        "-framework CoreVideo"
        "-framework CoreGraphics"
        "-framework ImageIO")
    # On macOS the dylib's filename Studio looks for is
    # libBambuSource.dylib; CMake already picks .dylib on Apple but
    # be explicit so a future BUILD_SHARED_LIBS=NO override doesn't
    # accidentally produce a static archive.
    set_target_properties(BambuSource PROPERTIES SUFFIX ".dylib")
endif()

if(OBN_VIDEO_BACKEND STREQUAL "ffmpeg")
    # libavcodec / libavutil / libswscale headers only -- enough for
    # the AVFrame / AVCodecContext / AVPixelFormat types and for the
    # AV_LOG_*, AV_PIX_FMT_*, FF_QP2LAMBDA, AV_INPUT_BUFFER_PADDING_SIZE
    # macros our decoder + scaler + MJPEG encoder depend on. The actual
    # libraries are NEVER linked: at runtime ffmpeg_dyn.cpp resolves
    # the symbols via dlsym(RTLD_DEFAULT, ...), picking up whatever
    # libav copies Bambu Studio's bundle has already DT_NEEDED'd into
    # the process. That guarantees ABI compatibility with whatever
    # libavutil/libavcodec minor pair Studio shipped, even when the
    # build host's system libav is a different release. libavformat is
    # not used anywhere in the plugin -- the RTSP / RTSPS protocol is
    # implemented in stubs/rtsp_client.cpp -- so we deliberately do
    # NOT pkg_check_modules it here; build hosts can be missing
    # libavformat-dev entirely.
    pkg_check_modules(AVCODEC   REQUIRED libavcodec)
    pkg_check_modules(AVUTIL    REQUIRED libavutil)
    pkg_check_modules(SWSCALE   REQUIRED libswscale)
    target_include_directories(BambuSource PRIVATE
        ${AVCODEC_INCLUDE_DIRS}
        ${AVUTIL_INCLUDE_DIRS}
        ${SWSCALE_INCLUDE_DIRS}
    )
    target_link_libraries(BambuSource PRIVATE ${CMAKE_DL_LIBS})
endif()

# --------------------------------------------------------------------------
# liblive555.so  (stub; used by the real BambuSource internally)
# --------------------------------------------------------------------------

add_library(live555 SHARED stubs/live555.cpp)
set_target_properties(live555 PROPERTIES OUTPUT_NAME "live555" PREFIX "lib")

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

# BambuSource and live555 always ship under their stock names -- both
# slicers dlopen them by fixed file name. The main plugin .so file
# differs by client:
#   bambu_studio -> libbambu_networking.so          (fixed name)
#   orca_slicer  -> libbambu_networking_<VER>.so    (Orca dlopens
#                   "libbambu_networking_${network_plugin_version}.so",
#                   so the file name carries the version. We rename
#                   our build artefact at install time so the source
#                   tree still produces a single libbambu_networking.so
#                   regardless of OBN_CLIENT_TYPE.)
install(TARGETS BambuSource live555
    LIBRARY DESTINATION plugins
)
if(OBN_CLIENT_PLUGIN_NAME STREQUAL "bambu_networking")
    install(TARGETS bambu_networking
        LIBRARY DESTINATION plugins
    )
else()
    install(FILES $<TARGET_FILE:bambu_networking>
        DESTINATION plugins
        RENAME "lib${OBN_CLIENT_PLUGIN_NAME}.so")
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
if(OBN_PATCH_CLIENT_CONF AND UNIX AND NOT APPLE)
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
    add_executable(probe_plugin tests/probe_plugin.cpp)
    target_include_directories(probe_plugin PRIVATE include)
    target_link_libraries(probe_plugin PRIVATE dl)
    add_test(NAME plugin_symbols
        COMMAND probe_plugin $<TARGET_FILE:bambu_networking>)

    # Live test: skipped unless OBN_PRINTER_IP etc. are exported when ctest
    # runs. Links against the same library as the plugin so it can exercise
    # obn::Agent directly.
    add_executable(ssdp_listener_test tests/ssdp_listener_test.cpp
        src/log.cpp
        src/ssdp.cpp)
    target_include_directories(ssdp_listener_test PRIVATE include)

    add_executable(ftps_live_test tests/ftps_live_test.cpp
        src/ftps.cpp
        src/log.cpp)
    target_include_directories(ftps_live_test PRIVATE include)
    target_link_libraries(ftps_live_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)

    # Hermetic unit test for src/ftps_parse.hpp. Exercises the `ls -l`
    # parser that populates Entry::mtime -- a regression there causes
    # every file in Studio's storage tab to show up as 1970 (Bambu
    # firmware has no MLSD, so LIST is the only thing we have).
    add_executable(ftps_parse_test tests/ftps_parse_test.cpp)
    target_include_directories(ftps_parse_test PRIVATE include src)
    add_test(NAME ftps_parse COMMAND ftps_parse_test)

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
        src/log.cpp
        src/mqtt_client.cpp
        src/ssdp.cpp
        src/zip_reader.cpp)
    target_include_directories(lan_live_test PRIVATE include)
    target_compile_definitions(lan_live_test PRIVATE
        OBN_VERSION_STRING="${OBN_VERSION}"
        ABI_VERSION=${OBN_ABI_VERSION_HEX}
    )
    target_link_libraries(lan_live_test PRIVATE
        obn_mosquitto_iface
        PkgConfig::CURL
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
    )
    add_test(NAME lan_live COMMAND lan_live_test)
endif()
