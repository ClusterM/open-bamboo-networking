# Bambu Bridge — module CMake.
#
# Phase 0 produced a STATIC library `bambu_bridge` with just Service.
# Phase 1 adds CloudInventory and a small `bridge_cli` executable.
# Phase 2 adds tls/CertFactory (per-device self-signed TLS certs) and
#         picks up an OpenSSL dependency. The find_package() call is at
#         REQUIRED severity so a missing libssl/libcrypto fails at cmake
#         time with a clear message instead of at link time.
# Phase 3 adds server/SsdpResponder (pure POSIX sockets, Linux-only for
#         now). Also gains an `announce` subcommand on bridge_cli.
# Phase 7 adds server/FtpsServer (implicit-TLS FTP on port 990 for slicer
#         .3mf uploads) and the IUploadSink interface plus three sinks
#         (Null/Lan/Cloud). Plus an `ftps` subcommand on bridge_cli that
#         logs received uploads to /tmp/bridge_uploads/.
# Phase 10 adds headless/App + headless/SignalHandler that are
#         consumed by BambuStudio's `--bridge-only` entry point. The
#         multi-device orchestrator walks the cloud inventory and stands
#         up the full SSDP/MQTT/FTPS/RTSP stack for every cloud-bound
#         device with one shared plugin handle. SIGINT/SIGTERM trigger a
#         clean RTSP→FTPS→MQTT→SSDP teardown. There is no standalone
#         daemon binary: the proprietary `bambu_networking` plugin
#         fingerprints its host process and only operates when loaded
#         by BambuStudio.
#
# Standalone configure (no parent project) is preserved so the bridge tree
# can be smoke-built without the full BambuStudio dep stack. Top-level Boost
# 1.83 etc. is not required here.

cmake_minimum_required(VERSION 3.13)

if (NOT DEFINED PROJECT_NAME)
    # Standalone build (no parent project). Bootstrap just enough to produce
    # the library + tests + bridge_cli without dragging in the rest of Slic3r.
    # C is enabled too so the standalone daemon can compile the vendored
    # miniz.c (LanUploadSink's .3mf zip rewriting) directly.
    project(bambu_bridge_standalone CXX C)
    enable_testing()
    set(BAMBU_BRIDGE_STANDALONE TRUE)
else ()
    set(BAMBU_BRIDGE_STANDALONE FALSE)
endif ()

# OpenSSL is mandatory from phase 2 onward (CertFactory needs it; phases
# 4+ will reuse it for the MQTT broker's TLS termination). Fail loudly at
# configure time so missing devel headers don't show up as a link error
# half-way through the build.
find_package(OpenSSL REQUIRED)

# Ship-2: CloudSession + CloudDeviceList make HTTPS calls to api.bambulab.com
# via libcurl. We prefer the parent project's libcurl import target if it's
# already defined (BambuStudio's deps tree provides one named `libcurl`);
# otherwise fall back to find_package(CURL).
if (TARGET libcurl)
    set(BAMBU_BRIDGE_CURL_TARGET libcurl)
else ()
    find_package(CURL REQUIRED)
    set(BAMBU_BRIDGE_CURL_TARGET CURL::libcurl)
endif ()

add_library(bambu_bridge STATIC
    Service.cpp
    Service.hpp
    BambuNetworkingPluginHandle.cpp
    BambuNetworkingPluginHandle.hpp
    BambuSourceHandle.cpp
    BambuSourceHandle.hpp
    CloudInventory.cpp
    CloudInventory.hpp
    CloudSession.cpp
    CloudSession.hpp
    CloudDeviceList.cpp
    CloudDeviceList.hpp
    EncMsgEnvelope.cpp
    EncMsgEnvelope.hpp
    tls/CertFactory.cpp
    tls/CertFactory.hpp
    server/SsdpResponder.cpp
    server/SsdpResponder.hpp
    server/SsdpListener.cpp
    server/SsdpListener.hpp
    server/MqttFraming.cpp
    server/MqttFraming.hpp
    server/MqttBroker.cpp
    server/MqttBroker.hpp
    server/IUplink.hpp
    server/FtpsServer.cpp
    server/FtpsServer.hpp
    server/IUploadSink.hpp
    server/ICameraSource.hpp
    server/RtspServer.cpp
    server/RtspServer.hpp
    server/RtspJpegPacketiser.hpp
    server/PassthroughCameraSource.cpp
    server/PassthroughCameraSource.hpp
    server/VirtualTunnelServer.cpp
    server/VirtualTunnelServer.hpp
    router/NullUplink.cpp
    router/NullUplink.hpp
    router/LanUplink.cpp
    router/LanUplink.hpp
    router/RawMqttPublisher.cpp
    router/RawMqttPublisher.hpp
    router/Tier2Commands.cpp
    router/Tier2Commands.hpp
    router/CloudUplink.cpp
    router/CloudUplink.hpp
    router/NullUploadSink.cpp
    router/NullUploadSink.hpp
    router/LanUploadSink.cpp
    router/LanUploadSink.hpp
    router/CloudUploadSink.cpp
    router/CloudUploadSink.hpp
    router/UploadSpool.cpp
    router/UploadSpool.hpp
    router/NullCameraSource.cpp
    router/NullCameraSource.hpp
    router/LanCameraSource.cpp
    router/LanCameraSource.hpp
    router/CloudCameraSource.cpp
    router/CloudCameraSource.hpp
    router/JpegCameraSource.cpp
    router/JpegCameraSource.hpp
    router/UplinkHealth.cpp
    router/UplinkHealth.hpp
    router/SessionRouter.cpp
    router/SessionRouter.hpp
    router/UploadSinkRouter.cpp
    router/UploadSinkRouter.hpp
    router/CameraSourceRouter.cpp
    router/CameraSourceRouter.hpp
    router/CameraFrameFanout.cpp
    router/CameraFrameFanout.hpp
    router/LocalControlTunnel.cpp
    router/LocalControlTunnel.hpp
    router/NativeStorageDelegate.cpp
    router/NativeStorageDelegate.hpp
    headless/App.cpp
    headless/App.hpp
    headless/AppCliArgs.cpp
    headless/AppCliArgs.hpp
    headless/Launcher.cpp
    headless/Launcher.hpp
    headless/SignalHandler.cpp
    headless/SignalHandler.hpp
)

target_link_libraries(bambu_bridge PUBLIC OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(bambu_bridge PUBLIC ${BAMBU_BRIDGE_CURL_TARGET})

target_include_directories(bambu_bridge
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        # third_party/ holds vendored header-only deps (nlohmann/json). We
        # keep it PRIVATE so callers don't accidentally pin to our vendored
        # copy if the parent project ships its own.
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

set_target_properties(bambu_bridge PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

if (UNIX AND NOT APPLE)
    # libdl for dlopen/dlsym on Linux.
    target_link_libraries(bambu_bridge PUBLIC dl)
endif ()
# Note: previously linked libavcodec / libswscale / libavutil / x264 for the
# MJPEG → H.264 transcoder. The bridge now passes camera frames through
# unchanged (RtspServer's RTP packetiser already handles RFC 6184 H.264 and
# RFC 2435 MJPEG natively); the ffmpeg/x264 deps went away with that.

# pthread is needed for std::mutex on most Linux toolchains.
find_package(Threads QUIET)
if (Threads_FOUND)
    target_link_libraries(bambu_bridge PUBLIC Threads::Threads)
endif ()

# Defensive Windows-side link list. The bridge server's sockets/SSDP/MQTT
# layers go through boost::asio so the slicer pipeline picks ws2_32 +
# crypt32 up transitively from libcurl/wxWidgets today, but anyone
# building bambu_bridge standalone on Windows otherwise hits unresolved
# winsock symbols.
if (WIN32)
    target_link_libraries(bambu_bridge PUBLIC ws2_32 crypt32)
endif ()

# ---- bridge_cli executable ----------------------------------------------
#
# Tiny TSV-emitter for headless inspection of the cloud inventory. The
# binary lives next to the library so phase 12's E2E suite can shell out
# to it.
add_executable(bridge_cli
    cli/cli.cpp
)
target_link_libraries(bridge_cli PRIVATE bambu_bridge)
set_target_properties(bridge_cli PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# ---- bambu-daemon executable -------------------------------------
#
# GUI-free headless entry point. Links ONLY libbambu_bridge.a + OpenSSL +
# libcurl + dl — never libslic3r_gui / wxWidgets / the slicer core. This is
# the small (~2-4 MB) binary whose `main` never reaches the GUI, so the
# static linker drops the 139 MB of reachable GUI code entirely. Drives the
# proprietary plugin's real sign path via a CLI-seeded printer_source
# (--dev-id / --access-code / --lan-ip), bypassing CloudInventory::refresh().
add_executable(bambu-daemon
    headless/bambu_daemon.cpp
    # LanUploadSink.cpp (in libbambu_bridge) uses miniz for .3mf zip
    # rewriting. In the full BambuStudio build miniz comes from the parent
    # project; for a standalone daemon link we compile it in here.
    ${CMAKE_CURRENT_SOURCE_DIR}/../miniz/miniz.c
)
target_link_libraries(bambu-daemon PRIVATE bambu_bridge)
set_target_properties(bambu-daemon PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Skippable in standalone mode: some tests reference slicer sources
# (PrintDispatcher.cpp under src/slic3r/Utils/) via CMAKE_SOURCE_DIR, which
# in a bare bambu_bridge-only configure resolves to the wrong tree and the
# generate step fails. Building JUST the library + daemon doesn't need them,
# so a -DBAMBU_BRIDGE_BUILD_TESTS=OFF configure produces the daemon cleanly.
option(BAMBU_BRIDGE_BUILD_TESTS "Build the bridge unit/E2E tests" ON)
if (BAMBU_BRIDGE_STANDALONE AND BAMBU_BRIDGE_BUILD_TESTS)
    # In standalone mode the parent CMakeLists.txt would normally pull in
    # tests/bridge/ for us; do it here instead so a bare phase-0/1 configure
    # gives runnable tests.
    set(_bridge_tests_dir "${CMAKE_CURRENT_SOURCE_DIR}/../../tests/bridge")
    if (EXISTS "${_bridge_tests_dir}/CMakeLists.txt")
        add_subdirectory("${_bridge_tests_dir}" "${CMAKE_CURRENT_BINARY_DIR}/tests_bridge")
    endif ()
endif ()
