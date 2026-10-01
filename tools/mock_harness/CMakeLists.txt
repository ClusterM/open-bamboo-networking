# Standalone project for the clean-room :3000 detect sidecar (plan 04-02).
# Lives under tools/mock_harness/ so the sidecar builds WITHOUT configuring
# the repo root CMakeLists (root build files stay untouched -- D-08/D-10).
#
# The source closure mirrors the proven lan_bind_tcp_test target in the root
# CMakeLists.txt (same six sources, include dirs, ABI_VERSION define and
# OpenSSL link): detect_responder only needs our own obn::lan_bind_tcp codec
# and obn::json -- no curl, no minizip, no plugin code.
cmake_minimum_required(VERSION 3.20)
project(mock_harness LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

# Same shape as tools/plugin_runner/CMakeLists.txt: the ABI macro gates
# include/obn/bambu_networking.hpp layout. Default matches the OQ3 pin
# (--abi 02.08.01); override with -DOBN_ABI_VERSION_HEX=0xMMmmpp.
set(OBN_ABI_VERSION_HEX "0x020801" CACHE STRING
    "Hex literal for ABI_VERSION (e.g. 0x020801).")

find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)

set(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

# Mirror the root configure_file block (CMakeLists.txt:87-99): config.cpp
# includes obn_conf_default.h, generated from packaging/obn.conf.in at
# configure time.
set(OBN_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${OBN_GENERATED_DIR}")
file(READ "${REPO_ROOT}/packaging/obn.conf.in" OBN_CONF_DEFAULT_TEMPLATE)
configure_file(
    "${REPO_ROOT}/cmake/obn_conf_default.h.in"
    "${OBN_GENERATED_DIR}/obn_conf_default.h"
    @ONLY)

add_executable(detect_responder
    detect_responder.cpp
    ${REPO_ROOT}/src/lan_bind_tcp.cpp
    ${REPO_ROOT}/src/config.cpp
    ${REPO_ROOT}/src/json_lite.cpp
    ${REPO_ROOT}/src/lan_tls.cpp
    ${REPO_ROOT}/src/log.cpp
    ${REPO_ROOT}/src/os_compat.cpp
)

target_include_directories(detect_responder PRIVATE
    ${REPO_ROOT}/include
    ${OBN_GENERATED_DIR}
)

target_compile_definitions(detect_responder PRIVATE
    ABI_VERSION=${OBN_ABI_VERSION_HEX}
)

target_link_libraries(detect_responder PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

message(STATUS "detect_responder: ABI_VERSION=${OBN_ABI_VERSION_HEX}")
