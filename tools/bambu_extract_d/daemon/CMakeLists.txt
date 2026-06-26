

cmake_minimum_required(VERSION 3.16)
project(bambu_oss LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif ()

add_compile_options(-ffunction-sections -fdata-sections -Os -flto)
add_link_options(-Wl,--gc-sections -flto -Os)

find_package(Threads REQUIRED)

set(BAMBU_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/bambu)

set(BAMBU_SOURCES
    ${BAMBU_DIR}/BambuNetworkingPluginHandle.cpp
    ${BAMBU_DIR}/router/LanUplink.cpp
    ${BAMBU_DIR}/headless/App.cpp
    ${BAMBU_DIR}/headless/SignalHandler.cpp
    ${BAMBU_DIR}/headless/bambu_daemon.cpp
)

add_executable(bambu-daemon ${BAMBU_SOURCES})

target_include_directories(bambu-daemon PRIVATE
    ${BAMBU_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nlohmann/single_include
)

target_link_libraries(bambu-daemon PRIVATE
    Threads::Threads
    ${CMAKE_DL_LIBS}
)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(bambu-daemon PRIVATE -s)
endif ()
