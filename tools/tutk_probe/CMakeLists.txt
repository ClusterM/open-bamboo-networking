cmake_minimum_required(VERSION 3.20)
project(tutk_probe LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

add_executable(tutk_probe main.cpp)
target_compile_options(tutk_probe PRIVATE -Wall -Wextra)
target_link_libraries(tutk_probe PRIVATE dl pthread)
