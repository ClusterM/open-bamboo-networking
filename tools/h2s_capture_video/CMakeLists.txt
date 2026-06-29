add_executable(h2s_capture_video
    main.cpp
    ${CMAKE_SOURCE_DIR}/src/config.cpp
    ${CMAKE_SOURCE_DIR}/src/json_lite.cpp
    ${CMAKE_SOURCE_DIR}/src/lan_tls.cpp
    ${CMAKE_SOURCE_DIR}/src/log.cpp
    ${CMAKE_SOURCE_DIR}/src/net_compat.cpp
    ${CMAKE_SOURCE_DIR}/src/os_compat.cpp
    ${CMAKE_SOURCE_DIR}/src/tls_dial.cpp
    ${CMAKE_SOURCE_DIR}/src/tunnel_local.cpp
)
target_include_directories(h2s_capture_video PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${OBN_GENERATED_DIR}
)
target_link_libraries(h2s_capture_video PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_compile_features(h2s_capture_video PRIVATE cxx_std_17)
