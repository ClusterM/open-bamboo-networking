add_executable(tutk_lan_probe
    main.cpp
    ${CMAKE_SOURCE_DIR}/src/camera/oss_tutk/IotcClient.cpp
    ${CMAKE_SOURCE_DIR}/src/log.cpp
    ${CMAKE_SOURCE_DIR}/src/os_compat.cpp
)
target_include_directories(tutk_lan_probe PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${OBN_GENERATED_DIR}
)
target_link_libraries(tutk_lan_probe PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread)
target_compile_features(tutk_lan_probe PRIVATE cxx_std_17)
