# OpenSSL 3.5+ (e.g. Fedora 44 openssl-devel) no longer ships openssl/engine.h when
# ENGINE is disabled. Mosquitto v2.1.2 includes it unconditionally; wrap with
# OPENSSL_NO_ENGINE like upstream OpenSSL headers. See:
# https://github.com/ClusterM/open-bambu-networking/issues/19

function(obn_patch_mosquitto_openssl35_engine _src_root)
    if(NOT IS_DIRECTORY "${_src_root}/lib")
        message(FATAL_ERROR "obn: mosquitto patch: missing lib/ under '${_src_root}'")
    endif()

    set(_mark "obn: OpenSSL 3.5 fix")

    set(_h "${_src_root}/lib/tls_mosq.h")
    file(READ "${_h}" _tls)
    string(FIND "${_tls}" "${_mark}" _obn_patch_pos)
    if(_obn_patch_pos LESS 0)
        string(REGEX REPLACE
            "#([ \t]*)include[ \t]*<openssl/engine\\.h>"
            "\n/* ${_mark} */\n#ifndef OPENSSL_NO_ENGINE\n#\\1include <openssl/engine.h>\n#endif"
            _tls "${_tls}")
        file(WRITE "${_h}" "${_tls}")
    endif()

    set(_c "${_src_root}/lib/net_mosq.c")
    file(READ "${_c}" _net)
    string(FIND "${_net}" "${_mark}" _obn_patch_pos)
    if(_obn_patch_pos LESS 0)
        string(REGEX REPLACE
            "#([ \t]*)include[ \t]*<openssl/engine\\.h>"
            "\n/* ${_mark} */\n#ifndef OPENSSL_NO_ENGINE\n#\\1include <openssl/engine.h>\n#endif"
            _net "${_net}")
        file(WRITE "${_c}" "${_net}")
    endif()

    set(_o "${_src_root}/lib/options.c")
    file(READ "${_o}" _opt)
    string(FIND "${_opt}" "${_mark}" _obn_patch_pos)
    if(_obn_patch_pos LESS 0)
        string(REGEX REPLACE
            "#([ \t]*)include[ \t]*<openssl/engine\\.h>"
            "\n/* ${_mark} */\n#ifndef OPENSSL_NO_ENGINE\n#\\1include <openssl/engine.h>\n#endif"
            _opt "${_opt}")
        file(WRITE "${_o}" "${_opt}")
    endif()
endfunction()
