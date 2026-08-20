# Keep the real Winsock error for SSL_ERROR_SYSCALL instead of overwriting it
# with CRT errno, which is always 0 on Windows for socket failures.
#
# Without this, mosquitto_connect_async() + TLS fails instantly on Windows:
# the non-blocking connect() is still pending when send__connect() writes the
# CONNECT packet inline (packet__queue does that while mosq->threaded is
# mosq_ts_none, i.e. before mosquitto_loop_start()), SSL_write() reports
# SSL_ERROR_SYSCALL with WSAENOTCONN, net__handle_ssl() replaces that error
# with 0, and the WSAENOTCONN branch in packet__write() — added upstream
# precisely to tolerate this case for plain TCP (issue #373, PR #698) — no
# longer matches. mosquitto then treats it as MOSQ_ERR_ERRNO, tears down the
# half-open socket, and a P1-series printer left with an aborted TLS handshake
# stops accepting connections for ~20s (OBN issues #34, #38).
#
# Still unfixed upstream as of v2.1.2 / develop (eclipse-mosquitto/mosquitto
# issue #3218).

function(obn_patch_mosquitto_win_ssl_errno _src_root)
    if(NOT IS_DIRECTORY "${_src_root}/lib")
        message(FATAL_ERROR "obn: mosquitto win ssl errno patch: missing lib/ under '${_src_root}'")
    endif()

    set(_mark "obn: win ssl errno")
    set(_net "${_src_root}/lib/net_mosq.c")
    file(READ "${_net}" _body)
    string(FIND "${_body}" "${_mark}" _pos)
    if(_pos GREATER_EQUAL 0)
        return()
    endif()

    set(_head "static void net__handle_ssl(struct mosquitto *mosq, int ret)\n{\n\tint err;\n")
    string(FIND "${_body}" "${_head}" _pos)
    if(_pos LESS 0)
        message(FATAL_ERROR
            "obn: mosquitto win ssl errno patch: net__handle_ssl() prologue not "
            "found in '${_net}' — upstream layout changed, re-check the patch")
    endif()
    string(REPLACE
        "${_head}"
        "${_head}#ifdef WIN32\n\tint obn_wsa_err = WSAGetLastError(); /* ${_mark} */\n#endif\n"
        _body "${_body}")

    set(_tail "\tERR_clear_error();\n#ifdef WIN32\n\tWSASetLastError(errno);\n#endif\n")
    string(FIND "${_body}" "${_tail}" _pos)
    if(_pos LESS 0)
        message(FATAL_ERROR
            "obn: mosquitto win ssl errno patch: WSASetLastError() epilogue not "
            "found in '${_net}' — upstream layout changed, re-check the patch")
    endif()
    string(REPLACE
        "${_tail}"
        "\tERR_clear_error();\n#ifdef WIN32\n\t/* ${_mark}: SSL_ERROR_SYSCALL deliberately leaves errno\n\t * alone, and on Windows that means 0, so restore the socket error the\n\t * caller still needs (e.g. WSAENOTCONN, tolerated by packet__write). */\n\tif(err == SSL_ERROR_SYSCALL){\n\t\tWSASetLastError(obn_wsa_err);\n\t}else{\n\t\tWSASetLastError(errno);\n\t}\n#endif\n"
        _body "${_body}")

    file(WRITE "${_net}" "${_body}")
endfunction()
