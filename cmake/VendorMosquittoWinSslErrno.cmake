# Windows + TLS: keep the real Winsock error for SSL_ERROR_SYSCALL, and make
# the event loop wait for the socket to become writable when TCP is still
# connecting (WSAENOTCONN).
#
# mosquitto_connect_async() + TLS writes the CONNECT packet before TCP is
# up. SSL_write() then reports SSL_ERROR_SYSCALL with WSAENOTCONN.
#
# Two separate holes:
#
# 1. net__handle_ssl() used to overwrite that Winsock error with CRT errno
#    (always 0 on Windows). packet__write() then saw MOSQ_ERR_ERRNO and
#    aborted the half-open socket (upstream #3218).
#
# 2. After (1) is fixed, packet__write() correctly treats WSAENOTCONN as
#    "try later" (upstream #373 / PR #698) — but mosquitto_loop() only
#    polls writefds when want_write is set, and that flag is set only on
#    SSL_ERROR_WANT_WRITE, not on SYSCALL. The connecting socket is
#    watched for readability; TCP completion on Windows is a writable
#    event. The loop then idles until keepalive fires (~20s) and a
#    blocking reconnect succeeds (OBN #38).
#
# Still unfixed upstream as of v2.1.2 / develop.

function(obn_patch_mosquitto_win_ssl_errno _src_root)
    if(NOT IS_DIRECTORY "${_src_root}/lib")
        message(FATAL_ERROR "obn: mosquitto win ssl errno patch: missing lib/ under '${_src_root}'")
    endif()

    set(_errno_mark "obn: win ssl errno")
    set(_wait_mark "obn: win ssl want_write")
    set(_net "${_src_root}/lib/net_mosq.c")
    set(_pkt "${_src_root}/lib/packet_mosq.c")

    file(READ "${_net}" _net_body)
    string(FIND "${_net_body}" "${_wait_mark}" _wait_pos)
    if(_wait_pos LESS 0)
        string(FIND "${_net_body}" "${_errno_mark}" _errno_pos)
        if(_errno_pos LESS 0)
            set(_head "static void net__handle_ssl(struct mosquitto *mosq, int ret)\n{\n\tint err;\n")
            string(FIND "${_net_body}" "${_head}" _pos)
            if(_pos LESS 0)
                message(FATAL_ERROR
                    "obn: mosquitto win ssl errno patch: net__handle_ssl() prologue not "
                    "found in '${_net}' — upstream layout changed, re-check the patch")
            endif()
            string(REPLACE
                "${_head}"
                "${_head}#ifdef WIN32\n\tint obn_wsa_err = WSAGetLastError(); /* ${_errno_mark} */\n#endif\n"
                _net_body "${_net_body}")

            set(_tail "\tERR_clear_error();\n#ifdef WIN32\n\tWSASetLastError(errno);\n#endif\n")
            string(FIND "${_net_body}" "${_tail}" _pos)
            if(_pos LESS 0)
                message(FATAL_ERROR
                    "obn: mosquitto win ssl errno patch: WSASetLastError() epilogue not "
                    "found in '${_net}' — upstream layout changed, re-check the patch")
            endif()
            string(REPLACE
                "${_tail}"
                "\tERR_clear_error();\n#ifdef WIN32\n\t/* ${_errno_mark}: SSL_ERROR_SYSCALL deliberately leaves errno\n\t * alone, and on Windows that means 0, so restore the socket error. */\n\tif(err == SSL_ERROR_SYSCALL){\n\t\tWSASetLastError(obn_wsa_err);\n\t\t/* ${_wait_mark}: TCP is still connecting — wait for writable,\n\t\t * same as SSL_ERROR_WANT_WRITE. Otherwise select() watches only\n\t\t * readfds and we idle until keepalive. */\n\t\tif(obn_wsa_err == WSAENOTCONN || obn_wsa_err == WSAEWOULDBLOCK ||\n\t\t\t\tobn_wsa_err == WSAEINPROGRESS){\n#ifndef WITH_BROKER\n\t\t\tmosq->want_write = true;\n#endif\n\t\t\terrno = EAGAIN;\n\t\t}\n\t}else{\n\t\tWSASetLastError(errno);\n\t}\n#endif\n"
                _net_body "${_net_body}")
        else()
            set(_old_syscall
                "\tif(err == SSL_ERROR_SYSCALL){\n\t\tWSASetLastError(obn_wsa_err);\n\t}else{\n\t\tWSASetLastError(errno);\n\t}\n")
            string(FIND "${_net_body}" "${_old_syscall}" _pos)
            if(_pos LESS 0)
                message(FATAL_ERROR
                    "obn: mosquitto win ssl want_write upgrade: old SYSCALL block not "
                    "found in '${_net}' — re-check the patch")
            endif()
            string(REPLACE
                "${_old_syscall}"
                "\tif(err == SSL_ERROR_SYSCALL){\n\t\tWSASetLastError(obn_wsa_err);\n\t\t/* ${_wait_mark}: TCP is still connecting — wait for writable,\n\t\t * same as SSL_ERROR_WANT_WRITE. Otherwise select() watches only\n\t\t * readfds and we idle until keepalive. */\n\t\tif(obn_wsa_err == WSAENOTCONN || obn_wsa_err == WSAEWOULDBLOCK ||\n\t\t\t\tobn_wsa_err == WSAEINPROGRESS){\n#ifndef WITH_BROKER\n\t\t\tmosq->want_write = true;\n#endif\n\t\t\terrno = EAGAIN;\n\t\t}\n\t}else{\n\t\tWSASetLastError(errno);\n\t}\n"
                _net_body "${_net_body}")
        endif()
        file(WRITE "${_net}" "${_net_body}")
    endif()

    file(READ "${_pkt}" _pkt_body)
    string(FIND "${_pkt_body}" "${_wait_mark}" _pkt_pos)
    if(_pkt_pos GREATER_EQUAL 0)
        return()
    endif()

    set(_pkt_old
        "#ifdef WIN32\n\t\t\t\t\t\t|| errno == WSAENOTCONN\n#endif\n\t\t\t\t\t\t){\n\t\t\t\t\treturn MOSQ_ERR_SUCCESS;\n")
    string(FIND "${_pkt_body}" "${_pkt_old}" _pos)
    if(_pos LESS 0)
        message(FATAL_ERROR
            "obn: mosquitto win ssl want_write patch: WSAENOTCONN branch not "
            "found in '${_pkt}' — upstream layout changed, re-check the patch")
    endif()
    string(REPLACE
        "${_pkt_old}"
        "#ifdef WIN32\n\t\t\t\t\t\t|| errno == WSAENOTCONN\n#endif\n\t\t\t\t\t\t){\n#ifdef WIN32\n\t\t\t\t\t/* ${_wait_mark} */\n\t\t\t\t\tif(errno == WSAENOTCONN){\n#ifndef WITH_BROKER\n\t\t\t\t\t\tmosq->want_write = true;\n#endif\n\t\t\t\t\t}\n#endif\n\t\t\t\t\treturn MOSQ_ERR_SUCCESS;\n"
        _pkt_body "${_pkt_body}")
    file(WRITE "${_pkt}" "${_pkt_body}")
endfunction()
