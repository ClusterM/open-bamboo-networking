# Allow TLS hostname/SNI verification against a name different from the TCP
# connect host (Bambu LAN: TCP to IP, verify CN=serial).

function(obn_patch_mosquitto_tls_verify_host _src_root)
    if(NOT IS_DIRECTORY "${_src_root}/lib")
        message(FATAL_ERROR "obn: mosquitto tls_verify_host patch: missing lib/ under '${_src_root}'")
    endif()

    set(_mark "obn: tls_verify_hostname")
    set(_partial_mark "obn: X509_V_FLAG_PARTIAL_CHAIN")

    set(_internal "${_src_root}/lib/mosquitto_internal.h")
    file(READ "${_internal}" _body)
    string(FIND "${_body}" "${_mark}" _pos)
    if(_pos LESS 0)
        string(REPLACE
            "bool tls_insecure;"
            "bool tls_insecure;\n\tchar *tls_verify_hostname; /* ${_mark} */"
            _body "${_body}")
        file(WRITE "${_internal}" "${_body}")
    endif()

    set(_net "${_src_root}/lib/net_mosq.c")
    file(READ "${_net}" _body)
    string(FIND "${_body}" "${_mark}" _pos)
    if(_pos LESS 0)
        string(REPLACE
            "if(SSL_set_tlsext_host_name(mosq->ssl, host) != 1){"
            "const char *tls_host = (mosq->tls_verify_hostname && mosq->tls_verify_hostname[0]) ? mosq->tls_verify_hostname : host; /* ${_mark} */\n\t\tif(SSL_set_tlsext_host_name(mosq->ssl, tls_host) != 1){"
            _body "${_body}")
        string(REPLACE
            "if(tls__set_verify_hostname(mosq, host)){"
            "if(tls__set_verify_hostname(mosq, tls_host)){"
            _body "${_body}")
        file(WRITE "${_net}" "${_body}")
    endif()

    file(READ "${_net}" _body)
    string(FIND "${_body}" "${_partial_mark}" _pos)
    if(_pos LESS 0)
        string(REPLACE
            "#include <openssl/ui.h>"
            "#include <openssl/ui.h>\n#include <openssl/x509v3.h>\n#include <openssl/x509_vfy.h> /* ${_partial_mark} */"
            _body "${_body}")
        string(REPLACE
            "SSL_CTX_set_verify(mosq->ssl_ctx, SSL_VERIFY_PEER, mosquitto__server_certificate_verify);\n\t\t\t}"
            "SSL_CTX_set_verify(mosq->ssl_ctx, SSL_VERIFY_PEER, mosquitto__server_certificate_verify);\n\t\t\t\tX509_VERIFY_PARAM *vpm = SSL_CTX_get0_param(mosq->ssl_ctx); /* ${_partial_mark} */\n\t\t\t\tif(vpm){\n\t\t\t\t\tX509_VERIFY_PARAM_set_flags(vpm, X509_VERIFY_PARAM_get_flags(vpm) | X509_V_FLAG_PARTIAL_CHAIN);\n\t\t\t\tX509_VERIFY_PARAM_set_hostflags(vpm, (X509_VERIFY_PARAM_get_hostflags(vpm) | X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT) & ~X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);\n\t\t\t\t}\n\t\t\t}"
            _body "${_body}")
        file(WRITE "${_net}" "${_body}")
    endif()

    set(_opts "${_src_root}/lib/options.c")
    file(READ "${_opts}" _body)
    string(FIND "${_body}" "mosquitto_tls_verify_hostname_set" _pos)
    if(_pos LESS 0)
        string(REPLACE
            "int mosquitto_tls_insecure_set(struct mosquitto *mosq, bool value)\n{\n#ifdef WITH_TLS\n\tif(!mosq){\n\t\treturn MOSQ_ERR_INVAL;\n\t}\n\tmosq->tls_insecure = value;\n\treturn MOSQ_ERR_SUCCESS;\n#else\n\tUNUSED(mosq);\n\tUNUSED(value);\n\n\treturn MOSQ_ERR_NOT_SUPPORTED;\n#endif\n}\n\n\nint mosquitto_string_option"
            "int mosquitto_tls_insecure_set(struct mosquitto *mosq, bool value)\n{\n#ifdef WITH_TLS\n\tif(!mosq){\n\t\treturn MOSQ_ERR_INVAL;\n\t}\n\tmosq->tls_insecure = value;\n\treturn MOSQ_ERR_SUCCESS;\n#else\n\tUNUSED(mosq);\n\tUNUSED(value);\n\n\treturn MOSQ_ERR_NOT_SUPPORTED;\n#endif\n}\n\n\nint mosquitto_tls_verify_hostname_set(struct mosquitto *mosq, const char *hostname)\n{\n#ifdef WITH_TLS\n\tif(!mosq){\n\t\treturn MOSQ_ERR_INVAL;\n\t}\n\tmosquitto_FREE(mosq->tls_verify_hostname);\n\tif(hostname && hostname[0]){\n\t\tmosq->tls_verify_hostname = mosquitto_strdup(hostname);\n\t\tif(!mosq->tls_verify_hostname){\n\t\t\treturn MOSQ_ERR_NOMEM;\n\t\t}\n\t}else{\n\t\tmosq->tls_verify_hostname = NULL;\n\t}\n\treturn MOSQ_ERR_SUCCESS;\n#else\n\tUNUSED(mosq);\n\tUNUSED(hostname);\n\treturn MOSQ_ERR_NOT_SUPPORTED;\n#endif\n}\n\n\nint mosquitto_string_option"
            _body "${_body}")
        file(WRITE "${_opts}" "${_body}")
    endif()

    set(_tls_h "${_src_root}/include/mosquitto/libmosquitto_tls.h")
    file(READ "${_tls_h}" _body)
    string(FIND "${_body}" "mosquitto_tls_verify_hostname_set" _pos)
    if(_pos LESS 0)
        string(REPLACE
            "libmosq_EXPORT int mosquitto_tls_insecure_set(struct mosquitto *mosq, bool value);\n\n/*"
            "libmosq_EXPORT int mosquitto_tls_insecure_set(struct mosquitto *mosq, bool value);\n\n/* obn: verify hostname separate from TCP connect host */\nlibmosq_EXPORT int mosquitto_tls_verify_hostname_set(struct mosquitto *mosq, const char *hostname);\n\n/*"
            _body "${_body}")
        file(WRITE "${_tls_h}" "${_body}")
    endif()

    set(_lib "${_src_root}/lib/libmosquitto.c")
    file(READ "${_lib}" _body)
    string(FIND "${_body}" "tls_verify_hostname" _pos)
    if(_pos LESS 0)
        string(REPLACE
            "mosquitto_FREE(mosq->tls_alpn);"
            "mosquitto_FREE(mosq->tls_alpn);\n\tmosquitto_FREE(mosq->tls_verify_hostname);"
            _body "${_body}")
        file(WRITE "${_lib}" "${_body}")
    endif()
endfunction()
