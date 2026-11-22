# Allow TLS hostname/SNI verification against a name different from the TCP
# connect host (Bambu LAN: TCP to IP, verify CN=serial).

function(obn_patch_mosquitto_tls_verify_host _src_root)
    if(NOT IS_DIRECTORY "${_src_root}/lib")
        message(FATAL_ERROR "obn: mosquitto tls_verify_host patch: missing lib/ under '${_src_root}'")
    endif()

    set(_mark "obn: tls_verify_hostname")
    set(_partial_mark "obn: X509_V_FLAG_PARTIAL_CHAIN")
    set(_hostflags_mark "obn: ALWAYS_CHECK_SUBJECT for LAN only")

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

    # Verify-param block on mosq->ssl_ctx. Re-runs on every configure (the
    # FetchContent POPULATED guard in VendorMosquitto.cmake is per-cmake-run,
    # not per source tree), so it has to recognise trees patched by an older
    # OBN and upgrade them in place — otherwise a reused build directory keeps
    # the old policy while a clean one gets the new (#157).
    set(_set_flags "\t\t\t\t\tX509_VERIFY_PARAM_set_flags(vpm, X509_VERIFY_PARAM_get_flags(vpm) | X509_V_FLAG_PARTIAL_CHAIN);\n")
    # ALWAYS_CHECK_SUBJECT is for the LAN printer only: its leaf is CN=<serial>
    # with no subjectAltName, and OpenSSL 4.1 stopped consulting the subject DN.
    # Cloud MQTT keeps the default SAN-only policy — there the flag would let a
    # trusted certificate whose CN matches the broker pass with mismatched SANs.
    # mosq->tls_verify_hostname is set (LAN) or left NULL (cloud) by
    # obn::mqtt::Client::connect() before mosquitto_connect() builds the ctx.
    set(_host_flags "\t\t\t\t\tif(mosq->tls_verify_hostname && mosq->tls_verify_hostname[0]){ /* ${_hostflags_mark} */\n\t\t\t\t\t\tX509_VERIFY_PARAM_set_hostflags(vpm, X509_VERIFY_PARAM_get_hostflags(vpm) | X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT);\n\t\t\t\t\t}\n")
    # Ungated host flags as first shipped in #157, before the LAN/cloud split.
    set(_host_flags_v1 "\t\t\t\tX509_VERIFY_PARAM_set_hostflags(vpm, (X509_VERIFY_PARAM_get_hostflags(vpm) | X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT) & ~X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);\n")

    file(READ "${_net}" _body)
    string(FIND "${_body}" "${_hostflags_mark}" _pos)
    if(_pos LESS 0)
        string(FIND "${_body}" "${_host_flags_v1}" _v1_pos)
        string(FIND "${_body}" "${_partial_mark}" _partial_pos)
        if(_v1_pos GREATER_EQUAL 0)
            string(REPLACE "${_host_flags_v1}" "${_host_flags}" _body "${_body}")
        elseif(_partial_pos GREATER_EQUAL 0)
            string(FIND "${_body}" "${_set_flags}" _pos)
            if(_pos LESS 0)
                message(FATAL_ERROR
                    "obn: mosquitto host flags upgrade: PARTIAL_CHAIN block not found "
                    "in '${_net}' — re-check the patch")
            endif()
            string(REPLACE "${_set_flags}" "${_set_flags}${_host_flags}" _body "${_body}")
        else()
            set(_anchor "SSL_CTX_set_verify(mosq->ssl_ctx, SSL_VERIFY_PEER, mosquitto__server_certificate_verify);\n\t\t\t}")
            string(FIND "${_body}" "${_anchor}" _pos)
            if(_pos LESS 0)
                message(FATAL_ERROR
                    "obn: mosquitto verify-param patch: SSL_CTX_set_verify() call not "
                    "found in '${_net}' — upstream layout changed, re-check the patch")
            endif()
            string(REPLACE
                "${_anchor}"
                "SSL_CTX_set_verify(mosq->ssl_ctx, SSL_VERIFY_PEER, mosquitto__server_certificate_verify);\n\t\t\t\tX509_VERIFY_PARAM *vpm = SSL_CTX_get0_param(mosq->ssl_ctx); /* ${_partial_mark} */\n\t\t\t\tif(vpm){\n${_set_flags}${_host_flags}\t\t\t\t}\n\t\t\t}"
                _body "${_body}")
        endif()
        # Separately idempotent: a tree patched before #157 already has
        # x509v3.h but not x509_vfy.h, where the host-flag accessors live.
        # Reverse order: each one is inserted right after ui.h.
        foreach(_hdr "openssl/x509_vfy.h" "openssl/x509v3.h")
            string(FIND "${_body}" "${_hdr}" _pos)
            if(_pos LESS 0)
                string(REPLACE
                    "#include <openssl/ui.h>"
                    "#include <openssl/ui.h>\n#include <${_hdr}> /* ${_partial_mark} */"
                    _body "${_body}")
            endif()
        endforeach()
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
