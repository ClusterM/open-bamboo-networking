#include "output.h"
#include "logging.h"
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

std::string slurp(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::stringstream ss; ss << f.rdbuf(); return ss.str();
}

bool write_pem_output(const std::string& path,
                      const DRecon& R, const bn::BigInt& N) {
    auto bn_from_bigint = [](const bn::BigInt& x) -> BIGNUM* {
        BIGNUM* b = nullptr;
        std::string h = bn::to_hex_str(x, false);
        BN_hex2bn(&b, h.c_str());
        return b;
    };

    RSA* rsa = RSA_new();
    if (!rsa) { LOG_E("RSA_new failed"); return false; }

    BIGNUM* n  = bn_from_bigint(N);
    BIGNUM* e  = BN_new();
    BIGNUM* d  = bn_from_bigint(R.d);
    BIGNUM* p  = bn_from_bigint(R.p);
    BIGNUM* q  = bn_from_bigint(R.q);
    BIGNUM* dp = bn_from_bigint(R.dp);
    BIGNUM* dq = bn_from_bigint(R.dq);
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* qi  = BN_new();

    if (!n || !e || !d || !p || !q || !dp || !dq || !ctx || !qi) {
        LOG_E("OpenSSL BIGNUM allocation failed");
        BN_free(n); BN_free(e); BN_free(d); BN_free(p); BN_free(q);
        BN_free(dp); BN_free(dq); BN_free(qi); BN_CTX_free(ctx);
        RSA_free(rsa);
        return false;
    }

    BN_set_word(e, 65537);
    if (!BN_mod_inverse(qi, q, p, ctx)) {
        LOG_E("BN_mod_inverse failed");
        BN_free(n); BN_free(e); BN_free(d); BN_free(p); BN_free(q);
        BN_free(dp); BN_free(dq); BN_free(qi); BN_CTX_free(ctx);
        RSA_free(rsa);
        return false;
    }
    BN_CTX_free(ctx);

    RSA_set0_key(rsa, n, e, d);
    RSA_set0_factors(rsa, p, q);
    RSA_set0_crt_params(rsa, dp, dq, qi);

    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        LOG_E("open(%s): %s", path.c_str(), strerror(errno));
        RSA_free(rsa);
        return false;
    }
    FILE* f = fdopen(fd, "w");
    if (!f) { close(fd); RSA_free(rsa); return false; }

    int ok = PEM_write_RSAPrivateKey(f, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    if (!ok) { RSA_free(rsa); LOG_E("PEM_write_RSAPrivateKey failed"); return false; }

    auto slash = path.rfind('/');
    std::string dir = (slash == std::string::npos) ? "." : path.substr(0, slash);

    std::string pubkey_path = dir + "/slicer_pubkey.pem";
    FILE* pf = fopen(pubkey_path.c_str(), "w");
    if (pf) {
        PEM_write_RSA_PUBKEY(pf, rsa);
        fclose(pf);
        LOG_I("slicer_pubkey.pem written: %s", pubkey_path.c_str());
    } else {
        LOG_W("could not write slicer_pubkey.pem: %s", strerror(errno));
    }

    static const char kFallbackCertId[] =
        "a4e8faaa1a38e3650a0ea590d192383f"
        "CN=GLOF3813734089.bambulab.com";
    std::string cert_id_path = dir + "/slicer_cert_id.txt";
    int cifd = open(cert_id_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (cifd >= 0) {
        std::string line = std::string(kFallbackCertId) + "\n";
        (void)write(cifd, line.data(), line.size());
        close(cifd);
        LOG_I("slicer_cert_id.txt written: %s", cert_id_path.c_str());
    }

    RSA_free(rsa);
    return true;
}

bool write_output(const std::string& path,
                  const DRecon& R, const bn::BigInt& N,
                  int env_pass, int env_total) {
    if (path.size() >= 4 && path.compare(path.size() - 4, 4, ".pem") == 0)
        return write_pem_output(path, R, N);

    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        LOG_E("open(%s): %s", path.c_str(), strerror(errno));
        return false;
    }
    std::string body;
    body += "{\n";
    body += "  \"p_hex\":  \"" + bn::to_hex_str(R.p)  + "\",\n";
    body += "  \"q_hex\":  \"" + bn::to_hex_str(R.q)  + "\",\n";
    body += "  \"dp_hex\": \"" + bn::to_hex_str(R.dp) + "\",\n";
    body += "  \"dq_hex\": \"" + bn::to_hex_str(R.dq) + "\",\n";
    body += "  \"d_hex\":  \"" + bn::to_hex_str(R.d)  + "\",\n";
    body += "  \"N_hex\":  \"" + bn::to_hex_str(N)    + "\",\n";
    body += "  \"E\": 65537,\n";
    body += "  \"mode\": \"" + R.mode + "\",\n";
    body += "  \"k_factor\": " + std::to_string(R.k_found) + ",\n";
    body += "  \"envelope_pass_count\": " + std::to_string(env_pass) + ",\n";
    body += "  \"envelope_total\": " + std::to_string(env_total) + ",\n";
    body += "  \"_security\": \"SECRET: slicer RSA-2048 d. Mode 0600.\"\n";
    body += "}\n";
    ssize_t w = write(fd, body.data(), body.size());
    close(fd);
    if (w != (ssize_t)body.size()) {
        LOG_E("short write to %s", path.c_str());
        return false;
    }
    return true;
}
