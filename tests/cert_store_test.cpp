#include "obn/cert_store.hpp"
#include "obn/config.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

namespace obn::config {
    Settings& test_settings();
    std::string& test_dir();
}

#define CHECK(cond) do {                                                    \
    if (!(cond)) {                                                          \
        std::cerr << "FAIL " << __FILE__ << ":" << __LINE__                \
                  << ": " #cond "\n";                                       \
        return 1;                                                           \
    }                                                                       \
} while (0)

static EVP_PKEY* gen_key()
{
    return EVP_RSA_gen(2048);
}

static std::string make_self_signed_cert_pem(EVP_PKEY* key, const char* cn)
{
    X509* cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn),
                               -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    X509_NAME_free(name);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_set_pubkey(cert, key);
    X509_sign(cert, key, EVP_sha256());

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);
    BIO_free(bio);
    X509_free(cert);
    return pem;
}

static void write_file(const fs::path& p, const std::string& content)
{
    fs::create_directories(p.parent_path());
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    ofs << content;
}

int main()
{
    fs::path test_root = fs::temp_directory_path() /
        ("obn_cert_test_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(test_root / "certs");
    obn::config::test_dir() = test_root.string();

    EVP_PKEY* key_A = gen_key();
    EVP_PKEY* key_B = gen_key();
    CHECK(key_A && key_B);
    CHECK(EVP_PKEY_cmp(key_A, key_B) == 0); // keys differ

    std::string pem_A = make_self_signed_cert_pem(key_A, "DeviceA");
    std::string pem_B = make_self_signed_cert_pem(key_B, "DeviceB");
    CHECK(!pem_A.empty() && !pem_B.empty());

    // -----------------------------------------------------------------------
    // Test 1: Cold-start disk fallback loads from config_dir/certs/<dev>.pem
    // -----------------------------------------------------------------------
    {
        const std::string dev1 = "DEV_COLD_START";
        fs::path p1 = obn::cert_store::device_cert_path(obn::config::dir(), dev1);
        write_file(p1, pem_A);

        EVP_PKEY* loaded = obn::cert_store::get_printer_pub_key(dev1);
        CHECK(loaded != nullptr);
        CHECK(EVP_PKEY_cmp(loaded, key_A) == 1);
        EVP_PKEY_free(loaded);

        obn::cert_store::forget_printer(dev1);
    }

    // -----------------------------------------------------------------------
    // Test 2: In-memory authoritative key is NOT clobbered by cert on disk
    // -----------------------------------------------------------------------
    {
        const std::string dev2 = "DEV_AUTHORITATIVE";
        fs::path p2 = obn::cert_store::device_cert_path(obn::config::dir(), dev2);
        write_file(p2, pem_B); // Disk has B

        // In-memory gets authoritative device cert A (e.g. from app_cert_install)
        CHECK(obn::cert_store::set_printer_pub_key_from_cert_pem(dev2, pem_A));

        // Connect/reconnect calls prime_pub_key_from_cert_file with disk cert B
        CHECK(obn::cert_store::prime_pub_key_from_cert_file(dev2, p2.string()));

        // In-memory A must win; disk B must NOT clobber A
        EVP_PKEY* k = obn::cert_store::get_printer_pub_key(dev2);
        CHECK(k != nullptr);
        CHECK(EVP_PKEY_cmp(k, key_A) == 1);
        CHECK(EVP_PKEY_cmp(k, key_B) == 0);
        EVP_PKEY_free(k);

        obn::cert_store::forget_printer(dev2);
    }

    // -----------------------------------------------------------------------
    // Test 3: Unparseable/corrupt disk file does not destroy good in-memory key
    // -----------------------------------------------------------------------
    {
        const std::string dev3 = "DEV_CORRUPT_DISK";
        CHECK(obn::cert_store::set_printer_pub_key_from_cert_pem(dev3, pem_A));

        fs::path p3 = obn::cert_store::device_cert_path(obn::config::dir(), dev3);
        write_file(p3, "-----BEGIN CERTIFICATE-----\ncorrupted_data_truncated\n");

        EVP_PKEY* k = obn::cert_store::get_printer_pub_key(dev3);
        CHECK(k != nullptr);
        CHECK(EVP_PKEY_cmp(k, key_A) == 1);
        EVP_PKEY_free(k);

        obn::cert_store::forget_printer(dev3);
    }

    // -----------------------------------------------------------------------
    // Test 4: Negative cache suppresses repeat stat, clears on set
    // -----------------------------------------------------------------------
    {
        const std::string dev4 = "DEV_NEG_CACHE";
        fs::path p4 = obn::cert_store::device_cert_path(obn::config::dir(), dev4);

        // No cert in memory, no file on disk -> null, enters negative cache
        CHECK(obn::cert_store::get_printer_pub_key(dev4) == nullptr);

        // Writing file now should NOT immediately be picked up due to negative cache TTL
        write_file(p4, pem_A);
        CHECK(obn::cert_store::get_printer_pub_key(dev4) == nullptr);

        // set_printer_pub_key_from_cert_pem clears negative cache
        CHECK(obn::cert_store::set_printer_pub_key_from_cert_pem(dev4, pem_A));
        EVP_PKEY* k = obn::cert_store::get_printer_pub_key(dev4);
        CHECK(k != nullptr);
        CHECK(EVP_PKEY_cmp(k, key_A) == 1);
        EVP_PKEY_free(k);

        obn::cert_store::forget_printer(dev4);
    }

    EVP_PKEY_free(key_A);
    EVP_PKEY_free(key_B);

    std::error_code ec;
    fs::remove_all(test_root, ec);

    std::cout << "cert_store_test: ALL TESTS PASSED\n";
    return 0;
}
