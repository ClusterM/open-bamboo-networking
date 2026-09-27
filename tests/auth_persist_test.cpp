// Hermetic unit tests for obn::auth::Store persistence, covering the
// firmware_beta_open field and backwards compatibility with JSON files
// written before that field was added.
//
// No network access; all I/O goes to tmpfs.

#include "obn/auth.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#if !defined(_WIN32)
#  include <sys/stat.h>
#endif

namespace fs = std::filesystem;

#define EXPECT(r, cond)                                              \
    do {                                                             \
        if (cond) {                                                  \
            (r).passed++;                                            \
        } else {                                                     \
            (r).failed++;                                            \
            std::fprintf(stderr, "FAIL %s:%d: %s\n",                \
                         __FILE__, __LINE__, #cond);                 \
        }                                                            \
    } while (0)

struct Result { int failed = 0; int passed = 0; };

static std::string tmp_path(const char* tag)
{
    return (fs::temp_directory_path() /
            (std::string("obn_auth_test_") + tag + ".json")).string();
}

// firmware_beta_open should be false in a default-constructed Session.
void test_firmware_beta_default(Result& r)
{
    obn::auth::Session s;
    EXPECT(r, s.firmware_beta_open == false);
}

// Setting firmware_beta_open=true survives a save+reload cycle.
void test_firmware_beta_persist_true(Result& r)
{
    std::string path = tmp_path("beta_true");
    {
        obn::auth::Store store(path);
        obn::auth::Session s;
        s.access_token = "tok";
        s.user_id = "123";
        s.firmware_beta_open = true;
        store.set(s);
    }
    {
        obn::auth::Store store(path);
        store.load();
        auto s = store.snapshot();
        EXPECT(r, s.firmware_beta_open == true);
        EXPECT(r, s.access_token == "tok");
        EXPECT(r, s.user_id == "123");
    }
    fs::remove(path);
}

// Setting firmware_beta_open=false survives a save+reload cycle.
void test_firmware_beta_persist_false(Result& r)
{
    std::string path = tmp_path("beta_false");
    {
        obn::auth::Store store(path);
        obn::auth::Session s;
        s.access_token = "tok2";
        s.user_id = "456";
        s.firmware_beta_open = false;
        store.set(s);
    }
    {
        obn::auth::Store store(path);
        store.load();
        EXPECT(r, store.snapshot().firmware_beta_open == false);
    }
    fs::remove(path);
}

// update_firmware_beta() toggles the field and persists it without
// disturbing other session fields.
void test_update_firmware_beta(Result& r)
{
    std::string path = tmp_path("update_beta");
    obn::auth::Store store(path);
    obn::auth::Session s;
    s.access_token = "tok3";
    s.user_id = "789";
    s.firmware_beta_open = false;
    store.set(s);

    EXPECT(r, store.snapshot().firmware_beta_open == false);
    EXPECT(r, store.snapshot().access_token == "tok3");

    store.update_firmware_beta(true);
    EXPECT(r, store.snapshot().firmware_beta_open == true);
    EXPECT(r, store.snapshot().access_token == "tok3");

    store.update_firmware_beta(false);
    EXPECT(r, store.snapshot().firmware_beta_open == false);

    // Verify it round-tripped through disk as well.
    {
        obn::auth::Store store2(path);
        store2.load();
        EXPECT(r, store2.snapshot().firmware_beta_open == false);
        EXPECT(r, store2.snapshot().access_token == "tok3");
    }
    fs::remove(path);
}

// A JSON file written before firmware_beta_open existed (no such field)
// loads with firmware_beta_open defaulting to false.
void test_load_legacy_json(Result& r)
{
    std::string path = tmp_path("legacy");
    {
        std::ofstream out(path);
        out << "{\n"
            << "  \"region\": \"GLOBAL\",\n"
            << "  \"account\": \"user@example.com\",\n"
            << "  \"access_token\": \"legacytok\",\n"
            << "  \"refresh_token\": \"\",\n"
            << "  \"expires_at\": \"2099-01-01T00:00:00Z\",\n"
            << "  \"user_id\": \"999\",\n"
            << "  \"user_name\": \"Test User\",\n"
            << "  \"nick_name\": \"\",\n"
            << "  \"avatar\": \"\"\n"
            << "}\n";
    }
    {
        obn::auth::Store store(path);
        store.load();
        auto s = store.snapshot();
        EXPECT(r, s.access_token == "legacytok");
        EXPECT(r, s.user_id == "999");
        EXPECT(r, s.firmware_beta_open == false);
    }
    fs::remove(path);
}

// clear() wipes the session including firmware_beta_open.
void test_clear_resets_beta(Result& r)
{
    std::string path = tmp_path("clear_beta");
    obn::auth::Store store(path);
    obn::auth::Session s;
    s.access_token = "tok4";
    s.user_id = "111";
    s.firmware_beta_open = true;
    store.set(s);
    EXPECT(r, store.snapshot().firmware_beta_open == true);
    store.clear();
    EXPECT(r, store.snapshot().firmware_beta_open == false);
    EXPECT(r, store.snapshot().access_token.empty());
}

#if !defined(_WIN32)
// The token file must be 0600 without relying on a chmod after the tokens are
// already on disk - including when a stale, world-readable .tmp is lying
// around from an older build.
void test_persist_is_private(Result& r)
{
    std::string path = tmp_path("perms");
    std::string tmp  = path + ".tmp";
    fs::remove(path);
    { std::ofstream(tmp) << "stale"; }
    fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write |
                         fs::perms::group_read | fs::perms::others_read);

    const mode_t old_umask = ::umask(022);
    {
        obn::auth::Store store(path);
        obn::auth::Session s;
        s.access_token = "secret";
        s.user_id      = "1";
        store.set(s);
    }
    ::umask(old_umask);

    struct stat st{};
    EXPECT(r, ::stat(path.c_str(), &st) == 0);
    EXPECT(r, (st.st_mode & 0777) == 0600);
    EXPECT(r, !fs::exists(tmp));
    fs::remove(path);
}
#endif

int main()
{
    Result r;
#if !defined(_WIN32)
    test_persist_is_private(r);
#endif
    test_firmware_beta_default(r);
    test_firmware_beta_persist_true(r);
    test_firmware_beta_persist_false(r);
    test_update_firmware_beta(r);
    test_load_legacy_json(r);
    test_clear_resets_beta(r);
    std::printf("auth_persist_test: %d passed, %d failed\n", r.passed, r.failed);
    return r.failed == 0 ? 0 : 1;
}
