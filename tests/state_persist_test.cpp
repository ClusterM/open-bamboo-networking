#include "obn/state.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

#define EXPECT(r, cond)                                              \
    do {                                                             \
        if (cond) {                                                  \
            (r).passed++;                                            \
        } else {                                                     \
            (r).failed++;                                            \
            std::fprintf(stderr, "FAIL %s:%d: %s\n",                \
                         __FILE__, __LINE__, #cond);                  \
        }                                                            \
    } while (0)

struct Result { int failed = 0; int passed = 0; };

static fs::path tmp_path(const char* tag)
{
    return fs::temp_directory_path() /
           (std::string("obn_state_test_") + tag + ".json");
}

void test_selection_survives_restart(Result& r)
{
    const fs::path path = tmp_path("restart");
    fs::remove(path);
    {
        obn::state::Store store(path.string());
        store.load();
        EXPECT(r, store.remembered_machine().empty());
        store.remember_machine("31B8AP5C0101591");
    }
    {
        obn::state::Store restarted(path.string());
        restarted.load();
        EXPECT(r, restarted.remembered_machine() == "31B8AP5C0101591");
    }
    fs::remove(path);
}

void test_deselection_keeps_last_printer(Result& r)
{
    const fs::path path = tmp_path("deselect");
    fs::remove(path);
    {
        obn::state::Store store(path.string());
        store.remember_machine("printer-a");
        store.remember_machine("");
        EXPECT(r, store.remembered_machine() == "printer-a");
    }
    {
        obn::state::Store restarted(path.string());
        restarted.load();
        EXPECT(r, restarted.remembered_machine() == "printer-a");
    }
    fs::remove(path);
}

void test_malformed_state_is_safe(Result& r)
{
    const fs::path path = tmp_path("malformed");
    {
        std::ofstream out(path);
        out << "not json";
    }
    obn::state::Store store(path.string());
    store.load();
    EXPECT(r, store.remembered_machine().empty());
    fs::remove(path);
}

void test_json_escaping_round_trip(Result& r)
{
    const fs::path path = tmp_path("escaping");
    fs::remove(path);
    const std::string unusual = "printer-\"test\\id";
    {
        obn::state::Store store(path.string());
        store.remember_machine(unusual);
    }
    {
        obn::state::Store restarted(path.string());
        restarted.load();
        EXPECT(r, restarted.remembered_machine() == unusual);
    }
    fs::remove(path);
}

void test_rewrite_replaces_existing_file(Result& r)
{
    // Windows std::filesystem::rename refuses an existing destination, so the
    // second write is the one that catches a broken replace path.
    const fs::path path = tmp_path("rewrite");
    fs::remove(path);
    {
        obn::state::Store store(path.string());
        store.remember_machine("printer-a");
        store.remember_machine("printer-b");
    }
    {
        obn::state::Store restarted(path.string());
        restarted.load();
        EXPECT(r, restarted.remembered_machine() == "printer-b");
    }
    EXPECT(r, !fs::exists(path.string() + ".tmp"));
    fs::remove(path);
}

void test_failed_persist_retries(Result& r)
{
    // persist_locked writes path+".tmp" then renames onto path. Occupying
    // `path` with a directory makes the rename fail so we can see a retry.
    const fs::path path = tmp_path("retry");
    fs::remove_all(path);
    fs::create_directory(path);
    {
        obn::state::Store store(path.string());
        store.remember_machine("printer-a");
        EXPECT(r, store.remembered_machine() == "printer-a");
        EXPECT(r, fs::is_directory(path));
        fs::remove_all(path);
        store.remember_machine("printer-a");
        EXPECT(r, store.remembered_machine() == "printer-a");
    }
    {
        obn::state::Store restarted(path.string());
        restarted.load();
        EXPECT(r, restarted.remembered_machine() == "printer-a");
    }
    fs::remove(path);
}

int main()
{
    Result r;
    test_selection_survives_restart(r);
    test_deselection_keeps_last_printer(r);
    test_malformed_state_is_safe(r);
    test_json_escaping_round_trip(r);
    test_rewrite_replaces_existing_file(r);
    test_failed_persist_retries(r);
    std::printf("state_persist_test: %d passed, %d failed\n",
                r.passed, r.failed);
    return r.failed == 0 ? 0 : 1;
}
