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
        EXPECT(r, store.selected_machine().empty());
        store.set_selected_machine("31B8AP5C0101591");
    }
    {
        obn::state::Store restarted(path.string());
        restarted.load();
        EXPECT(r, restarted.selected_machine() == "31B8AP5C0101591");
    }
    fs::remove(path);
}

void test_deselection_survives_restart(Result& r)
{
    const fs::path path = tmp_path("deselect");
    fs::remove(path);
    {
        obn::state::Store store(path.string());
        store.set_selected_machine("printer-a");
        store.set_selected_machine("");
    }
    {
        obn::state::Store restarted(path.string());
        restarted.load();
        EXPECT(r, restarted.selected_machine().empty());
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
    EXPECT(r, store.selected_machine().empty());
    fs::remove(path);
}

void test_json_escaping_round_trip(Result& r)
{
    const fs::path path = tmp_path("escaping");
    fs::remove(path);
    const std::string unusual = "printer-\"test\\id";
    {
        obn::state::Store store(path.string());
        store.set_selected_machine(unusual);
    }
    {
        obn::state::Store restarted(path.string());
        restarted.load();
        EXPECT(r, restarted.selected_machine() == unusual);
    }
    fs::remove(path);
}

int main()
{
    Result r;
    test_selection_survives_restart(r);
    test_deselection_survives_restart(r);
    test_malformed_state_is_safe(r);
    test_json_escaping_round_trip(r);
    std::printf("state_persist_test: %d passed, %d failed\n",
                r.passed, r.failed);
    return r.failed == 0 ? 0 : 1;
}
