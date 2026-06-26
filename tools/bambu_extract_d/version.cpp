#include "version.h"
#include <sys/stat.h>

const VersionProfile PROFILES[] = {
    // warmup_s: how long after daemon start to wait before SEIZE.
    // 4s gives the plugin time to dlopen+init while WD_V2_FAKE_TRACEME
    // suppresses the VMP sentinel so DR0 can be armed on all threads.
    // Dynamic discovery finds the accumulator after warmup (K-table absent
    // at 4s — VMP decodes lazily on first sign); VersionProfile offset used.
    {"02.04.00.84",  4474056,  4.0, 0},
    {"02.05.01.52",  4655128,  4.0, 0},
    {"02.05.03.63",  4589752,  4.0, version_02_05_03_63::ACCUMULATOR_OFFSET},
    {"02.06.00.50",  4589320,  4.0, 0},
    {"02.06.01.50", 13864088,  4.0, 0},
    {"02.07.01.51", 14775608,  4.0, 0},
    {"02.05.03.63*", 15705656, 4.0, version_02_05_03_63::ACCUMULATOR_OFFSET},
    {nullptr, 0, 4.0, 0},  // sentinel
};

const VersionProfile* identify_version(const std::string& plugin_path) {
    struct stat st{};
    if (stat(plugin_path.c_str(), &st) != 0) return nullptr;
    uint64_t sz = (uint64_t)st.st_size;
    for (const auto& p : PROFILES) {
        if (!p.tag) break;
        if (p.so_size == sz) return &p;
    }
    return nullptr;  // unknown
}
