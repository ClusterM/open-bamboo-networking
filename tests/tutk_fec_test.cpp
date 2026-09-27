// Hermetic unit tests for src/camera/tutk/Fec.{hpp,cpp}.

#include "Fec.hpp"

#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

namespace fec = obn::camera::tutk::fec;

static int g_fail = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("  FAIL: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        ++g_fail; \
    } \
} while (0)

using Blocks = std::vector<std::vector<uint8_t>>;

static Blocks random_blocks(std::mt19937& rng, int k, size_t len)
{
    Blocks out(k, std::vector<uint8_t>(len));
    for (auto& b : out)
        for (auto& v : b) v = (uint8_t)rng();
    return out;
}

// Parity coefficients observed on a P2S stream (k = 20, one parity packet).
static void test_known_parity_row()
{
    static const uint8_t kExpected[20] = {
        0x8f, 0xae, 0x5b, 0x70, 0xd0, 0xcd, 0x54, 0x43, 0x39, 0xa3,
        0xc9, 0x58, 0x1b, 0xbb, 0xb3, 0x18, 0x1b, 0x1c, 0x12, 0x14,
    };
    Blocks unit(20, std::vector<uint8_t>(20, 0));
    for (int i = 0; i < 20; ++i) unit[i][i] = 1;
    const auto parity = fec::encode(unit, 20);
    CHECK(parity.size() == 20);
    for (int i = 0; i < 20 && i < (int)parity.size(); ++i) CHECK(parity[i] == kExpected[i]);
}

static void test_recover(int k, int m, const std::vector<int>& lost)
{
    std::mt19937 rng(1234 + k * 7 + m);
    const size_t len = 1044;
    const Blocks data = random_blocks(rng, k, len);

    Blocks group = data;
    for (int i = 0; i < m; ++i) group.push_back(fec::encode(data, k + i));
    for (int idx : lost) group[idx].clear();

    CHECK(fec::recover(group, k, len));
    for (int i = 0; i < k; ++i) CHECK(group[i] == data[i]);
}

static void test_not_enough_blocks()
{
    std::mt19937 rng(99);
    const Blocks data = random_blocks(rng, 10, 64);
    Blocks group = data;
    group.push_back(fec::encode(data, 10));
    group[2].clear();
    group[5].clear();
    CHECK(!fec::recover(group, 10, 64));
}

int main()
{
    test_known_parity_row();
    test_recover(20, 1, {7});
    test_recover(25, 1, {0});
    test_recover(25, 1, {24});
    test_recover(20, 1, {});
    test_recover(16, 2, {3, 11});
    test_recover(16, 3, {0, 15, 16});
    test_not_enough_blocks();

    if (g_fail) {
        std::printf("tutk_fec_test: %d failure(s)\n", g_fail);
        return 1;
    }
    std::printf("tutk_fec_test: OK\n");
    return 0;
}
