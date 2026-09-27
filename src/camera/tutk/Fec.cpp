#include "Fec.hpp"

#include <array>

namespace obn {
namespace camera {
namespace tutk {
namespace fec {

namespace {

struct Gf {
    std::array<uint8_t, 512> exp{};
    std::array<int, 256>     log{};

    Gf()
    {
        int x = 1;
        for (int i = 0; i < 255; ++i) {
            exp[i] = (uint8_t)x;
            log[x] = i;
            x <<= 1;
            if (x & 0x100) x ^= 0x11d;
        }
        for (int i = 255; i < 512; ++i) exp[i] = exp[i - 255];
    }

    uint8_t mul(uint8_t a, uint8_t b) const
    {
        return (a && b) ? exp[log[a] + log[b]] : 0;
    }
    uint8_t inv(uint8_t a) const { return exp[255 - log[a]]; }
    uint8_t pow(uint8_t a, int n) const
    {
        if (n == 0) return 1;
        return a ? exp[(log[a] * n) % 255] : 0;
    }
};

const Gf& gf()
{
    static const Gf g;
    return g;
}

using Matrix = std::vector<std::vector<uint8_t>>;

// Gauss-Jordan inverse; false when singular.
bool invert(Matrix& m)
{
    const Gf& g = gf();
    const size_t n = m.size();
    Matrix inv(n, std::vector<uint8_t>(n, 0));
    for (size_t i = 0; i < n; ++i) inv[i][i] = 1;
    for (size_t col = 0; col < n; ++col) {
        size_t piv = col;
        while (piv < n && m[piv][col] == 0) ++piv;
        if (piv == n) return false;
        std::swap(m[piv], m[col]);
        std::swap(inv[piv], inv[col]);
        const uint8_t f = g.inv(m[col][col]);
        for (size_t j = 0; j < n; ++j) {
            m[col][j]   = g.mul(m[col][j], f);
            inv[col][j] = g.mul(inv[col][j], f);
        }
        for (size_t r = 0; r < n; ++r) {
            if (r == col || m[r][col] == 0) continue;
            const uint8_t c = m[r][col];
            for (size_t j = 0; j < n; ++j) {
                m[r][j]   ^= g.mul(c, m[col][j]);
                inv[r][j] ^= g.mul(c, inv[col][j]);
            }
        }
    }
    m.swap(inv);
    return true;
}

// Row `row` of the systematic generator: unit vector for data rows.
std::vector<uint8_t> generator_row(int k, int row)
{
    std::vector<uint8_t> out(k, 0);
    if (row < k) {
        out[row] = 1;
        return out;
    }
    const Gf& g = gf();
    Matrix top(k, std::vector<uint8_t>(k));
    for (int r = 0; r < k; ++r)
        for (int c = 0; c < k; ++c) top[r][c] = g.pow((uint8_t)r, c);
    invert(top);
    for (int c = 0; c < k; ++c) {
        uint8_t v = 0;
        for (int j = 0; j < k; ++j) v ^= g.mul(g.pow((uint8_t)row, j), top[j][c]);
        out[c] = v;
    }
    return out;
}

} // namespace

std::vector<uint8_t> encode(const std::vector<std::vector<uint8_t>>& data, int row)
{
    const Gf& g = gf();
    const int k = (int)data.size();
    const auto coef = generator_row(k, row);
    std::vector<uint8_t> out(k ? data[0].size() : 0, 0);
    for (int c = 0; c < k; ++c)
        for (size_t i = 0; i < out.size(); ++i) out[i] ^= g.mul(coef[c], data[c][i]);
    return out;
}

bool recover(std::vector<std::vector<uint8_t>>& blocks, int k, size_t len)
{
    const Gf& g = gf();
    if (k <= 0 || (int)blocks.size() < k || k > 255) return false;

    std::vector<int> rows;
    for (int i = 0; i < (int)blocks.size() && (int)rows.size() < k; ++i)
        if (blocks[i].size() == len) rows.push_back(i);
    if ((int)rows.size() < k) return false;

    Matrix m;
    for (int r : rows) m.push_back(generator_row(k, r));
    if (!invert(m)) return false;

    for (int d = 0; d < k; ++d) {
        if (blocks[d].size() == len) continue;
        std::vector<uint8_t> out(len, 0);
        for (int j = 0; j < k; ++j) {
            const uint8_t c = m[d][j];
            if (!c) continue;
            const auto& src = blocks[rows[j]];
            for (size_t i = 0; i < len; ++i) out[i] ^= g.mul(c, src[i]);
        }
        blocks[d].swap(out);
    }
    return true;
}

} // namespace fec
} // namespace tutk
} // namespace camera
} // namespace obn
