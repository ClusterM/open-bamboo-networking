// Forward error correction of the TUTK AV transport: groups of k data
// packets followed by m parity packets, a systematic Vandermonde code over
// GF(2^8) (polynomial 0x11d). Parity packet i (row r = k + i) is
// sum_c P[r][c] * data[c], P = V[k..] * inverse(V[0..k)), V[r][c] = r^c.

#ifndef OBN_CAMERA_TUTK_FEC_HPP
#define OBN_CAMERA_TUTK_FEC_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

namespace obn {
namespace camera {
namespace tutk {
namespace fec {

// Parity block for row `row` (>= k) over k equally sized data blocks.
std::vector<uint8_t> encode(const std::vector<std::vector<uint8_t>>& data, int row);

// blocks[i] holds block i of the group (data for i < k, parity row i
// otherwise) or is empty when missing; every present block is `len` bytes
// (data zero-padded). Fills in the missing data blocks. Returns false when
// fewer than k blocks are present.
bool recover(std::vector<std::vector<uint8_t>>& blocks, int k, size_t len);

} // namespace fec
} // namespace tutk
} // namespace camera
} // namespace obn

#endif
