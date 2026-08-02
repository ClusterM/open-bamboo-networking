#include "h264_avcc.hpp"

namespace obn {
namespace h264 {
namespace {

// Find the next Annex-B start code at or after `off`.
// Returns the index of the first 0x00 of the start code, or `size` if none.
// On success, `*sc_len` is 3 or 4.
size_t find_start_code(const uint8_t* data, size_t size, size_t off, size_t* sc_len)
{
    for (size_t i = off; i + 2 < size; ++i) {
        if (data[i] == 0x00 && data[i + 1] == 0x00) {
            if (data[i + 2] == 0x01) {
                *sc_len = 3;
                return i;
            }
            if (i + 3 < size && data[i + 2] == 0x00 && data[i + 3] == 0x01) {
                *sc_len = 4;
                return i;
            }
        }
    }
    return size;
}

struct NalView {
    const uint8_t* data;
    size_t         size;
    uint8_t        type; // nal_unit_type (low 5 bits of first byte)
};

// Invoke `fn(NalView)` for every NAL in the Annex-B buffer.
template <typename Fn>
void for_each_nal(const uint8_t* data, size_t size, Fn fn)
{
    size_t sc_len = 0;
    size_t sc     = find_start_code(data, size, 0, &sc_len);
    while (sc < size) {
        size_t nal_start = sc + sc_len;
        size_t next_sc_len = 0;
        size_t next = find_start_code(data, size, nal_start, &next_sc_len);
        if (nal_start < next && nal_start < size) {
            NalView v;
            v.data = data + nal_start;
            v.size = next - nal_start;
            // Keep the NAL bytes verbatim (including any trailing_zero_8bits
            // the encoder left before the next start code). Stripping 0x00
            // would corrupt slice payloads that legitimately end in zero.
            v.type = (v.size > 0) ? static_cast<uint8_t>(v.data[0] & 0x1f) : 0;
            if (v.size > 0) fn(v);
        }
        if (next >= size) break;
        sc     = next;
        sc_len = next_sc_len;
    }
}

void append_avcc_nal(std::vector<uint8_t>& out, const uint8_t* nal, size_t nal_size)
{
    const uint32_t n = static_cast<uint32_t>(nal_size);
    out.push_back(static_cast<uint8_t>((n >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((n >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((n >>  8) & 0xff));
    out.push_back(static_cast<uint8_t>( n        & 0xff));
    out.insert(out.end(), nal, nal + nal_size);
}

} // namespace

bool extract_parameter_sets(const uint8_t* data, size_t size, ParameterSets* out)
{
    if (!data || !out) return false;
    out->sps.clear();
    out->pps.clear();
    for_each_nal(data, size, [&](const NalView& v) {
        if (v.type == 7) out->sps.assign(v.data, v.data + v.size);
        else if (v.type == 8) out->pps.assign(v.data, v.data + v.size);
    });
    return !out->sps.empty() && !out->pps.empty();
}

bool annexb_to_avcc(const uint8_t* data, size_t size, AvccFrame* out)
{
    if (!data || !out) return false;
    out->data.clear();
    out->contains_idr = false;
    for_each_nal(data, size, [&](const NalView& v) {
        // Parameter sets and AUDs belong in the format description / are
        // not sample payload for AVSampleBufferDisplayLayer.
        if (v.type == 7 || v.type == 8 || v.type == 9) return;
        if (v.type == 5) out->contains_idr = true;
        append_avcc_nal(out->data, v.data, v.size);
    });
    return !out->data.empty();
}

bool contains_idr(const uint8_t* data, size_t size)
{
    if (!data) return false;
    bool found = false;
    for_each_nal(data, size, [&](const NalView& v) {
        if (v.type == 5) found = true;
    });
    return found;
}

} // namespace h264
} // namespace obn
