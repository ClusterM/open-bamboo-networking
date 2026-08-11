#include "h264_avcc.hpp"

#include <cstdint>
#include <limits>
#include <vector>

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
            // Bytes between this start code and the next. The scanner
            // consumes the next start-code prefix (00 00 01 / 00 00 00 01),
            // so those zeros are not part of this NAL. Any
            // trailing_zero_8bits that sit *before* that prefix remain in
            // v.size. Do not strip trailing 0x00 — that would corrupt
            // slice payloads that legitimately end in zero.
            v.size = next - nal_start;
            v.type = (v.size > 0) ? static_cast<uint8_t>(v.data[0] & 0x1f) : 0;
            if (v.size > 0) fn(v);
        }
        if (next >= size) break;
        sc     = next;
        sc_len = next_sc_len;
    }
}

// Append one length-prefixed NAL. AVCC lengths are 32-bit; reject anything
// that would truncate. Returns false on overflow.
bool append_avcc_nal(std::vector<uint8_t>& out, const uint8_t* nal, size_t nal_size)
{
    if (nal_size > static_cast<size_t>(std::numeric_limits<uint32_t>::max()))
        return false;
    const uint32_t n = static_cast<uint32_t>(nal_size);
    out.push_back(static_cast<uint8_t>((n >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((n >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((n >>  8) & 0xff));
    out.push_back(static_cast<uint8_t>( n        & 0xff));
    out.insert(out.end(), nal, nal + nal_size);
    return true;
}

// Bit reader over an RBSP: the emulation-prevention 0x03 bytes are
// stripped up front so the SPS syntax elements can be read straight out
// of the bit stream. Every accessor is bounds-checked and latches `ok_`
// on overrun, so a truncated SPS fails the parse instead of reading past
// the buffer.
class RbspReader {
public:
    RbspReader(const uint8_t* data, size_t n)
    {
        buf_.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            if (i + 2 < n && data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 3) {
                buf_.push_back(0);
                buf_.push_back(0);
                i += 2;
                continue;
            }
            buf_.push_back(data[i]);
        }
    }

    uint32_t u(int bits)
    {
        uint32_t v = 0;
        for (int i = 0; i < bits; ++i) {
            const size_t byte = bit_ >> 3;
            if (byte >= buf_.size()) { ok_ = false; return 0; }
            const int shift = 7 - static_cast<int>(bit_ & 7);
            v = (v << 1) | ((buf_[byte] >> shift) & 1u);
            ++bit_;
        }
        return v;
    }

    uint32_t ue()
    {
        int zeros = 0;
        while (ok_ && u(1) == 0) {
            if (++zeros > 31) { ok_ = false; return 0; }
        }
        if (!ok_ || zeros == 0) return 0;
        return (1u << zeros) - 1 + u(zeros);
    }

    int32_t se()
    {
        const uint32_t k = ue();
        if (k == 0) return 0;
        const int32_t mag = static_cast<int32_t>((k + 1) / 2);
        return (k & 1) ? mag : -mag;
    }

    bool ok() const { return ok_; }

private:
    std::vector<uint8_t> buf_;
    size_t               bit_ = 0;
    bool                 ok_  = true;
};

// True for the profiles whose SPS carries the chroma_format_idc block
// (Annex A high profiles). Bambu encodes High, so this branch matters.
bool profile_has_chroma_block(int profile_idc)
{
    switch (profile_idc) {
    case 100: case 110: case 122: case 244:
    case  44: case  83: case  86: case 118:
    case 128: case 138: case 139: case 134: case 135:
        return true;
    default:
        return false;
    }
}

void skip_scaling_list(RbspReader& r, int size)
{
    int32_t last = 8, next = 8;
    for (int i = 0; i < size && r.ok(); ++i) {
        if (next != 0) next = (last + r.se() + 256) % 256;
        last = (next == 0) ? last : next;
    }
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
    bool ok = true;
    for_each_nal(data, size, [&](const NalView& v) {
        if (!ok) return;
        // Parameter sets and AUDs belong in the format description / are
        // not sample payload for AVSampleBufferDisplayLayer.
        if (v.type == 7 || v.type == 8 || v.type == 9) return;
        if (v.type == 5) out->contains_idr = true;
        if (!append_avcc_nal(out->data, v.data, v.size)) ok = false;
    });
    if (!ok) {
        out->data.clear();
        out->contains_idr = false;
        return false;
    }
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

bool parse_sps_geometry(const uint8_t* sps, size_t size, SpsGeometry* out)
{
    if (!sps || !out || size < 4) return false;
    RbspReader r(sps + 1, size - 1);              // skip the NAL header

    const int profile_idc = static_cast<int>(r.u(8));
    r.u(8);                                       // constraint flags + reserved
    r.u(8);                                       // level_idc
    r.ue();                                       // seq_parameter_set_id

    uint32_t chroma_format_idc          = 1;      // 4:2:0 unless stated
    bool     separate_colour_plane_flag = false;
    if (profile_has_chroma_block(profile_idc)) {
        chroma_format_idc = r.ue();
        if (chroma_format_idc == 3) separate_colour_plane_flag = r.u(1) != 0;
        r.ue();                                   // bit_depth_luma_minus8
        r.ue();                                   // bit_depth_chroma_minus8
        r.u(1);                                   // qpprime_y_zero_transform_bypass
        if (r.u(1)) {                             // seq_scaling_matrix_present
            const int lists = (chroma_format_idc != 3) ? 8 : 12;
            for (int i = 0; i < lists && r.ok(); ++i) {
                if (r.u(1)) skip_scaling_list(r, i < 6 ? 16 : 64);
            }
        }
    }

    r.ue();                                       // log2_max_frame_num_minus4
    const uint32_t poc_type = r.ue();
    if (poc_type == 0) {
        r.ue();                                   // log2_max_poc_lsb_minus4
    } else if (poc_type == 1) {
        r.u(1);                                   // delta_pic_order_always_zero
        r.se();                                   // offset_for_non_ref_pic
        r.se();                                   // offset_for_top_to_bottom_field
        const uint32_t n = r.ue();
        for (uint32_t i = 0; i < n && r.ok(); ++i) r.se();
    }
    r.ue();                                       // max_num_ref_frames
    r.u(1);                                       // gaps_in_frame_num_allowed

    const uint32_t width_mbs   = r.ue() + 1;
    const uint32_t height_maps = r.ue() + 1;
    const bool     frame_mbs_only = r.u(1) != 0;
    if (!frame_mbs_only) r.u(1);                  // mb_adaptive_frame_field
    r.u(1);                                       // direct_8x8_inference

    uint32_t crop_l = 0, crop_r = 0, crop_t = 0, crop_b = 0;
    if (r.u(1)) {                                 // frame_cropping_flag
        crop_l = r.ue();
        crop_r = r.ue();
        crop_t = r.ue();
        crop_b = r.ue();
    }

    int fps = 0;
    if (r.u(1)) {                                 // vui_parameters_present
        if (r.u(1)) {                             // aspect_ratio_info_present
            if (r.u(8) == 255) { r.u(16); r.u(16); }   // sar_width / sar_height
        }
        if (r.u(1)) r.u(1);                       // overscan
        if (r.u(1)) {                             // video_signal_type_present
            r.u(3);                               // video_format
            r.u(1);                               // video_full_range
            if (r.u(1)) { r.u(8); r.u(8); r.u(8); }    // colour description
        }
        if (r.u(1)) { r.ue(); r.ue(); }           // chroma_loc_info
        if (r.u(1)) {                             // timing_info_present
            const uint32_t num_units_in_tick = r.u(32);
            const uint32_t time_scale        = r.u(32);
            r.u(1);                               // fixed_frame_rate_flag
            if (r.ok() && num_units_in_tick > 0 && time_scale > 0) {
                // H.264 ties one tick to a field, so a frame takes two.
                const double v = static_cast<double>(time_scale) /
                                 (2.0 * static_cast<double>(num_units_in_tick));
                if (v > 0.0 && v < 1000.0) fps = static_cast<int>(v + 0.5);
            }
        }
    }

    if (!r.ok()) return false;

    // Cropping offsets count chroma sample units (spec 7.4.2.1.1).
    const uint32_t chroma_array_type =
        separate_colour_plane_flag ? 0 : chroma_format_idc;
    uint32_t sub_w = 1, sub_h = 1;
    switch (chroma_array_type) {
    case 1: sub_w = 2; sub_h = 2; break;          // 4:2:0
    case 2: sub_w = 2; sub_h = 1; break;          // 4:2:2
    default: break;                               // 4:4:4 / monochrome
    }
    const uint32_t unit_x = (chroma_array_type == 0) ? 1 : sub_w;
    const uint32_t unit_y = ((chroma_array_type == 0) ? 1 : sub_h) *
                            (frame_mbs_only ? 1u : 2u);

    const int64_t w = static_cast<int64_t>(width_mbs) * 16 -
                      static_cast<int64_t>(crop_l + crop_r) * unit_x;
    const int64_t h = static_cast<int64_t>(height_maps) * 16 *
                          (frame_mbs_only ? 1 : 2) -
                      static_cast<int64_t>(crop_t + crop_b) * unit_y;
    if (w <= 0 || h <= 0 || w > 16384 || h > 16384) return false;

    out->width  = static_cast<int>(w);
    out->height = static_cast<int>(h);
    out->fps    = fps;
    return true;
}

} // namespace h264
} // namespace obn
