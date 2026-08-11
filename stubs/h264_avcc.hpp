// Portable H.264 Annex-B helpers used by the macOS BambuPlayer adapter
// (and unit-tested on Linux CI). No Apple / ObjC dependencies.
//
// Annex-B: NAL units prefixed with 00 00 01 or 00 00 00 01 start codes.
// AVCC:   each NAL prefixed with a 4-byte big-endian length (no start codes).
// AVSampleBufferDisplayLayer / CMVideoFormatDescription expect AVCC samples
// plus out-of-band SPS/PPS parameter sets.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace obn {
namespace h264 {

struct ParameterSets {
    std::vector<uint8_t> sps; // raw NAL (no start code), type 7
    std::vector<uint8_t> pps; // raw NAL (no start code), type 8
};

struct AvccFrame {
    std::vector<uint8_t> data; // one or more length-prefixed NALs
    bool                 contains_idr = false;
};

// Walk Annex-B `data` and keep the last SPS (type 7) and PPS (type 8).
// Returns true if both SPS and PPS were found.
bool extract_parameter_sets(const uint8_t* data, size_t size, ParameterSets* out);

// Convert an Annex-B access unit to AVCC. SPS / PPS / AUD NALs are dropped
// from the payload (they belong in the format description). Returns false
// if no convertible NAL remains.
bool annexb_to_avcc(const uint8_t* data, size_t size, AvccFrame* out);

// True if the Annex-B buffer contains an IDR slice (NAL type 5).
bool contains_idr(const uint8_t* data, size_t size);

// Display geometry carried by an SPS. `fps` is 0 when the SPS omits VUI
// timing information, which is optional.
struct SpsGeometry {
    int width  = 0;
    int height = 0;
    int fps    = 0;
};

// Decode display geometry (cropping applied) and the frame rate from a
// raw SPS NAL -- `sps` includes the 1-byte NAL header but no Annex-B
// start code. Returns false when the SPS does not parse, leaving *out
// untouched.
bool parse_sps_geometry(const uint8_t* sps, size_t size, SpsGeometry* out);

} // namespace h264
} // namespace obn
