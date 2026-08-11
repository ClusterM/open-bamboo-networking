// Hermetic unit tests for stubs/h264_avcc.{hpp,cpp}.
// Covers 3- and 4-byte Annex-B start codes, SPS/PPS extraction,
// AVCC length framing, and IDR detection.

#include "h264_avcc.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

using obn::h264::AvccFrame;
using obn::h264::ParameterSets;
using obn::h264::annexb_to_avcc;
using obn::h264::contains_idr;
using obn::h264::extract_parameter_sets;

static int g_fail = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("  FAIL: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        ++g_fail; \
    } \
} while (0)

static void append_sc4(std::vector<uint8_t>& v)
{
    v.push_back(0); v.push_back(0); v.push_back(0); v.push_back(1);
}

static void append_sc3(std::vector<uint8_t>& v)
{
    v.push_back(0); v.push_back(0); v.push_back(1);
}

static void append_nal(std::vector<uint8_t>& v, uint8_t type,
                       const uint8_t* payload, size_t n)
{
    append_sc4(v);
    v.push_back(static_cast<uint8_t>(0x00 | (type & 0x1f))); // forbidden_zero=0, nal_ref_idc=0
    if (payload && n > 0)
        v.insert(v.end(), payload, payload + n);
}

static uint32_t be32(const uint8_t* p)
{
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) <<  8) |  uint32_t(p[3]);
}

int main()
{
    // Fake SPS/PPS/slice payloads (content is opaque to the helper).
    const uint8_t sps_body[] = { 0x42, 0x00, 0x1e, 0xaa };
    const uint8_t pps_body[] = { 0xce, 0x01 };
    const uint8_t idr_body[] = { 0x88, 0x84, 0x21 };
    const uint8_t p_body[]   = { 0x9a, 0x10 };

    // 1. extract_parameter_sets from a classic AU (4-byte start codes).
    {
        std::vector<uint8_t> au;
        append_nal(au, 7, sps_body, sizeof(sps_body));
        append_nal(au, 8, pps_body, sizeof(pps_body));
        append_nal(au, 5, idr_body, sizeof(idr_body));

        ParameterSets ps;
        CHECK(extract_parameter_sets(au.data(), au.size(), &ps));
        CHECK(ps.sps.size() == 1 + sizeof(sps_body));
        CHECK(ps.pps.size() == 1 + sizeof(pps_body));
        CHECK(ps.sps[0] == 7);
        CHECK(ps.pps[0] == 8);
        CHECK(std::memcmp(ps.sps.data() + 1, sps_body, sizeof(sps_body)) == 0);
        CHECK(contains_idr(au.data(), au.size()));
    }

    // 2. 3-byte start codes also work.
    {
        std::vector<uint8_t> au;
        append_sc3(au); au.push_back(7);
        au.insert(au.end(), sps_body, sps_body + sizeof(sps_body));
        append_sc3(au); au.push_back(8);
        au.insert(au.end(), pps_body, pps_body + sizeof(pps_body));
        append_sc3(au); au.push_back(1); // non-IDR slice
        au.insert(au.end(), p_body, p_body + sizeof(p_body));

        ParameterSets ps;
        CHECK(extract_parameter_sets(au.data(), au.size(), &ps));
        CHECK(ps.sps[0] == 7);
        CHECK(ps.pps[0] == 8);
        CHECK(!contains_idr(au.data(), au.size()));
    }

    // 3. annexb_to_avcc drops SPS/PPS/AUD and length-prefixes the rest.
    {
        std::vector<uint8_t> au;
        append_nal(au, 7, sps_body, sizeof(sps_body));
        append_nal(au, 8, pps_body, sizeof(pps_body));
        append_nal(au, 9, nullptr, 0); // AUD (header only)
        append_nal(au, 5, idr_body, sizeof(idr_body));

        AvccFrame f;
        CHECK(annexb_to_avcc(au.data(), au.size(), &f));
        CHECK(f.contains_idr);
        // One NAL: 4-byte length + 1 type byte + idr_body
        const size_t nal_size = 1 + sizeof(idr_body);
        CHECK(f.data.size() == 4 + nal_size);
        CHECK(be32(f.data.data()) == nal_size);
        CHECK(f.data[4] == 5);
        CHECK(std::memcmp(f.data.data() + 5, idr_body, sizeof(idr_body)) == 0);
    }

    // 4. Non-IDR P-frame → contains_idr false, still convertible.
    {
        std::vector<uint8_t> au;
        append_nal(au, 1, p_body, sizeof(p_body));
        AvccFrame f;
        CHECK(annexb_to_avcc(au.data(), au.size(), &f));
        CHECK(!f.contains_idr);
        CHECK(f.data.size() == 4 + 1 + sizeof(p_body));
        CHECK(f.data[4] == 1);
    }

    // 5. Empty / SPS-only input → annexb_to_avcc fails (nothing left).
    {
        std::vector<uint8_t> au;
        append_nal(au, 7, sps_body, sizeof(sps_body));
        AvccFrame f;
        CHECK(!annexb_to_avcc(au.data(), au.size(), &f));
        CHECK(f.data.empty());
    }

    // 6. Mixed 3- and 4-byte start codes in one AU.
    {
        std::vector<uint8_t> au;
        append_sc4(au); au.push_back(7);
        au.insert(au.end(), sps_body, sps_body + sizeof(sps_body));
        append_sc3(au); au.push_back(8);
        au.insert(au.end(), pps_body, pps_body + sizeof(pps_body));
        append_sc4(au); au.push_back(5);
        au.insert(au.end(), idr_body, idr_body + sizeof(idr_body));

        ParameterSets ps;
        CHECK(extract_parameter_sets(au.data(), au.size(), &ps));
        AvccFrame f;
        CHECK(annexb_to_avcc(au.data(), au.size(), &f));
        CHECK(f.contains_idr);
    }

    // 7. parse_sps_geometry against real x264 output. Both fixtures are
    //    the SPS NAL as it appears on the wire; ffmpeg reports 1168x720
    //    @ 24.67 fps and 1280x720 @ 30 fps for them respectively, and
    //    the first one exercises the crop path (80 macroblocks = 1280
    //    coded pixels cropped down to 1168) plus the High-profile
    //    chroma_format_idc block.
    {
        const uint8_t sps_high_1168x720[] = {
            0x67, 0x64, 0x00, 0x1f, 0xac, 0xd9, 0x40, 0x49, 0x05, 0xbb,
            0x01, 0x10, 0x00, 0x00, 0x03, 0x00, 0x30, 0x00, 0x00, 0x09,
            0x40, 0xf1, 0x83, 0x19, 0x60,
        };
        obn::h264::SpsGeometry g;
        CHECK(obn::h264::parse_sps_geometry(sps_high_1168x720,
                                            sizeof(sps_high_1168x720), &g));
        CHECK(g.width  == 1168);
        CHECK(g.height == 720);
        CHECK(g.fps    == 25);   // 24.67 fps, rounded
    }
    {
        const uint8_t sps_baseline_1280x720[] = {
            0x67, 0x42, 0xc0, 0x1f, 0xd9, 0x00, 0x50, 0x05, 0xbb, 0x01,
            0x10, 0x00, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x03, 0x03,
            0xc0, 0xf1, 0x83, 0x24, 0x80,
        };
        obn::h264::SpsGeometry g;
        CHECK(obn::h264::parse_sps_geometry(sps_baseline_1280x720,
                                            sizeof(sps_baseline_1280x720), &g));
        CHECK(g.width  == 1280);
        CHECK(g.height == 720);
        CHECK(g.fps    == 30);
    }

    // 8. Truncated and empty SPS inputs must fail rather than read past
    //    the buffer or invent a geometry.
    {
        const uint8_t truncated[] = { 0x67, 0x64, 0x00 };
        obn::h264::SpsGeometry g;
        CHECK(!obn::h264::parse_sps_geometry(truncated, sizeof(truncated), &g));
        CHECK(!obn::h264::parse_sps_geometry(nullptr, 0, &g));
        CHECK(g.width == 0 && g.height == 0 && g.fps == 0);
    }

    if (g_fail) {
        std::printf("h264_avcc_test FAILED (%d)\n", g_fail);
        return 1;
    }
    std::printf("h264_avcc_test OK\n");
    return 0;
}
