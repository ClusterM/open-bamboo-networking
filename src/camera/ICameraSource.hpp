// `RtspServer` (also in this directory) re-serves a printer's live camera
// to slicers on the LAN. It doesn't care WHERE the H.264 / MJPEG frames come
// from — only that they arrive as length-prefixed NAL units with usable
// SPS/PPS for SDP advertising. That indirection is `ICameraSource`.
//
// Implementations included in this OSS plugin:
//
//   - LanCameraSource:    direct LAN-RTSPS via the proprietary BambuSource
//                         library (the same one the slicer GUI uses). Only
//                         active when the host injects a BambuSourceHandle.
//   - JpegCameraSource:   A1 / P1 native port-6000 MJPEG-over-TLS protocol.
//                         No proprietary dependency — OpenSSL only.
//   - CloudCameraSource:  TUTK/Agora cloud relay. Stubbed in this OSS build
//                         because the TUTK SDK is not OSS-compatible. The
//                         class is wired so a host that ships its own
//                         BambuSourceHandle + BambuNetworkingPluginHandle
//                         can attach them at runtime and the cloud path
//                         lights up; without attachments, open() fails fast.
//   - NullCameraSource:   test-pattern source (single keyframe SPS/PPS/IDR
//                         re-emitted at a configurable rate).
//
// Frame encoding (documented once here):
//   - H264 sources emit `VideoFrame::nal_data` as one OR MORE NAL units in
//     Annex-B form (each prefixed by `00 00 00 01`). The packetiser splits
//     on start codes and runs RFC-6184 framing.
//   - MJPEG sources emit one raw JPEG per VideoFrame (no start code, no
//     length prefix; payload begins `FF D8` and ends `FF D9`).
//   - `pts_us` is microseconds, monotonic per stream.
//   - `is_keyframe` is advisory.
//
// `StreamInfo::sps` / `pps` MUST be raw NAL bodies (no start code, no length
// prefix) for the SDP `sprop-parameter-sets` advertising.

#ifndef BAMBU_NET_CAMERA_I_CAMERA_SOURCE_HPP
#define BAMBU_NET_CAMERA_I_CAMERA_SOURCE_HPP

#include <cstdint>
#include <optional>
#include <vector>

namespace bambu_net {
namespace camera {

struct VideoFrame {
    // One or more H.264 NAL units in Annex-B form (each prefixed by
    // 00 00 00 01) for H264 sources; raw JPEG for MJPEG sources.
    std::vector<uint8_t> nal_data;
    // Presentation timestamp in microseconds. Monotonic per stream.
    int64_t              pts_us      = 0;
    // Advisory: true iff this access unit contains an IDR / SPS / PPS NAL
    // (H264) or always-true for MJPEG (every JPEG is independent).
    bool                 is_keyframe = false;
};

class ICameraSource {
public:
    virtual ~ICameraSource() = default;

    // Lifecycle. `open` returns true iff the source is ready to deliver
    // frames; on failure the source stays closed and the server can fall
    // back to another source. `close` is idempotent; `is_open` is cheap.
    virtual bool open()           = 0;
    virtual void close()          = 0;
    virtual bool is_open() const  = 0;

    // Pull the next frame. Blocks up to `timeout_ms` milliseconds. Returns
    // `std::nullopt` on timeout OR on end-of-stream — disambiguate via
    // `is_open()` (false means EOS / source dropped).
    virtual std::optional<VideoFrame> next_frame(int timeout_ms) = 0;

    enum class Codec {
        H264_AnnexB = 0,
        MotionJpeg  = 1,
    };

    struct StreamInfo {
        int                   width  = 0;
        int                   height = 0;
        int                   fps    = 0;
        Codec                 codec  = Codec::H264_AnnexB;
        std::vector<uint8_t>  sps;
        std::vector<uint8_t>  pps;
    };
    virtual StreamInfo info() const = 0;
};

}  // namespace camera
}  // namespace bambu_net

#endif  // BAMBU_NET_CAMERA_I_CAMERA_SOURCE_HPP
