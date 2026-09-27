// TutkCameraSource: ICameraSource over a TUTK session.
//
// URL: bambu:///tutk?uid=<UID>&authkey=<KEY>&passwd=<PASSWD>&region=<cn|eu|us>
//                   [&channel=<RELAY_ID>]
//
// Frames arrive on the session's worker thread and are queued for
// next_frame(); the codec (H.264 or MJPEG) is taken from the first frame.

#pragma once

#include "ICameraSource.hpp"
#include "tutk/TutkSession.hpp"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <optional>
#include <string>

namespace obn {
namespace camera {

// Fills p from a bambu:///tutk URL; false when uid or passwd is missing.
bool parse_tutk_url(const std::string& url, tutk::TutkSessionParams& p);

class TutkCameraSource : public ICameraSource {
public:
    explicit TutkCameraSource(std::string url);
    ~TutkCameraSource() override;

    TutkCameraSource(const TutkCameraSource&) = delete;
    TutkCameraSource& operator=(const TutkCameraSource&) = delete;

    bool open()          override;
    void close()         override;
    bool is_open() const override;
    std::optional<VideoFrame> next_frame(int timeout_ms) override;
    StreamInfo info() const override;

private:
    void push_frame(const uint8_t* data, int len, int64_t pts_us, bool keyframe);

    static constexpr size_t kMaxQueuedFrames = 120;

    std::string              url_;
    tutk::TutkSessionParams  params_;
    tutk::TutkSession        session_;
    std::atomic<bool>        open_{false};

    mutable std::mutex       mu_;
    std::condition_variable  cv_;
    std::deque<VideoFrame>   frames_;
    bool                     codec_known_ = false;
    Codec                    codec_       = Codec::H264_AnnexB;
    int                      width_       = 1280;
    int                      height_      = 720;
};

}  // namespace camera
}  // namespace obn
