#include "CameraSourceFactory.hpp"
#include "JpegCameraSource.hpp"
#include "OssTutkCameraSource.hpp"
#include "AgoraUrl.hpp"                   // AgoraUrl::parse
#include "oss_agora/OssAgoraEngine.hpp"   // OssFrameQueue, OssVideoFrame
#include "oss_agora/OssAgoraSignaling.hpp"

#include "obn/camera.hpp"
#include "obn/log.hpp"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

namespace obn {
namespace camera {

// ---------------------------------------------------------------------------
// AgoraCameraSource — ICameraSource adapter backed by OssAgoraSignaling.
// Handles bambu:///agora?... URLs without the BambuSourceHandle layer.
// ---------------------------------------------------------------------------

namespace {

class AgoraCameraSource : public bambu_net::camera::ICameraSource {
public:
    explicit AgoraCameraSource(bambu_net::camera::AgoraUrl url)
        : url_(std::move(url)) {}

    ~AgoraCameraSource() override { close(); }

    AgoraCameraSource(const AgoraCameraSource&) = delete;
    AgoraCameraSource& operator=(const AgoraCameraSource&) = delete;

    bool open() override {
        if (open_.load()) return true;

        using namespace bambu_net::camera::oss_agora;
        AgoraJoinParams p;
        p.app_id      = url_.app_id;
        p.channel     = url_.channel;
        p.token       = url_.token;
        p.dtls_passwd = url_.passwd;
        p.av_passwd   = url_.passwd;
        p.uid         = url_.uid;
        p.area_code   = static_cast<uint32_t>(url_.region);
        p.tutk_uid    = url_.tutk_uid.empty() ? url_.device : url_.tutk_uid;

        OBN_INFO("camera: Agora open channel=%.20s tutk_uid=%.20s",
                 p.channel.c_str(), p.tutk_uid.c_str());

        int rc = signaling_.join(p, [this](const uint8_t* data, int len,
                                            int64_t pts_us, bool key) {
            OssVideoFrame f;
            f.data.assign(data, data + len);
            f.pts_us      = pts_us;
            f.is_keyframe = key;
            queue_.push(std::move(f));
        });

        if (rc != 0) {
            OBN_WARN("camera: Agora signaling join failed channel=%.20s",
                     p.channel.c_str());
            return false;
        }
        open_.store(true);
        return true;
    }

    void close() override {
        if (!open_.exchange(false)) return;
        signaling_.leave();
    }

    bool is_open() const override { return open_.load(); }

    std::optional<bambu_net::camera::VideoFrame>
    next_frame(int timeout_ms) override {
        if (!open_.load()) return std::nullopt;
        const auto deadline = std::chrono::steady_clock::now()
                            + std::chrono::milliseconds(timeout_ms);
        while (open_.load()) {
            bambu_net::camera::oss_agora::OssVideoFrame f;
            if (queue_.pop(f)) {
                bambu_net::camera::VideoFrame out;
                out.nal_data    = std::move(f.data);
                out.pts_us      = f.pts_us;
                out.is_keyframe = f.is_keyframe;
                return out;
            }
            if (std::chrono::steady_clock::now() >= deadline)
                return std::nullopt;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        return std::nullopt;
    }

    StreamInfo info() const override {
        StreamInfo si;
        si.width  = 1920; si.height = 1080; si.fps = 30;
        si.codec  = Codec::H264_AnnexB;
        return si;
    }

private:
    bambu_net::camera::AgoraUrl                     url_;
    bambu_net::camera::oss_agora::OssAgoraSignaling signaling_;
    bambu_net::camera::oss_agora::OssFrameQueue     queue_;
    std::atomic<bool>                                open_{false};
};

} // anonymous namespace

// ---------------------------------------------------------------------------
// CameraSourceFactory::make
// ---------------------------------------------------------------------------

std::shared_ptr<bambu_net::camera::ICameraSource>
CameraSourceFactory::make(const CameraSpec& spec) const
{
    const std::string& url = spec.camera_url;

    // 1. Agora cloud relay URL (bambu:///agora?...)
    if (!url.empty() && url.find("agora?") != std::string::npos) {
        bambu_net::camera::AgoraUrl parsed;
        std::string err;
        if (!bambu_net::camera::AgoraUrl::parse(url, parsed, err)) {
            OBN_WARN("camera: factory agora URL parse failed: %s", err.c_str());
            return nullptr;
        }
        return std::make_shared<AgoraCameraSource>(std::move(parsed));
    }

    // 2. TUTK direct/relay URL (bambu:///tutk?...)
    if (!url.empty() && url.find("tutk?") != std::string::npos) {
        return std::make_shared<OssTutkCameraSource>(url);
    }

    // 3. LAN JPEG (A1/P1/N1/N2S/C13/C14 families)
    if (url.empty() && is_jpeg_model(spec.model) && !spec.lan_ip.empty()) {
        JpegConfig cfg;
        cfg.dev_id      = spec.dev_id;
        cfg.ip          = spec.lan_ip;
        cfg.access_code = spec.access_code;
        return std::make_shared<JpegCameraSource>(cfg);
    }

    OBN_DEBUG("camera: factory no source for dev=%s model=%s url=%s",
              spec.dev_id.c_str(), spec.model.c_str(), url.c_str());
    return nullptr;
}

}  // namespace camera
}  // namespace obn
