#include "OssAgoraBambuSource.hpp"

#include "OssAgoraEngine.hpp"
#include "OssAgoraSignaling.hpp"
#include "../AgoraUrl.hpp"

#include <cstring>

#include "obn/log.hpp"
#include <mutex>
#include <deque>

namespace bambu_net {
namespace camera {
namespace oss_agora {

struct BambuSample {
    int                  itrack;
    int                  size;
    int                  flags;
    unsigned char const* buffer;
    unsigned long long   decode_time;
};

struct BambuStreamInfo {
    int type;
    int sub_type;
    union {
        struct { int width; int height; int frame_rate; } video;
        struct { int sample_rate; int channel_count; int sample_size; } audio;
    } format;
    int            format_type;
    int            format_size;
    int            max_frame_size;
    unsigned char* format_buffer;
};

struct OssAgoraTunnel {
    AgoraUrl                    url;
    OssFrameQueue               queue;
    OssAgoraSignaling           signal;
    std::string                 last_error;
    std::vector<uint8_t>        last_buf;  // kept alive until next bambu_read_sample call

    int   width  = 1920;
    int   height = 1080;
    int   fps    = 30;

    BambuSourceHandle::Logger log_fn  = nullptr;
    void*                     log_ctx = nullptr;
};

OssAgoraBambuSource::OssAgoraBambuSource()  = default;
OssAgoraBambuSource::~OssAgoraBambuSource() = default;

void OssAgoraBambuSource::set_test_mode(bool enabled)
{
    m_test_mode = enabled;
}

bool OssAgoraBambuSource::init()
{
    set_library_ready_for_test(true);
    return true;
}

bool OssAgoraBambuSource::library_ready() const
{
    return BambuSourceHandle::library_ready();
}

int OssAgoraBambuSource::bambu_create(void** out_tunnel, const std::string& url)
{
    if (!out_tunnel) return -1;
    auto* t = new OssAgoraTunnel();
    std::string err;
    if (!AgoraUrl::parse(url, t->url, err)) {
        OBN_ERROR("[oss-agora-src] bad URL: %s", err.c_str());
        delete t;
        return -1;
    }
    if (m_test_mode) t->signal.set_test_mode(true);
    *out_tunnel = t;
    return 0;
}

void OssAgoraBambuSource::bambu_destroy(void* tunnel)
{
    delete static_cast<OssAgoraTunnel*>(tunnel);
}

int OssAgoraBambuSource::bambu_open(void* tunnel)
{
    auto* t = static_cast<OssAgoraTunnel*>(tunnel);
    if (!t) return -1;

    AgoraJoinParams p;
    p.app_id      = t->url.app_id;
    p.channel     = t->url.channel;
    p.token       = t->url.token;
    p.dtls_passwd = t->url.passwd;
    p.av_passwd   = t->url.passwd; // same value as dtls_passwd
    p.uid         = t->url.uid;
    p.area_code   = static_cast<uint32_t>(t->url.region);
    // tutk_uid may differ from the device serial; fall back to device if absent.
    p.tutk_uid  = t->url.tutk_uid.empty() ? t->url.device : t->url.tutk_uid;

    OBN_INFO("[oss-agora-src] open: channel=%s token=<redacted> tutk_uid=%s device=%s region=0x%x",
        p.channel.c_str(), p.tutk_uid.c_str(),
        t->url.device.c_str(), p.area_code);

    int rc = t->signal.join(p, [t](const uint8_t* data, int len,
                                    int64_t pts_us, bool key) {
        OssVideoFrame f;
        f.data.assign(data, data + len);
        f.pts_us      = pts_us;
        f.is_keyframe = key;
        t->queue.push(std::move(f));
    });

    if (rc != 0 && !m_test_mode) {
        t->last_error = "signaling join failed";
        return -1;
    }
    return 0;
}

void OssAgoraBambuSource::bambu_close(void* tunnel)
{
    auto* t = static_cast<OssAgoraTunnel*>(tunnel);
    if (!t) return;
    t->signal.leave();
}

int OssAgoraBambuSource::bambu_start_stream(void* tunnel, bool video)
{
    return bambu_start_stream_ex(tunnel, video ? 0x3000 : 0x2000);
}

int OssAgoraBambuSource::bambu_start_stream_ex(void* /*tunnel*/, int /*type*/)
{
    return 0;  // frames arrive passively via the FrameCallback registered in bambu_open
}

int OssAgoraBambuSource::bambu_send_message(void* /*t*/, int /*ctrl*/,
                                              const char* /*data*/, int /*len*/)
{
    return 0;
}

void OssAgoraBambuSource::bambu_set_logger(void* tunnel,
                                            BambuSourceHandle::Logger logger,
                                            void* ctx)
{
    auto* t = static_cast<OssAgoraTunnel*>(tunnel);
    if (!t) return;
    t->log_fn  = logger;
    t->log_ctx = ctx;
}

std::string OssAgoraBambuSource::bambu_get_last_error_msg()
{
    return {};
}

int OssAgoraBambuSource::bambu_get_stream_count(void* /*t*/)
{
    return 1;
}

int OssAgoraBambuSource::bambu_get_stream_info(void* tunnel, int index,
                                                 void* info_out)
{
    auto* t    = static_cast<OssAgoraTunnel*>(tunnel);
    auto* info = static_cast<BambuStreamInfo*>(info_out);
    if (!t || !info || index != 0) return -1;
    std::memset(info, 0, sizeof(*info));
    info->type                   = 0;
    info->format.video.width     = t->width;
    info->format.video.height    = t->height;
    info->format.video.frame_rate = t->fps;
    info->max_frame_size         = t->width * t->height * 4;
    return 0;
}

int OssAgoraBambuSource::bambu_read_sample(void* tunnel, void* sample_out)
{
    auto* t   = static_cast<OssAgoraTunnel*>(tunnel);
    auto* out = static_cast<BambuSample*>(sample_out);
    if (!t || !out) return -1;

    OssVideoFrame f;
    if (!t->queue.pop(f)) return 2;  // kBambuWouldBlock

    t->last_buf = std::move(f.data);

    out->itrack      = 0;
    out->size        = static_cast<int>(t->last_buf.size());
    out->flags       = f.is_keyframe ? 1 : 0;
    out->buffer      = t->last_buf.data();
    out->decode_time = static_cast<unsigned long long>(
                           f.pts_us > 0 ? f.pts_us / 1000ULL : 0ULL);
    return 0;
}

} // namespace oss_agora
} // namespace camera
} // namespace bambu_net
