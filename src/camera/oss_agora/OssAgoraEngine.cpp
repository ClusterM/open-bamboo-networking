#include "OssAgoraEngine.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <mutex>
#include <new>

#include "obn/log.hpp"

#if !defined(_WIN32)

namespace bambu_net {
namespace camera {
namespace oss_agora {

static int  oss_noop(void*, ...) { return 0; }
static void oss_noop_v(void*, ...) {}

// IVideoFrameObserver vtable (Agora 4.x, Itanium ABI).
// slot 6 = onRenderVideoFrame(uid, channelId, VideoFrame&) — remote frame delivery.
// 3.x omits channelId; libBambuSource.so uses 4.x layout.

// Agora VideoFrame (encoded-data variant, SDK 4.x).
// Only fields we read are named; the rest are left in _pad.
struct AgoraVideoFrame {
    int      type;           // VIDEO_BUFFER_RAW_DATA=1
    int      width;
    int      height;
    int      yStride;
    int      uStride;
    int      vStride;
    uint8_t* yBuffer;
    uint8_t* uBuffer;
    uint8_t* vBuffer;
    int      rotation;
    int64_t  renderTimeMs;
    int      avsync_type;
    uint8_t* encodedData;    // encoded H.264 payload (0x48 into struct)
    int      encodedDataLen; // (0x50)
    int      frameType;      // 0=delta 1=key (0x54)
    char     _pad[256];
};

static bool obs_on_render_video_frame(OssVideoObserver* self,
                                      unsigned int /*uid*/,
                                      const char* /*channelId*/,
                                      AgoraVideoFrame* frame)
{
    if (!self || !self->engine || !frame) return true;
    auto* q = self->engine->frame_queue;
    if (!q) return true;

    if (frame->encodedData && frame->encodedDataLen > 0) {
        OssVideoFrame f;
        f.pts_us      = frame->renderTimeMs * 1000LL;
        f.is_keyframe = (frame->frameType == 1);
        f.data.assign(frame->encodedData,
                      frame->encodedData + frame->encodedDataLen);
        q->push(std::move(f));
    }
    return true;
}

static bool obs_noop_bool(OssVideoObserver*, ...) { return false; }
static int  obs_get_pos(OssVideoObserver*)         { return 1; }   // POST_CAPTURER
static bool obs_is_external(OssVideoObserver*)     { return true; }
static int  obs_get_fmt(OssVideoObserver*)         { return 0; }   // DEFAULT

void** oss_make_video_observer_vtable()
{
    static void* kVideoObsVtable[] = {
        /* [0]  dtor D1                       */ (void*)oss_noop_v,
        /* [1]  dtor D0 (deleting)            */ (void*)oss_noop_v,
        /* [2]  onCaptureVideoFrame           */ (void*)obs_noop_bool,
        /* [3]  onPreEncodeVideoFrame         */ (void*)obs_noop_bool,
        /* [4]  onSecondaryCameraCapture      */ (void*)obs_noop_bool,
        /* [5]  onSecondaryPreEncode          */ (void*)obs_noop_bool,
        /* [6]  onRenderVideoFrame (4.x)      */ (void*)obs_on_render_video_frame,
        /* [7]  onTranscodedVideoFrame        */ (void*)obs_noop_bool,
        /* [8]  getObservedFramePosition      */ (void*)obs_get_pos,
        /* [9]  isExternal                    */ (void*)obs_is_external,
        /* [10] getVideoFormatPreference      */ (void*)obs_get_fmt,
        /* [11] getRotationApplied            */ (void*)obs_noop_bool,
        /* [12] getMirrorApplied              */ (void*)obs_noop_bool,
        /* [13] getSmoothRenderingEnabled     */ (void*)obs_noop_bool,
    };
    return kVideoObsVtable;
}

// IMediaEngine vtable shim — obtained via queryInterface(AGORA_IID_MEDIA_ENGINE=4).
// slot 3 = registerVideoFrameObserver, used by libBambuSource::RegisterObserver.

static int media_registerVideoFrameObserver(OssMediaEngine* self, void* observer)
{
    if (self && self->engine) {
        self->engine->registered_observer = observer;
    }
    OBN_DEBUG("[oss-agora] registerVideoFrameObserver(%p)", observer);
    return 0;
}

static void* kMediaEngineVtable[] = {
    /* [0]  dtor D1                                */ (void*)oss_noop_v,
    /* [1]  dtor D0                                */ (void*)oss_noop_v,
    /* [2]  registerAudioFrameObserver             */ (void*)oss_noop,
    /* [3]  registerVideoFrameObserver             */ (void*)media_registerVideoFrameObserver,
    /* [4]  registerVideoEncodedFrameObserver      */ (void*)oss_noop,
    /* [5]  pushAudioFrame                         */ (void*)oss_noop,
    /* [6]  pullAudioFrame                         */ (void*)oss_noop,
    /* [7]  setExternalVideoSource                 */ (void*)oss_noop,
    /* [8]  setExternalAudioSource                 */ (void*)oss_noop,
    /* [9]  setExternalAudioSink                   */ (void*)oss_noop,
    /* [10] enableCustomAudioLocalPlayback         */ (void*)oss_noop,
    /* [11] setDirectExternalAudioSource           */ (void*)oss_noop,
    /* [12] pushDirectAudioFrame                   */ (void*)oss_noop,
    /* [13] setExternalAudioDevice                 */ (void*)oss_noop,
    /* [14] release                                */ (void*)oss_noop_v,
};

// IRtcEngine vtable — 300 slots; all default to oss_noop; active slots overridden below.

// Forward declarations
static void  eng_dtor_d1(OssEngine* self);  // NOLINT — used via vtable
static void  eng_dtor_d0(OssEngine* self);  // NOLINT — used via vtable
static int   eng_queryInterface(OssEngine* self, int iid, void** out);
static void  eng_release(OssEngine* self, bool sync);
static int   eng_initialize(OssEngine* self, const void* ctx);
static int   eng_joinChannel(OssEngine* self,
                              const char* token,
                              const void* ch_struct,   // {char* channel, uint32 uid}
                              const void* options,
                              void*       event_handler);
static int   eng_enableEncryption(OssEngine* self,
                                   bool enabled,
                                   const void* config);
static int   eng_leaveChannel(OssEngine* self);

// Agora 4.x RtcEngineContext (partial); we only read app_id and area_code.
struct AgoraRtcEngineCtx {
    void*       event_handler;
    const char* app_id;
    void*       context;
    char _pad[256]; // area_code and other fields at caller-defined offsets
};

static int eng_initialize(OssEngine* self, const void* ctx_raw)
{
    auto* ctx = static_cast<const AgoraRtcEngineCtx*>(ctx_raw);
    if (ctx && ctx->app_id) {
        self->app_id = ctx->app_id;
    }
    OBN_INFO("[oss-agora] initialize(app_id=%s)", self->app_id.c_str());

    self->edge_servers = agora_discover_edge_servers(self->app_id, self->area_code);
    OBN_DEBUG("[oss-agora] initialize: %zu edge server(s) discovered",
              self->edge_servers.size());

    if (!self->signaling) {
        self->signaling = new OssAgoraSignaling();
    }
    return 0;
}

static void eng_release(OssEngine* self, bool /*sync*/)
{
    OBN_DEBUG("[oss-agora] release()");
    self->released = true;
    if (self->signaling) {
        self->signaling->leave();
        delete self->signaling;
        self->signaling = nullptr;
    }
    delete self;
}

static void eng_dtor_d1(OssEngine* self)
{
    if (self->signaling) {
        self->signaling->leave();
        delete self->signaling;
        self->signaling = nullptr;
    }
    self->~OssEngine();
}

static void eng_dtor_d0(OssEngine* self)
{
    delete self;
}

static int eng_queryInterface(OssEngine* self, int iid, void** out)
{
    if (!out) return -1;
    *out = nullptr;
    if (iid == 4 && self) {
        // AGORA_IID_MEDIA_ENGINE — hand out the engine's embedded shim. It is
        // freed together with the engine; the Agora release() slot is a no-op,
        // so allocating a fresh shim here (as before) would leak it.
        self->media_engine.vtable = kMediaEngineVtable;
        self->media_engine.engine = self;
        *out = &self->media_engine;
        return 0;
    }
    return -1;
}

// joinChannel (slot 252 / 0x7E0): third arg is a std::string* whose first 8 bytes
// are the char* data pointer (Itanium std::string layout).
static int eng_joinChannel(OssEngine* self,
                            const char* token,
                            const void* ch_ptr,
                            const void* /*options*/,
                            void*       /*event_handler*/)
{
    if (token)  self->token   = token;
    // ch_ptr points to a std::string whose first 8 bytes are the char* data ptr.
    if (ch_ptr) {
        const char* const* ch_str = static_cast<const char* const*>(ch_ptr);
        if (*ch_str) self->channel = *ch_str;
    }
    self->joined.store(true);
    OBN_INFO("[oss-agora] joinChannel(channel=%s uid=%u)",
             self->channel.c_str(), self->uid);

    // On-demand creation in case eng_initialize was skipped.
    if (!self->signaling) {
        if (self->edge_servers.empty()) {
            self->edge_servers = agora_discover_edge_servers(self->app_id,
                                                              self->area_code);
        }
        self->signaling = new OssAgoraSignaling();
    }

    AgoraJoinParams p;
    p.app_id    = self->app_id;
    p.channel   = self->channel;
    p.token     = self->token;
    p.uid       = self->uid;
    p.area_code = self->area_code;

    // Capture self rather than fields — frame_queue and registered_observer
    // may be set after joinChannel returns and must be read at delivery time.
    OssEngine* eng = self;
    int rc = self->signaling->join(p, [eng](const uint8_t* data, int len,
                                             int64_t pts_us, bool key) {
        OssFrameQueue* q = eng->frame_queue;
        if (q) {
            OssVideoFrame f;
            f.data.assign(data, data + len);
            f.pts_us      = pts_us;
            f.is_keyframe = key;
            q->push(std::move(f));
        }

        // Also dispatch through IVideoFrameObserver slot 6 if one is registered.
        void* obs = eng->registered_observer;
        if (obs) {
            AgoraVideoFrame vf{};
            vf.encodedData    = const_cast<uint8_t*>(data);
            vf.encodedDataLen = len;
            vf.renderTimeMs   = pts_us / 1000LL;
            vf.frameType      = key ? 1 : 0;
            using RenderFn = bool(*)(void*, unsigned int, const char*,
                                     AgoraVideoFrame*);
            void** vt = *reinterpret_cast<void***>(obs);
            auto fn = reinterpret_cast<RenderFn>(vt[6]);
            fn(obs, eng->uid, eng->channel.c_str(), &vf);
        }
    });

    if (rc != 0) {
        OBN_ERROR("[oss-agora] joinChannel: signaling join failed");
        self->joined.store(false);
        return -1;
    }
    return 0;
}

static int eng_leaveChannel(OssEngine* self)
{
    self->joined.store(false);
    OBN_DEBUG("[oss-agora] leaveChannel()");
    if (self->signaling) {
        self->signaling->leave();
    }
    return 0;
}

// enableEncryption (slot 278 / 0x8B0): EncryptionConfig holds AES-128 key from streamKey+streamSalt.
static int eng_enableEncryption(OssEngine* self,
                                 bool enabled,
                                 const void* /*config*/)
{
    OBN_DEBUG("[oss-agora] enableEncryption(enabled=%d)", (int)enabled);
    return 0;
}

#define NOOP ((void*)oss_noop)
#define NOOP_V ((void*)oss_noop_v)

static void* kEngineVtable[300];

static void init_engine_vtable()
{
    for (int i = 0; i < 300; ++i) kEngineVtable[i] = NOOP;
    kEngineVtable[0]   = (void*)eng_dtor_d1;                    // dtor D1
    kEngineVtable[1]   = (void*)eng_dtor_d0;                    // dtor D0
    kEngineVtable[2]   = (void*)eng_queryInterface;             // queryInterface
    kEngineVtable[3]   = (void*)eng_release;                    // release
    kEngineVtable[4]   = (void*)eng_initialize;                 // initialize
    kEngineVtable[25]  = NOOP;   // 0xC8 setup call in initAgora (setChannelProfile?)
    kEngineVtable[42]  = (void*)eng_leaveChannel;               // leaveChannel 0x150
    kEngineVtable[43]  = NOOP;   // 0x158 cleanup call in initAgora
    kEngineVtable[53]  = NOOP;   // 0x1A8 enable call arg=0 in initAgora
    kEngineVtable[54]  = NOOP;   // 0x1B0 enable call arg=1 in initAgora
    kEngineVtable[252] = (void*)eng_joinChannel;                // joinChannel
    kEngineVtable[278] = (void*)eng_enableEncryption;           // enableEncryption
}

static std::once_flag g_vtable_once;

extern "C" void* createAgoraRtcEngine()
{
    std::call_once(g_vtable_once, init_engine_vtable);
    auto* e = new OssEngine();
    e->vtable      = kEngineVtable;
    e->frame_queue = nullptr;
    OBN_DEBUG("[oss-agora] createAgoraRtcEngine() -> %p", e);
    return e;
}

// Inject the frame queue after creation (frame_queue may arrive after joinChannel).
extern "C" void oss_agora_set_frame_queue(void* engine_raw, OssFrameQueue* q)
{
    auto* e = static_cast<OssEngine*>(engine_raw);
    if (e) e->frame_queue = q;
}

} // namespace oss_agora
} // namespace camera
} // namespace bambu_net

#endif // !defined(_WIN32)

#ifdef _WIN32
namespace bambu_net {
namespace camera {
namespace oss_agora {

extern "C" void* createAgoraRtcEngine()
{
    return nullptr; // Agora vtable shim not available on Windows
}

extern "C" void oss_agora_set_frame_queue(void* /*engine_raw*/, OssFrameQueue* /*q*/)
{
    // no-op on Windows
}

} // namespace oss_agora
} // namespace camera
} // namespace bambu_net
#endif // _WIN32
