// Clean-room Objective-C++ BambuPlayer for macOS LAN LiveView.
//
// OrcaSlicer / Bambu Studio wxMediaCtrl2.mm looks up this class with
//   dlsym(libBambuSource.dylib, "OBJC_CLASS_$_BambuPlayer")
// and drives LAN camera playback through it. Transport and Annex-B
// production reuse the existing Bambu_* C ABI in this same dylib;
// this file only owns display (AVSampleBufferDisplayLayer) and the
// ObjC lifecycle Studio expects.
//
// Compiled with -fno-objc-arc (MRC): wxMediaCtrl2::~wxMediaCtrl2 calls
// [player dealloc] directly.

#import <Foundation/Foundation.h>
#import <Cocoa/Cocoa.h>
#import <QuartzCore/QuartzCore.h>
#import <AVFoundation/AVSampleBufferDisplayLayer.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>

#include "h264_avcc.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal Bambu_* C ABI declarations (same dylib; stubs/BambuSource.cpp).
// ---------------------------------------------------------------------------

extern "C" {

typedef void* Bambu_Tunnel;

enum Bambu_Error {
    Bambu_success      = 0,
    Bambu_stream_end   = 1,
    Bambu_would_block  = 2,
    Bambu_buffer_limit = 3,
};

struct Bambu_Sample {
    int                  itrack;
    int                  size;
    int                  flags;
    unsigned char const* buffer;
    unsigned long long   decode_time;
};

struct Bambu_StreamInfo {
    int type;
    int sub_type;
    union {
        struct { int width; int height; int frame_rate; } video;
        struct { int sample_rate; int channel_count; int sample_size; } audio;
    } format;
    int                  format_type;
    int                  format_size;
    int                  max_frame_size;
    unsigned char const* format_buffer;
};

using Bambu_Logger = void (*)(void* context, int level, char const* msg);

int          Bambu_Create(Bambu_Tunnel* tunnel, char const* path);
void         Bambu_Destroy(Bambu_Tunnel tunnel);
void         Bambu_SetLogger(Bambu_Tunnel tunnel, Bambu_Logger logger, void* context);
int          Bambu_Open(Bambu_Tunnel tunnel);
int          Bambu_StartStream(Bambu_Tunnel tunnel, bool video);
int          Bambu_GetStreamInfo(Bambu_Tunnel tunnel, int index, Bambu_StreamInfo* info);
int          Bambu_ReadSample(Bambu_Tunnel tunnel, Bambu_Sample* sample);
void         Bambu_Close(Bambu_Tunnel tunnel);
char const*  Bambu_GetLastErrorMsg();

} // extern "C"

// ---------------------------------------------------------------------------
// Clean-room structs matching Studio's BambuPlayer.h / BambuTunnel.h layout
// (reconstructed from wxMediaCtrl2.mm field usage — not copied from GPL).
// ---------------------------------------------------------------------------

typedef struct __PlayerEventC {
    const char* event_name;
    const char* module;
    const char* phase;
    const char* result;
    const char* error_code;
    const char* error_message;
    const char* event_data_body;
} PlayerEventC;

typedef struct {
    int64_t first_packet_ms;
    int64_t decode_ms;
    int64_t render_ms;
    int     codec;
    int     width;
    int     height;
} BambuFirstFrameInfo;

typedef struct {
    long long session_duration_ms;
    long long freeze_total_ms;
    int       freeze_count;
    float     avg_fps;
    float     avg_bitrate_kbps;
    float     avg_jitter_ms;
    float     max_jitter_ms;
} BambuSessionEndInfo;

using PlayerLoggerFn =
    void (*)(void const* context, int level, char const* msg);
using TrackReporterFn =
    void (*)(void* ctx, const PlayerEventC* event);
using FirstFrameFn =
    void (*)(void const* ctx, const BambuFirstFrameInfo* info);
using SessionEndFn =
    void (*)(void const* ctx, const BambuSessionEndInfo* info);

// ---------------------------------------------------------------------------
// C++ state (ObjC ivars cannot host non-trivial C++ types safely).
// ---------------------------------------------------------------------------

struct BambuPlayerImpl {
    Bambu_Tunnel   tunnel = nullptr;
    std::thread*   reader = nullptr;
    std::atomic<bool> running{false};
    // recursive: display helpers may log while already holding mu
    std::recursive_mutex mu;

    PlayerLoggerFn  logger = nullptr;
    void const*     loggerCtx = nullptr;
    TrackReporterFn trackReporter = nullptr;
    void*           trackCtx = nullptr;
    FirstFrameFn    firstFrameCb = nullptr;
    void const*     firstFrameCtx = nullptr;
    SessionEndFn    sessionEndCb = nullptr;
    void const*     sessionEndCtx = nullptr;

    CMVideoFormatDescriptionRef formatDesc = nullptr;
    std::vector<uint8_t> sps;
    std::vector<uint8_t> pps;
    int videoW = 0;
    int videoH = 0;

    std::chrono::steady_clock::time_point openTime{};
    std::chrono::steady_clock::time_point sessionStart{};
    std::chrono::steady_clock::time_point lastFrameTime{};
    bool     gotFirstPacket = false;
    bool     gotFirstFrame  = false;
    bool     sessionReported = false;
    int64_t  firstPacketMs = 0;
    int64_t  firstDecodeMs = 0;
    uint64_t frameCount = 0;
    uint64_t byteCount  = 0;
    int      freezeCount = 0;
    long long freezeTotalMs = 0;
    double   jitterSumMs = 0.0;
    float    maxJitterMs = 0.f;

    // Render queue and pending frames.
    dispatch_queue_t renderQueue =
        dispatch_queue_create("com.obn.bambuplayer.render", DISPATCH_QUEUE_SERIAL);
    std::mutex                    pendingMu;
    std::deque<CMSampleBufferRef> pending;
    bool                          mediaRequested = false;
    uint64_t                      droppedFrames  = 0;
    std::chrono::steady_clock::time_point lastDropLog{};
    std::chrono::steady_clock::time_point lastFailLog{};

    ~BambuPlayerImpl()
    {
        if (formatDesc) {
            CFRelease(formatDesc);
            formatDesc = nullptr;
        }
        for (CMSampleBufferRef s : pending) CFRelease(s);
        pending.clear();
        if (renderQueue) {
            dispatch_release(renderQueue);
            renderQueue = nullptr;
        }
    }
};

// Buffer up to one second at 30 fps.
static constexpr size_t kMaxPendingFrames = 30;

// Limit backpressure diagnostics to once per second.
static bool throttle_ready(std::chrono::steady_clock::time_point& last)
{
    auto const now = std::chrono::steady_clock::now();
    if (last.time_since_epoch().count() != 0 &&
        now - last < std::chrono::seconds(1)) {
        return false;
    }
    last = now;
    return true;
}

// ---------------------------------------------------------------------------
// BambuPlayer
// ---------------------------------------------------------------------------

__attribute__((visibility("default")))
@interface BambuPlayer : NSObject {
    NSView*                     _imageView;
    AVSampleBufferDisplayLayer* _displayLayer;
    BOOL                        _ownsDisplayLayer;
    BambuPlayerImpl*            _impl;
}

+ (void)initialize;

- (instancetype)initWithDisplayLayer:(AVSampleBufferDisplayLayer*)layer;
- (instancetype)initWithImageView:(NSView*)view;
- (int)open:(char const*)url;
- (NSSize)videoSize;
- (int)play;
- (void)stop;
- (void)close;

- (void)setLogger:(PlayerLoggerFn)logger withContext:(void const*)context;
- (void)setTrackReporter:(TrackReporterFn)reporter withContext:(void*)ctx;
- (void)setFirstFrameCallback:(FirstFrameFn)cb withContext:(void const*)ctx;
- (void)setSessionEndCallback:(SessionEndFn)cb withContext:(void const*)ctx;

@end

@implementation BambuPlayer

+ (void)initialize
{
}

- (instancetype)init
{
    self = [super init];
    if (!self) return nil;
    _impl = new BambuPlayerImpl();
    _ownsDisplayLayer = NO;
    return self;
}

- (instancetype)initWithDisplayLayer:(AVSampleBufferDisplayLayer*)layer
{
    self = [self init];
    if (!self) return nil;
    _displayLayer = [layer retain];
    _ownsDisplayLayer = NO;
    return self;
}

- (instancetype)initWithImageView:(NSView*)view
{
    self = [self init];
    if (!self) return nil;
    _imageView = [view retain];

    void (^setup)(void) = ^{
        if (!_imageView.layer) {
            _imageView.layer = [[[CALayer alloc] init] autorelease];
            _imageView.wantsLayer = YES;
        }
        AVSampleBufferDisplayLayer* layer =
            [[AVSampleBufferDisplayLayer alloc] init];
        layer.videoGravity = AVLayerVideoGravityResizeAspect;
        layer.frame = _imageView.bounds;
        layer.autoresizingMask = kCALayerWidthSizable | kCALayerHeightSizable;
        [_imageView.layer addSublayer:layer];
        _displayLayer = layer;
        _ownsDisplayLayer = YES;
    };
    if ([NSThread isMainThread]) setup();
    else dispatch_sync(dispatch_get_main_queue(), setup);
    return self;
}

- (void)dealloc
{
    [self close];
    delete _impl;
    _impl = nullptr;
    if (_displayLayer) {
        if (_ownsDisplayLayer) {
            [_displayLayer removeFromSuperlayer];
        }
        [_displayLayer release];
        _displayLayer = nil;
    }
    [_imageView release];
    _imageView = nil;
    [super dealloc];
}

// ---- callbacks ----------------------------------------------------------

- (void)setLogger:(PlayerLoggerFn)logger withContext:(void const*)context
{
    std::lock_guard<std::recursive_mutex> lk(_impl->mu);
    _impl->logger    = logger;
    _impl->loggerCtx = context;
}

- (void)setTrackReporter:(TrackReporterFn)reporter withContext:(void*)ctx
{
    std::lock_guard<std::recursive_mutex> lk(_impl->mu);
    _impl->trackReporter = reporter;
    _impl->trackCtx      = ctx;
}

- (void)setFirstFrameCallback:(FirstFrameFn)cb withContext:(void const*)ctx
{
    std::lock_guard<std::recursive_mutex> lk(_impl->mu);
    _impl->firstFrameCb  = cb;
    _impl->firstFrameCtx = ctx;
}

- (void)setSessionEndCallback:(SessionEndFn)cb withContext:(void const*)ctx
{
    std::lock_guard<std::recursive_mutex> lk(_impl->mu);
    _impl->sessionEndCb  = cb;
    _impl->sessionEndCtx = ctx;
}

- (void)logAt:(int)level message:(char const*)msg
{
    PlayerLoggerFn fn = nullptr;
    void const*    ctx = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lk(_impl->mu);
        fn  = _impl->logger;
        ctx = _impl->loggerCtx;
    }
    if (fn && msg) fn(ctx, level, msg);
}

- (void)emitTrack:(char const*)name
            phase:(char const*)phase
           result:(char const*)result
            error:(char const*)error
{
    TrackReporterFn fn = nullptr;
    void*           ctx = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lk(_impl->mu);
        fn  = _impl->trackReporter;
        ctx = _impl->trackCtx;
    }
    if (!fn || !name) return;
    PlayerEventC ev{};
    ev.event_name      = name;
    ev.module          = "BambuPlayer";
    ev.phase           = phase;
    ev.result          = result;
    ev.error_code      = error;
    ev.error_message   = error;
    ev.event_data_body = nullptr;
    fn(ctx, &ev);
}

static void bambu_logger_bridge(void* context, int level, char const* msg)
{
    BambuPlayer* self = static_cast<BambuPlayer*>(context);
    if (!self) return;
    if (!msg) {
        [self logAt:level message:""];
        return;
    }
    // Sanitize access-code material before it reaches Studio logs.
    std::string s(msg);
    auto redact = [&](const char* key) {
        const std::string k = key;
        size_t pos = 0;
        while ((pos = s.find(k, pos)) != std::string::npos) {
            size_t val = pos + k.size();
            size_t end = s.find_first_of("& \t\n\r\"'", val);
            if (end == std::string::npos) end = s.size();
            s.replace(val, end - val, "***");
            pos = val + 3;
        }
    };
    redact("passwd=");
    redact("password=");
    [self logAt:level message:s.c_str()];
}

// ---- lifecycle ----------------------------------------------------------

- (NSSize)videoSize
{
    std::lock_guard<std::recursive_mutex> lk(_impl->mu);
    if (_impl->videoW > 0 && _impl->videoH > 0)
        return NSMakeSize(_impl->videoW, _impl->videoH);
    if (_impl->formatDesc) {
        CMVideoDimensions d =
            CMVideoFormatDescriptionGetDimensions(_impl->formatDesc);
        if (d.width > 0 && d.height > 0)
            return NSMakeSize(d.width, d.height);
    }
    return NSMakeSize(0, 0);
}

- (int)open:(char const*)url
{
    [self close];
    if (!url || !*url) {
        [self logAt:1 message:"open: empty url [-1]"];
        return -1;
    }

    Bambu_Tunnel tunnel = nullptr;
    int rc = Bambu_Create(&tunnel, url);
    if (rc != Bambu_success || !tunnel) {
        [self logAt:1 message:"open: Bambu_Create failed [-1]"];
        [self emitTrack:"liveview_open" phase:"create" result:"fail" error:"create"];
        return -1;
    }
    Bambu_SetLogger(tunnel, bambu_logger_bridge, self);

    rc = Bambu_Open(tunnel);
    if (rc != Bambu_success) {
        Bambu_Destroy(tunnel);
        char buf[256];
        snprintf(buf, sizeof(buf), "open: Bambu_Open failed [%d]", rc);
        [self logAt:1 message:buf];
        [self emitTrack:"liveview_open" phase:"open" result:"fail" error:"open"];
        return rc < 0 ? rc : -1;
    }

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    for (;;) {
        rc = Bambu_StartStream(tunnel, true);
        if (rc != Bambu_would_block) break;
        if (std::chrono::steady_clock::now() >= deadline) {
            Bambu_Close(tunnel);
            Bambu_Destroy(tunnel);
            [self logAt:1 message:"open: StartStream timeout [-1]"];
            [self emitTrack:"liveview_open" phase:"start" result:"fail" error:"timeout"];
            return -1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (rc != Bambu_success) {
        Bambu_Close(tunnel);
        Bambu_Destroy(tunnel);
        char buf[256];
        snprintf(buf, sizeof(buf), "open: Bambu_StartStream failed [%d]", rc);
        [self logAt:1 message:buf];
        [self emitTrack:"liveview_open" phase:"start" result:"fail" error:"start"];
        return rc < 0 ? rc : -1;
    }

    Bambu_StreamInfo info{};
    if (Bambu_GetStreamInfo(tunnel, 0, &info) == Bambu_success) {
        if (info.format.video.width > 0)  _impl->videoW = info.format.video.width;
        if (info.format.video.height > 0) _impl->videoH = info.format.video.height;
        // format_type 2 = video_jpeg — ASBDL cannot display JPEG samples.
        if (info.format_type == 2 /*video_jpeg*/) {
            Bambu_Close(tunnel);
            Bambu_Destroy(tunnel);
            [self logAt:1 message:"open: MJPEG not supported by BambuPlayer [-3]"];
            [self emitTrack:"liveview_open" phase:"format" result:"fail" error:"mjpeg"];
            return -3;
        }
    }

    {
        std::lock_guard<std::recursive_mutex> lk(_impl->mu);
        _impl->tunnel          = tunnel;
        _impl->openTime        = std::chrono::steady_clock::now();
        _impl->sessionStart    = _impl->openTime;
        _impl->gotFirstPacket  = false;
        _impl->gotFirstFrame   = false;
        _impl->sessionReported = false;
        _impl->firstPacketMs   = 0;
        _impl->firstDecodeMs   = 0;
        _impl->frameCount      = 0;
        _impl->byteCount       = 0;
        _impl->freezeCount     = 0;
        _impl->freezeTotalMs   = 0;
        _impl->jitterSumMs     = 0.0;
        _impl->maxJitterMs     = 0.f;
        _impl->sps.clear();
        _impl->pps.clear();
        if (_impl->formatDesc) {
            CFRelease(_impl->formatDesc);
            _impl->formatDesc = nullptr;
        }
    }

    [self emitTrack:"liveview_open" phase:"open" result:"ok" error:nullptr];
    [self logAt:0 message:"open: ok"];
    return 0;
}

- (int)play
{
    // Reap a previous reader that exited on its own (EOF/error) without
    // close. Joining must happen *outside* the mutex — readerLoop may
    // still be taking _impl->mu on its way out. Deleting a joinable
    // std::thread is UB (std::terminate).
    std::thread* stale = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lk(_impl->mu);
        if (!_impl->tunnel) {
            [self logAt:1 message:"play: no open tunnel [-1]"];
            return -1;
        }
        if (_impl->running.load()) return 0;
        stale = _impl->reader;
        _impl->reader = nullptr;
    }
    if (stale) {
        if (stale->joinable()) stale->join();
        delete stale;
    }

    {
        std::lock_guard<std::recursive_mutex> lk(_impl->mu);
        if (!_impl->tunnel) {
            [self logAt:1 message:"play: no open tunnel [-1]"];
            return -1;
        }
        if (_impl->running.load()) return 0;
        _impl->running.store(true);
        _impl->sessionStart  = std::chrono::steady_clock::now();
        _impl->lastFrameTime = _impl->sessionStart;
        _impl->reader = new std::thread([self] { [self readerLoop]; });
    }
    [self emitTrack:"liveview_play" phase:"play" result:"ok" error:nullptr];
    return 0;
}

- (void)stop
{
    [self close];
}

- (void)close
{
    _impl->running.store(false);

    std::thread* thr = nullptr;
    Bambu_Tunnel tunnel = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lk(_impl->mu);
        thr = _impl->reader;
        _impl->reader = nullptr;
        tunnel = _impl->tunnel;
        _impl->tunnel = nullptr;
    }

    if (thr) {
        if (thr->joinable()) thr->join();
        delete thr;
    }

    if (tunnel) {
        Bambu_Close(tunnel);
        Bambu_Destroy(tunnel);
    }

    [self shutdownRenderPump];

    AVSampleBufferDisplayLayer* layer = _displayLayer;
    if (layer) {
        void (^flush)(void) = ^{
            if ([layer respondsToSelector:@selector(flushAndRemoveImage)])
                [layer flushAndRemoveImage];
            else
                [layer flush];
        };
        if ([NSThread isMainThread]) flush();
        else dispatch_sync(dispatch_get_main_queue(), flush);
    }

    [self fireSessionEndIfNeeded];
}

- (void)fireSessionEndIfNeeded
{
    SessionEndFn cb = nullptr;
    void const*  ctx = nullptr;
    BambuSessionEndInfo info{};
    {
        std::lock_guard<std::recursive_mutex> lk(_impl->mu);
        if (_impl->sessionReported) return;
        if (_impl->frameCount == 0 && !_impl->gotFirstFrame) return;
        _impl->sessionReported = true;
        cb  = _impl->sessionEndCb;
        ctx = _impl->sessionEndCtx;
        auto now = std::chrono::steady_clock::now();
        info.session_duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - _impl->sessionStart).count();
        info.freeze_total_ms = _impl->freezeTotalMs;
        info.freeze_count    = _impl->freezeCount;
        if (info.session_duration_ms > 0 && _impl->frameCount > 0) {
            info.avg_fps = static_cast<float>(
                (1000.0 * static_cast<double>(_impl->frameCount)) /
                static_cast<double>(info.session_duration_ms));
            info.avg_bitrate_kbps = static_cast<float>(
                (8.0 * static_cast<double>(_impl->byteCount) / 1000.0) /
                (static_cast<double>(info.session_duration_ms) / 1000.0));
        }
        if (_impl->frameCount > 1) {
            info.avg_jitter_ms = static_cast<float>(
                _impl->jitterSumMs / static_cast<double>(_impl->frameCount - 1));
        }
        info.max_jitter_ms = _impl->maxJitterMs;
    }
    if (cb) cb(ctx, &info);
    [self emitTrack:"liveview_session_end" phase:"close" result:"ok" error:nullptr];
}

// ---- reader / display ---------------------------------------------------

- (BOOL)ensureFormatDescWithSps:(const std::vector<uint8_t>&)sps
                            pps:(const std::vector<uint8_t>&)pps
{
    // Caller holds _impl->mu.
    if (sps.empty() || pps.empty()) return NO;
    if (_impl->formatDesc && sps == _impl->sps && pps == _impl->pps) return YES;

    const uint8_t* sets[2]  = { sps.data(), pps.data() };
    size_t         sizes[2] = { sps.size(), pps.size() };
    CMVideoFormatDescriptionRef desc = nullptr;
    OSStatus st = CMVideoFormatDescriptionCreateFromH264ParameterSets(
        kCFAllocatorDefault, 2, sets, sizes, 4, &desc);
    if (st != noErr || !desc) {
        char buf[128];
        snprintf(buf, sizeof(buf), "formatDesc create failed status=%d", (int)st);
        [self logAt:1 message:buf];
        return NO;
    }
    if (_impl->formatDesc) CFRelease(_impl->formatDesc);
    _impl->formatDesc = desc;
    _impl->sps = sps;
    _impl->pps = pps;
    CMVideoDimensions d = CMVideoFormatDescriptionGetDimensions(desc);
    if (d.width > 0 && d.height > 0) {
        _impl->videoW = d.width;
        _impl->videoH = d.height;
    }
    return YES;
}

- (BOOL)enqueueAnnexB:(const uint8_t*)data
                 size:(size_t)size
                 sync:(BOOL)isSync
{
    obn::h264::ParameterSets ps;
    const bool havePs = obn::h264::extract_parameter_sets(data, size, &ps);

    CMVideoFormatDescriptionRef fmt = nullptr;
    AVSampleBufferDisplayLayer* layer = nil;
    {
        std::lock_guard<std::recursive_mutex> lk(_impl->mu);
        if (havePs) {
            if (![self ensureFormatDescWithSps:ps.sps pps:ps.pps]) return NO;
        }
        fmt   = _impl->formatDesc;
        layer = _displayLayer;
        if (!fmt || !layer) return NO;
        CFRetain(fmt);
        [layer retain];
    }

    obn::h264::AvccFrame avcc;
    if (!obn::h264::annexb_to_avcc(data, size, &avcc)) {
        CFRelease(fmt);
        [layer release];
        return NO;
    }

    CMBlockBufferRef block = nullptr;
    OSStatus st = CMBlockBufferCreateWithMemoryBlock(
        kCFAllocatorDefault, nullptr, avcc.data.size(),
        kCFAllocatorDefault, nullptr, 0, avcc.data.size(),
        kCMBlockBufferAssureMemoryNowFlag, &block);
    if (st != noErr || !block) {
        CFRelease(fmt);
        [layer release];
        return NO;
    }
    st = CMBlockBufferReplaceDataBytes(avcc.data.data(), block, 0, avcc.data.size());
    if (st != noErr) {
        CFRelease(block);
        CFRelease(fmt);
        [layer release];
        return NO;
    }

    CMSampleBufferRef sample = nullptr;
    size_t sampleSize = avcc.data.size();
    CMSampleTimingInfo timing;
    timing.duration              = kCMTimeInvalid;
    timing.presentationTimeStamp = kCMTimeInvalid;
    timing.decodeTimeStamp       = kCMTimeInvalid;
    st = CMSampleBufferCreateReady(
        kCFAllocatorDefault, block, fmt, 1, 1, &timing, 1, &sampleSize, &sample);
    CFRelease(block);
    CFRelease(fmt);
    if (st != noErr || !sample) {
        [layer release];
        return NO;
    }

    CFArrayRef attachments = CMSampleBufferGetSampleAttachmentsArray(sample, true);
    if (attachments && CFArrayGetCount(attachments) > 0) {
        CFMutableDictionaryRef dict =
            (CFMutableDictionaryRef)CFArrayGetValueAtIndex(attachments, 0);
        CFDictionarySetValue(dict, kCMSampleAttachmentKey_DisplayImmediately,
                             kCFBooleanTrue);
        if (!isSync && !avcc.contains_idr) {
            CFDictionarySetValue(dict, kCMSampleAttachmentKey_NotSync,
                                 kCFBooleanTrue);
        }
    }

    if (layer.status == AVQueuedSampleBufferRenderingStatusFailed) {
        // Reset the failed layer; the next frame restarts the pump.
        [self recoverFailedLayer:layer];
        CFRelease(sample);
        [layer release];
        return NO;
    }

    [self queueSampleForDisplay:sample layer:layer];
    CFRelease(sample);
    [layer release];
    return YES;
}

// Queue a frame without blocking the reader.
- (void)queueSampleForDisplay:(CMSampleBufferRef)sample
                        layer:(AVSampleBufferDisplayLayer*)layer
{
    CMSampleBufferRef dropped = nullptr;
    uint64_t dropTotal = 0;
    bool     logDrop   = false;
    bool     startPump = false;
    {
        std::lock_guard<std::mutex> lk(_impl->pendingMu);
        if (_impl->pending.size() >= kMaxPendingFrames) {
            dropped = _impl->pending.front();
            _impl->pending.pop_front();
            _impl->droppedFrames += 1;
            dropTotal = _impl->droppedFrames;
            logDrop   = throttle_ready(_impl->lastDropLog);
        }
        CFRetain(sample);
        _impl->pending.push_back(sample);
        startPump = !_impl->mediaRequested;
        _impl->mediaRequested = true;
    }

    if (dropped) CFRelease(dropped);
    if (logDrop) {
        char buf[96];
        snprintf(buf, sizeof(buf), "renderer behind, dropped %llu frame(s)",
                 (unsigned long long)dropTotal);
        [self logAt:0 message:buf];
    }
    if (startPump) [self startRenderPumpForLayer:layer];
}

- (void)startRenderPumpForLayer:(AVSampleBufferDisplayLayer*)layer
{
    if (!_impl->renderQueue) return;
    // Avoid a layer-block-self retain cycle.
    __unsafe_unretained BambuPlayer* me = self;
    __unsafe_unretained AVSampleBufferDisplayLayer* l = layer;
    [layer requestMediaDataWhenReadyOnQueue:_impl->renderQueue usingBlock:^{
        [me pumpLayer:l];
    }];
}

// Pump frames while the layer has capacity.
- (void)pumpLayer:(AVSampleBufferDisplayLayer*)layer
{
    while (layer.isReadyForMoreMediaData) {
        if (layer.status == AVQueuedSampleBufferRenderingStatusFailed) {
            [self recoverFailedLayer:layer];
            return;
        }

        CMSampleBufferRef sample = nullptr;
        {
            std::lock_guard<std::mutex> lk(_impl->pendingMu);
            if (_impl->pending.empty()) {
                // Stop until another frame arrives.
                [layer stopRequestingMediaData];
                _impl->mediaRequested = false;
                return;
            }
            sample = _impl->pending.front();
            _impl->pending.pop_front();
        }

        [layer enqueueSampleBuffer:sample];
        CFRelease(sample);
    }
}

// Flush the failed layer; the reader restarts the pump.
- (void)recoverFailedLayer:(AVSampleBufferDisplayLayer*)layer
{
    bool logFail = false;
    {
        std::lock_guard<std::mutex> lk(_impl->pendingMu);
        logFail = throttle_ready(_impl->lastFailLog);
    }
    if (logFail) {
        NSError*    err   = layer.error;
        NSString*   desc  = err ? err.localizedDescription : nil;
        char const* cdesc = desc ? desc.UTF8String : nullptr;
        char buf[160];
        snprintf(buf, sizeof(buf), "layer failed, flushing: %s",
                 cdesc ? cdesc : "(no description)");
        [self logAt:1 message:buf];
    }

    [layer flush];

    std::deque<CMSampleBufferRef> stale;
    {
        std::lock_guard<std::mutex> lk(_impl->pendingMu);
        stale.swap(_impl->pending);
        if (_impl->mediaRequested) [layer stopRequestingMediaData];
        _impl->mediaRequested = false;
    }
    for (CMSampleBufferRef s : stale) CFRelease(s);
}

// Stop the pump before destroying _impl.
- (void)shutdownRenderPump
{
    AVSampleBufferDisplayLayer* layer = _displayLayer;
    std::deque<CMSampleBufferRef> stale;
    {
        std::lock_guard<std::mutex> lk(_impl->pendingMu);
        stale.swap(_impl->pending);
        if (_impl->mediaRequested && layer) [layer stopRequestingMediaData];
        _impl->mediaRequested = false;
    }
    for (CMSampleBufferRef s : stale) CFRelease(s);
    if (_impl->renderQueue) dispatch_sync(_impl->renderQueue, ^{});
}

- (void)readerLoop
{
    [self logAt:0 message:"reader: start"];
    while (_impl->running.load()) {
        Bambu_Tunnel tunnel = nullptr;
        {
            std::lock_guard<std::recursive_mutex> lk(_impl->mu);
            tunnel = _impl->tunnel;
        }
        if (!tunnel) break;

        Bambu_Sample sample{};
        int rc = Bambu_ReadSample(tunnel, &sample);
        if (rc == Bambu_would_block) {
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
            continue;
        }
        if (rc == Bambu_stream_end || rc < 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "reader: stream ended rc=%d", rc);
            [self logAt:-1 message:buf];
            [self emitTrack:"liveview_stream" phase:"read" result:"end" error:"eof"];
            break;
        }
        if (rc != Bambu_success || !sample.buffer || sample.size <= 0) {
            continue;
        }

        auto now = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::recursive_mutex> lk(_impl->mu);
            if (!_impl->gotFirstPacket) {
                _impl->gotFirstPacket = true;
                _impl->firstPacketMs =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - _impl->openTime).count();
            }
            if (_impl->frameCount > 0) {
                auto gap = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - _impl->lastFrameTime).count();
                float gapf = static_cast<float>(gap);
                if (gap > 500) {
                    _impl->freezeCount += 1;
                    _impl->freezeTotalMs += gap;
                }
                float jitter = gapf - 33.f;
                if (jitter < 0) jitter = -jitter;
                _impl->jitterSumMs += jitter;
                if (jitter > _impl->maxJitterMs) _impl->maxJitterMs = jitter;
            }
            _impl->lastFrameTime = now;
            _impl->byteCount += static_cast<uint64_t>(sample.size);
        }

        const bool isSync = (sample.flags & 1) != 0 ||
            obn::h264::contains_idr(sample.buffer,
                                    static_cast<size_t>(sample.size));

        // sample.buffer is borrowed until the next Bambu_ReadSample; we
        // consume it synchronously here (and enqueueAnnexB copies into a
        // CMBlockBuffer), so no intermediate std::vector is needed.
        auto decode_start = std::chrono::steady_clock::now();
        BOOL ok = [self enqueueAnnexB:sample.buffer
                                 size:static_cast<size_t>(sample.size)
                                 sync:isSync ? YES : NO];
        auto decode_end = std::chrono::steady_clock::now();
        if (!ok) continue;

        FirstFrameFn ffCb = nullptr;
        void const*  ffCtx = nullptr;
        BambuFirstFrameInfo ffInfo{};
        bool fireFirst = false;
        {
            std::lock_guard<std::recursive_mutex> lk(_impl->mu);
            _impl->frameCount += 1;
            if (!_impl->gotFirstFrame) {
                _impl->gotFirstFrame = true;
                _impl->firstDecodeMs =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        decode_end - decode_start).count();
                ffInfo.first_packet_ms = _impl->firstPacketMs;
                ffInfo.decode_ms       = _impl->firstDecodeMs;
                ffInfo.render_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        decode_end - _impl->openTime).count();
                ffInfo.codec  = 0;
                ffInfo.width  = _impl->videoW;
                ffInfo.height = _impl->videoH;
                ffCb  = _impl->firstFrameCb;
                ffCtx = _impl->firstFrameCtx;
                fireFirst = true;
            }
        }
        if (fireFirst) {
            if (ffCb) ffCb(ffCtx, &ffInfo);
            [self emitTrack:"liveview_first_frame" phase:"play" result:"ok" error:nullptr];
            [self logAt:0 message:"reader: first frame"];
        }
    }

    [self logAt:0 message:"reader: exit"];
    _impl->running.store(false);
}

@end
