// OssAgoraEngine
//
// Exports createAgoraRtcEngine() with the same ABI that libBambuSource.so
// expects (Agora SDK 4.x, x86_64 Linux Itanium ABI).
//
// The engine object is a plain-C struct with a manually
// constructed vtable so the exact slot positions are under our control.
//
// Known vtable slots (byte offset → slot index = offset/8):
//   IRtcEngine:
//     0x00 → slot  0: dtor D1 (complete-object destructor)
//     0x08 → slot  1: dtor D0 (deleting destructor)
//     0x10 → slot  2: queryInterface(iid, **out)     [IEngineBase]
//     0x18 → slot  3: release(bool sync)
//     0x20 → slot  4: initialize(RtcEngineContext*)
//     0xC8 → slot 25: (setup call, no args)
//     0x150→ slot 42: leaveChannel()
//     0x158→ slot 43: (cleanup call, no args)
//     0x1A8→ slot 53: (enable call, arg=0)
//     0x1B0→ slot 54: (enable call, arg=1)
//     0x7E0→ slot252: joinChannelWithOptions(token,ch,info,uid,opts,evtHdlr)
//     0x8B0→ slot278: enableEncryption(ch,key,mode)
//
//   IMediaEngine (obtained via queryInterface(4, &out)):
//     slot 0: dtor D1
//     slot 1: dtor D0
//     slot 2: registerAudioFrameObserver(*)
//     slot 3: registerVideoFrameObserver(*)           ← used by RegisterObserver
//     ...
//
// All unimplemented slots default to oss_noop (returns 0).

#pragma once

#include "OssAgoraSignaling.hpp"

#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace bambu_net {
namespace camera {
namespace oss_agora {

// Plain structs with manually-built vtables; no C++ virtual dispatch.

struct OssVideoFrame {
    std::vector<uint8_t> data;
    int64_t pts_us      = 0;
    bool    is_keyframe = false;
};

struct OssFrameQueue {
    std::mutex              mu;
    std::deque<OssVideoFrame> frames;
    static constexpr size_t kMaxFrames = 120;

    void push(OssVideoFrame f) {
        std::lock_guard<std::mutex> lk(mu);
        if (frames.size() >= kMaxFrames) frames.pop_front();
        frames.push_back(std::move(f));
    }

    bool pop(OssVideoFrame& out) {
        std::lock_guard<std::mutex> lk(mu);
        if (frames.empty()) return false;
        out = std::move(frames.front());
        frames.pop_front();
        return true;
    }
};

// Engine state. First field MUST be the vtable pointer.
struct OssEngine {
    void**         vtable;          // ← must be first — C++ ABI requires this
    std::string    app_id;
    uint32_t       area_code = 0xFFFFFFFF;
    OssFrameQueue* frame_queue = nullptr; // borrowed; owned by caller

    // Populated by joinChannel.
    std::string    channel;
    std::string    token;
    uint32_t       uid = 0;

    std::atomic<bool> joined{false};
    bool           released = false;

    OssAgoraSignaling* signaling = nullptr;

    // IVideoFrameObserver* from libBambuSource::registerVideoFrameObserver();
    // called back through vtable slot 6 (onRenderVideoFrame) on each frame.
    void* registered_observer = nullptr;

    std::vector<AgoraEdgeServer> edge_servers;
};

// IMediaEngine shim — returned by queryInterface(4).
struct OssMediaEngine {
    void**      vtable;
    OssEngine*  engine;
};

// IVideoFrameObserver shim — registered by libBambuSource's RegisterObserver.
struct OssVideoObserver {
    void**         vtable;
    OssEngine*     engine;
};

// Called by libBambuSource.so via dlsym.  Returns OssEngine*; caller calls release().
extern "C" void* createAgoraRtcEngine();

} // namespace oss_agora
} // namespace camera
} // namespace bambu_net
