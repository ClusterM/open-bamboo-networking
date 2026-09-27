// TutkSession: one TUTK camera session with a printer.
//
// A worker thread finds the printer (LAN search first, then the ThroughTek
// relay), runs the DTLS-PSK handshake, logs in to the AV server and delivers
// reassembled video frames through the callback until leave() is called or
// the session cannot be re-established.

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace obn {
namespace camera {
namespace tutk {

// Values of a bambu:///tutk URL.
struct TutkSessionParams {
    std::string uid;       // 20-character device UID, uppercase
    std::string passwd;    // DTLS PSK source and AV login password
    std::string authkey;   // 8-character key for LAN search and rendezvous
    std::string region;    // relay region: "cn", "eu" or "us"
    std::string relay_id;  // relay subdomain; defaults to the UID
};

// Called on the worker thread with one frame: H.264 Annex-B or a JPEG.
using FrameCallback = std::function<void(const uint8_t* data, int len,
                                         int64_t pts_us, bool keyframe)>;

class TutkSession {
public:
    TutkSession();
    ~TutkSession();

    TutkSession(const TutkSession&) = delete;
    TutkSession& operator=(const TutkSession&) = delete;

    // Starts the worker; returns immediately. Frames arrive through cb.
    void join(const TutkSessionParams& params, FrameCallback cb);
    // Stops the worker and waits for it to close the session.
    void leave();

    bool is_joined() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace tutk
} // namespace camera
} // namespace obn
