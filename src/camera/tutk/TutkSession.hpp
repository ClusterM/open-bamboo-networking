// TutkSession: one TUTK camera session with a printer.
//
// A worker thread finds the printer (LAN search first, then the ThroughTek
// relay), runs the DTLS-PSK handshake, logs in to the AV server and delivers
// reassembled video frames (or file-browser replies) through the callback
// until leave() is called or the session cannot be re-established.

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

// Called on the worker thread with one frame: H.264 Annex-B or a JPEG, or
// in Mode::Ctrl one file-browser reply ("<json>[\n\n<binary>]").
using FrameCallback = std::function<void(const uint8_t* data, int len,
                                         int64_t pts_us, bool keyframe)>;

class TutkSession {
public:
    // Video: IPCAM_START after login, frames are H.264 / JPEG.
    // Ctrl: no stream is started; send_ctrl() carries PrinterFileSystem
    // JSON as IOCtrl 0x3001 and every frame the printer sends back is a
    // reply. Ctrl needs the framed transport.
    enum class Mode { Video, Ctrl };

    // Largest JSON send_ctrl() accepts (it goes out as a single packet).
    static constexpr size_t kMaxCtrlLen = 1200;

    TutkSession();
    ~TutkSession();

    TutkSession(const TutkSession&) = delete;
    TutkSession& operator=(const TutkSession&) = delete;

    // Starts the worker; returns immediately. Frames arrive through cb.
    void join(const TutkSessionParams& params, FrameCallback cb, Mode mode = Mode::Video);
    // Stops the worker and waits for it to close the session.
    void leave();

    bool is_joined() const;
    // Mode::Ctrl: the AV login succeeded and send_ctrl() reaches the printer.
    bool is_ready() const;
    // Mode::Ctrl: queues one request; false when it is too long or the
    // session is gone.
    bool send_ctrl(const std::string& json);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace tutk
} // namespace camera
} // namespace obn
