// libBambuSource.so: LAN-only video source for Bambu Lab printers, as
// consumed by Bambu Studio's `gstbambusrc` element.
//
// Bambu Studio loads this library via NetworkAgent::get_bambu_source_entry()
// (`dlopen` of `<data_dir>/plugins/libBambuSource.so`). We support both
// LAN video protocols:
//
//   * MJPG over TLS on port 6000 - used by A1 / A1 mini / P1 / P1P.
//     Protocol is the 80-byte auth packet + 16-byte frame headers
//     documented in OpenBambuAPI/video.md and implemented below.
//
//   * RTSPS on port 322 - used by X1 / P1S / P2S / N7. The RTSP/RTSPS
//     handshake plus RTP-H.264 depacketisation lives in
//     stubs/rtsp_client.cpp; stubs/rtsp_passthrough.cpp wraps that in
//     a worker thread that hands Annex-B-framed access units to the
//     C ABI. We do NOT decode or transcode: gstbambusrc.c (vendored
//     verbatim by both Bambu Studio and Orca Slicer on Linux) feeds
//     whatever Bambu_ReadSample returns into h264parse + avdec_h264 /
//     openh264dec / vaapih264dec, so the slicer-side pipeline does
//     all the heavy lifting and we stay free of any in-process
//     libavcodec dependency.
//
// URL formats we accept (all three appear in Studio's source):
//
//   bambu:///local/<ip>?port=6000&user=<u>&passwd=<p>&...
//   bambu:///local/<ip>.?port=6000&user=<u>&passwd=<p>&...        (legacy)
//       -> TCP/TLS MJPG on port 6000 (P1/A1 firmware protocol)
//
//   bambu:///rtsps___<user>:<passwd>@<ip>/streaming/live/1?proto=rtsps
//   bambu:///rtsp___<user>:<passwd>@<ip>/streaming/live/1?proto=rtsp
//       -> RTSP(S) on port 322 (X1/P1S/P2S/N7 firmware protocol);
//          routed through obn::rtsp::Passthrough (raw H.264 byte stream).
//
// Extra query parameters (device=, net_ver=, dev_ver=, cli_id=, ...) are
// ignored by the printer but device= is used for LAN TLS verify (SNI +
// CN=serial). The printer only cares about the auth packet (MJPG) or
// the RTSP DESCRIBE/SETUP/PLAY exchange.
//
// Protocol summary (see OpenBambuAPI/video.md for the canonical spec):
//
//   1. TLS handshake over TCP on <ip>:<port>; chain + CN=serial verified
//      via printer.cer unless OBN_SKIP_TLS_VERIFY is set.
//   2. Send 80-byte auth packet:
//        [0..3]   little-endian uint32 = 0x40          (payload size)
//        [4..7]   little-endian uint32 = 0x3000        (type: auth)
//        [8..11]  little-endian uint32 = 0             (flags)
//        [12..15] little-endian uint32 = 0
//        [16..47] 32 bytes: ASCII username, NUL-padded
//        [48..79] 32 bytes: ASCII password, NUL-padded
//   3. Server then streams frames indefinitely. Each frame is:
//        16-byte header (payload_size u32, itrack u32, flags u32, pad u32)
//        followed by `payload_size` bytes of JPEG data (FF D8 ... FF D9).
//
// gstbambusrc contract (see gstbambusrc.c):
//
//   Bambu_Create    (parse URL, allocate tunnel)
//   Bambu_SetLogger (attach log callback)
//   Bambu_Open      (blocking connect + TLS handshake + auth)
//   Bambu_StartStream(video=1) until it returns != would_block
//   Bambu_GetStreamCount / Bambu_GetStreamInfo   (once)
//   loop {
//     Bambu_ReadSample()      // would_block is fine, gst sleeps 33 ms
//     ...if success, emit buffer...
//   }
//   Bambu_Close + Bambu_Destroy at teardown.
//
// Thread safety: `gstbambusrc` calls us from a single streaming thread per
// tunnel; we only need to be safe against the logger callback being fired
// from that same thread. No global locks are held.

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "obn/os_compat.hpp"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "obn/config.hpp"
#include "obn/ftps.hpp"
#include "obn/json_lite.hpp"
#include "obn/lan_tls.hpp"
#include "obn/lan_tls_env.hpp"
#include "obn/tunnel_local.hpp"

#include "source_log.hpp"
#include "rtsp_passthrough.hpp"
#include "tls_socket.hpp"

#if defined(_WIN32)
#    define OBN_EXPORT extern "C" __declspec(dllexport)
#else
#    define OBN_EXPORT extern "C" __attribute__((visibility("default")))
#endif

// -----------------------------------------------------------------------
// Types redeclared from BambuTunnel.h. We do NOT include the original
// header because it is part of Bambu Studio's proprietary build tree
// (GPL-incompatible). All layout / enum values are checked against
// OpenBambuAPI documentation and gstbambusrc.c behaviour.
// -----------------------------------------------------------------------

extern "C" {

typedef void* Bambu_Tunnel;
// Studio's tchar contract differs by platform: Linux/macOS pass char*,
// Windows passes wchar_t* (matches wxMediaCtrl2's Bambu_FreeLogMsg /
// gstbambusrc's bambu_log signature).
#if defined(_WIN32)
using tchar = wchar_t;
#else
using tchar = char;
#endif

enum Bambu_StreamType { VIDE = 0, AUDI = 1 };
enum Bambu_VideoSubType { AVC1 = 0, MJPG = 1 };
enum Bambu_FormatType {
    video_avc_packet = 0,
    video_avc_byte_stream,
    video_jpeg,
    audio_raw,
    audio_adts,
};
enum Bambu_Error { Bambu_success = 0, Bambu_stream_end, Bambu_would_block, Bambu_buffer_limit };

struct Bambu_StreamInfo {
    int type;       // Bambu_StreamType
    int sub_type;   // Bambu_VideoSubType / Bambu_AudioSubType
    union {
        struct {
            int width;
            int height;
            int frame_rate;
        } video;
        struct {
            int sample_rate;
            int channel_count;
            int sample_size;
        } audio;
    } format;
    int                   format_type;    // Bambu_FormatType
    int                   format_size;
    int                   max_frame_size;
    unsigned char const*  format_buffer;
};

struct Bambu_Sample {
    int                   itrack;
    int                   size;
    int                   flags;
    unsigned char const*  buffer;
    unsigned long long    decode_time; // 100ns units, per gstbambusrc expectations
};

// Studio's Logger typedef. We keep the C-visible alias so the
// exported Bambu_SetLogger / Bambu_FreeLogMsg signatures stay
// byte-identical with what gstbambusrc and wxMediaCtrl2 expect.
using Logger = void (*)(void* context, int level, tchar const* msg);

} // extern "C"

// -----------------------------------------------------------------------
// All log/last-error helpers live in stubs/source_log.{hpp,cpp} so the
// RTSP client can share them. We pull the names into
// the anonymous namespace below so existing call sites (`log_fmt`,
// `log_at`, `mirror_log_fp`, `set_last_error`, `LL_DEBUG`, ...) keep
// compiling unchanged.
// -----------------------------------------------------------------------

namespace {

using obn::source::log_at;
using obn::source::log_fmt;
using obn::source::mirror_log_fp;
using obn::source::noop_logger;
using obn::source::set_last_error;
using obn::source::LL_TRACE;
using obn::source::LL_DEBUG;
using obn::source::LL_INFO;
using obn::source::LL_WARN;
using obn::source::LL_ERROR;
using obn::source::LL_OFF;

// -----------------------------------------------------------------------
// URL parser. Bambu URLs:
//   bambu:///local/<ip>?port=6000&user=<u>&passwd=<p>&...
//   bambu:///local/<ip>.?port=6000&...       (note the trailing dot)
// -----------------------------------------------------------------------

enum class Scheme {
    Local, // MJPG over TCP/TLS on <port> (default 6000)
    Rtsps, // RTSPS on <port> (default 322)
    Rtsp,  // plain RTSP on <port> (default 554)
};

struct TunnelUrl {
    Scheme      scheme = Scheme::Local;
    std::string host;
    int         port = 6000;
    std::string user = "bblp";
    std::string passwd;
    std::string device;
    std::string cli_id;
    std::string cli_ver;
    std::string net_ver;
    std::string path = "/streaming/live/1"; // RTSP(S) only
};

std::string url_decode(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return 10 + c - 'a';
                if (c >= 'A' && c <= 'F') return 10 + c - 'A';
                return -1;
            };
            int a = hex(s[i + 1]);
            int b = hex(s[i + 2]);
            if (a >= 0 && b >= 0) {
                out.push_back(static_cast<char>((a << 4) | b));
                i += 2;
                continue;
            }
        }
        out.push_back(s[i] == '+' ? ' ' : s[i]);
    }
    return out;
}

bool parse_url(const std::string& url, TunnelUrl* out)
{
    // Recognise the three URL shapes Studio hands us. Whichever it is,
    // strip the prefix and leave `rest` = "<...>[?query]".
    static const std::string p_local  = "bambu:///local/";
    static const std::string p_rtsps  = "bambu:///rtsps___";
    static const std::string p_rtsp   = "bambu:///rtsp___";

    std::string rest;
    if (url.compare(0, p_local.size(), p_local) == 0) {
        out->scheme = Scheme::Local;
        out->port   = 6000;
        rest = url.substr(p_local.size());
    } else if (url.compare(0, p_rtsps.size(), p_rtsps) == 0) {
        out->scheme = Scheme::Rtsps;
        out->port   = 322;
        rest = url.substr(p_rtsps.size());
    } else if (url.compare(0, p_rtsp.size(), p_rtsp) == 0) {
        out->scheme = Scheme::Rtsp;
        out->port   = 554;
        rest = url.substr(p_rtsp.size());
    } else {
        // Bare "<ip>:<port>/..." fallback.
        out->scheme = Scheme::Local;
        out->port   = 6000;
        rest = url;
    }

    // Split host.part vs ?query.
    auto q_pos = rest.find('?');
    std::string host_part = (q_pos == std::string::npos) ? rest : rest.substr(0, q_pos);
    std::string query     = (q_pos == std::string::npos) ? ""   : rest.substr(q_pos + 1);

    if (out->scheme == Scheme::Rtsps || out->scheme == Scheme::Rtsp) {
        // "<user>:<passwd>@<host>[:port]/<path>" (path is required and
        // Studio always sends "streaming/live/1").
        auto at_pos = host_part.find('@');
        if (at_pos != std::string::npos) {
            std::string userinfo = host_part.substr(0, at_pos);
            host_part            = host_part.substr(at_pos + 1);
            auto col             = userinfo.find(':');
            if (col != std::string::npos) {
                out->user   = url_decode(userinfo.substr(0, col));
                out->passwd = url_decode(userinfo.substr(col + 1));
            } else {
                out->user = url_decode(userinfo);
            }
        }
        auto slash = host_part.find('/');
        if (slash != std::string::npos) {
            out->path = host_part.substr(slash); // includes leading '/'
            host_part = host_part.substr(0, slash);
        }
        // Host may still carry ":<port>". Fall through to the colon
        // handling below.
    } else {
        // Legacy MJPG URL: "<ip>.?port=..." -> trim trailing . and /
        while (!host_part.empty() &&
               (host_part.back() == '/' || host_part.back() == '.'))
            host_part.pop_back();
    }

    // Optional ":<port>" in host_part.
    auto colon = host_part.find(':');
    if (colon != std::string::npos) {
        out->host = host_part.substr(0, colon);
        try {
            out->port = std::stoi(host_part.substr(colon + 1));
        } catch (...) {
            return false;
        }
    } else {
        out->host = host_part;
    }

    // Parse query. Local-scheme URLs carry user/passwd here;
    // RTSP(S) URLs carry them in the userinfo above, so these are
    // effectively a no-op for those.
    size_t i = 0;
    while (i < query.size()) {
        auto amp = query.find('&', i);
        if (amp == std::string::npos) amp = query.size();
        auto kv = query.substr(i, amp - i);
        auto eq = kv.find('=');
        std::string key = (eq == std::string::npos) ? kv : kv.substr(0, eq);
        std::string val = (eq == std::string::npos) ? "" : url_decode(kv.substr(eq + 1));
        if      (key == "port")   { try { out->port = std::stoi(val); } catch (...) { /* keep default */ } }
        else if (key == "user")   { out->user = val; }
        else if (key == "passwd") { out->passwd = val; }
        else if (key == "device") { out->device = val; }
        else if (key == "cli_id") { out->cli_id = val; }
        else if (key == "cli_ver") { out->cli_ver = val; }
        else if (key == "net_ver") { out->net_ver = val; }
        i = amp + 1;
    }

    return !out->host.empty() && out->port > 0;
}

// -----------------------------------------------------------------------
// OpenSSL one-time init via tls_socket (shared with RTSPS / FTPS paths).
// -----------------------------------------------------------------------

void ssl_init_once()
{
    // Ensures OpenSSL + the shared tls_socket SSL_CTX are ready.
    (void)obn::tls::shared_ctx();
}

// -----------------------------------------------------------------------
// Tunnel state. All network IO is synchronous (blocking) on purpose;
// gstbambusrc already runs us on a dedicated streaming thread.
// -----------------------------------------------------------------------

// Reasonable upper bound for a single 1280x720 JPEG frame. The stock
// camera tops out around 60 KB but we give ourselves a whole megabyte
// of headroom in case Bambu ships higher-res firmware later.
constexpr size_t kMaxFrameSize = 1u << 20;

// --------------------------------------------------------------------
// PrinterFileSystem CTRL state.
//
// Studio opens a port-6000 tunnel through us (Bambu_Create/Bambu_Open
// on `bambu:///local/<ip>.?port=6000&user=bblp&passwd=<code>&...`) and
// then calls `Bambu_StartStreamEx(tunnel, CTRL_TYPE=0x3001)`. After
// that point it stops asking for video and instead pushes JSON request
// strings through `Bambu_SendMessage(CTRL_TYPE)`, expecting JSON
// responses through `Bambu_ReadSample`. We forward those frames to
// printer firmware over the same TLS :6000 session (native passthrough).
// --------------------------------------------------------------------

constexpr int kCtrlType    = 0x3001;

// PrinterFileSystem command types (req.cmdtype). Only the ones the
// FTPS bridge serves locally are listed; everything else is forwarded
// to firmware verbatim.
constexpr int kCmdListInfo            = 0x0001;
constexpr int kCmdSubFile             = 0x0002;
constexpr int kCmdFileDel             = 0x0003;
constexpr int kCmdFileDownload        = 0x0004;
constexpr int kCmdRequestMediaAbility = 0x0007;
constexpr int kCmdTaskCancel          = 0x1000;

// PrinterFileSystem result codes (reply.result).
constexpr int kResOK           = 0;
constexpr int kResContinue     = 1;
constexpr int kResErrCancel    = 4;
constexpr int kResFileNoExist  = 10;
constexpr int kResStorUnavail  = 17;
constexpr int kResApiUnsupport = 18;

struct CtrlRequest {
    int         cmdtype = 0;
    int         sequence = 0;
    std::string body; // full JSON text, including "{...}\n\n<blob>" if present
};

struct CtrlReply {
    // "<json>\n\n<optional blob>" in PrinterFileSystem wire format.
    std::string data;
};

struct Tunnel {
    TunnelUrl        url;
    Logger           logger  = noop_logger;
    void*            log_ctx = nullptr;

    // ---- MJPG/TLS state (Scheme::Local) ----
    obn::os::socket_t fd     = obn::os::kInvalidSocket;
    SSL*             ssl     = nullptr;

    // ---- RTSP(S) state (Scheme::Rtsps/Rtsp) ----
    // Custom RTSP/RTSPS client wrapped by an Annex-B passthrough
    // worker (rtsp_passthrough.hpp). Built lazily by open_rtsp();
    // destroyed by tunnel_close(). Hands raw H.264 byte-stream
    // straight to gstbambusrc, which decodes via h264parse +
    // avdec_h264/openh264dec on the slicer side -- no in-process
    // libavcodec is required (Bambu Studio's bundled libavcodec is
    // decoder-only, and Orca Slicer doesn't ship one at all).
    std::unique_ptr<obn::rtsp::Passthrough> rtsp_pass;

    // Subtype of the video carried by this tunnel, filled in by
    // Bambu_GetStreamInfo. MJPG for local-scheme tunnels (port 6000,
    // A1/P1/A1 mini), AVC1 for RTSP(S) tunnels (X1/P1S/P2S/N7).
    int              sub_type = MJPG;

    // Bookkeeping for GetStreamInfo. We don't know the real frame rate
    // until we've observed several frames, so these are "advisory" and
    // Studio uses them only for display.
    int              width      = 1280;
    int              height     = 720;
    int              frame_rate = 15;

    // Reused across ReadSample calls so the Bambu_Sample::buffer pointer
    // stays valid until the NEXT ReadSample is invoked (matches what
    // gstbambusrc does with `g_memdup(sample.buffer, sample.size)`).
    std::vector<uint8_t> frame_buf;

    // Monotonic "decode_time" in the 100-ns units gstbambusrc feeds to
    // gstreamer. We derive it from a steady_clock zeroed at Open() time.
    std::chrono::steady_clock::time_point t0{};
    bool                                  started = false;

    // Cancellation flag set from a different thread by Bambu_Close.
    std::atomic<bool> closing{false};

    // Serialises access to `ssl` / `fd` against tunnel_close. Held by
    // every SSL_read iteration on the streaming thread, and acquired
    // by tunnel_close after it has shut the socket down (which wakes
    // any blocked SSL_read so the lock can actually be obtained).
    // Without this Studio's reconnect-on-stall path used to free SSL
    // out from under the reader and segfault.
    std::mutex mjpg_io_mu;

    // Diagnostic counter; we log a line every Nth frame so the mirror
    // file tells us "stream is alive" without drowning in per-frame spam.
    std::uint64_t frame_count = 0;

    // Local MJPEG auth is deferred until Bambu_StartStream (file browser
    // uses Bambu_StartStreamEx without the 80-byte 0x3000 auth packet).
    bool mjpg_authed = false;

    // ---- PrinterFileSystem CTRL state (Scheme::Local + CTRL_TYPE) ----
    // When Studio calls Bambu_StartStreamEx(CTRL_TYPE), we keep the TLS
    // :6000 socket open and forward CTRL JSON to printer firmware.
    bool             ctrl_mode = false;

    std::unique_ptr<obn::tunnel_local::Session> tl_session;

    // ---- FTPS bridge state (force_ftps=1) ----
    // When force_ftps is enabled we serve LIST_INFO / FILE_DOWNLOAD /
    // SUB_FILE / REQUEST_MEDIA_ABILITY locally over FTPS (port 990)
    // instead of forwarding them over the native :6000 CTRL channel.
    std::unique_ptr<obn::ftps::Client> ftp;
    // True if the FTPS root == storage mount (P2S / USB-only printers).
    bool             root_is_storage = false;
    // Studio-facing label: "sdcard" (legacy SD mount) or "udisk" (USB).
    std::string      storage_label;
    // FTPS path prefix: "/sdcard", "/usb", or "" when root IS the storage.
    std::string      ftp_prefix;

    // CTRL request inbox (Bambu_SendMessage) and reply outbox
    // (Bambu_ReadSample). Both guarded by ctrl_mu.
    std::mutex                 ctrl_mu;
    std::condition_variable    ctrl_cv;
    std::deque<CtrlRequest>    ctrl_in;
    std::deque<CtrlReply>      ctrl_out;
    // Sequence numbers the caller asked to cancel. The FTPS handlers
    // check this set between multi-chunk responses (long downloads).
    std::unordered_set<int>    ctrl_cancelled;
    std::atomic<bool>          ctrl_stop{false};
    std::thread                ctrl_worker;

    // Scratch storage for the CtrlReply currently exposed via
    // Bambu_ReadSample's `sample->buffer`. We keep it alive until the
    // NEXT ReadSample call (same contract as frame_buf above).
    std::string                ctrl_current_reply;
};

void tunnel_close(Tunnel* t)
{
    if (!t) return;
    t->closing.store(true, std::memory_order_release);
    log_at(LL_DEBUG, t->logger, t->log_ctx,
           "tunnel_close: shutting down (fd=%lld ssl=%p frames=%llu)",
           static_cast<long long>(t->fd), static_cast<void*>(t->ssl),
           static_cast<unsigned long long>(t->frame_count));

    // Step 1 (no lock): wake the reader. SSL_read on the streaming
    // thread sits in recv() up to SO_RCVTIMEO (5 s); shutting down
    // the socket from under it makes recv() return immediately so it
    // can drop mjpg_io_mu and let us free the SSL object below. This
    // is intentionally done WITHOUT mjpg_io_mu -- we'd deadlock against
    // the in-flight SSL_read otherwise.
    if (obn::os::socket_valid(t->fd)) obn::os::shutdown_both(t->fd);

    // Step 2: serialise with the reader. Once we hold mjpg_io_mu nobody
    // can be inside SSL_read on this tunnel, so SSL_free is safe.
    {
        std::lock_guard<std::mutex> lk(t->mjpg_io_mu);
        if (t->ssl) {
            // Best-effort close_notify; the printer doesn't care and
            // the socket is already half-shut so SSL_shutdown will
            // return quickly even if the write fails.
            SSL_shutdown(t->ssl);
            SSL_free(t->ssl);
            t->ssl = nullptr;
        }
        if (obn::os::socket_valid(t->fd)) {
            obn::os::close_socket(t->fd);
            t->fd = obn::os::kInvalidSocket;
        }
    }

    if (t->rtsp_pass) {
        // stop() joins the worker thread and tears the RTSP client
        // down. Reset the unique_ptr afterwards so a half-destroyed
        // passthrough cannot be reached again on a Bambu_Open retry.
        t->rtsp_pass->stop();
        t->rtsp_pass.reset();
    }
}

// Reads exactly `len` bytes. Returns 0 on OK, 1 on EOF, -1 on error.
//
// The SSL object and SSL_get_error access are taken under
// `t->mjpg_io_mu` so a concurrent tunnel_close() cannot pull SSL out
// from under us. tunnel_close() shuts the socket down first, which
// causes the in-flight SSL_read to return promptly with an error so
// we drop the lock and let the closer make progress.
int ssl_read_all(Tunnel* t, void* buf, size_t len)
{
    auto* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < len) {
        if (t->closing.load(std::memory_order_acquire)) return -1;
        int n;
        int err = SSL_ERROR_NONE;
        {
            std::lock_guard<std::mutex> lk(t->mjpg_io_mu);
            if (!t->ssl || t->closing.load(std::memory_order_acquire))
                return -1;
            n = SSL_read(t->ssl, p + got, static_cast<int>(len - got));
            if (n <= 0) err = SSL_get_error(t->ssl, n);
        }
        if (n <= 0) {
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
            if (err == SSL_ERROR_ZERO_RETURN) {
                log_at(LL_DEBUG, t->logger, t->log_ctx,
                       "ssl_read_all: clean EOF after %zu/%zu bytes",
                       got, len);
                return 1;
            }
            log_at(LL_DEBUG, t->logger, t->log_ctx,
                   "ssl_read_all: SSL_read failed n=%d err=%d errno=%d "
                   "after %zu/%zu bytes",
                   n, err, errno, got, len);
            return -1;
        }
        got += static_cast<size_t>(n);
    }
    return 0;
}

// -----------------------------------------------------------------------
// RTSP(S) video. We do not transcode: the printer sends H.264 over
// RTP and gstbambusrc.c (vendored verbatim by both Bambu Studio and
// Orca Slicer on Linux) feeds whatever Bambu_ReadSample returns into
// `h264parse ! avdec_h264 / openh264dec / vaapih264dec`. So this side
// only has to do RTSP/RTSPS handshake + RTP depacketisation + Annex-B
// framing. All of that lives in stubs/rtsp_client.cpp and
// stubs/rtsp_passthrough.cpp; here we just glue them onto the C ABI.
// -----------------------------------------------------------------------

[[maybe_unused]] int open_rtsp(Tunnel* t)
{
    auto pass = std::make_unique<obn::rtsp::Passthrough>(t->logger, t->log_ctx);

    log_fmt(t->logger, t->log_ctx,
            "open_rtsp: dialing %s://%s:%d (user=%s)",
            t->url.scheme == Scheme::Rtsps ? "rtsps" : "rtsp",
            t->url.host.c_str(), t->url.port, t->url.user.c_str());

    if (pass->start(t->url.host, t->url.port, t->url.user, t->url.passwd,
                    t->url.path, t->url.scheme == Scheme::Rtsps,
                    t->url.device) != 0) {
        return -1;
    }

    t->rtsp_pass = std::move(pass);
    // gstbambusrc looks at sub_type via Bambu_GetStreamInfo; AVC1 +
    // video_avc_byte_stream is the format gstbambusrc's downstream
    // pipeline already speaks (h264parse copes with any framing
    // h264parse can detect, and Annex-B is the simplest one).
    t->sub_type   = AVC1;
    // Width/height/frame_rate are advisory until h264parse pulls them
    // out of SPS; surface the firmware's well-known 1280x720@30 default
    // so Studio's UI shows reasonable numbers from the start.
    t->width      = 1280;
    t->height     = 720;
    t->frame_rate = 30;
    t->t0         = std::chrono::steady_clock::now();
    t->started    = true;
    log_fmt(t->logger, t->log_ctx,
            "open_rtsp: passthrough ready (avc1 %dx%d, gstbambusrc decodes)",
            t->width, t->height);
    return Bambu_success;
}

int read_rtsp(Tunnel* t, Bambu_Sample* sample)
{
    if (!t->rtsp_pass) return -1;
    const std::uint8_t* buf      = nullptr;
    std::size_t         size     = 0;
    std::uint64_t       dt_100ns = 0;
    int                 flags    = 0;
    auto rc = t->rtsp_pass->try_pull(&buf, &size, &dt_100ns, &flags);
    switch (rc) {
        case obn::rtsp::Passthrough::Pull_Ok:
            break;
        case obn::rtsp::Passthrough::Pull_WouldBlock:
            return Bambu_would_block;
        case obn::rtsp::Passthrough::Pull_StreamEnd:
            return Bambu_stream_end;
        case obn::rtsp::Passthrough::Pull_Error:
        default:
            return -1;
    }

    sample->itrack      = 0;
    sample->size        = static_cast<int>(size);
    sample->flags       = flags;
    sample->buffer      = buf;
    sample->decode_time = static_cast<unsigned long long>(dt_100ns);
    return Bambu_success;
}


// -----------------------------------------------------------------------
// Build the 80-byte auth packet per OpenBambuAPI/video.md.
// -----------------------------------------------------------------------
void build_auth_packet(const TunnelUrl& url, uint8_t out[80])
{
    std::memset(out, 0, 80);
    auto put_u32_le = [&](size_t off, uint32_t v) {
        out[off + 0] = static_cast<uint8_t>( v        & 0xff);
        out[off + 1] = static_cast<uint8_t>((v >> 8)  & 0xff);
        out[off + 2] = static_cast<uint8_t>((v >> 16) & 0xff);
        out[off + 3] = static_cast<uint8_t>((v >> 24) & 0xff);
    };
    put_u32_le(0,  0x40);       // payload size (always 0x40 for auth)
    put_u32_le(4,  0x3000);     // packet type (auth)
    put_u32_le(8,  0);          // flags
    put_u32_le(12, 0);
    // Username / password into 32-byte fixed-size fields, NUL-padded.
    std::memcpy(out + 16, url.user.data(),
                std::min<size_t>(url.user.size(), 32));
    std::memcpy(out + 48, url.passwd.data(),
                std::min<size_t>(url.passwd.size(), 32));
}

void push_reply(Tunnel* t, CtrlReply r)
{
    std::lock_guard<std::mutex> lk(t->ctrl_mu);
    t->ctrl_out.emplace_back(std::move(r));
    t->ctrl_cv.notify_all();
}

// --------------------------------------------------------------------
// FTPS bridge (force_ftps=1): serve the file browser over FTPS (990)
// instead of the native TLS :6000 CTRL protocol. Used as a workaround
// for printers whose :6000 file browser is broken (some A1 firmware).
// Thumbnails are NOT served in this mode (stubbed with empty blobs);
// only file listing, download and whole-archive (zip) fetches work.
// --------------------------------------------------------------------

// True when the user enabled the FTPS file-transfer workaround.
// BambuSource compiles its own copy of config.cpp (self-contained .so),
// so config::current() here returns defaults — the main plugin's
// load_or_create never touches our static. The main plugin's
// Main plugin writes OBN_FORCE_FTPS into <config_dir>/obn.env;
// env_var_get hydrates that file on miss (required on Windows across DLLs).
bool ftps_bridge_enabled()
{
    const char* env = obn::lan_tls::env_var_get(obn::lan_tls::kEnvForceFtps);
    return env && env[0] == '1';
}

bool camera_preview_disabled()
{
    const char* env =
        obn::lan_tls::env_var_get(obn::lan_tls::kEnvDisableCameraPreview);
    return env && env[0] == '1';
}

bool req_is_mem_download_path(const obn::json::Value& req)
{
    std::string path = req.find("path").as_string();
    if (path.empty()) path = req.find("file").as_string();
    return !path.empty() && path.rfind("mem:", 0) == 0;
}

// Builds the on-wire reply bytes Studio expects: the
// `{cmdtype, sequence, result, reply}` envelope, optionally followed by
// "\n\n" and a binary blob.
std::string make_wire_reply(const obn::json::Value& env,
                            const std::uint8_t*     blob,
                            std::size_t             blob_len)
{
    std::string s = env.dump();
    if (blob_len > 0) {
        s += "\n\n";
        s.append(reinterpret_cast<const char*>(blob), blob_len);
    }
    return s;
}

obn::json::Value make_reply_envelope(int cmdtype, int sequence, int result,
                                     obn::json::Value reply)
{
    obn::json::Object o;
    o["cmdtype"]  = obn::json::Value(static_cast<double>(cmdtype));
    o["sequence"] = obn::json::Value(static_cast<double>(sequence));
    o["result"]   = obn::json::Value(static_cast<double>(result));
    o["reply"]    = std::move(reply);
    return obn::json::Value(std::move(o));
}

void stub_blocked_mem_download(Tunnel* t, int sequence, const std::string& path)
{
    obn::json::Object extra;
    extra["path"]   = obn::json::Value(path);
    extra["offset"] = obn::json::Value(0.0);
    extra["total"]  = obn::json::Value(0.0);
    extra["size"]   = obn::json::Value(0.0);
    auto env = make_reply_envelope(kCmdFileDownload, sequence, kResFileNoExist,
                                   obn::json::Value(std::move(extra)));
    push_reply(t, {make_wire_reply(env, nullptr, 0)});
}

bool ctrl_is_cancelled(Tunnel* t, int sequence)
{
    std::lock_guard<std::mutex> lk(t->ctrl_mu);
    return t->ctrl_cancelled.count(sequence) > 0;
}

// Removes the sequence from the cancelled set on scope exit so the set
// does not grow unbounded during a long-lived CTRL session.
struct CancelledGuard {
    Tunnel* t;
    int     seq;
    ~CancelledGuard() {
        std::lock_guard<std::mutex> lk(t->ctrl_mu);
        t->ctrl_cancelled.erase(seq);
    }
};

// Connects a fresh FTPS client on demand (first CTRL request) and probes
// the storage mount. Kept on the tunnel so requests reuse the channel.
std::string ensure_ftp(Tunnel* t)
{
    if (t->ftp) return {};
    t->ftp = std::make_unique<obn::ftps::Client>();
    obn::ftps::ConnectConfig cfg;
    cfg.host     = t->url.host;
    cfg.port     = 990;
    cfg.username = t->url.user.empty() ? "bblp" : t->url.user;
    cfg.password = t->url.passwd;
    if (!obn::lan_tls::skip_verify_from_env()) {
        if (const char* ca = obn::lan_tls::resolve_lan_ca_file()) {
            cfg.ca_file = ca;
        }
        if (const char* serial = obn::lan_tls::wait_env_serial(
                cfg.host.c_str(), obn::lan_tls::serial_env_wait_ms())) {
            cfg.tls_verify_hostname = serial;
        }
    }
    log_fmt(t->logger, t->log_ctx,
            "ctrl: FTPS connect host=%s user=%s", cfg.host.c_str(),
            cfg.username.c_str());
    std::string err = t->ftp->connect(cfg);
    if (!err.empty()) {
        log_fmt(t->logger, t->log_ctx,
                "ctrl: FTPS connect failed: %s", err.c_str());
        t->ftp.reset();
        return err;
    }

    // Probe storage roots to figure out our prefix. P1/X1 with an SD
    // card exposes `/sdcard`; P2S/A-series with a USB stick exposes
    // `/usb`. Some P2S units expose neither because the root IS storage.
    if (t->ftp->cwd("/sdcard").empty()) {
        t->storage_label   = "sdcard";
        t->ftp_prefix      = "/sdcard";
        t->root_is_storage = false;
    } else if (t->ftp->cwd("/usb").empty()) {
        t->storage_label   = "udisk";
        t->ftp_prefix      = "/usb";
        t->root_is_storage = false;
    } else if (t->ftp->cwd("/").empty()) {
        // USB-only printers: FTPS root is the stick; Studio expects "udisk".
        t->storage_label   = "udisk";
        t->ftp_prefix      = "";
        t->root_is_storage = true;
    } else {
        log_fmt(t->logger, t->log_ctx,
                "ctrl: no accessible storage mount (neither /sdcard, /usb, nor /)");
        return "no storage mount";
    }
    log_fmt(t->logger, t->log_ctx,
            "ctrl: storage=%s prefix='%s' root_is_storage=%d",
            t->storage_label.c_str(), t->ftp_prefix.c_str(),
            t->root_is_storage ? 1 : 0);
    return {};
}

// Bambu firmware drops idle FTPS control connections after ~5 minutes.
// Reconnect-once on first error masks the timeout transparently.
std::string reconnect_ftp(Tunnel* t)
{
    if (t->ftp) {
        log_at(LL_DEBUG, t->logger, t->log_ctx,
               "ctrl: dropping stale FTPS session");
        t->ftp->quit();
        t->ftp.reset();
    }
    return ensure_ftp(t);
}

// Subtree where Studio's `type` argument routes:
//   timelapse -> <prefix>/timelapse, video -> <prefix>/ipcam,
//   model / other -> <prefix>/ (root).
std::string resolve_subtree(const Tunnel* t, const std::string& type)
{
    if (type == "timelapse") return t->ftp_prefix + "/timelapse";
    if (type == "video")     return t->ftp_prefix + "/ipcam";
    return t->ftp_prefix.empty() ? "/" : t->ftp_prefix;
}

// True when req.storage (from LIST_INFO) targets the volume we probed on
// FTPS. Studio uses "" / absent for External, "internal" for Internal
// timelapse tab, and on P2S also "emmc" / "udisk". The FTPS bridge only
// serves one mount — requests for internal/emmc when we probed udisk must
// not return the external listing (empty list instead).
bool ftps_storage_matches_request(const Tunnel* t, const std::string& req_storage)
{
    if (req_storage.empty()) {
        // External tab: match udisk/sdcard mounts, not a hypothetical emmc-only probe.
        return t->storage_label != "emmc";
    }
    if (req_storage == "internal" || req_storage == "emmc")
        return t->storage_label == "emmc";
    if (req_storage == "udisk" || req_storage == "usb")
        return t->storage_label == "udisk";
    if (req_storage == "sdcard")
        return t->storage_label == "sdcard";
    return req_storage == t->storage_label;
}

// Extensions a listing should surface to Studio for a given file type.
bool keep_for_type(const std::string& type, const std::string& name)
{
    auto ends_with = [&](const char* suf) {
        std::size_t n = std::strlen(suf);
        return name.size() >= n &&
               std::equal(name.end() - n, name.end(), suf,
                          [](char a, char b) {
                              return std::tolower(static_cast<unsigned char>(a)) ==
                                     std::tolower(static_cast<unsigned char>(b));
                          });
    };
    if (type == "timelapse") return ends_with(".mp4") || ends_with(".avi");
    if (type == "video")     return ends_with(".mp4");
    if (type == "model")     return ends_with(".3mf") || ends_with(".gcode")
                                 || ends_with(".gcode.3mf");
    return true;
}

// Time formatter Studio expects in LIST_INFO entries.
std::string format_time_studio(std::uint64_t epoch)
{
    if (epoch == 0) return "";
    std::time_t tt = static_cast<std::time_t>(epoch);
    std::tm tm{};
    obn::os::gmtime_safe(tt, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%F %T", &tm);
    return buf;
}

void ftps_handle_media_ability(Tunnel* t, int sequence,
                               const obn::json::Value& /*req*/)
{
    std::string err = ensure_ftp(t);
    obn::json::Object reply;
    obn::json::Array  storage;
    if (err.empty()) storage.emplace_back(t->storage_label);
    reply["storage"] = obn::json::Value(std::move(storage));
    auto env = make_reply_envelope(kCmdRequestMediaAbility, sequence,
                                   err.empty() ? kResOK : kResStorUnavail,
                                   obn::json::Value(std::move(reply)));
    push_reply(t, {make_wire_reply(env, nullptr, 0)});
}

void ftps_handle_list_info(Tunnel* t, int sequence, const obn::json::Value& req)
{
    std::string type    = req.find("type").as_string();
    std::string storage = req.find("storage").as_string();
    std::string err     = ensure_ftp(t);
    if (!err.empty()) {
        auto env = make_reply_envelope(kCmdListInfo, sequence, kResStorUnavail,
                                       obn::json::Value(obn::json::Object{}));
        push_reply(t, {make_wire_reply(env, nullptr, 0)});
        return;
    }
    if (!ftps_storage_matches_request(t, storage)) {
        log_fmt(t->logger, t->log_ctx,
                "ctrl: LIST_INFO type=%s storage=%s not served by FTPS mount %s",
                type.c_str(), storage.c_str(), t->storage_label.c_str());
        obn::json::Object reply;
        reply["file_lists"] = obn::json::Value(obn::json::Array{});
        auto env = make_reply_envelope(kCmdListInfo, sequence, kResOK,
                                       obn::json::Value(std::move(reply)));
        push_reply(t, {make_wire_reply(env, nullptr, 0)});
        return;
    }
    std::string path = resolve_subtree(t, type);
    std::vector<obn::ftps::Entry> entries;
    err = t->ftp->list_entries(path, &entries);
    if (!err.empty()) {
        // Could be a missing directory or a stale FTPS session. Retry
        // once with a fresh session before surfacing an empty list.
        log_at(LL_DEBUG, t->logger, t->log_ctx,
               "ctrl: LIST_INFO type=%s path=%s: %s -- reconnecting once",
               type.c_str(), path.c_str(), err.c_str());
        if (reconnect_ftp(t).empty()) {
            path = resolve_subtree(t, type);
            entries.clear();
            err = t->ftp->list_entries(path, &entries);
        }
    }
    if (!err.empty()) {
        // Directory missing (e.g. no timelapses yet): return empty list.
        log_fmt(t->logger, t->log_ctx,
                "ctrl: LIST_INFO type=%s path=%s: %s (returning empty)",
                type.c_str(), path.c_str(), err.c_str());
        obn::json::Object reply;
        reply["file_lists"] = obn::json::Value(obn::json::Array{});
        auto env = make_reply_envelope(kCmdListInfo, sequence, kResOK,
                                       obn::json::Value(std::move(reply)));
        push_reply(t, {make_wire_reply(env, nullptr, 0)});
        return;
    }

    obn::json::Array files;
    for (const auto& e : entries) {
        if (e.is_dir) continue;
        if (!keep_for_type(type, e.name)) continue;
        obn::json::Object f;
        f["name"] = obn::json::Value(e.name);
        std::string full = (path == "/") ? ("/" + e.name)
                                         : (path + "/" + e.name);
        f["path"] = obn::json::Value(full);
        f["size"] = obn::json::Value(static_cast<double>(e.size));
        if (e.mtime != 0) {
            f["time"] = obn::json::Value(static_cast<double>(e.mtime));
            f["date"] = obn::json::Value(format_time_studio(e.mtime));
        }
        files.emplace_back(obn::json::Value(std::move(f)));
    }
    obn::json::Object reply;
    reply["file_lists"] = obn::json::Value(std::move(files));
    auto env = make_reply_envelope(kCmdListInfo, sequence, kResOK,
                                   obn::json::Value(std::move(reply)));
    push_reply(t, {make_wire_reply(env, nullptr, 0)});
}

// SUB_FILE in FTPS mode:
//   * zip=true (FetchModel): stream the whole .3mf archive back in
//     256 KB chunks so Studio's load_gcode_3mf_from_stream succeeds.
//   * everything else (thumbnails / metadata): stubbed -- reply size=0
//     for each requested entry so Studio falls back to its default icon
//     instead of hanging. Thumbnails are not available over FTPS.
void ftps_handle_sub_file(Tunnel* t, int sequence, const obn::json::Value& req)
{
    CancelledGuard cg{t, sequence};
    std::string err = ensure_ftp(t);
    if (!err.empty()) {
        auto env = make_reply_envelope(kCmdSubFile, sequence, kResStorUnavail,
                                       obn::json::Value(obn::json::Object{}));
        push_reply(t, {make_wire_reply(env, nullptr, 0)});
        return;
    }

    obn::json::Value paths_v = req.find("paths");
    obn::json::Value files_v = req.find("files");
    const auto& paths = paths_v.as_array();
    const auto& files = files_v.as_array();
    bool zip_mode = req.find("zip").as_bool(false);

    auto push_chunk = [&](int result, const obn::json::Object& extra,
                          const std::uint8_t* blob, std::size_t blen) {
        obn::json::Object r = extra;
        auto env = make_reply_envelope(kCmdSubFile, sequence, result,
                                       obn::json::Value(std::move(r)));
        push_reply(t, {make_wire_reply(env, blob, blen)});
    };

    if (!paths.empty() && zip_mode) {
        // Studio wants a real ZIP archive (FetchModel). Hand back the
        // source .3mf bytes unchanged, streamed in chunks. Buffer the
        // whole archive first so the LAST non-empty chunk is reliably
        // flagged continue=false even when the size is an exact multiple
        // of the chunk boundary. .3mf files on the printer are typically
        // single-digit MB; the worst case is ~50-100 MB for complex
        // multi-plate projects, which is acceptable for a transient buffer.
        std::vector<std::string> bases;
        bases.reserve(paths.size());
        for (std::size_t i = 0; i < paths.size(); ++i) {
            std::string full = paths[i].as_string();
            auto hash = full.find('#');
            if (hash != std::string::npos) full = full.substr(0, hash);
            if (std::find(bases.begin(), bases.end(), full) == bases.end())
                bases.push_back(full);
        }
        constexpr std::size_t kChunkSize = 256 * 1024;
        for (std::size_t bi = 0; bi < bases.size(); ++bi) {
            const std::string& full = bases[bi];
            if (ctrl_is_cancelled(t, sequence)) {
                push_chunk(kResErrCancel, {}, nullptr, 0);
                return;
            }
            std::uint64_t total_size = 0;
            t->ftp->size(full, &total_size);
            std::vector<std::uint8_t> archive;
            archive.reserve(static_cast<std::size_t>(
                total_size ? total_size : kChunkSize));
            bool cancelled = false;
            auto retr_into_archive = [&]() {
                archive.clear();
                cancelled = false;
                return t->ftp->retr(full, [&](const void* data, std::size_t len) {
                    if (ctrl_is_cancelled(t, sequence)) { cancelled = true; return false; }
                    const std::uint8_t* p = static_cast<const std::uint8_t*>(data);
                    archive.insert(archive.end(), p, p + len);
                    return true;
                });
            };
            std::string rerr = retr_into_archive();
            if (!rerr.empty() && !cancelled) {
                log_at(LL_DEBUG, t->logger, t->log_ctx,
                       "ctrl: SUB_FILE(zip) %s failed (%s) -- reconnecting once",
                       full.c_str(), rerr.c_str());
                if (reconnect_ftp(t).empty()) {
                    t->ftp->size(full, &total_size);
                    rerr = retr_into_archive();
                }
            }
            if (cancelled) {
                push_chunk(kResErrCancel, {}, nullptr, 0);
                return;
            }
            if (!rerr.empty()) {
                log_fmt(t->logger, t->log_ctx,
                        "ctrl: SUB_FILE(zip) %s failed: %s", full.c_str(),
                        rerr.c_str());
                auto env = make_reply_envelope(kCmdSubFile, sequence,
                                               kResFileNoExist,
                                               obn::json::Value(obn::json::Object{}));
                push_reply(t, {make_wire_reply(env, nullptr, 0)});
                return;
            }

            const bool is_last_file = (bi + 1 == bases.size());
            const std::size_t total = archive.size();
            log_fmt(t->logger, t->log_ctx,
                    "ctrl: SUB_FILE(zip) seq=%d %s bytes=%zu last_file=%d",
                    sequence, full.c_str(), total, is_last_file ? 1 : 0);

            if (total == 0) {
                obn::json::Object extra;
                extra["path"]     = obn::json::Value(full);
                extra["mimetype"] = obn::json::Value("application/zip");
                extra["size"]     = obn::json::Value(static_cast<double>(0));
                extra["offset"]   = obn::json::Value(static_cast<double>(0));
                extra["total"]    = obn::json::Value(static_cast<double>(0));
                extra["continue"] = obn::json::Value(false);
                push_chunk(is_last_file ? kResOK : kResContinue, extra, nullptr, 0);
                continue;
            }

            std::size_t offset = 0;
            while (offset < total) {
                std::size_t chunk = std::min(kChunkSize, total - offset);
                bool last_chunk = (offset + chunk == total);
                obn::json::Object extra;
                extra["path"]     = obn::json::Value(full);
                extra["mimetype"] = obn::json::Value("application/zip");
                extra["size"]     = obn::json::Value(static_cast<double>(chunk));
                extra["offset"]   = obn::json::Value(static_cast<double>(offset));
                extra["total"]    = obn::json::Value(static_cast<double>(total));
                extra["continue"] = obn::json::Value(!last_chunk);
                bool is_final = last_chunk && is_last_file;
                push_chunk(is_final ? kResOK : kResContinue, extra,
                           archive.data() + offset, chunk);
                offset += chunk;
            }
        }
        return;
    }

    if (!paths.empty()) {
        // Thumbnails / metadata: not available over FTPS. Reply size=0
        // for each entry, echoing the request path so Studio matches the
        // reply to the right File and shows its default icon.
        std::size_t total = paths.size();
        for (std::size_t i = 0; i < total; ++i) {
            if (ctrl_is_cancelled(t, sequence)) {
                push_chunk(kResErrCancel, {}, nullptr, 0);
                return;
            }
            obn::json::Object extra;
            extra["path"]     = obn::json::Value(paths[i].as_string());
            extra["mimetype"] = obn::json::Value("application/octet-stream");
            extra["size"]     = obn::json::Value(static_cast<double>(0));
            extra["offset"]   = obn::json::Value(static_cast<double>(0));
            extra["total"]    = obn::json::Value(static_cast<double>(0));
            push_chunk((i + 1 == total) ? kResOK : kResContinue, extra, nullptr, 0);
        }
        return;
    }

    if (!files.empty()) {
        // Legacy per-name thumbnail fetch: also stubbed.
        std::size_t total = files.size();
        for (std::size_t i = 0; i < total; ++i) {
            if (ctrl_is_cancelled(t, sequence)) {
                push_chunk(kResErrCancel, {}, nullptr, 0);
                return;
            }
            obn::json::Object extra;
            extra["name"]     = obn::json::Value(files[i].as_string());
            extra["mimetype"] = obn::json::Value("image/jpeg");
            extra["size"]     = obn::json::Value(static_cast<double>(0));
            push_chunk((i + 1 == total) ? kResOK : kResContinue, extra, nullptr, 0);
        }
        return;
    }

    push_chunk(kResApiUnsupport, {}, nullptr, 0);
}

void ftps_handle_file_download(Tunnel* t, int sequence,
                               const obn::json::Value& req)
{
    CancelledGuard cg{t, sequence};
    std::string err = ensure_ftp(t);
    if (!err.empty()) {
        auto env = make_reply_envelope(kCmdFileDownload, sequence, kResStorUnavail,
                                       obn::json::Value(obn::json::Object{}));
        push_reply(t, {make_wire_reply(env, nullptr, 0)});
        return;
    }
    std::string path = req.find("path").as_string();
    if (path.empty()) path = req.find("file").as_string();
    if (path.empty()) {
        auto env = make_reply_envelope(kCmdFileDownload, sequence, kResFileNoExist,
                                       obn::json::Value(obn::json::Object{}));
        push_reply(t, {make_wire_reply(env, nullptr, 0)});
        return;
    }

    // Total size up front so Studio's progress bar can render; SIZE also
    // probes the control connection (reconnect once if it timed out).
    std::uint64_t total = 0;
    {
        std::string size_err = t->ftp->size(path, &total);
        if (!size_err.empty()) {
            log_at(LL_DEBUG, t->logger, t->log_ctx,
                   "ctrl: FILE_DOWNLOAD SIZE %s failed (%s) -- reconnecting once",
                   path.c_str(), size_err.c_str());
            if (reconnect_ftp(t).empty()) t->ftp->size(path, &total);
        }
    }

    // Studio's download callback reads resp["file_md5"] once
    // offset+size == total; a missing field aborts the recv thread.
    std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> md_ctx(
        EVP_MD_CTX_new(),
        [](EVP_MD_CTX* c){ if (c) EVP_MD_CTX_free(c); });
    if (!md_ctx || EVP_DigestInit_ex(md_ctx.get(), EVP_md5(), nullptr) != 1) {
        auto env = make_reply_envelope(kCmdFileDownload, sequence, kResFileNoExist,
                                       obn::json::Value(obn::json::Object{}));
        push_reply(t, {make_wire_reply(env, nullptr, 0)});
        return;
    }

    constexpr std::size_t kChunkSize = 256 * 1024;
    std::vector<std::uint8_t> buf;
    buf.reserve(kChunkSize);
    std::uint64_t sent = 0;

    auto finalize_md5 = [&]() -> std::string {
        unsigned char digest[EVP_MAX_MD_SIZE] = {0};
        unsigned      digest_len = 0;
        EVP_DigestFinal_ex(md_ctx.get(), digest, &digest_len);
        static const char kHex[] = "0123456789abcdef";
        std::string hex;
        hex.resize(digest_len * 2);
        for (unsigned i = 0; i < digest_len; ++i) {
            hex[2*i    ] = kHex[(digest[i] >> 4) & 0xF];
            hex[2*i + 1] = kHex[ digest[i]       & 0xF];
        }
        return hex;
    };

    auto flush_chunk = [&](bool last) {
        obn::json::Object extra;
        extra["path"]   = obn::json::Value(path);
        extra["offset"] = obn::json::Value(static_cast<double>(sent));
        extra["total"]  = obn::json::Value(static_cast<double>(total));
        extra["size"]   = obn::json::Value(static_cast<double>(buf.size()));
        if (last) extra["file_md5"] = obn::json::Value(finalize_md5());
        auto env = make_reply_envelope(kCmdFileDownload, sequence,
                                       last ? kResOK : kResContinue,
                                       obn::json::Value(std::move(extra)));
        push_reply(t, {make_wire_reply(env, buf.data(), buf.size())});
        sent += buf.size();
        buf.clear();
    };

    bool cancelled = false;
    auto run_retr = [&]() {
        return t->ftp->retr(path, [&](const void* data, std::size_t len) {
            if (ctrl_is_cancelled(t, sequence)) { cancelled = true; return false; }
            EVP_DigestUpdate(md_ctx.get(), data, len);
            const std::uint8_t* p = static_cast<const std::uint8_t*>(data);
            while (len > 0) {
                std::size_t take = std::min(len, kChunkSize - buf.size());
                buf.insert(buf.end(), p, p + take);
                p   += take;
                len -= take;
                if (buf.size() == kChunkSize) flush_chunk(/*last=*/false);
            }
            return true;
        });
    };
    err = run_retr();
    if (!err.empty() && !cancelled && sent == 0 && buf.empty()) {
        log_at(LL_DEBUG, t->logger, t->log_ctx,
               "ctrl: FILE_DOWNLOAD %s failed (%s) -- reconnecting once",
               path.c_str(), err.c_str());
        if (reconnect_ftp(t).empty()) {
            EVP_MD_CTX_reset(md_ctx.get());
            EVP_DigestInit_ex(md_ctx.get(), EVP_md5(), nullptr);
            err = run_retr();
        }
    }

    if (cancelled) {
        auto env = make_reply_envelope(kCmdFileDownload, sequence, kResErrCancel,
                                       obn::json::Value(obn::json::Object{}));
        push_reply(t, {make_wire_reply(env, nullptr, 0)});
        return;
    }
    if (!err.empty()) {
        log_fmt(t->logger, t->log_ctx,
                "ctrl: FILE_DOWNLOAD %s failed: %s", path.c_str(), err.c_str());
        auto env = make_reply_envelope(kCmdFileDownload, sequence, kResFileNoExist,
                                       obn::json::Value(obn::json::Object{}));
        push_reply(t, {make_wire_reply(env, nullptr, 0)});
        return;
    }
    // If SIZE failed (or returned 0 for a non-empty file), correct total
    // from the actual bytes transferred so Studio's offset+size==total
    // check fires on the final chunk and it reads file_md5.
    std::uint64_t actual = sent + buf.size();
    if (total == 0 || total != actual) total = actual;
    flush_chunk(/*last=*/true);
}

void ftps_handle_file_del(Tunnel* t, int sequence, const obn::json::Value& req)
{
    std::string err = ensure_ftp(t);
    if (!err.empty()) {
        auto env = make_reply_envelope(kCmdFileDel, sequence, kResStorUnavail,
                                       obn::json::Value(obn::json::Object{}));
        push_reply(t, {make_wire_reply(env, nullptr, 0)});
        return;
    }
    obn::json::Value paths_v = req.find("paths");
    const auto& paths = paths_v.as_array();
    obn::json::Array ok_names;
    int result = kResOK;
    bool reconnected = false;
    for (const auto& v : paths) {
        std::string p = v.as_string();
        if (p.empty()) continue;
        std::string e = t->ftp->dele(p);
        if (!e.empty() && !reconnected) {
            log_at(LL_DEBUG, t->logger, t->log_ctx,
                   "ctrl: DELE %s failed (%s) -- reconnecting once",
                   p.c_str(), e.c_str());
            reconnected = true;
            if (reconnect_ftp(t).empty()) e = t->ftp->dele(p);
        }
        if (!e.empty()) {
            log_fmt(t->logger, t->log_ctx, "ctrl: DELE %s failed: %s",
                    p.c_str(), e.c_str());
            result = kResFileNoExist;
        } else {
            ok_names.emplace_back(obn::json::Value(p));
        }
    }
    obn::json::Object reply;
    reply["paths"] = obn::json::Value(std::move(ok_names));
    auto env = make_reply_envelope(kCmdFileDel, sequence, result,
                                   obn::json::Value(std::move(reply)));
    push_reply(t, {make_wire_reply(env, nullptr, 0)});
}

void ftps_handle_task_cancel(Tunnel* t, int sequence, const obn::json::Value& req)
{
    obn::json::Value tasks_v = req.find("tasks");
    const auto& tasks = tasks_v.as_array();
    obn::json::Array cancelled;
    {
        std::lock_guard<std::mutex> lk(t->ctrl_mu);
        // Cap the set so late/stale cancels from one-shot commands
        // (LIST_INFO, FILE_DEL, etc.) that don't use CancelledGuard
        // cannot leak memory over a very long CTRL session.
        if (t->ctrl_cancelled.size() > 256) t->ctrl_cancelled.clear();
        for (const auto& v : tasks) {
            int seq = static_cast<int>(v.as_number());
            t->ctrl_cancelled.insert(seq);
            cancelled.emplace_back(obn::json::Value(static_cast<double>(seq)));
        }
    }
    obn::json::Object reply;
    reply["tasks"] = obn::json::Value(std::move(cancelled));
    auto env = make_reply_envelope(kCmdTaskCancel, sequence, kResOK,
                                   obn::json::Value(std::move(reply)));
    push_reply(t, {make_wire_reply(env, nullptr, 0)});
}

// Returns true if the request was served locally over FTPS (caller must
// then skip the native :6000 forward). Only the file-browser cmdtypes
// are intercepted; everything else falls through to native passthrough.
bool ftps_dispatch(Tunnel* t, int cmdtype, int sequence,
                   const obn::json::Value& body)
{
    switch (cmdtype) {
    case kCmdRequestMediaAbility: ftps_handle_media_ability(t, sequence, body); return true;
    case kCmdListInfo:            ftps_handle_list_info(t, sequence, body);     return true;
    case kCmdSubFile:             ftps_handle_sub_file(t, sequence, body);      return true;
    case kCmdFileDownload:        ftps_handle_file_download(t, sequence, body); return true;
    case kCmdFileDel:             ftps_handle_file_del(t, sequence, body);      return true;
    case kCmdTaskCancel:          ftps_handle_task_cancel(t, sequence, body);   return true;
    default:                      return false;
    }
}

bool parse_ctrl_request(const std::string& wire, int* cmdtype, int* sequence,
                        obn::json::Value* req)
{
    std::size_t j_end = wire.find("\n\n");
    std::string j = (j_end == std::string::npos) ? wire : wire.substr(0, j_end);
    std::string perr;
    auto v = obn::json::parse(j, &perr);
    if (!v) return false;
    auto ct = v->find("cmdtype");
    auto sq = v->find("sequence");
    if (!ct.is_number() || !sq.is_number()) return false;
    *cmdtype  = static_cast<int>(ct.as_number());
    *sequence = static_cast<int>(sq.as_number());
    *req      = v->find("req");
    return true;
}

static int parse_wire_result(const std::string& wire)
{
    const std::size_t j_end = wire.find("\n\n");
    const std::string j =
        (j_end == std::string::npos) ? wire : wire.substr(0, j_end);
    std::string perr;
    const auto v = obn::json::parse(j, &perr);
    if (!v) return -1;
    return static_cast<int>(v->find("result").as_int(-1));
}

static void native_ctrl_send_worker(Tunnel* t)
{
    log_fmt(t->logger, t->log_ctx, "ctrl: native send worker started");
    while (!t->ctrl_stop.load(std::memory_order_acquire)) {
        CtrlRequest req;
        {
            std::unique_lock<std::mutex> lk(t->ctrl_mu);
            t->ctrl_cv.wait_for(lk, std::chrono::milliseconds(200), [&] {
                return t->ctrl_stop.load(std::memory_order_acquire) ||
                       !t->ctrl_in.empty();
            });
            if (t->ctrl_stop.load(std::memory_order_acquire)) break;
            if (t->ctrl_in.empty()) continue;
            req = std::move(t->ctrl_in.front());
            t->ctrl_in.pop_front();
        }
        if (!t->ssl || !t->tl_session) continue;
        int cmdtype = 0, sequence = 0;
        obn::json::Value body;
        bool parsed = parse_ctrl_request(req.body, &cmdtype, &sequence, &body);
        if (parsed && cmdtype == kCmdFileDownload && camera_preview_disabled() &&
            req_is_mem_download_path(body)) {
            std::string path = body.find("path").as_string();
            if (path.empty()) path = body.find("file").as_string();
            log_fmt(t->logger, t->log_ctx,
                    "ctrl: mem preview blocked (disable_camera_preview) %s",
                    path.c_str());
            stub_blocked_mem_download(t, sequence, path);
            continue;
        }
        // force_ftps: serve the file browser over FTPS (990) instead of
        // forwarding to the native :6000 CTRL channel. Only the
        // file-browser cmdtypes are intercepted; everything else still
        // goes to firmware verbatim.
        if (parsed && ftps_bridge_enabled() &&
            ftps_dispatch(t, cmdtype, sequence, body)) {
            log_fmt(t->logger, t->log_ctx,
                    "ctrl: FTPS bridge served cmd=0x%04x seq=%d",
                    cmdtype, sequence);
            continue;
        }
        if (parsed) {
            log_fmt(t->logger, t->log_ctx,
                    "ctrl: native forward cmd=0x%04x seq=%d (%zu bytes)",
                    cmdtype, sequence, req.body.size());
        } else {
            log_fmt(t->logger, t->log_ctx,
                    "ctrl: native forward %zu bytes (unparsed)", req.body.size());
        }
        if (t->tl_session->send_abi_json(t->ssl, req.body, &t->mjpg_io_mu) != 0) {
            log_fmt(t->logger, t->log_ctx, "ctrl: native send failed");
            set_last_error("BambuTunnelLocal send failed");
            continue;
        }
        for (;;) {
            std::vector<std::uint8_t> wire;
            if (t->tl_session->recv_payload(t->ssl, &wire, &t->mjpg_io_mu) != 0) {
                log_fmt(t->logger, t->log_ctx, "ctrl: native recv failed");
                set_last_error("BambuTunnelLocal recv failed");
                break;
            }
            CtrlReply reply;
            reply.data.assign(reinterpret_cast<const char*>(wire.data()),
                              wire.size());
            log_fmt(t->logger, t->log_ctx,
                    "ctrl: native recv %zu bytes", reply.data.size());
            const int result = parse_wire_result(reply.data);
            push_reply(t, std::move(reply));
            if (result != kResContinue) break;
        }
    }
    log_fmt(t->logger, t->log_ctx, "ctrl: native send worker exited");
}

static int start_native_ctrl_handshake(Tunnel* t)
{
    if (!t->ssl) {
        set_last_error("CTRL: TLS session not open");
        return -1;
    }
    // StartStreamEx is polled (Bambu_would_block between steps). Keep one
    // Session across polls — recreating it here re-sent login on every tick.
    if (!t->tl_session) {
        t->tl_session = std::make_unique<obn::tunnel_local::Session>(
            static_cast<std::uint32_t>(std::rand()));
    }
    obn::tunnel_local::Config cfg;
    cfg.username    = t->url.user;
    cfg.access_code = t->url.passwd;
    cfg.client_id   = t->url.cli_id;
    if (!t->url.cli_ver.empty()) {
        cfg.client_ver = t->url.cli_ver;
    } else if (!t->url.net_ver.empty()) {
        cfg.client_ver = t->url.net_ver;
    }

    const int hs = t->tl_session->handshake_step(t->ssl, cfg, &t->mjpg_io_mu);
    if (hs < 0) {
        const auto ph = t->tl_session->phase();
        log_fmt(t->logger, t->log_ctx,
                "ctrl: native handshake failed (phase=%d)",
                static_cast<int>(ph));
        t->tl_session.reset();
        set_last_error("BambuTunnelLocal handshake failed");
        return -1;
    }
    if (hs > 0) return Bambu_would_block;

    if (!t->ctrl_mode) {
        t->ctrl_mode        = true;
        t->ctrl_stop.store(false, std::memory_order_release);
        t->ctrl_worker      = std::thread(native_ctrl_send_worker, t);
        log_fmt(t->logger, t->log_ctx,
                "ctrl: native :6000 passthrough ready (pid=%s ver=%s)",
                cfg.client_id.c_str(), cfg.client_ver.c_str());
    }
    return Bambu_success;
}

// Shuts the worker down. Idempotent.
void stop_ctrl_mode(Tunnel* t)
{
    if (!t->ctrl_mode) return;
    {
        std::lock_guard<std::mutex> lk(t->ctrl_mu);
        t->ctrl_stop.store(true, std::memory_order_release);
        t->ctrl_cv.notify_all();
    }
    if (t->ctrl_worker.joinable()) t->ctrl_worker.join();
    t->tl_session.reset();
    if (t->ftp) {
        t->ftp->quit();
        t->ftp.reset();
    }
    t->ctrl_cancelled.clear();
    t->ctrl_mode = false;
}

} // namespace

// =======================================================================
// Exported BambuLib API
// =======================================================================

OBN_EXPORT int Bambu_Init()
{
    ssl_init_once();
    return Bambu_success;
}

OBN_EXPORT void Bambu_Deinit()
{
    // No-op: we intentionally leak the global SSL_CTX until process exit.
    // Tearing it down while other tunnels might still be alive on a
    // different GstElement is not worth the race risk.
}

OBN_EXPORT int Bambu_Create(Bambu_Tunnel* tunnel, char const* path)
{
    if (!tunnel || !path) return -1;
    ssl_init_once();
    auto* t = new Tunnel();
    // Hide the password from the mirror log but keep the host/port/user
    // portion so we know what the caller actually asked for.
    log_fmt(t->logger, t->log_ctx, "Bambu_Create: url=%.160s%s", path,
            std::strlen(path) > 160 ? "..." : "");
    if (!parse_url(path, &t->url)) {
        log_fmt(t->logger, t->log_ctx, "Bambu_Create: bad URL");
        delete t;
        set_last_error("bad URL");
        return -1;
    }
    const char* scheme_name = (t->url.scheme == Scheme::Rtsps) ? "rtsps"
                            : (t->url.scheme == Scheme::Rtsp)  ? "rtsp"
                            :                                    "local";
    log_fmt(t->logger, t->log_ctx,
            "Bambu_Create: parsed scheme=%s host=%s port=%d path=%s "
            "user=%s passwd=%s",
            scheme_name, t->url.host.c_str(), t->url.port,
            t->url.path.c_str(), t->url.user.c_str(),
            t->url.passwd.empty() ? "(empty!)" : "***");
    if (!t->url.device.empty() && !t->url.host.empty()) {
        obn::lan_tls::registry_put_ip_serial(t->url.host, t->url.device);
    }
    *tunnel = t;
    return Bambu_success;
}

OBN_EXPORT void Bambu_SetLogger(Bambu_Tunnel tunnel, Logger logger, void* context)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t) return;
    t->logger  = logger ? logger : noop_logger;
    t->log_ctx = context;
}

OBN_EXPORT int Bambu_Open(Bambu_Tunnel tunnel)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t) return -1;

    // RTSP(S) is so different from MJPG that it gets its own code path
    // (passthrough worker + RTSP handshake); MJPG stays as manual
    // TLS + auth packet below. Both the stock plugin and our passthrough
    // hand raw H.264 byte-stream back to gstbambusrc, so this path is
    // gated only on the URL scheme.
    if (t->url.scheme == Scheme::Rtsps || t->url.scheme == Scheme::Rtsp) {
        return open_rtsp(t);
    }

    log_fmt(t->logger, t->log_ctx, "Bambu_Open: dialing tls://%s:%d",
            t->url.host.c_str(), t->url.port);

    const char* serial =
        t->url.device.empty() ? nullptr : t->url.device.c_str();
    if (obn::tls::dial_tls(t->url.host, t->url.port, /*timeout_ms=*/5000,
                           &t->fd, &t->ssl, serial) != 0) {
        log_fmt(t->logger, t->log_ctx, "Bambu_Open: TLS dial failed: %s",
                obn::source::get_last_error());
        return -1;
    }

    log_fmt(t->logger, t->log_ctx,
            "Bambu_Open: TLS established (cipher=%s)",
            SSL_get_cipher(t->ssl));

    t->t0      = std::chrono::steady_clock::now();
    t->started = true;
    log_fmt(t->logger, t->log_ctx,
            "Bambu_Open: TLS ready (MJPEG auth deferred to StartStream)");
    return Bambu_success;
}

OBN_EXPORT int Bambu_StartStream(Bambu_Tunnel tunnel, bool /*video*/)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t) return -1;
    if (t->url.scheme == Scheme::Local && !t->ssl) return -1;
    if ((t->url.scheme == Scheme::Rtsps ||
         t->url.scheme == Scheme::Rtsp) && !t->rtsp_pass) return -1;

    if (t->url.scheme == Scheme::Local && !t->ctrl_mode && !t->mjpg_authed) {
        uint8_t auth[80];
        build_auth_packet(t->url, auth);
        std::lock_guard<std::mutex> lk(t->mjpg_io_mu);
        if (obn::tls::ssl_write_all(t->ssl, auth, sizeof(auth)) != 0) {
            set_last_error("MJPEG auth write failed");
            return -1;
        }
        t->mjpg_authed = true;
        log_fmt(t->logger, t->log_ctx,
                "Bambu_StartStream: sent %zu-byte MJPEG auth", sizeof(auth));
    }
    return Bambu_success;
}

OBN_EXPORT int Bambu_StartStreamEx(Bambu_Tunnel tunnel, int type)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t) return -1;
    // CTRL_TYPE (0x3001) opens the PrinterFileSystem channel: keep TLS
    // :6000 open and forward CTRL JSON to printer firmware.
    if (type == kCtrlType) {
        return start_native_ctrl_handshake(t);
    }
    return Bambu_StartStream(tunnel, true);
}

OBN_EXPORT int Bambu_GetStreamCount(Bambu_Tunnel tunnel)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t) return 0;
    if (t->url.scheme == Scheme::Local && !t->ssl)      return 0;
    if ((t->url.scheme == Scheme::Rtsps ||
         t->url.scheme == Scheme::Rtsp) && !t->rtsp_pass) return 0;
    return 1; // one video track (MJPEG for local-scheme, AVC1 for RTSP).
}

OBN_EXPORT int Bambu_GetStreamInfo(Bambu_Tunnel tunnel, int index,
                                   Bambu_StreamInfo* info)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t || !info || index != 0) return -1;
    std::memset(info, 0, sizeof(*info));
    info->type                    = VIDE;
    info->sub_type                = t->sub_type;
    info->format.video.width      = t->width;
    info->format.video.height     = t->height;
    info->format.video.frame_rate = t->frame_rate;
    // For H.264, gstbambusrc feeds the buffer into a decoder bin which
    // sniffs the byte stream; video_avc_byte_stream mirrors what the
    // proprietary plugin advertises in RTSP mode.
    info->format_type             = (t->sub_type == MJPG)
                                        ? video_jpeg
                                        : video_avc_byte_stream;
    info->format_size             = 0;
    info->max_frame_size          = static_cast<int>(kMaxFrameSize);
    info->format_buffer           = nullptr;
    return Bambu_success;
}

OBN_EXPORT unsigned long Bambu_GetDuration(Bambu_Tunnel /*tunnel*/)
{
    return 0; // live stream, no duration
}

OBN_EXPORT int Bambu_Seek(Bambu_Tunnel /*tunnel*/, unsigned long /*time*/)
{
    return Bambu_success; // meaningless for a live stream
}

OBN_EXPORT int Bambu_ReadSample(Bambu_Tunnel tunnel, Bambu_Sample* sample)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t || !sample) return -1;

    // CTRL channel: drain one reply from the outbox. PrinterFileSystem
    // on Studio's side will loop calling us until would_block or until
    // it sees the terminal reply it's waiting on.
    if (t->ctrl_mode) {
        std::unique_lock<std::mutex> lk(t->ctrl_mu);
        if (t->ctrl_out.empty()) return Bambu_would_block;
        CtrlReply r = std::move(t->ctrl_out.front());
        t->ctrl_out.pop_front();
        lk.unlock();
        // Stash on the tunnel so the pointer stays valid until next
        // ReadSample (matches the contract with gstbambusrc). PrinterFileSystem
        // treats decode_time as irrelevant; we set it to 0.
        t->ctrl_current_reply = std::move(r.data);
        sample->itrack      = 0;
        sample->size        = static_cast<int>(t->ctrl_current_reply.size());
        sample->flags       = 0;
        sample->buffer      = reinterpret_cast<const unsigned char*>(
                                   t->ctrl_current_reply.data());
        sample->decode_time = 0;
        return Bambu_success;
    }

    // RTSP: pull from the IVideoPipeline. MJPG path continues below.
    if (t->url.scheme == Scheme::Rtsps || t->url.scheme == Scheme::Rtsp) {
        return read_rtsp(t, sample);
    }

    if (!t->ssl) return -1;

    // Read 16-byte frame header.
    uint8_t hdr[16];
    int rc = ssl_read_all(t, hdr, sizeof(hdr));
    if (rc < 0) {
        set_last_error("header read failed");
        return -1;
    }
    if (rc > 0) return Bambu_stream_end;

    auto u32 = [&](size_t off) -> uint32_t {
        return  (static_cast<uint32_t>(hdr[off + 0]))
              | (static_cast<uint32_t>(hdr[off + 1]) << 8)
              | (static_cast<uint32_t>(hdr[off + 2]) << 16)
              | (static_cast<uint32_t>(hdr[off + 3]) << 24);
    };
    uint32_t payload_size = u32(0);
    uint32_t itrack       = u32(4);
    uint32_t flags        = u32(8);

    if (payload_size == 0 || payload_size > kMaxFrameSize) {
        log_fmt(t->logger, t->log_ctx,
                "Bambu_ReadSample: bogus payload size %u", payload_size);
        set_last_error("bogus payload size");
        return -1;
    }

    t->frame_buf.resize(payload_size);
    rc = ssl_read_all(t, t->frame_buf.data(), payload_size);
    if (rc < 0) {
        set_last_error("payload read failed");
        return -1;
    }
    if (rc > 0) return Bambu_stream_end;

    // Sanity check: MJPG frames start with 0xFF 0xD8 and end with
    // 0xFF 0xD9. If the magic is wrong we probably lost sync; bailing
    // out lets gstbambusrc tear the pipeline down and reconnect.
    if (payload_size < 4 ||
        t->frame_buf[0] != 0xFF || t->frame_buf[1] != 0xD8 ||
        t->frame_buf[payload_size - 2] != 0xFF ||
        t->frame_buf[payload_size - 1] != 0xD9) {
        log_fmt(t->logger, t->log_ctx,
                "Bambu_ReadSample: JPEG magic mismatch size=%u", payload_size);
        set_last_error("JPEG magic mismatch");
        return -1;
    }

    auto now = std::chrono::steady_clock::now();
    auto ns  = std::chrono::duration_cast<std::chrono::nanoseconds>(now - t->t0).count();

    if (++t->frame_count == 1 || (t->frame_count % 60) == 0) {
        log_fmt(t->logger, t->log_ctx,
                "Bambu_ReadSample: frame #%llu size=%u itrack=%u flags=%u",
                static_cast<unsigned long long>(t->frame_count),
                payload_size, itrack, flags);
    }

    sample->itrack      = static_cast<int>(itrack);
    sample->size        = static_cast<int>(payload_size);
    sample->flags       = static_cast<int>(flags);
    sample->buffer      = t->frame_buf.data();
    // gstbambusrc multiplies decode_time by 100 to get ns, so we divide.
    sample->decode_time = static_cast<unsigned long long>(ns / 100);
    return Bambu_success;
}

OBN_EXPORT int Bambu_SendMessage(Bambu_Tunnel tunnel, int ctrl,
                                 char const* data, int len)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t || !data || len <= 0) return -1;
    // Only CTRL_TYPE is known to us. Any other ctrl channel is a
    // no-op (returns success so the caller doesn't interpret it as
    // pipe-dead); stock firmware uses the same channel number.
    if (ctrl != kCtrlType) return Bambu_success;
    if (!t->ctrl_mode) {
        set_last_error("CTRL channel not ready");
        return -1;
    }
    CtrlRequest req;
    req.body.assign(data, static_cast<std::size_t>(len));
    {
        std::lock_guard<std::mutex> lk(t->ctrl_mu);
        t->ctrl_in.emplace_back(std::move(req));
        t->ctrl_cv.notify_all();
    }
    return Bambu_success;
}

OBN_EXPORT int Bambu_RecvMessage(Bambu_Tunnel /*tunnel*/, int* /*ctrl*/,
                                 char* /*data*/, int* /*len*/)
{
    // Studio uses Bambu_ReadSample for CTRL replies, not RecvMessage.
    // Keep this as a polite "no data".
    return Bambu_would_block;
}

OBN_EXPORT void Bambu_Close(Bambu_Tunnel tunnel)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t) return;
    // CTRL worker must be joined before the rest of the tunnel is
    // dismantled (it holds references to SSL that tunnel_close would
    // would invalidate).
    stop_ctrl_mode(t);
    tunnel_close(t);
}

OBN_EXPORT void Bambu_Destroy(Bambu_Tunnel tunnel)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t) return;
    stop_ctrl_mode(t);
    tunnel_close(t);
    delete t;
}

OBN_EXPORT char const* Bambu_GetLastErrorMsg()
{
    // Stock plugin returns a static string; we return a thread-local
    // pointer that remains valid until the next set_last_error on
    // the same thread. That matches how Studio actually uses it
    // (printed immediately, not stored).
    return obn::source::get_last_error();
}

OBN_EXPORT void Bambu_FreeLogMsg(tchar const* msg)
{
    // We allocated with strdup_for_logger() in log_fmt(): strdup() on
    // POSIX, malloc(wcslen+1) on Windows. Both come back to free().
    if (msg) std::free(const_cast<tchar*>(msg));
}

// Legacy probe: the older stub exported this so callers could tell at a
// glance that they loaded our build. Keep it around (no-op).
OBN_EXPORT int bambu_source_is_stub()
{
    return 0; // now a real implementation
}
