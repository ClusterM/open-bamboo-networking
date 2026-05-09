// RTSP/RTSPS client implementation.
//
// The control plane (OPTIONS / DESCRIBE / SETUP / PLAY) is plain text
// over TLS, line-oriented per RFC 2326. After PLAY the same TCP
// connection carries interleaved RTP/RTCP frames in the wire format
//
//     '$' <channel:1> <length:2> <rtp-or-rtcp-packet>
//
// from RFC 2326 section 10.12. The interleaved channels are picked at
// SETUP time -- we always ask for 0 = RTP, 1 = RTCP.
//
// The control plane keeps running after PLAY: GET_PARAMETER keepalive
// requests fire every 15 seconds on a worker thread to avoid Bambu's
// 30 s idle teardown. Their responses come back through the same TCP
// connection; we let them flow into the demux loop, which recognises
// them by the leading "RTSP/" string instead of the '$' interleave
// marker, drains the response, and continues.

#include "rtsp_client.hpp"

#include "source_log.hpp"
#include "tls_socket.hpp"

#include "obn/os_compat.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <windows.h>
#else
#  include <sys/socket.h>
#  include <unistd.h>
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace obn::rtsp {

namespace {

using obn::source::log_at;
using obn::source::log_fmt;
using obn::source::Logger;
using obn::source::LL_DEBUG;
using obn::source::LL_TRACE;
using obn::source::LL_WARN;
using obn::source::set_last_error;

// Hard caps to keep a misbehaving server from making us allocate
// arbitrarily large buffers. Every Bambu RTSP message we have seen is
// well under 4 KB; any single RTP packet is under 64 KB by definition
// (the interleave length field is 16 bits).
constexpr std::size_t kMaxResponseBody = 64u << 10;
constexpr std::size_t kMaxRtpPacket    = 64u << 10;

// ---------- base64 (small, inline) ----------

constexpr char kB64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::uint8_t* data, std::size_t n)
{
    std::string out;
    out.reserve(((n + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 3 <= n) {
        std::uint32_t v = (std::uint32_t(data[i]) << 16)
                        | (std::uint32_t(data[i + 1]) << 8)
                        |  std::uint32_t(data[i + 2]);
        out.push_back(kB64Alphabet[(v >> 18) & 0x3f]);
        out.push_back(kB64Alphabet[(v >> 12) & 0x3f]);
        out.push_back(kB64Alphabet[(v >>  6) & 0x3f]);
        out.push_back(kB64Alphabet[ v        & 0x3f]);
        i += 3;
    }
    if (i + 1 == n) {
        std::uint32_t v = std::uint32_t(data[i]) << 16;
        out.push_back(kB64Alphabet[(v >> 18) & 0x3f]);
        out.push_back(kB64Alphabet[(v >> 12) & 0x3f]);
        out.push_back('=');
        out.push_back('=');
    } else if (i + 2 == n) {
        std::uint32_t v = (std::uint32_t(data[i]) << 16)
                        | (std::uint32_t(data[i + 1]) << 8);
        out.push_back(kB64Alphabet[(v >> 18) & 0x3f]);
        out.push_back(kB64Alphabet[(v >> 12) & 0x3f]);
        out.push_back(kB64Alphabet[(v >>  6) & 0x3f]);
        out.push_back('=');
    }
    return out;
}

bool base64_decode(const std::string& in, std::vector<std::uint8_t>* out)
{
    out->clear();
    out->reserve((in.size() / 4) * 3);
    std::uint32_t buf  = 0;
    int           bits = 0;
    for (char c : in) {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') {
            if (c == '=') break;
            continue;
        }
        int v;
        if      (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+')             v = 62;
        else if (c == '/')             v = 63;
        else                           return false;
        buf = (buf << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out->push_back(static_cast<std::uint8_t>((buf >> bits) & 0xff));
        }
    }
    return true;
}

// ---------- MD5 (for Digest auth) ----------

// Bambu printers run live555 on port 322 and reply to every DESCRIBE
// with `WWW-Authenticate: Digest realm="LIVE555 Streaming Media",
// nonce="..."`. Implementing the RFC 2617 Digest algorithm ourselves
// is half a screen of code and saves us from adding a curl / glib-net /
// gstrtsp runtime dependency. EVP_Digest is in libcrypto, which we
// already link for TLS, so no new soname enters DT_NEEDED.
std::string md5_hex(const std::string& in)
{
    unsigned char  digest[EVP_MAX_MD_SIZE];
    unsigned int   dlen = 0;
    EVP_Digest(in.data(), in.size(), digest, &dlen, EVP_md5(), nullptr);
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(dlen * 2);
    for (unsigned int i = 0; i < dlen; ++i) {
        out[2 * i]     = kHex[digest[i] >> 4];
        out[2 * i + 1] = kHex[digest[i] & 0x0f];
    }
    return out;
}

// 16 random hex chars for the cnonce field. std::random_device is fine
// here -- the cnonce only needs to be non-repeating per request.
std::string random_cnonce()
{
    std::random_device                       rd;
    std::uniform_int_distribution<std::uint64_t> dist;
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016lx",
                  static_cast<unsigned long>(dist(rd)));
    return std::string(buf, 16);
}

// Parse a comma-separated `key=value` list as it appears in an
// RFC 2617 WWW-Authenticate header (after the `Digest ` prefix).
// Values may be quoted ("...") with embedded commas; unquoted values
// run until the next comma or end-of-string. Keys are lower-cased.
void parse_auth_params(const std::string& s,
                       std::vector<std::pair<std::string, std::string>>* out)
{
    out->clear();
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == ',' || s[i] == '\t')) ++i;
        if (i >= s.size()) break;
        std::size_t key_begin = i;
        while (i < s.size() && s[i] != '=' && s[i] != ',') ++i;
        std::string k(s.data() + key_begin, i - key_begin);
        std::string v;
        if (i < s.size() && s[i] == '=') {
            ++i;
            if (i < s.size() && s[i] == '"') {
                ++i;
                std::size_t v_begin = i;
                while (i < s.size() && s[i] != '"') {
                    if (s[i] == '\\' && i + 1 < s.size()) ++i;
                    ++i;
                }
                v.assign(s.data() + v_begin, i - v_begin);
                if (i < s.size() && s[i] == '"') ++i;
            } else {
                std::size_t v_begin = i;
                while (i < s.size() && s[i] != ',') ++i;
                v.assign(s.data() + v_begin, i - v_begin);
            }
        }
        // Trim & lowercase the key; trim the value.
        while (!k.empty() && std::isspace(static_cast<unsigned char>(k.back())))
            k.pop_back();
        std::size_t kb = 0;
        while (kb < k.size() && std::isspace(static_cast<unsigned char>(k[kb]))) ++kb;
        k.erase(0, kb);
        for (auto& c : k) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        while (!v.empty() && std::isspace(static_cast<unsigned char>(v.back())))
            v.pop_back();
        std::size_t vb = 0;
        while (vb < v.size() && std::isspace(static_cast<unsigned char>(v[vb]))) ++vb;
        v.erase(0, vb);
        out->emplace_back(std::move(k), std::move(v));
    }
}

// ---------- string helpers ----------

std::string lc(std::string s)
{
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(const std::string& s)
{
    std::size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    std::size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

bool starts_with(const std::string& s, const char* prefix)
{
    std::size_t n = std::strlen(prefix);
    return s.size() >= n && std::memcmp(s.data(), prefix, n) == 0;
}

// Resolve a SETUP target. RFC 2326 lets `a=control:` be either an
// absolute URL or a relative one; in the absolute case we use it as
// is, in the relative case we append it to the original DESCRIBE URL.
std::string resolve_control(const std::string& base, const std::string& control)
{
    if (control.empty() || control == "*") return base;
    if (starts_with(control, "rtsp://") || starts_with(control, "rtsps://"))
        return control;
    if (control.front() == '/') {
        // Authority-relative: keep base scheme://host:port and replace path.
        auto p = base.find("://");
        if (p == std::string::npos) return base + control;
        auto slash = base.find('/', p + 3);
        std::string root = (slash == std::string::npos) ? base : base.substr(0, slash);
        return root + control;
    }
    if (!base.empty() && base.back() == '/') return base + control;
    return base + "/" + control;
}

// Build a request URL from the parsed Url for the control channel.
// We always reuse the same URL for OPTIONS / DESCRIBE / PLAY /
// GET_PARAMETER -- only SETUP gets the per-track variant.
std::string base_url(const Url& url)
{
    std::string s = url.tls ? "rtsps://" : "rtsp://";
    s += url.host;
    s += ":";
    s += std::to_string(url.port);
    if (!url.path.empty() && url.path.front() != '/') s += "/";
    s += url.path;
    return s;
}

// ---------- RTSP response parsing ----------

struct Response {
    int                                          status = 0;
    std::string                                  reason;
    // Header keys lower-cased; values trimmed.
    std::vector<std::pair<std::string, std::string>> headers;
    std::string                                  body;

    std::string header(const char* key) const
    {
        std::string k = lc(key);
        for (auto const& h : headers)
            if (h.first == k) return h.second;
        return {};
    }
};

// Read one RTSP response off the SSL stream. `prefetch_byte` is the
// already-consumed first byte of the status line, or -1 if the caller
// has not peeked. The prefetch path is required after PLAY: live555
// pipelines the first interleaved RTP frame ahead of the PLAY 200 OK,
// so the demux loop in Impl::await_response peeks one byte to tell
// `$` frames apart from `R` (RTSP/1.0 ...) responses, then hands the
// `R` here to be re-stitched into the status line.
//
// Returns 0 / 1 / -1 like ssl_read_full.
int read_response(SSL* ssl, Response* out, int prefetch_byte = -1)
{
    out->headers.clear();
    out->body.clear();
    out->status = 0;
    out->reason.clear();

    std::string line;
    if (prefetch_byte >= 0) {
        // Read the rest of the status line, byte by byte, with the
        // supplied byte as the seed. Mirrors ssl_read_line semantics.
        line.push_back(static_cast<char>(prefetch_byte));
        char prev = static_cast<char>(prefetch_byte);
        while (line.size() < 8192) {
            char c = '\0';
            int  n = SSL_read(ssl, &c, 1);
            if (n <= 0) {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    continue;
                if (err == SSL_ERROR_ZERO_RETURN) return 1;
                return -1;
            }
            if (prev == '\r' && c == '\n') {
                line.pop_back(); // strip the CR we just pushed
                break;
            }
            line.push_back(c);
            prev = c;
        }
    } else {
        int rc = obn::tls::ssl_read_line(ssl, &line);
        if (rc != 0) return rc;
    }
    // "RTSP/1.0 200 OK"
    if (line.size() < 12 || std::memcmp(line.data(), "RTSP/1.", 7) != 0) {
        set_last_error(("rtsp: malformed status line: " + line).c_str());
        return -1;
    }
    auto sp1 = line.find(' ', 9);
    if (sp1 == std::string::npos) {
        set_last_error("rtsp: status line missing reason");
        return -1;
    }
    out->status = std::atoi(line.substr(9, sp1 - 9).c_str());
    out->reason = trim(line.substr(sp1 + 1));

    // Headers.
    std::size_t content_length = 0;
    for (;;) {
        int hrc = obn::tls::ssl_read_line(ssl, &line);
        if (hrc != 0) return hrc;
        if (line.empty()) break;
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string k = lc(trim(line.substr(0, colon)));
        std::string v = trim(line.substr(colon + 1));
        if (k == "content-length") content_length = static_cast<std::size_t>(std::atoi(v.c_str()));
        out->headers.emplace_back(std::move(k), std::move(v));
    }

    if (content_length > kMaxResponseBody) {
        set_last_error("rtsp: response body exceeds cap");
        return -1;
    }
    if (content_length > 0) {
        out->body.resize(content_length);
        int brc = obn::tls::ssl_read_full(ssl, out->body.data(), content_length);
        if (brc != 0) return brc;
    }
    return 0;
}

// ---------- SDP parsing ----------

// Find the first H.264 video track, fill *track and *control_attr.
// Returns true if we have at least the rtpmap; sprop-parameter-sets
// are optional (decoder will catch up with in-band SPS/PPS).
bool parse_sdp(const std::string& sdp, H264Track* track, std::string* control)
{
    track->sps.clear();
    track->pps.clear();
    track->clock_rate = 90000;
    track->rtp_pt     = -1;
    control->clear();

    int  current_pt   = -1;
    bool in_video     = false;
    bool seen_rtpmap  = false;
    int  video_pt     = -1;

    std::size_t i = 0;
    while (i < sdp.size()) {
        std::size_t end = sdp.find('\n', i);
        std::string line = sdp.substr(i, (end == std::string::npos ? sdp.size() : end) - i);
        i = (end == std::string::npos) ? sdp.size() : end + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.size() < 2 || line[1] != '=') continue;
        char tag = line[0];
        std::string val = line.substr(2);

        if (tag == 'm') {
            // m=<media> <port> <proto> <fmt-list>
            in_video = starts_with(val, "video ");
            if (in_video) {
                // Pick the first payload type listed; multiple PT lines are
                // legal but Bambu uses one.
                auto last_sp = val.rfind(' ');
                if (last_sp != std::string::npos)
                    video_pt = std::atoi(val.substr(last_sp + 1).c_str());
                track->rtp_pt = video_pt;
            }
        } else if (in_video && tag == 'a') {
            if (starts_with(val, "control:")) {
                if (control->empty()) *control = trim(val.substr(8));
            } else if (starts_with(val, "rtpmap:")) {
                // a=rtpmap:<pt> <encoding>/<clock>[/...]
                std::string rest = val.substr(7);
                auto sp = rest.find(' ');
                if (sp == std::string::npos) continue;
                int pt = std::atoi(rest.substr(0, sp).c_str());
                std::string enc = rest.substr(sp + 1);
                if (pt != video_pt) continue;
                auto slash = enc.find('/');
                if (slash == std::string::npos) continue;
                std::string codec = lc(enc.substr(0, slash));
                if (codec != "h264") {
                    set_last_error(("rtsp: unsupported codec " + codec).c_str());
                    return false;
                }
                seen_rtpmap = true;
                track->clock_rate = static_cast<std::uint32_t>(
                    std::atoi(enc.substr(slash + 1).c_str()));
                if (track->clock_rate == 0) track->clock_rate = 90000;
            } else if (starts_with(val, "fmtp:")) {
                // a=fmtp:<pt> <param>=<value>;<param>=<value>;...
                std::string rest = val.substr(5);
                auto sp = rest.find(' ');
                if (sp == std::string::npos) continue;
                int pt = std::atoi(rest.substr(0, sp).c_str());
                if (pt != video_pt) continue;
                std::string params = rest.substr(sp + 1);
                // Split on ';' and look for sprop-parameter-sets.
                std::size_t p = 0;
                while (p < params.size()) {
                    std::size_t q = params.find(';', p);
                    std::string kv = params.substr(p, (q == std::string::npos ? params.size() : q) - p);
                    p = (q == std::string::npos) ? params.size() : q + 1;
                    auto eq = kv.find('=');
                    if (eq == std::string::npos) continue;
                    std::string k = lc(trim(kv.substr(0, eq)));
                    std::string v = trim(kv.substr(eq + 1));
                    if (k == "sprop-parameter-sets") {
                        // Comma-separated base64 NAL units; first SPS,
                        // then PPS, sometimes SEI follows.
                        std::size_t r = 0;
                        int idx = 0;
                        while (r < v.size()) {
                            std::size_t s = v.find(',', r);
                            std::string b64 = v.substr(r, (s == std::string::npos ? v.size() : s) - r);
                            r = (s == std::string::npos) ? v.size() : s + 1;
                            std::vector<std::uint8_t> nal;
                            if (!base64_decode(b64, &nal) || nal.empty()) continue;
                            int nal_type = nal[0] & 0x1f;
                            if (nal_type == 7 && track->sps.empty())      track->sps = std::move(nal);
                            else if (nal_type == 8 && track->pps.empty()) track->pps = std::move(nal);
                            (void)idx;
                            ++idx;
                        }
                    }
                }
            }
        } else if (tag == 'm') {
            (void)current_pt;
        }
    }
    if (!seen_rtpmap) {
        set_last_error("rtsp: SDP had no usable H.264 video track");
        return false;
    }
    return true;
}

} // namespace

// ============================================================
// Client::Impl
// ============================================================

struct Client::Impl {
    Logger logger;
    void*  log_ctx;

    obn::os::socket_t fd  = obn::os::kInvalidSocket;
    SSL*              ssl = nullptr;

    // Mutex protects ssl/fd against the keepalive thread writing
    // GET_PARAMETER requests while the data thread is reading
    // interleaved frames. Reads on the data thread don't take it
    // (single reader); only the writer-side does.
    std::mutex io_mu;

    // Demux state.
    std::deque<Nalu>          nalu_queue;
    std::vector<std::uint8_t> fu_buf;  // FU-A reassembly
    std::uint32_t             fu_ts = 0;
    bool                      fu_au_end = false;

    // Sequencing.
    int           cseq      = 1;
    std::string   session;       // RTSP Session header value (with timeout=...)
    std::string   session_id;    // session value with timeout suffix stripped
    std::string   url_full;      // base URL for OPTIONS/DESCRIBE/PLAY/GET_PARAMETER
    std::string   url_setup;     // resolved control URL for SETUP / TEARDOWN

    // Auth state. user / passwd are stashed at start() time so the
    // 401 -> retry path and the keepalive thread can rebuild a Digest
    // header without reaching back into the original Url.
    std::string   user;
    std::string   passwd;

    // Auth scheme picked from the most recent WWW-Authenticate. Empty
    // until the first 401 Unauthorized response carries a challenge.
    // When set, every subsequent request (including keepalive and
    // teardown) reuses these fields with the existing nonce until the
    // server invalidates it -- at which point we re-handshake the
    // challenge transparently inside request_with_auth.
    enum class AuthScheme { None, Basic, Digest };
    AuthScheme    auth_scheme = AuthScheme::None;

    // Digest state (RFC 2617). qop / opaque / algorithm are optional
    // in the challenge; live555 sends realm + nonce only. We keep the
    // others around in case a future printer firmware switches to a
    // qop=auth challenge with an opaque echoback.
    std::string   digest_realm;
    std::string   digest_nonce;
    std::string   digest_qop;
    std::string   digest_opaque;
    std::string   digest_algorithm;
    std::uint32_t digest_nc = 0;  // nonce-count, used only with qop

    // Keepalive.
    std::thread             keepalive;
    std::atomic<bool>       stop_flag{false};
    std::condition_variable keepalive_cv;
    std::mutex              keepalive_mu;

    H264Track track;

    Impl(Logger l, void* c) : logger(l ? l : obn::source::noop_logger), log_ctx(c) {}

    ~Impl() = default;

    // ----- request helpers -----

    // Build a fresh `Authorization: ...\r\n` header for the current
    // (method, uri) pair, or return an empty string if we have no
    // credentials yet. Called for every outbound request once the
    // 401-handshake has populated digest_*.
    std::string compute_authorization(const char* method, const std::string& uri)
    {
        if (auth_scheme == AuthScheme::None) return std::string();
        if (auth_scheme == AuthScheme::Basic) {
            std::string up = user + ":" + passwd;
            return "Authorization: Basic " +
                   base64_encode(reinterpret_cast<const std::uint8_t*>(up.data()),
                                 up.size()) +
                   "\r\n";
        }
        // Digest. Live555 omits qop; RFC 2069 simple-mode formula:
        //   HA1      = MD5(user:realm:passwd)
        //   HA2      = MD5(method:uri)
        //   response = MD5(HA1:nonce:HA2)
        // RFC 2617 with qop=auth adds nc + cnonce into the response
        // hash, which we honour for forward-compat even though no
        // Bambu firmware we have seen uses it.
        std::string ha1 = md5_hex(user + ":" + digest_realm + ":" + passwd);
        std::string ha2 = md5_hex(std::string(method) + ":" + uri);
        std::string response;
        std::string extra;
        if (!digest_qop.empty()) {
            // qop in the challenge can be "auth" or a list ("auth,auth-int").
            // We always negotiate auth.
            std::string cnonce = random_cnonce();
            char nc_buf[9];
            std::snprintf(nc_buf, sizeof(nc_buf), "%08x", ++digest_nc);
            response = md5_hex(ha1 + ":" + digest_nonce + ":" + nc_buf + ":" +
                               cnonce + ":auth:" + ha2);
            extra = std::string(", qop=auth, nc=") + nc_buf +
                    ", cnonce=\"" + cnonce + "\"";
        } else {
            response = md5_hex(ha1 + ":" + digest_nonce + ":" + ha2);
        }
        std::string hdr = "Authorization: Digest username=\"" + user + "\", realm=\"" +
                          digest_realm + "\", nonce=\"" + digest_nonce + "\", uri=\"" +
                          uri + "\", response=\"" + response + "\"";
        if (!digest_opaque.empty())
            hdr += ", opaque=\"" + digest_opaque + "\"";
        if (!digest_algorithm.empty())
            hdr += ", algorithm=" + digest_algorithm;
        hdr += extra;
        hdr += "\r\n";
        return hdr;
    }

    // Adopts a new challenge from a 401 response. Returns true if we
    // could understand the challenge (Basic or Digest), false if the
    // server demanded something exotic we cannot satisfy (mutual TLS
    // auth, NTLM, etc.) -- in which case the caller should fail with
    // a clear error rather than spin forever on retries.
    bool adopt_challenge(const Response& resp)
    {
        std::string www = resp.header("www-authenticate");
        if (www.empty()) return false;
        if (lc(www.substr(0, 7)) == "digest ") {
            std::vector<std::pair<std::string, std::string>> p;
            parse_auth_params(www.substr(7), &p);
            digest_realm.clear();
            digest_nonce.clear();
            digest_qop.clear();
            digest_opaque.clear();
            digest_algorithm.clear();
            for (auto const& kv : p) {
                if      (kv.first == "realm")     digest_realm     = kv.second;
                else if (kv.first == "nonce")     digest_nonce     = kv.second;
                else if (kv.first == "qop")       digest_qop       = kv.second;
                else if (kv.first == "opaque")    digest_opaque    = kv.second;
                else if (kv.first == "algorithm") digest_algorithm = kv.second;
            }
            if (digest_realm.empty() || digest_nonce.empty()) return false;
            digest_nc   = 0;
            auth_scheme = AuthScheme::Digest;
            log_fmt(logger, log_ctx,
                    "rtsp: adopted Digest challenge (realm=\"%s\", qop=\"%s\")",
                    digest_realm.c_str(), digest_qop.c_str());
            return true;
        }
        if (lc(www.substr(0, 6)) == "basic ") {
            auth_scheme = AuthScheme::Basic;
            log_fmt(logger, log_ctx,
                    "rtsp: adopted Basic challenge (realm in challenge ignored)");
            return true;
        }
        return false;
    }

    int send_request(const char* method, const std::string& url,
                     const std::string& extra_headers,
                     const std::string& body)
    {
        char buf[4096];
        int  n = std::snprintf(buf, sizeof(buf),
            "%s %s RTSP/1.0\r\n"
            "CSeq: %d\r\n"
            "User-Agent: open-bambu-networking/0.1\r\n"
            "%s%s%s",
            method, url.c_str(), cseq++,
            session_id.empty() ? "" : "Session: ",
            session_id.empty() ? "" : session_id.c_str(),
            session_id.empty() ? "" : "\r\n");
        if (n < 0 || n >= static_cast<int>(sizeof(buf))) {
            set_last_error("rtsp: request too long");
            return -1;
        }
        std::string req(buf, static_cast<std::size_t>(n));
        req += compute_authorization(method, url);
        req += extra_headers;
        if (!body.empty()) {
            char clbuf[64];
            std::snprintf(clbuf, sizeof(clbuf), "Content-Length: %zu\r\n", body.size());
            req += clbuf;
        }
        req += "\r\n";
        if (!body.empty()) req += body;

        log_at(LL_TRACE, logger, log_ctx, "rtsp -> %s %s", method, url.c_str());
        std::lock_guard<std::mutex> lk(io_mu);
        if (!ssl) {
            set_last_error("rtsp: ssl is null");
            return -1;
        }
        if (obn::tls::ssl_write_all(ssl, req.data(), req.size()) != 0) {
            set_last_error("rtsp: write failed");
            return -1;
        }
        return 0;
    }

    // High-level wrapper: send a request and read the response, with
    // one transparent retry on `401 Unauthorized + WWW-Authenticate`.
    // Returns 0/1/-1 like await_response (1 == clean EOS before any
    // bytes were read).
    int request_with_auth(const char* method, const std::string& url,
                          const std::string& extra_headers,
                          const std::string& body,
                          Response* out)
    {
        if (send_request(method, url, extra_headers, body) != 0) return -1;
        int rc = await_response(out);
        if (rc != 0) return rc;
        if (out->status != 401) return 0;
        // First 401, or a follow-up 401 telling us the nonce went stale.
        // Either way, adopt the (possibly new) challenge and retry once.
        if (!adopt_challenge(*out)) {
            set_last_error("rtsp: 401 Unauthorized with no usable "
                           "WWW-Authenticate (Bambu access code wrong, "
                           "or unsupported auth scheme)");
            return -1;
        }
        if (send_request(method, url, extra_headers, body) != 0) return -1;
        rc = await_response(out);
        if (rc != 0) return rc;
        if (out->status == 401) {
            set_last_error("rtsp: 401 Unauthorized after Digest retry "
                           "-- access code rejected by printer");
            return -1;
        }
        return 0;
    }

    int await_response(Response* out)
    {
        // No mutex: only the start() / read_nalu() / keepalive thread
        // ever calls this, and they coordinate higher up. Specifically,
        // the keepalive thread does not read the response itself; it
        // lets the demux loop in read_nalu() consume it (or, before
        // PLAY, start() reads each response inline).
        //
        // After PLAY, live555 streams interleaved RTP frames on the
        // same TCP connection; in TCP-interleaved transport it can
        // pipeline the first $-frame ahead of the PLAY 200 OK
        // response (which is allowed by the RFC -- the response only
        // has to arrive on the same connection, not first). Peek one
        // byte to disambiguate: '$' = interleaved frame, anything
        // else = start of an RTSP status line. Buffer any pre-PLAY
        // frames into nalu_queue for the data path to drain later.
        for (;;) {
            std::uint8_t prefix;
            int rc = obn::tls::ssl_read_full(ssl, &prefix, 1);
            if (rc != 0) return rc;
            if (prefix == '$') {
                std::uint8_t hdr[3];
                rc = obn::tls::ssl_read_full(ssl, hdr, 3);
                if (rc != 0) return rc;
                int channel = hdr[0];
                std::uint16_t plen = static_cast<std::uint16_t>(
                    (std::uint16_t(hdr[1]) << 8) | hdr[2]);
                if (plen > kMaxRtpPacket) {
                    set_last_error("rtsp: implausible interleaved frame length");
                    return -1;
                }
                std::vector<std::uint8_t> rtp(plen);
                if (plen > 0) {
                    rc = obn::tls::ssl_read_full(ssl, rtp.data(), plen);
                    if (rc != 0) return rc;
                }
                // Channel 0 = RTP, anything else (RTCP, etc.) we drop.
                // The early frames are real video; keeping them avoids
                // a brief blank at PLAY time once the data path picks
                // up read_nalu().
                if (channel == 0) decode_rtp_h264(rtp);
                log_at(LL_TRACE, logger, log_ctx,
                       "rtsp: buffered $-frame ahead of response "
                       "(ch=%d len=%u)", channel, static_cast<unsigned>(plen));
                continue;
            }
            int read_rc = read_response(ssl, out, static_cast<int>(prefix));
            if (read_rc != 0) return read_rc;
            log_at(LL_TRACE, logger, log_ctx,
                   "rtsp <- %d %s (body=%zu)",
                   out->status, out->reason.c_str(), out->body.size());
            return 0;
        }
    }

    // ----- handshake -----

    int do_options(const Url&)
    {
        Response resp;
        // OPTIONS routinely succeeds without auth on Bambu firmware
        // (live555 only authenticates DESCRIBE+SETUP+PLAY), but we
        // still go through request_with_auth so a future revision
        // that does demand auth here gets the same retry path.
        if (request_with_auth("OPTIONS", url_full, "", "", &resp) != 0) return -1;
        if (resp.status != 200) {
            char e[128];
            std::snprintf(e, sizeof(e), "rtsp: OPTIONS returned %d %s",
                          resp.status, resp.reason.c_str());
            set_last_error(e);
            return -1;
        }
        return 0;
    }

    int do_describe(const Url&, std::string* sdp_out)
    {
        Response resp;
        if (request_with_auth("DESCRIBE", url_full,
                              "Accept: application/sdp\r\n", "", &resp) != 0)
            return -1;
        if (resp.status != 200) {
            char e[128];
            std::snprintf(e, sizeof(e), "rtsp: DESCRIBE returned %d %s",
                          resp.status, resp.reason.c_str());
            set_last_error(e);
            return -1;
        }
        *sdp_out = std::move(resp.body);
        return 0;
    }

    int do_setup(const Url&)
    {
        Response resp;
        if (request_with_auth("SETUP", url_setup,
                              "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n",
                              "", &resp) != 0)
            return -1;
        if (resp.status != 200) {
            char e[128];
            std::snprintf(e, sizeof(e), "rtsp: SETUP returned %d %s",
                          resp.status, resp.reason.c_str());
            set_last_error(e);
            return -1;
        }
        session = resp.header("session");
        if (session.empty()) {
            set_last_error("rtsp: SETUP did not return a Session header");
            return -1;
        }
        // Strip the optional "; timeout=NN" suffix; stash the bare id
        // for subsequent requests.
        auto semi = session.find(';');
        session_id = (semi == std::string::npos) ? session : session.substr(0, semi);
        session_id = trim(session_id);
        return 0;
    }

    int do_play(const Url&)
    {
        Response resp;
        if (request_with_auth("PLAY", url_full,
                              "Range: npt=0.000-\r\n", "", &resp) != 0)
            return -1;
        if (resp.status != 200) {
            char e[128];
            std::snprintf(e, sizeof(e), "rtsp: PLAY returned %d %s",
                          resp.status, resp.reason.c_str());
            set_last_error(e);
            return -1;
        }
        return 0;
    }

    void do_teardown_best_effort()
    {
        if (session_id.empty() || !ssl) return;
        // Best-effort fire-and-forget; the response (if any) is
        // discarded. We ignore errors here because by the time we
        // call this the user is already exiting.
        std::string auth = compute_authorization("TEARDOWN", url_full);
        std::string req  = std::string("TEARDOWN ") + url_full + " RTSP/1.0\r\n" +
                           "CSeq: " + std::to_string(cseq++) + "\r\n" +
                           "Session: " + session_id + "\r\n" +
                           auth +
                           "\r\n";
        std::lock_guard<std::mutex> lk(io_mu);
        if (ssl)
            (void)obn::tls::ssl_write_all(ssl, req.data(), req.size());
    }

    // ----- keepalive -----

    void keepalive_main()
    {
        while (!stop_flag.load(std::memory_order_acquire)) {
            std::unique_lock<std::mutex> lk(keepalive_mu);
            keepalive_cv.wait_for(lk, std::chrono::seconds(15), [&] {
                return stop_flag.load(std::memory_order_acquire);
            });
            if (stop_flag.load(std::memory_order_acquire)) break;
            // GET_PARAMETER with no body is the standard idle ping
            // live555 accepts. Build the request inline (instead of
            // through send_request) so we keep the Session: header
            // even if the data path also wants the io_mu mutex.
            std::string auth = compute_authorization("GET_PARAMETER", url_full);
            std::string req  = std::string("GET_PARAMETER ") + url_full +
                               " RTSP/1.0\r\n" +
                               "CSeq: " + std::to_string(cseq++) + "\r\n" +
                               "Session: " + session_id + "\r\n" +
                               auth +
                               "\r\n";

            std::lock_guard<std::mutex> io_lk(io_mu);
            if (!ssl) break;
            if (obn::tls::ssl_write_all(ssl, req.data(), req.size()) != 0) {
                log_at(LL_DEBUG, logger, log_ctx, "rtsp: keepalive write failed");
                break;
            }
            log_at(LL_TRACE, logger, log_ctx, "rtsp: keepalive sent");
        }
    }

    // ----- demux -----

    // Read the next chunk on the wire, classify it, and either:
    //   * push one or more decoded NALUs into nalu_queue (data plane),
    //   * silently drain a stray RTSP keepalive response (control plane),
    //   * return 1 on clean EOS, -1 on hard error, 0 on "made progress
    //     but no NAL ready yet" -- caller loops.
    int pull_one_message()
    {
        std::uint8_t prefix;
        int rc = obn::tls::ssl_read_full(ssl, &prefix, 1);
        if (rc != 0) return rc;
        if (prefix == '$') {
            // Interleaved RTP/RTCP frame.
            std::uint8_t hdr[3];
            rc = obn::tls::ssl_read_full(ssl, hdr, 3);
            if (rc != 0) return rc;
            int channel = hdr[0];
            std::uint16_t plen = static_cast<std::uint16_t>(
                (std::uint16_t(hdr[1]) << 8) | hdr[2]);
            if (plen == 0 || plen > kMaxRtpPacket) {
                set_last_error("rtsp: implausible interleaved frame length");
                return -1;
            }
            std::vector<std::uint8_t> rtp(plen);
            rc = obn::tls::ssl_read_full(ssl, rtp.data(), plen);
            if (rc != 0) return rc;
            // Channel 0 = RTP, channel 1 = RTCP. Bambu only sends 0
            // for video, but we filter defensively.
            if (channel != 0) return 0;
            decode_rtp_h264(rtp);
            return 0;
        }
        if (prefix == 'R') {
            // Stray RTSP response (e.g. to our keepalive GET_PARAMETER).
            // Re-prepend the 'R' we already consumed and parse normally.
            std::string status = "R";
            std::string rest;
            rc = obn::tls::ssl_read_line(ssl, &rest);
            if (rc != 0) return rc;
            status += rest;
            (void)status;
            // Drain headers + (optional) body.
            std::size_t content_length = 0;
            for (;;) {
                std::string line;
                rc = obn::tls::ssl_read_line(ssl, &line);
                if (rc != 0) return rc;
                if (line.empty()) break;
                auto colon = line.find(':');
                if (colon != std::string::npos) {
                    std::string k = lc(trim(line.substr(0, colon)));
                    std::string v = trim(line.substr(colon + 1));
                    if (k == "content-length")
                        content_length = static_cast<std::size_t>(std::atoi(v.c_str()));
                }
            }
            if (content_length > kMaxResponseBody) {
                set_last_error("rtsp: stray response body exceeds cap");
                return -1;
            }
            if (content_length > 0) {
                std::vector<std::uint8_t> body(content_length);
                rc = obn::tls::ssl_read_full(ssl, body.data(), content_length);
                if (rc != 0) return rc;
            }
            log_at(LL_TRACE, logger, log_ctx, "rtsp: drained stray response");
            return 0;
        }
        // Unknown leading byte: protocol desync. There is no robust
        // re-sync strategy on a TCP-interleaved stream; fail and let
        // the upper layer reconnect.
        char e[128];
        std::snprintf(e, sizeof(e),
                      "rtsp: unexpected wire byte 0x%02x (expected '$' or 'R')",
                      prefix);
        set_last_error(e);
        return -1;
    }

    void decode_rtp_h264(const std::vector<std::uint8_t>& rtp)
    {
        if (rtp.size() < 12) return;
        std::uint8_t b0 = rtp[0];
        std::uint8_t b1 = rtp[1];
        if ((b0 >> 6) != 2) return;             // V must be 2
        std::uint8_t cc = b0 & 0x0f;
        bool         x  = (b0 & 0x10) != 0;
        bool         m  = (b1 & 0x80) != 0;
        int          pt = b1 & 0x7f;
        if (pt != track.rtp_pt) return;
        std::uint32_t ts = (std::uint32_t(rtp[4]) << 24)
                         | (std::uint32_t(rtp[5]) << 16)
                         | (std::uint32_t(rtp[6]) <<  8)
                         |  std::uint32_t(rtp[7]);

        std::size_t off = 12 + 4 * cc;
        if (x) {
            if (rtp.size() < off + 4) return;
            std::uint16_t ext_len_words =
                static_cast<std::uint16_t>(
                    (std::uint16_t(rtp[off + 2]) << 8) | rtp[off + 3]);
            off += 4 + std::size_t(ext_len_words) * 4;
        }
        if (off >= rtp.size()) return;
        const std::uint8_t* p = rtp.data() + off;
        std::size_t         n = rtp.size() - off;
        if (n == 0) return;

        std::uint8_t nal0     = p[0];
        int          nal_type = nal0 & 0x1f;

        if (nal_type >= 1 && nal_type <= 23) {
            // Single NAL unit.
            Nalu nu;
            nu.data.assign(p, p + n);
            nu.rtp_ts_90khz = ts;
            nu.au_end       = m;
            nalu_queue.emplace_back(std::move(nu));
            return;
        }
        if (nal_type == 24) {
            // STAP-A: skip the STAP header byte, then iterate
            // [size16 | NALU]* sub-units.
            std::size_t i = 1;
            while (i + 2 <= n) {
                std::uint16_t sub_size =
                    static_cast<std::uint16_t>(
                        (std::uint16_t(p[i]) << 8) | p[i + 1]);
                i += 2;
                if (sub_size == 0 || i + sub_size > n) break;
                Nalu nu;
                nu.data.assign(p + i, p + i + sub_size);
                nu.rtp_ts_90khz = ts;
                nu.au_end       = m && (i + sub_size == n);
                nalu_queue.emplace_back(std::move(nu));
                i += sub_size;
            }
            return;
        }
        if (nal_type == 28) {
            // FU-A. First byte we already saw is the FU indicator; the
            // next is the FU header. Reassemble into fu_buf, emit on E.
            if (n < 2) return;
            std::uint8_t fu_ind = p[0];
            std::uint8_t fu_hdr = p[1];
            bool         start  = (fu_hdr & 0x80) != 0;
            bool         end    = (fu_hdr & 0x40) != 0;
            int          orig_t = fu_hdr & 0x1f;

            if (start) {
                fu_buf.clear();
                fu_buf.reserve(n);
                fu_buf.push_back(static_cast<std::uint8_t>(
                    (fu_ind & 0xe0) | (orig_t & 0x1f)));
                fu_buf.insert(fu_buf.end(), p + 2, p + n);
                fu_ts     = ts;
                fu_au_end = m;
            } else if (!fu_buf.empty()) {
                fu_buf.insert(fu_buf.end(), p + 2, p + n);
                if (m) fu_au_end = true;
            } else {
                // Mid/End packet without a Start: out-of-order or
                // recovery; safest to drop and wait for the next
                // Start.
                return;
            }

            if (end) {
                Nalu nu;
                nu.data         = std::move(fu_buf);
                nu.rtp_ts_90khz = fu_ts;
                nu.au_end       = fu_au_end;
                fu_buf.clear();
                fu_au_end = false;
                nalu_queue.emplace_back(std::move(nu));
            }
            return;
        }
        // 25..27 (MTAP) and 29..31 (FU-B / reserved) are not used by
        // Bambu firmware; log once at TRACE if we ever see them.
        log_at(LL_TRACE, logger, log_ctx,
               "rtsp: unhandled H.264 NAL type %d", nal_type);
    }
};

// ============================================================
// Client public surface
// ============================================================

Client::Client(obn::source::Logger logger, void* log_ctx)
    : impl_(std::make_unique<Impl>(logger, log_ctx)) {}

Client::~Client() { stop(); }

int Client::start(const Url& url, int connect_timeout_ms)
{
    auto& I = *impl_;
    log_fmt(I.logger, I.log_ctx,
            "rtsp: dialing %s://%s:%d",
            url.tls ? "rtsps" : "rtsp", url.host.c_str(), url.port);

    if (url.tls) {
        if (obn::tls::dial_tls(url.host, url.port, connect_timeout_ms,
                               &I.fd, &I.ssl) != 0) {
            log_fmt(I.logger, I.log_ctx, "rtsp: TLS dial failed: %s",
                    obn::source::get_last_error());
            return -1;
        }
        log_fmt(I.logger, I.log_ctx, "rtsp: TLS established (cipher=%s)",
                SSL_get_cipher(I.ssl));
    } else {
        I.fd = obn::tls::dial(url.host, url.port, connect_timeout_ms);
        if (!obn::os::socket_valid(I.fd)) {
            log_fmt(I.logger, I.log_ctx, "rtsp: dial failed: %s",
                    obn::source::get_last_error());
            return -1;
        }
        // No TLS path: we'd need a second helper to read/write plain
        // TCP. Bambu never uses it, so for now refuse cleanly.
        set_last_error("rtsp: plain rtsp:// is not supported");
        obn::os::close_socket(I.fd);
        I.fd = obn::os::kInvalidSocket;
        return -1;
    }

    I.url_full = base_url(url);
    I.user     = url.user;
    I.passwd   = url.passwd;
    // Auth scheme stays AuthScheme::None until the first 401 response
    // tells us what the server wants. request_with_auth then adopts
    // the challenge and retries.

    if (I.do_options(url) != 0)             goto fail;
    {
        std::string sdp;
        if (I.do_describe(url, &sdp) != 0)  goto fail;
        log_at(LL_TRACE, I.logger, I.log_ctx,
               "rtsp: SDP (%zu bytes) follows\n%s", sdp.size(), sdp.c_str());

        std::string control;
        if (!parse_sdp(sdp, &impl_->track, &control)) goto fail;
        I.url_setup = resolve_control(I.url_full, control);
        log_fmt(I.logger, I.log_ctx,
                "rtsp: track pt=%d clock=%u sps=%zuB pps=%zuB control=%s",
                impl_->track.rtp_pt, impl_->track.clock_rate,
                impl_->track.sps.size(), impl_->track.pps.size(),
                I.url_setup.c_str());
    }
    if (I.do_setup(url) != 0)               goto fail;
    if (I.do_play(url) != 0)                goto fail;

    log_fmt(I.logger, I.log_ctx, "rtsp: PLAY ok, session=%s", I.session_id.c_str());
    I.keepalive = std::thread(&Impl::keepalive_main, impl_.get());
    return 0;

fail:
    log_fmt(I.logger, I.log_ctx, "rtsp: handshake failed: %s",
            obn::source::get_last_error());
    obn::tls::close_tls(&I.fd, &I.ssl);
    return -1;
}

const H264Track& Client::track() const noexcept { return impl_->track; }

int Client::read_nalu(Nalu* out)
{
    auto& I = *impl_;
    while (I.nalu_queue.empty()) {
        if (I.stop_flag.load(std::memory_order_acquire) || !I.ssl) return -1;
        int rc = I.pull_one_message();
        if (rc != 0) return rc;
    }
    *out = std::move(I.nalu_queue.front());
    I.nalu_queue.pop_front();
    return 0;
}

void Client::stop()
{
    if (!impl_) return;
    auto& I = *impl_;
    if (I.stop_flag.exchange(true)) return;
    I.keepalive_cv.notify_all();
    if (obn::os::socket_valid(I.fd)) obn::os::shutdown_both(I.fd);
    if (I.keepalive.joinable()) I.keepalive.join();
    I.do_teardown_best_effort();
    std::lock_guard<std::mutex> lk(I.io_mu);
    obn::tls::close_tls(&I.fd, &I.ssl);
}

void Client::cancel()
{
    if (!impl_) return;
    auto& I = *impl_;
    if (obn::os::socket_valid(I.fd)) obn::os::shutdown_both(I.fd);
    I.keepalive_cv.notify_all();
}

} // namespace obn::rtsp
