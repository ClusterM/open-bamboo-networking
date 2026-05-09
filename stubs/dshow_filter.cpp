// DirectShow Source Filter for the bambu: URL scheme on Windows.
//
// On Linux/macOS Studio drives video via the Bambu_* C ABI exported
// from BambuSource.cpp. On Windows wxMediaCtrl2 instead asks COM for a
// filter registered against bambu: URLs (CLSID
// {233E64FB-2041-4A6C-AFAB-FF9BCF83E7AA}); the C ABI here is used only
// for the on-printer file browser.
//
// This translation unit owns the COM in-proc-server entry points
// (DllGetClassObject / DllCanUnloadNow / DllRegisterServer /
// DllUnregisterServer), a hand-rolled IClassFactory, an IBaseFilter +
// IFileSourceFilter implementation (BambuSourceFilter) plus a single
// output pin (BambuSourceOutPin) that pumps raw H.264 Annex-B samples
// from obn::rtsp::Passthrough downstream to whatever decoder filter
// the graph builder picks (typically Microsoft H.264 Decoder MFT
// fronted by the DMO Wrapper Filter).
//
// We deliberately avoid Microsoft's strmbase/CSource baseclasses --
// they are not part of any vcpkg port we use, and the surface we need
// (one push source pin) is small enough that hand-rolled IUnknown +
// IPin + IBaseFilter QI tables stay readable. The threading model is
// "Both" (apartment + free); the pin owns its own worker thread and
// never reentrantly calls back into the filter graph thread.
//
// Phase B status: H.264 (RTSPS, P1S/X1) is the priority path the user
// asked for first. MJPEG (TLS:6000, A1/P1P) is wired on the same pin
// with a different media type and a separate worker; that path is
// guarded by the URL scheme so a user without an MJPEG printer never
// sees code from the H.264 path race against it.

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif

#include <windows.h>
#include <objbase.h>
#include <strmif.h>
#include <uuids.h>
#include <dvdmedia.h>      // VIDEOINFOHEADER2
#include <amvideo.h>
#include <combaseapi.h>
#include <shlwapi.h>
#include <vfwmsgs.h>       // VFW_E_*
#include <olectl.h>        // SELFREG_E_CLASS
#include <cwchar>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "rtsp_passthrough.hpp"
#include "source_log.hpp"
#include "tls_socket.hpp"
#include "obn/os_compat.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace {

// ----------------------------------------------------------------------------
// CLSID and constants
// ----------------------------------------------------------------------------

// {233E64FB-2041-4A6C-AFAB-FF9BCF83E7AA} -- Studio's wxMediaCtrl2.cpp
// hard-codes this for the bambu: URL scheme. Changing it would mean
// patching Studio.
const GUID CLSID_BambuSource = {
    0x233E64FB, 0x2041, 0x4A6C,
    {0xAF, 0xAB, 0xFF, 0x9B, 0xCF, 0x83, 0xE7, 0xAA}
};

// MEDIASUBTYPE_H264. dvdmedia.h has it for some SDK revisions but not
// all; define our own copy keyed on the FOURCC layout used by the
// Microsoft H.264 decoder MFT.
const GUID kMediaSubtypeH264 = {
    0x34363248, 0x0000, 0x0010,
    {0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71}
};

// IID for IFileSourceFilter -- declared in strmif.h but the constant
// itself comes from strmiids.lib at link time. Reference it through
// the IID_PPV_ARGS-style helper below.
extern "C" const IID IID_IFileSourceFilter;

// Filter friendly name surfaced in registry / GraphEdit.
constexpr wchar_t kFilterName[] = L"Bambu Source Filter";

// Registry vendor / scheme metadata. HKCU is enough for both the COM
// in-proc registration and the URL handler entry; both require no
// admin rights and Studio's wxMediaCtrl2 reads from HKCU + HKCR.
constexpr wchar_t kBambuScheme[] = L"bambu";

// Logger context for filter-internal diagnostics. We emit through the
// same file mirror used by the C ABI (obn-bambusource.log) so a single
// file shows the whole picture for Windows users.
using obn::source::log_at;
using obn::source::log_fmt;
using obn::source::LL_DEBUG;
using obn::source::LL_INFO;
using obn::source::LL_WARN;
using obn::source::LL_ERROR;
using obn::source::set_last_error;

// dshow-side "logger callback" sink: nullptr for now. We keep the
// argument shape so log_at() / log_fmt() macros take the same forms
// as in BambuSource.cpp.
constexpr obn::source::Logger kNoLogger = nullptr;

// Module handle, captured in DllMain. Used by DllRegisterServer to
// write the absolute path to InprocServer32.
HMODULE g_module = nullptr;

// Lock count for DllCanUnloadNow. Bumped by every live filter / class
// factory; OLE32 polls this to decide whether to call FreeLibrary.
std::atomic<long> g_lock_count{0};

void module_lock()   { g_lock_count.fetch_add(1, std::memory_order_acq_rel); }
void module_unlock() { g_lock_count.fetch_sub(1, std::memory_order_acq_rel); }

// ----------------------------------------------------------------------------
// Diagnostics helpers
// ----------------------------------------------------------------------------
//
// Translating GUIDs to recognizable names makes the trace usable when
// Orca crashes mid-handshake: the IID told to QueryInterface is often
// the only signal we have about which interface negotiation was in
// progress. We keep a small table of the IIDs DShow source filters
// actually see; everything else falls back to the brace-form GUID.

const char* iid_short_name(REFIID iid)
{
    struct Entry { const GUID* g; const char* n; };
    static const Entry kTable[] = {
        {&IID_IUnknown,           "IUnknown"},
        {&IID_IClassFactory,      "IClassFactory"},
        {&IID_IPersist,           "IPersist"},
        {&IID_IMediaFilter,       "IMediaFilter"},
        {&IID_IBaseFilter,        "IBaseFilter"},
        {&IID_IFileSourceFilter,  "IFileSourceFilter"},
        {&IID_IPin,               "IPin"},
        {&IID_IMemInputPin,       "IMemInputPin"},
        {&IID_IMemAllocator,      "IMemAllocator"},
        {&IID_IEnumPins,          "IEnumPins"},
        {&IID_IEnumMediaTypes,    "IEnumMediaTypes"},
        {&IID_IQualityControl,    "IQualityControl"},
    };
    for (const auto& e : kTable) {
        if (e.g && IsEqualIID(iid, *e.g)) return e.n;
    }
    return nullptr;
}

// Small printable buffer for an IID. Returns a pointer into a static
// thread_local cache; safe to use as a single argument to log_at().
const char* iid_to_string(REFIID iid)
{
    if (const char* s = iid_short_name(iid)) return s;
    static thread_local char buf[64];
    std::snprintf(buf, sizeof(buf),
                  "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                  static_cast<unsigned long>(iid.Data1),
                  iid.Data2, iid.Data3,
                  iid.Data4[0], iid.Data4[1],
                  iid.Data4[2], iid.Data4[3], iid.Data4[4],
                  iid.Data4[5], iid.Data4[6], iid.Data4[7]);
    return buf;
}

// Translate a major/sub media-type GUID pair to a printable label
// for Connect/QueryAccept logs. Falls back to the iid_to_string form.
const char* mediatype_short_name(REFGUID g)
{
    if (IsEqualGUID(g, MEDIATYPE_Video))         return "MEDIATYPE_Video";
    if (IsEqualGUID(g, MEDIATYPE_Audio))         return "MEDIATYPE_Audio";
    if (IsEqualGUID(g, MEDIATYPE_Stream))        return "MEDIATYPE_Stream";
    if (IsEqualGUID(g, MEDIASUBTYPE_MJPG))       return "MEDIASUBTYPE_MJPG";
    if (IsEqualGUID(g, kMediaSubtypeH264))       return "MEDIASUBTYPE_H264";
    if (IsEqualGUID(g, FORMAT_VideoInfo))        return "FORMAT_VideoInfo";
    if (IsEqualGUID(g, FORMAT_VideoInfo2))       return "FORMAT_VideoInfo2";
    if (IsEqualGUID(g, GUID_NULL))               return "GUID_NULL";
    return nullptr;
}

const char* mediatype_to_string(REFGUID g)
{
    if (const char* s = mediatype_short_name(g)) return s;
    return iid_to_string(g);
}

// ----------------------------------------------------------------------------
// COM helpers
// ----------------------------------------------------------------------------

// Minimal QI table: one IID per row, paired with a function that
// returns a typed pointer. The callbacks return a base IUnknown* so
// the row table can stay homogeneous; we cast back at the call site.
// Standard COM aggregation is NOT supported -- we never set up an
// outer unknown.
struct QiEntry {
    REFIID iid;
    IUnknown* (*adapt)(void* self);
};

template <typename T>
IUnknown* qi_self(void* self) { return static_cast<T*>(self); }

// AM_MEDIA_TYPE management. dshow callers expect deep-copy semantics
// (pbFormat is CoTaskMemAlloc'd, fixed via FreeMediaType) so we do
// not memcpy AM_MEDIA_TYPE structs blindly.
void am_free_media_type(AM_MEDIA_TYPE* mt)
{
    if (!mt) return;
    if (mt->cbFormat != 0 && mt->pbFormat) {
        ::CoTaskMemFree(mt->pbFormat);
        mt->cbFormat = 0;
        mt->pbFormat = nullptr;
    }
    if (mt->pUnk) {
        mt->pUnk->Release();
        mt->pUnk = nullptr;
    }
}

void am_delete_media_type(AM_MEDIA_TYPE* mt)
{
    if (!mt) return;
    am_free_media_type(mt);
    ::CoTaskMemFree(mt);
}

bool am_copy_media_type(AM_MEDIA_TYPE* dst, const AM_MEDIA_TYPE* src)
{
    if (!dst || !src) return false;
    *dst = *src;
    // Null out anything that holds an aliased ownership before any
    // step can fail; we want am_free_media_type(dst) on a partially
    // initialised dst to be a no-op rather than double-Release the
    // src->pUnk we only just shallow-copied.
    dst->pbFormat = nullptr;
    dst->cbFormat = 0;
    dst->pUnk     = nullptr;
    if (src->cbFormat != 0 && src->pbFormat) {
        dst->pbFormat = static_cast<BYTE*>(::CoTaskMemAlloc(src->cbFormat));
        if (!dst->pbFormat) return false;
        std::memcpy(dst->pbFormat, src->pbFormat, src->cbFormat);
        dst->cbFormat = src->cbFormat;
    }
    if (src->pUnk) {
        src->pUnk->AddRef();
        dst->pUnk = src->pUnk;
    }
    return true;
}

// ----------------------------------------------------------------------------
// URL parser (subset; mirrors BambuSource.cpp's parse_url for the
// shapes that Studio's MediaPlayCtrl::Play actually emits)
// ----------------------------------------------------------------------------

enum class UrlScheme {
    Local, // MJPG over TCP/TLS on <port> (default 6000), A1/P1/P1P
    Rtsps, // RTSPS on <port> (default 322), X1/P1S/P2S/H-series/X2D
    Rtsp,  // plain RTSP, dev/test only
};

struct ParsedUrl {
    UrlScheme   scheme = UrlScheme::Local;
    std::string host;
    int         port = 6000;
    std::string user = "bblp";
    std::string passwd;
    std::string path = "/streaming/live/1";
};

std::string url_decode(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
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

bool parse_bambu_url(const std::string& url, ParsedUrl* out)
{
    // Orca/Studio's MediaPlayCtrl produces URLs like
    //   "bambu:///rtsps___bblp:pwd@host/streaming/live/1?proto=rtsps&..."
    //   "bambu:///rtsp___bblp:pwd@host/streaming/live/1?proto=rtsp&..."
    //   "bambu:///local/HOST.?port=6000&user=bblp&passwd=..."
    // wxURI normalises authority-less URIs and may collapse "///" into
    // "//" before handing the URL to IFileSourceFilter::Load (treating the
    // "rtsps___bblp:pwd" prefix as userinfo). Accept both forms.
    static const char kBambu[] = "bambu:";
    if (url.compare(0, sizeof(kBambu) - 1, kBambu) != 0)
        return false;
    std::size_t p = sizeof(kBambu) - 1;
    while (p < url.size() && url[p] == '/') ++p;
    std::string body = url.substr(p);

    static const std::string p_local = "local/";
    static const std::string p_rtsps = "rtsps___";
    static const std::string p_rtsp  = "rtsp___";

    std::string rest;
    if (body.compare(0, p_local.size(), p_local) == 0) {
        out->scheme = UrlScheme::Local;
        out->port   = 6000;
        rest = body.substr(p_local.size());
    } else if (body.compare(0, p_rtsps.size(), p_rtsps) == 0) {
        out->scheme = UrlScheme::Rtsps;
        out->port   = 322;
        rest = body.substr(p_rtsps.size());
    } else if (body.compare(0, p_rtsp.size(), p_rtsp) == 0) {
        out->scheme = UrlScheme::Rtsp;
        out->port   = 554;
        rest = body.substr(p_rtsp.size());
    } else {
        return false;
    }

    auto q_pos = rest.find('?');
    std::string head  = (q_pos == std::string::npos) ? rest : rest.substr(0, q_pos);
    std::string query = (q_pos == std::string::npos) ? ""   : rest.substr(q_pos + 1);

    if (out->scheme == UrlScheme::Rtsps || out->scheme == UrlScheme::Rtsp) {
        // user:passwd@host[:port]/path
        auto at = head.find('@');
        if (at != std::string::npos) {
            std::string ui = head.substr(0, at);
            head = head.substr(at + 1);
            auto col = ui.find(':');
            if (col != std::string::npos) {
                out->user   = url_decode(ui.substr(0, col));
                out->passwd = url_decode(ui.substr(col + 1));
            } else {
                out->user = url_decode(ui);
            }
        }
        auto sl = head.find('/');
        if (sl != std::string::npos) {
            out->path = head.substr(sl);
            head      = head.substr(0, sl);
        }
    } else {
        while (!head.empty() && (head.back() == '/' || head.back() == '.'))
            head.pop_back();
    }

    auto col = head.find(':');
    if (col != std::string::npos) {
        out->host = head.substr(0, col);
        try {
            out->port = std::stoi(head.substr(col + 1));
        } catch (...) {
            return false;
        }
    } else {
        out->host = head;
    }

    // Local-scheme URLs hide credentials in the query string.
    std::size_t i = 0;
    while (i < query.size()) {
        std::size_t e = query.find('&', i);
        std::string tok = query.substr(i, (e == std::string::npos) ? query.size() - i : e - i);
        std::size_t eq = tok.find('=');
        if (eq != std::string::npos) {
            std::string k = tok.substr(0, eq);
            std::string v = url_decode(tok.substr(eq + 1));
            if      (k == "user")   out->user   = v;
            else if (k == "passwd") out->passwd = v;
            else if (k == "port") {
                try { out->port = std::stoi(v); } catch (...) {}
            }
        }
        if (e == std::string::npos) break;
        i = e + 1;
    }

    return !out->host.empty();
}

// UTF-16 -> UTF-8 conversion for IFileSourceFilter::Load(LPCOLESTR).
std::string wide_to_utf8(const wchar_t* w)
{
    if (!w || !*w) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<std::size_t>(n - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), n, nullptr, nullptr);
    return out;
}

// ----------------------------------------------------------------------------
// Forward declarations -- pin and filter cross-reference each other
// ----------------------------------------------------------------------------

class BambuSourceFilter;

// Build a single H.264 Annex-B media type. caller owns *mt (deep copy
// semantics; free with am_free_media_type).
bool make_h264_media_type(AM_MEDIA_TYPE* mt)
{
    std::memset(mt, 0, sizeof(*mt));
    mt->majortype  = MEDIATYPE_Video;
    mt->subtype    = kMediaSubtypeH264;
    mt->bFixedSizeSamples = FALSE;
    mt->bTemporalCompression = TRUE;
    mt->lSampleSize = 0;
    mt->formattype  = FORMAT_VideoInfo2;
    mt->cbFormat    = sizeof(VIDEOINFOHEADER2);
    mt->pbFormat    = static_cast<BYTE*>(::CoTaskMemAlloc(mt->cbFormat));
    if (!mt->pbFormat) { mt->cbFormat = 0; return false; }
    std::memset(mt->pbFormat, 0, mt->cbFormat);
    auto* vih = reinterpret_cast<VIDEOINFOHEADER2*>(mt->pbFormat);
    vih->dwBitRate                = 0;
    vih->dwBitErrorRate           = 0;
    // 33 ms / frame ~= 30 fps; the decoder ignores AvgTimePerFrame for
    // live streams (it derives PTS from sample timestamps), but graph
    // builders sanity-check that this is non-zero.
    vih->AvgTimePerFrame          = 333333; // 100 ns units
    vih->dwInterlaceFlags         = 0;
    vih->dwCopyProtectFlags       = 0;
    vih->dwPictAspectRatioX       = 16;
    vih->dwPictAspectRatioY       = 9;
    vih->dwReserved1              = 0;
    vih->dwReserved2              = 0;
    vih->bmiHeader.biSize         = sizeof(BITMAPINFOHEADER);
    vih->bmiHeader.biWidth        = 1280;
    vih->bmiHeader.biHeight       = 720;
    vih->bmiHeader.biPlanes       = 1;
    vih->bmiHeader.biBitCount     = 24;
    vih->bmiHeader.biCompression  = MAKEFOURCC('H','2','6','4');
    vih->bmiHeader.biSizeImage    = 0;
    return true;
}

// Build a single MJPEG media type for A1 / P1 / P1P printers
// (TLS:6000 framed JPEG). Studio's downstream is the MJPEG decoder
// MFT or the standard MJPEG video decoder filter; both accept
// MEDIASUBTYPE_MJPG with a VIDEOINFOHEADER carrying a 'MJPG' fourcc.
bool make_mjpeg_media_type(AM_MEDIA_TYPE* mt)
{
    std::memset(mt, 0, sizeof(*mt));
    mt->majortype  = MEDIATYPE_Video;
    mt->subtype    = MEDIASUBTYPE_MJPG;
    mt->bFixedSizeSamples = FALSE;
    mt->bTemporalCompression = FALSE; // each JPEG is self-contained
    mt->lSampleSize = 0;
    mt->formattype  = FORMAT_VideoInfo;
    mt->cbFormat    = sizeof(VIDEOINFOHEADER);
    mt->pbFormat    = static_cast<BYTE*>(::CoTaskMemAlloc(mt->cbFormat));
    if (!mt->pbFormat) { mt->cbFormat = 0; return false; }
    std::memset(mt->pbFormat, 0, mt->cbFormat);
    auto* vih = reinterpret_cast<VIDEOINFOHEADER*>(mt->pbFormat);
    vih->AvgTimePerFrame          = 666666; // ~15 fps; A1/P1 cap there
    vih->bmiHeader.biSize         = sizeof(BITMAPINFOHEADER);
    vih->bmiHeader.biWidth        = 1280;
    vih->bmiHeader.biHeight       = 720;
    vih->bmiHeader.biPlanes       = 1;
    vih->bmiHeader.biBitCount     = 24;
    vih->bmiHeader.biCompression  = MAKEFOURCC('M','J','P','G');
    vih->bmiHeader.biSizeImage    = 0;
    return true;
}

bool make_media_type_for_scheme(AM_MEDIA_TYPE* mt, UrlScheme scheme)
{
    if (scheme == UrlScheme::Local) return make_mjpeg_media_type(mt);
    return make_h264_media_type(mt);
}

GUID subtype_for_scheme(UrlScheme scheme)
{
    return (scheme == UrlScheme::Local) ? MEDIASUBTYPE_MJPG : kMediaSubtypeH264;
}

// ----------------------------------------------------------------------------
// IEnumMediaTypes (single-type enumerator for the output pin)
// ----------------------------------------------------------------------------

class MediaTypeEnumerator : public IEnumMediaTypes {
public:
    MediaTypeEnumerator(UrlScheme scheme) : scheme_(scheme), ref_(1)
    {
        module_lock();
    }
    ~MediaTypeEnumerator() { module_unlock(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IEnumMediaTypes) {
            *ppv = static_cast<IEnumMediaTypes*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return static_cast<ULONG>(ref_.fetch_add(1, std::memory_order_acq_rel) + 1);
    }
    ULONG STDMETHODCALLTYPE Release() override
    {
        long n = ref_.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (n == 0) delete this;
        return static_cast<ULONG>(n);
    }
    HRESULT STDMETHODCALLTYPE Next(ULONG cMediaTypes, AM_MEDIA_TYPE** ppMediaTypes,
                                   ULONG* pcFetched) override
    {
        if (!ppMediaTypes) return E_POINTER;
        ULONG fetched = 0;
        for (ULONG i = 0; i < cMediaTypes; ++i) {
            if (cursor_ >= 1) break;
            auto* mt = static_cast<AM_MEDIA_TYPE*>(::CoTaskMemAlloc(sizeof(AM_MEDIA_TYPE)));
            if (!mt) return E_OUTOFMEMORY;
            if (!make_media_type_for_scheme(mt, scheme_)) {
                ::CoTaskMemFree(mt);
                return E_OUTOFMEMORY;
            }
            ppMediaTypes[i] = mt;
            ++cursor_;
            ++fetched;
        }
        if (pcFetched) *pcFetched = fetched;
        return (fetched == cMediaTypes) ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Skip(ULONG cMediaTypes) override
    {
        cursor_ += cMediaTypes;
        return (cursor_ <= 1) ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Reset() override { cursor_ = 0; return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumMediaTypes** ppEnum) override
    {
        if (!ppEnum) return E_POINTER;
        auto* clone = new MediaTypeEnumerator(scheme_);
        clone->cursor_ = cursor_;
        *ppEnum = clone;
        return S_OK;
    }

private:
    UrlScheme         scheme_;
    std::atomic<long> ref_;
    ULONG             cursor_ = 0;
};

// ----------------------------------------------------------------------------
// IEnumPins (single-pin enumerator for the filter)
// ----------------------------------------------------------------------------

class PinEnumerator : public IEnumPins {
public:
    PinEnumerator(IPin* pin) : pin_(pin), ref_(1)
    {
        if (pin_) pin_->AddRef();
        module_lock();
    }
    ~PinEnumerator()
    {
        if (pin_) pin_->Release();
        module_unlock();
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IEnumPins) {
            *ppv = static_cast<IEnumPins*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return static_cast<ULONG>(ref_.fetch_add(1, std::memory_order_acq_rel) + 1);
    }
    ULONG STDMETHODCALLTYPE Release() override
    {
        long n = ref_.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (n == 0) delete this;
        return static_cast<ULONG>(n);
    }
    HRESULT STDMETHODCALLTYPE Next(ULONG cPins, IPin** ppPins, ULONG* pcFetched) override
    {
        if (!ppPins) return E_POINTER;
        ULONG fetched = 0;
        for (ULONG i = 0; i < cPins; ++i) {
            if (cursor_ >= 1) break;
            ppPins[i] = pin_;
            if (pin_) pin_->AddRef();
            ++cursor_;
            ++fetched;
        }
        if (pcFetched) *pcFetched = fetched;
        return (fetched == cPins) ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Skip(ULONG cPins) override
    {
        cursor_ += cPins;
        return (cursor_ <= 1) ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Reset() override { cursor_ = 0; return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumPins** ppEnum) override
    {
        if (!ppEnum) return E_POINTER;
        auto* clone = new PinEnumerator(pin_);
        clone->cursor_ = cursor_;
        *ppEnum = clone;
        return S_OK;
    }

private:
    IPin*             pin_;
    std::atomic<long> ref_;
    ULONG             cursor_ = 0;
};

// ----------------------------------------------------------------------------
// BambuSourceOutPin
// ----------------------------------------------------------------------------
//
// Single H.264 output pin. Holds the worker thread that drives
// obn::rtsp::Passthrough and pushes IMediaSamples downstream via
// IMemInputPin::Receive. Connection / disconnection serialise on
// state_mu_; the worker only runs while connected and the filter is in
// State_Running.

class BambuSourceOutPin : public IPin, public IQualityControl {
public:
    BambuSourceOutPin(BambuSourceFilter* parent, const wchar_t* name);
    ~BambuSourceOutPin();

    // ---- IUnknown ----
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override;
    ULONG   STDMETHODCALLTYPE AddRef() override;
    ULONG   STDMETHODCALLTYPE Release() override;

    // ---- IPin ----
    HRESULT STDMETHODCALLTYPE Connect(IPin* pReceivePin, const AM_MEDIA_TYPE* pmt) override;
    HRESULT STDMETHODCALLTYPE ReceiveConnection(IPin*, const AM_MEDIA_TYPE*) override
    {
        return E_UNEXPECTED; // we are an output pin
    }
    HRESULT STDMETHODCALLTYPE Disconnect() override;
    HRESULT STDMETHODCALLTYPE ConnectedTo(IPin** pPin) override;
    HRESULT STDMETHODCALLTYPE ConnectionMediaType(AM_MEDIA_TYPE* pmt) override;
    HRESULT STDMETHODCALLTYPE QueryPinInfo(PIN_INFO* pInfo) override;
    HRESULT STDMETHODCALLTYPE QueryDirection(PIN_DIRECTION* pDir) override
    {
        if (!pDir) return E_POINTER;
        *pDir = PINDIR_OUTPUT;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE QueryId(LPWSTR* Id) override;
    HRESULT STDMETHODCALLTYPE QueryAccept(const AM_MEDIA_TYPE* pmt) override;
    HRESULT STDMETHODCALLTYPE EnumMediaTypes(IEnumMediaTypes** ppEnum) override;
    HRESULT STDMETHODCALLTYPE QueryInternalConnections(IPin**, ULONG*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE EndOfStream() override        { return S_OK; }
    HRESULT STDMETHODCALLTYPE BeginFlush() override         { return S_OK; }
    HRESULT STDMETHODCALLTYPE EndFlush() override           { return S_OK; }
    HRESULT STDMETHODCALLTYPE NewSegment(REFERENCE_TIME, REFERENCE_TIME, double) override
    {
        return S_OK;
    }

    // ---- IQualityControl ----
    HRESULT STDMETHODCALLTYPE Notify(IBaseFilter*, Quality) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetSink(IQualityControl*) override     { return S_OK; }

    // ---- internal helpers driven by BambuSourceFilter ----
    void start_streaming();
    void stop_streaming();

private:
    void worker_main();

    BambuSourceFilter* const  parent_;
    std::wstring              name_;
    std::atomic<long>         ref_;

    std::mutex                state_mu_;
    IPin*                     downstream_       = nullptr; // weak via AddRef'd pointer
    IMemInputPin*             downstream_input_ = nullptr;
    IMemAllocator*            allocator_        = nullptr;
    AM_MEDIA_TYPE             current_mt_{};
    bool                      have_mt_          = false;

    std::thread               worker_;
    std::atomic<bool>         worker_stop_{false};
    std::atomic<bool>         worker_running_{false};
};

// ----------------------------------------------------------------------------
// BambuSourceFilter
// ----------------------------------------------------------------------------

class BambuSourceFilter : public IBaseFilter, public IFileSourceFilter {
public:
    BambuSourceFilter();
    ~BambuSourceFilter();

    // ---- IUnknown ----
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override;
    ULONG   STDMETHODCALLTYPE AddRef() override;
    ULONG   STDMETHODCALLTYPE Release() override;

    // ---- IPersist ----
    HRESULT STDMETHODCALLTYPE GetClassID(CLSID* pClsID) override
    {
        if (!pClsID) return E_POINTER;
        *pClsID = CLSID_BambuSource;
        return S_OK;
    }

    // ---- IMediaFilter ----
    HRESULT STDMETHODCALLTYPE Stop() override;
    HRESULT STDMETHODCALLTYPE Pause() override;
    HRESULT STDMETHODCALLTYPE Run(REFERENCE_TIME tStart) override;
    HRESULT STDMETHODCALLTYPE GetState(DWORD dwMs, FILTER_STATE* pState) override;
    HRESULT STDMETHODCALLTYPE SetSyncSource(IReferenceClock* pClock) override;
    HRESULT STDMETHODCALLTYPE GetSyncSource(IReferenceClock** ppClock) override;

    // ---- IBaseFilter ----
    HRESULT STDMETHODCALLTYPE EnumPins(IEnumPins** ppEnum) override;
    HRESULT STDMETHODCALLTYPE FindPin(LPCWSTR Id, IPin** ppPin) override;
    HRESULT STDMETHODCALLTYPE QueryFilterInfo(FILTER_INFO* pInfo) override;
    HRESULT STDMETHODCALLTYPE JoinFilterGraph(IFilterGraph* pGraph, LPCWSTR pName) override;
    HRESULT STDMETHODCALLTYPE QueryVendorInfo(LPWSTR* pVendorInfo) override;

    // ---- IFileSourceFilter ----
    HRESULT STDMETHODCALLTYPE Load(LPCOLESTR lpwszFileName,
                                   const AM_MEDIA_TYPE* pmt) override;
    HRESULT STDMETHODCALLTYPE GetCurFile(LPOLESTR* ppszFileName,
                                         AM_MEDIA_TYPE* pmt) override;

    // ---- internal accessors used by the pin ----
    const ParsedUrl&    url() const noexcept     { return url_; }
    FILTER_STATE        state() const noexcept   { return state_.load(std::memory_order_acquire); }
    IReferenceClock*    clock() noexcept         { return clock_; }
    IFilterGraph*       graph() noexcept         { return graph_; }

private:
    std::atomic<long>    ref_;
    std::mutex           mu_;
    BambuSourceOutPin*   pin_;
    std::atomic<FILTER_STATE> state_{State_Stopped};
    IReferenceClock*     clock_  = nullptr;
    IFilterGraph*        graph_  = nullptr;     // weak: filter graph holds us
    std::wstring         graph_name_;
    std::wstring         url_w_;
    ParsedUrl            url_;
    bool                 url_loaded_ = false;
};

// ============================================================================
// BambuSourceOutPin implementation
// ============================================================================

BambuSourceOutPin::BambuSourceOutPin(BambuSourceFilter* parent, const wchar_t* name)
    : parent_(parent), name_(name ? name : L""), ref_(1)
{
    std::memset(&current_mt_, 0, sizeof(current_mt_));
    module_lock();
    log_at(LL_INFO, kNoLogger, nullptr,
        "dshow: Pin ctor this=%p parent=%p", this, parent);
}

BambuSourceOutPin::~BambuSourceOutPin()
{
    log_at(LL_INFO, kNoLogger, nullptr,
        "dshow: Pin dtor this=%p", this);
    stop_streaming();
    if (have_mt_) am_free_media_type(&current_mt_);
    if (allocator_)        allocator_->Release();
    if (downstream_input_) downstream_input_->Release();
    if (downstream_)       downstream_->Release();
    module_unlock();
}

HRESULT STDMETHODCALLTYPE BambuSourceOutPin::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown) {
        *ppv = static_cast<IPin*>(this);
    } else if (riid == IID_IPin) {
        *ppv = static_cast<IPin*>(this);
    } else if (riid == IID_IQualityControl) {
        *ppv = static_cast<IQualityControl*>(this);
    } else {
        log_at(LL_DEBUG, kNoLogger, nullptr,
            "dshow: Pin::QI(%s) -> E_NOINTERFACE",
            iid_to_string(riid));
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    AddRef();
    log_at(LL_DEBUG, kNoLogger, nullptr,
        "dshow: Pin::QI(%s) -> ok", iid_to_string(riid));
    return S_OK;
}

ULONG STDMETHODCALLTYPE BambuSourceOutPin::AddRef()
{
    return static_cast<ULONG>(ref_.fetch_add(1, std::memory_order_acq_rel) + 1);
}

ULONG STDMETHODCALLTYPE BambuSourceOutPin::Release()
{
    long n = ref_.fetch_sub(1, std::memory_order_acq_rel) - 1;
    if (n == 0) delete this;
    return static_cast<ULONG>(n);
}

HRESULT STDMETHODCALLTYPE BambuSourceOutPin::Connect(IPin* pReceivePin,
                                                     const AM_MEDIA_TYPE* pmt)
{
    log_at(LL_INFO, kNoLogger, nullptr,
        "dshow: Pin::Connect downstream=%p pmt=%p", pReceivePin, pmt);
    if (pmt) {
        log_at(LL_INFO, kNoLogger, nullptr,
            "dshow:   requested major=%s sub=%s fmt=%s cbFormat=%lu",
            mediatype_to_string(pmt->majortype),
            mediatype_to_string(pmt->subtype),
            mediatype_to_string(pmt->formattype),
            static_cast<unsigned long>(pmt->cbFormat));
    }
    if (!pReceivePin) return E_POINTER;

    std::lock_guard<std::mutex> lk(state_mu_);
    if (downstream_) {
        log_at(LL_WARN, kNoLogger, nullptr,
            "dshow: Pin::Connect -> VFW_E_ALREADY_CONNECTED");
        return VFW_E_ALREADY_CONNECTED;
    }

    AM_MEDIA_TYPE candidate{};
    UrlScheme scheme = parent_->url().scheme;
    if (pmt && pmt->majortype != GUID_NULL) {
        if (!am_copy_media_type(&candidate, pmt)) return E_OUTOFMEMORY;
    } else {
        if (!make_media_type_for_scheme(&candidate, scheme)) return E_OUTOFMEMORY;
    }

    HRESULT hr = pReceivePin->ReceiveConnection(static_cast<IPin*>(this), &candidate);
    if (FAILED(hr)) {
        am_free_media_type(&candidate);
        log_at(LL_WARN, kNoLogger, nullptr,
               "dshow: ReceiveConnection rejected our preferred type, hr=0x%08lx",
               static_cast<unsigned long>(hr));
        return hr;
    }
    log_at(LL_INFO, kNoLogger, nullptr,
        "dshow: ReceiveConnection accepted");

    IMemInputPin* mip = nullptr;
    hr = pReceivePin->QueryInterface(IID_IMemInputPin, reinterpret_cast<void**>(&mip));
    if (FAILED(hr) || !mip) {
        // Roll back the half-completed connection; downstream now
        // thinks we are connected and will route Receive() calls to
        // a pin we never finished wiring up.
        pReceivePin->Disconnect();
        am_free_media_type(&candidate);
        log_at(LL_WARN, kNoLogger, nullptr,
               "dshow: downstream pin lacks IMemInputPin (hr=0x%08lx); rolled back",
               static_cast<unsigned long>(hr));
        return hr;
    }

    // Allocator handshake: prefer downstream's, fall back to a default.
    IMemAllocator* alloc = nullptr;
    hr = mip->GetAllocator(&alloc);
    if (FAILED(hr) || !alloc) {
        hr = ::CoCreateInstance(CLSID_MemoryAllocator, nullptr, CLSCTX_INPROC_SERVER,
                                IID_IMemAllocator, reinterpret_cast<void**>(&alloc));
        if (FAILED(hr) || !alloc) {
            pReceivePin->Disconnect();
            am_free_media_type(&candidate);
            mip->Release();
            log_at(LL_ERROR, kNoLogger, nullptr,
                   "dshow: no allocator available (hr=0x%08lx)",
                   static_cast<unsigned long>(hr));
            return hr;
        }
        log_at(LL_INFO, kNoLogger, nullptr,
            "dshow: using default IMemAllocator (CLSID_MemoryAllocator)");
    } else {
        log_at(LL_INFO, kNoLogger, nullptr,
            "dshow: using downstream-provided IMemAllocator");
    }

    ALLOCATOR_PROPERTIES req{};
    req.cBuffers = 8;
    req.cbBuffer = 256 * 1024; // big enough for one H.264 access unit
    req.cbAlign  = 1;
    req.cbPrefix = 0;
    ALLOCATOR_PROPERTIES actual{};
    hr = alloc->SetProperties(&req, &actual);
    if (FAILED(hr)) {
        log_at(LL_WARN, kNoLogger, nullptr,
               "dshow: alloc->SetProperties failed hr=0x%08lx",
               static_cast<unsigned long>(hr));
    }
    hr = mip->NotifyAllocator(alloc, FALSE);
    if (FAILED(hr)) {
        log_at(LL_WARN, kNoLogger, nullptr,
               "dshow: NotifyAllocator failed hr=0x%08lx",
               static_cast<unsigned long>(hr));
    }
    // Do NOT Commit() here — downstream is free to call SetProperties
    // any time before the graph transitions to State_Paused/Running.
    // We Commit() in start_streaming() right before the worker calls
    // GetBuffer, then Decommit() in stop_streaming() to wake any
    // blocked GetBuffer.

    pReceivePin->AddRef();
    downstream_       = pReceivePin;
    downstream_input_ = mip; // already AddRef'd by QI
    allocator_        = alloc;
    if (have_mt_) am_free_media_type(&current_mt_);
    current_mt_ = candidate;
    have_mt_    = true;

    log_at(LL_INFO, kNoLogger, nullptr,
           "dshow: Pin::Connect ok (alloc cBuffers=%ld cbBuffer=%ld align=%ld prefix=%ld)",
           static_cast<long>(actual.cBuffers),
           static_cast<long>(actual.cbBuffer),
           static_cast<long>(actual.cbAlign),
           static_cast<long>(actual.cbPrefix));
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceOutPin::Disconnect()
{
    log_at(LL_INFO, kNoLogger, nullptr,
        "dshow: Pin::Disconnect this=%p downstream=%p",
        this, downstream_);
    stop_streaming();
    std::lock_guard<std::mutex> lk(state_mu_);
    if (allocator_) {
        // Decommit before Release so any pending GetBuffer in the
        // worker (if it raced past stop_streaming) returns immediately
        // instead of waiting forever for a freed allocator.
        allocator_->Decommit();
    }
    if (have_mt_) {
        am_free_media_type(&current_mt_);
        have_mt_ = false;
    }
    if (allocator_)        { allocator_->Release();        allocator_        = nullptr; }
    if (downstream_input_) { downstream_input_->Release(); downstream_input_ = nullptr; }
    if (downstream_)       { downstream_->Release();       downstream_       = nullptr; }
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceOutPin::ConnectedTo(IPin** pPin)
{
    if (!pPin) return E_POINTER;
    std::lock_guard<std::mutex> lk(state_mu_);
    if (!downstream_) {
        *pPin = nullptr;
        log_at(LL_DEBUG, kNoLogger, nullptr,
            "dshow: Pin::ConnectedTo -> VFW_E_NOT_CONNECTED");
        return VFW_E_NOT_CONNECTED;
    }
    *pPin = downstream_;
    downstream_->AddRef();
    log_at(LL_DEBUG, kNoLogger, nullptr,
        "dshow: Pin::ConnectedTo -> %p", downstream_);
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceOutPin::ConnectionMediaType(AM_MEDIA_TYPE* pmt)
{
    if (!pmt) return E_POINTER;
    std::lock_guard<std::mutex> lk(state_mu_);
    if (!have_mt_) {
        std::memset(pmt, 0, sizeof(*pmt));
        log_at(LL_DEBUG, kNoLogger, nullptr,
            "dshow: Pin::ConnectionMediaType -> VFW_E_NOT_CONNECTED");
        return VFW_E_NOT_CONNECTED;
    }
    return am_copy_media_type(pmt, &current_mt_) ? S_OK : E_OUTOFMEMORY;
}

HRESULT STDMETHODCALLTYPE BambuSourceOutPin::QueryPinInfo(PIN_INFO* pInfo)
{
    log_at(LL_DEBUG, kNoLogger, nullptr,
        "dshow: Pin::QueryPinInfo this=%p", this);
    if (!pInfo) return E_POINTER;
    std::memset(pInfo, 0, sizeof(*pInfo));
    pInfo->dir    = PINDIR_OUTPUT;
    pInfo->pFilter = reinterpret_cast<IBaseFilter*>(parent_);
    if (pInfo->pFilter) pInfo->pFilter->AddRef();
    auto n = name_.copy(pInfo->achName, MAX_PIN_NAME - 1);
    pInfo->achName[n] = L'\0';
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceOutPin::QueryId(LPWSTR* Id)
{
    log_at(LL_DEBUG, kNoLogger, nullptr,
        "dshow: Pin::QueryId this=%p", this);
    if (!Id) return E_POINTER;
    std::size_t bytes = (name_.size() + 1) * sizeof(wchar_t);
    auto* buf = static_cast<wchar_t*>(::CoTaskMemAlloc(bytes));
    if (!buf) return E_OUTOFMEMORY;
    std::memcpy(buf, name_.c_str(), bytes);
    *Id = buf;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceOutPin::QueryAccept(const AM_MEDIA_TYPE* pmt)
{
    if (!pmt) return E_POINTER;
    bool major_ok = IsEqualGUID(pmt->majortype, MEDIATYPE_Video);
    bool sub_ok   = IsEqualGUID(pmt->subtype, subtype_for_scheme(parent_->url().scheme));
    log_at(LL_DEBUG, kNoLogger, nullptr,
        "dshow: Pin::QueryAccept major=%s sub=%s -> %s",
        mediatype_to_string(pmt->majortype),
        mediatype_to_string(pmt->subtype),
        (major_ok && sub_ok) ? "S_OK" : "S_FALSE");
    return (major_ok && sub_ok) ? S_OK : S_FALSE;
}

HRESULT STDMETHODCALLTYPE BambuSourceOutPin::EnumMediaTypes(IEnumMediaTypes** ppEnum)
{
    log_at(LL_DEBUG, kNoLogger, nullptr,
        "dshow: Pin::EnumMediaTypes scheme=%d",
        static_cast<int>(parent_->url().scheme));
    if (!ppEnum) return E_POINTER;
    *ppEnum = new MediaTypeEnumerator(parent_->url().scheme);
    return S_OK;
}

void BambuSourceOutPin::start_streaming()
{
    if (worker_running_.exchange(true, std::memory_order_acq_rel)) return;
    worker_stop_.store(false, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk(state_mu_);
        if (allocator_) {
            HRESULT hr = allocator_->Commit();
            log_at(LL_INFO, kNoLogger, nullptr,
                "dshow: Pin::start_streaming alloc->Commit hr=0x%08lx",
                static_cast<unsigned long>(hr));
        } else {
            log_at(LL_WARN, kNoLogger, nullptr,
                "dshow: Pin::start_streaming with no allocator yet "
                "(downstream not connected?)");
        }
    }
    log_at(LL_INFO, kNoLogger, nullptr,
        "dshow: Pin::start_streaming this=%p (spawning worker)", this);
    worker_ = std::thread(&BambuSourceOutPin::worker_main, this);
}

void BambuSourceOutPin::stop_streaming()
{
    if (!worker_running_.load(std::memory_order_acquire)) {
        if (worker_.joinable()) worker_.join();
        return;
    }
    log_at(LL_INFO, kNoLogger, nullptr,
        "dshow: Pin::stop_streaming this=%p (waiting for worker join)", this);
    worker_stop_.store(true, std::memory_order_release);
    // Wake the worker if it is blocked inside an allocator GetBuffer
    // or downstream Receive() call. Decommit() is the standard way to
    // unblock a source filter's worker thread on Stop().
    {
        std::lock_guard<std::mutex> lk(state_mu_);
        if (allocator_) allocator_->Decommit();
    }
    if (worker_.joinable()) worker_.join();
    worker_running_.store(false, std::memory_order_release);
    log_at(LL_INFO, kNoLogger, nullptr,
        "dshow: Pin::stop_streaming this=%p done", this);
}

// ============================================================================
// BambuSourceFilter implementation
// ============================================================================

BambuSourceFilter::BambuSourceFilter() : ref_(1)
{
    pin_ = new BambuSourceOutPin(this, L"Output");
    module_lock();
    log_at(LL_INFO, kNoLogger, nullptr,
        "dshow: BambuSourceFilter ctor this=%p pin=%p", this, pin_);
}

BambuSourceFilter::~BambuSourceFilter()
{
    log_at(LL_INFO, kNoLogger, nullptr,
        "dshow: BambuSourceFilter dtor this=%p", this);
    if (pin_) {
        pin_->Disconnect();
        pin_->Release();
        pin_ = nullptr;
    }
    if (clock_) {
        clock_->Release();
        clock_ = nullptr;
    }
    module_unlock();
}

HRESULT STDMETHODCALLTYPE BambuSourceFilter::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_IPersist ||
        riid == IID_IMediaFilter || riid == IID_IBaseFilter) {
        *ppv = static_cast<IBaseFilter*>(this);
    } else if (riid == IID_IFileSourceFilter) {
        *ppv = static_cast<IFileSourceFilter*>(this);
    } else {
        log_at(LL_DEBUG, kNoLogger, nullptr,
            "dshow: Filter::QI(%s) -> E_NOINTERFACE",
            iid_to_string(riid));
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    AddRef();
    log_at(LL_DEBUG, kNoLogger, nullptr,
        "dshow: Filter::QI(%s) -> ok", iid_to_string(riid));
    return S_OK;
}

ULONG STDMETHODCALLTYPE BambuSourceFilter::AddRef()
{
    return static_cast<ULONG>(ref_.fetch_add(1, std::memory_order_acq_rel) + 1);
}

ULONG STDMETHODCALLTYPE BambuSourceFilter::Release()
{
    long n = ref_.fetch_sub(1, std::memory_order_acq_rel) - 1;
    if (n == 0) delete this;
    return static_cast<ULONG>(n);
}

HRESULT STDMETHODCALLTYPE BambuSourceFilter::Stop()
{
    log_at(LL_INFO, kNoLogger, nullptr, "dshow: Filter::Stop this=%p", this);
    state_.store(State_Stopped, std::memory_order_release);
    if (pin_) pin_->stop_streaming();
    log_at(LL_INFO, kNoLogger, nullptr, "dshow: Filter::Stop done");
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceFilter::Pause()
{
    log_at(LL_INFO, kNoLogger, nullptr, "dshow: Filter::Pause this=%p", this);
    state_.store(State_Paused, std::memory_order_release);
    if (pin_) pin_->start_streaming();
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceFilter::Run(REFERENCE_TIME tStart)
{
    log_at(LL_INFO, kNoLogger, nullptr,
        "dshow: Filter::Run this=%p tStart=%lld",
        this, static_cast<long long>(tStart));
    state_.store(State_Running, std::memory_order_release);
    if (pin_) pin_->start_streaming();
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceFilter::GetState(DWORD dwMs, FILTER_STATE* pState)
{
    if (!pState) return E_POINTER;
    *pState = state_.load(std::memory_order_acquire);
    log_at(LL_DEBUG, kNoLogger, nullptr,
        "dshow: Filter::GetState dwMs=%lu -> state=%d",
        static_cast<unsigned long>(dwMs), static_cast<int>(*pState));
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceFilter::SetSyncSource(IReferenceClock* pClock)
{
    log_at(LL_DEBUG, kNoLogger, nullptr,
        "dshow: Filter::SetSyncSource clock=%p", pClock);
    std::lock_guard<std::mutex> lk(mu_);
    if (clock_) clock_->Release();
    clock_ = pClock;
    if (clock_) clock_->AddRef();
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceFilter::GetSyncSource(IReferenceClock** ppClock)
{
    if (!ppClock) return E_POINTER;
    std::lock_guard<std::mutex> lk(mu_);
    *ppClock = clock_;
    if (clock_) clock_->AddRef();
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceFilter::EnumPins(IEnumPins** ppEnum)
{
    log_at(LL_DEBUG, kNoLogger, nullptr,
        "dshow: Filter::EnumPins this=%p pin=%p", this, pin_);
    if (!ppEnum) return E_POINTER;
    *ppEnum = new PinEnumerator(pin_);
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceFilter::FindPin(LPCWSTR Id, IPin** ppPin)
{
    if (!Id || !ppPin) return E_POINTER;
    char id_utf8[64] = {0};
    ::WideCharToMultiByte(CP_UTF8, 0, Id, -1, id_utf8, sizeof(id_utf8) - 1,
                          nullptr, nullptr);
    log_at(LL_DEBUG, kNoLogger, nullptr,
        "dshow: Filter::FindPin id='%s'", id_utf8);
    if (lstrcmpW(Id, L"Output") == 0) {
        *ppPin = pin_;
        if (pin_) pin_->AddRef();
        return S_OK;
    }
    *ppPin = nullptr;
    return VFW_E_NOT_FOUND;
}

HRESULT STDMETHODCALLTYPE BambuSourceFilter::QueryFilterInfo(FILTER_INFO* pInfo)
{
    log_at(LL_DEBUG, kNoLogger, nullptr,
        "dshow: Filter::QueryFilterInfo this=%p graph=%p", this, graph_);
    if (!pInfo) return E_POINTER;
    std::memset(pInfo, 0, sizeof(*pInfo));
    auto n = std::wcslen(kFilterName);
    if (n >= MAX_FILTER_NAME) n = MAX_FILTER_NAME - 1;
    std::memcpy(pInfo->achName, kFilterName, n * sizeof(wchar_t));
    pInfo->achName[n] = L'\0';
    pInfo->pGraph = graph_;
    if (graph_) graph_->AddRef();
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceFilter::JoinFilterGraph(IFilterGraph* pGraph,
                                                            LPCWSTR pName)
{
    char name_utf8[64] = {0};
    if (pName) {
        ::WideCharToMultiByte(CP_UTF8, 0, pName, -1, name_utf8,
                              sizeof(name_utf8) - 1, nullptr, nullptr);
    }
    log_at(LL_INFO, kNoLogger, nullptr,
        "dshow: Filter::JoinFilterGraph graph=%p name='%s'",
        pGraph, name_utf8);
    std::lock_guard<std::mutex> lk(mu_);
    graph_      = pGraph;       // weak: graph holds the reference, not us
    graph_name_ = pName ? pName : L"";
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceFilter::QueryVendorInfo(LPWSTR* pVendorInfo)
{
    if (!pVendorInfo) return E_POINTER;
    static const wchar_t k[] = L"open-bambu-networking";
    auto* buf = static_cast<wchar_t*>(::CoTaskMemAlloc(sizeof(k)));
    if (!buf) return E_OUTOFMEMORY;
    std::memcpy(buf, k, sizeof(k));
    *pVendorInfo = buf;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceFilter::Load(LPCOLESTR lpwszFileName,
                                                 const AM_MEDIA_TYPE* pmt)
{
    if (!lpwszFileName) return E_POINTER;
    std::string utf8 = wide_to_utf8(lpwszFileName);
    log_at(LL_INFO, kNoLogger, nullptr,
        "dshow: IFileSourceFilter::Load url='%s' pmt=%p", utf8.c_str(), pmt);
    ParsedUrl pu;
    if (!parse_bambu_url(utf8, &pu)) {
        log_at(LL_ERROR, kNoLogger, nullptr, "dshow: parse_bambu_url failed");
        return E_INVALIDARG;
    }
    log_at(LL_INFO, kNoLogger, nullptr,
        "dshow: parsed scheme=%d host=%s port=%d user=%s path=%s",
        static_cast<int>(pu.scheme), pu.host.c_str(), pu.port,
        pu.user.c_str(), pu.path.c_str());
    std::lock_guard<std::mutex> lk(mu_);
    url_w_      = lpwszFileName;
    url_        = std::move(pu);
    url_loaded_ = true;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE BambuSourceFilter::GetCurFile(LPOLESTR* ppszFileName,
                                                       AM_MEDIA_TYPE* pmt)
{
    log_at(LL_DEBUG, kNoLogger, nullptr,
        "dshow: IFileSourceFilter::GetCurFile pmt=%p", pmt);
    if (!ppszFileName) return E_POINTER;
    std::lock_guard<std::mutex> lk(mu_);
    std::size_t bytes = (url_w_.size() + 1) * sizeof(wchar_t);
    auto* buf = static_cast<wchar_t*>(::CoTaskMemAlloc(bytes));
    if (!buf) return E_OUTOFMEMORY;
    std::memcpy(buf, url_w_.c_str(), bytes);
    *ppszFileName = buf;
    if (pmt) {
        // Caller passes us a freshly zeroed AM_MEDIA_TYPE per the
        // contract; do not assume any pre-existing pbFormat/pUnk we
        // would need to release first.
        std::memset(pmt, 0, sizeof(*pmt));
        if (url_loaded_) make_media_type_for_scheme(pmt, url_.scheme);
    }
    return S_OK;
}

// ============================================================================
// Worker helpers
// ============================================================================

namespace {

// Push one already-encoded frame into the downstream input pin via
// the negotiated allocator. `data` is borrowed; we copy into the
// IMediaSample buffer because downstream filters cap how long they
// hold a borrowed pointer. dt_100ns is the wall-clock since stream
// start; sync indicates an IDR (H.264) or any-frame (MJPEG, where
// every JPEG is an I-frame in MPEG-1 parlance).
HRESULT push_sample_into(IMemAllocator* alloc, IMemInputPin* input,
                         const std::uint8_t* data, std::size_t size,
                         std::uint64_t dt_100ns, bool sync,
                         bool discontinuity, std::uint64_t fps_num)
{
    if (!alloc || !input || !data || size == 0) return E_POINTER;
    IMediaSample* sample = nullptr;
    HRESULT hr = alloc->GetBuffer(&sample, nullptr, nullptr, 0);
    if (FAILED(hr) || !sample) return hr;
    BYTE* dst = nullptr;
    sample->GetPointer(&dst);
    long cap = sample->GetSize();
    if (!dst || static_cast<long>(size) > cap) {
        sample->Release();
        return VFW_E_BUFFER_OVERFLOW;
    }
    std::memcpy(dst, data, size);
    sample->SetActualDataLength(static_cast<long>(size));
    sample->SetSyncPoint(sync ? TRUE : FALSE);
    sample->SetPreroll(FALSE);
    sample->SetDiscontinuity(discontinuity ? TRUE : FALSE);
    REFERENCE_TIME t_start = static_cast<REFERENCE_TIME>(dt_100ns);
    REFERENCE_TIME t_end   = t_start + static_cast<REFERENCE_TIME>(fps_num);
    sample->SetTime(&t_start, &t_end);
    hr = input->Receive(sample);
    sample->Release();
    return hr;
}

void build_mjpeg_auth(const ParsedUrl& url, std::uint8_t out[80])
{
    std::memset(out, 0, 80);
    auto put_u32_le = [&](std::size_t off, std::uint32_t v) {
        out[off + 0] = static_cast<std::uint8_t>( v        & 0xff);
        out[off + 1] = static_cast<std::uint8_t>((v >>  8) & 0xff);
        out[off + 2] = static_cast<std::uint8_t>((v >> 16) & 0xff);
        out[off + 3] = static_cast<std::uint8_t>((v >> 24) & 0xff);
    };
    put_u32_le(0,  0x40);    // payload size
    put_u32_le(4,  0x3000);  // packet type (auth)
    std::memcpy(out + 16, url.user.data(),
                std::min<std::size_t>(url.user.size(), 32));
    std::memcpy(out + 48, url.passwd.data(),
                std::min<std::size_t>(url.passwd.size(), 32));
}

} // anonymous namespace

// ============================================================================
// Worker thread dispatch
// ============================================================================

void BambuSourceOutPin::worker_main()
{
    const ParsedUrl& url = parent_->url();
    log_at(LL_INFO, kNoLogger, nullptr,
           "dshow: worker scheme=%d host=%s port=%d",
           static_cast<int>(url.scheme), url.host.c_str(), url.port);

    auto t0 = std::chrono::steady_clock::now();
    auto now_dt_100ns = [&]() -> std::uint64_t {
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - t0).count();
        return static_cast<std::uint64_t>(ns / 100);
    };

    auto borrow_targets = [&](IMemAllocator** ao, IMemInputPin** io) {
        std::lock_guard<std::mutex> lk(state_mu_);
        *ao = allocator_;
        *io = downstream_input_;
        if (*ao) (*ao)->AddRef();
        if (*io) (*io)->AddRef();
    };

    std::uint64_t pushed = 0;

    if (url.scheme == UrlScheme::Rtsps || url.scheme == UrlScheme::Rtsp) {
        // ---- RTSP/H.264 branch ----
        obn::rtsp::Passthrough pass(kNoLogger, nullptr);
        bool tls = (url.scheme == UrlScheme::Rtsps);
        if (pass.start(url.host, url.port, url.user, url.passwd, url.path, tls) != 0) {
            log_at(LL_ERROR, kNoLogger, nullptr,
                   "dshow: RTSP start failed: %s",
                   obn::source::get_last_error());
            return;
        }
        log_at(LL_INFO, kNoLogger, nullptr, "dshow: RTSP play started");
        // NOTE: don't gate pushes on State_Running. wmp/wxMediaCtrl keeps
        // the graph in Paused until it receives the first sample, so a
        // source that refuses to deliver in Paused will deadlock the
        // graph (renderer never transitions to Running) and we'd see
        // "playing forever / black frame". Standard DirectShow source
        // behaviour: deliver as soon as Pause() runs the allocator;
        // downstream applies any reference-clock gating itself.
        while (!worker_stop_.load(std::memory_order_acquire)) {
            const std::uint8_t* buf = nullptr;
            std::size_t         size = 0;
            std::uint64_t       dt = 0;
            int                 flags = 0;
            auto rc = pass.try_pull(&buf, &size, &dt, &flags);
            if (rc == obn::rtsp::Passthrough::Pull_WouldBlock) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            if (rc == obn::rtsp::Passthrough::Pull_StreamEnd) {
                log_at(LL_INFO, kNoLogger, nullptr, "dshow: RTSP stream end");
                break;
            }
            if (rc != obn::rtsp::Passthrough::Pull_Ok || !buf || size == 0) {
                log_at(LL_WARN, kNoLogger, nullptr,
                       "dshow: RTSP try_pull rc=%d", static_cast<int>(rc));
                break;
            }
            IMemAllocator* alloc = nullptr;
            IMemInputPin*  input = nullptr;
            borrow_targets(&alloc, &input);
            if (alloc && input) {
                bool first_push = (pushed == 0);
                HRESULT hr = push_sample_into(alloc, input, buf, size,
                                              dt, (flags & 1) != 0,
                                              first_push,
                                              333333 /*~30fps placeholder*/);
                if (FAILED(hr) && hr != S_FALSE) {
                    log_at(LL_WARN, kNoLogger, nullptr,
                           "dshow: RTSP push failed hr=0x%08lx size=%zu key=%d",
                           static_cast<unsigned long>(hr), size,
                           (flags & 1) != 0);
                }
                ++pushed;
                if (first_push) {
                    log_at(LL_INFO, kNoLogger, nullptr,
                           "dshow: RTSP first sample pushed (size=%zu key=%d hr=0x%08lx)",
                           size, (flags & 1) != 0,
                           static_cast<unsigned long>(hr));
                }
                if ((pushed & 0x3F) == 0) {
                    log_at(LL_DEBUG, kNoLogger, nullptr,
                           "dshow: RTSP pushed %llu samples",
                           static_cast<unsigned long long>(pushed));
                }
            }
            if (alloc) alloc->Release();
            if (input) input->Release();
        }
        pass.stop();
    } else {
        // ---- Local / framed-JPEG (MJPG) branch ----
        // Studio negotiates a 16-byte length-prefixed frame stream over
        // a TLS:6000 socket after a 80-byte auth packet. Format:
        //   bytes  0..3  payload_size (little-endian)
        //   bytes  4..7  itrack
        //   bytes  8..11 flags (bit 0 = sync)
        //   bytes 12..15 reserved (zero on every observed firmware)
        //   bytes 16..   payload_size bytes of JPEG (FF D8 ... FF D9)
        obn::os::socket_t fd = obn::os::kInvalidSocket;
        SSL*              ssl = nullptr;
        if (obn::tls::dial_tls(url.host, url.port, /*timeout_ms=*/5000,
                               &fd, &ssl) != 0) {
            log_at(LL_ERROR, kNoLogger, nullptr,
                   "dshow: MJPEG dial_tls failed: %s",
                   obn::source::get_last_error());
            return;
        }
        log_at(LL_INFO, kNoLogger, nullptr,
               "dshow: MJPEG TLS connected to %s:%d",
               url.host.c_str(), url.port);
        std::uint8_t auth[80];
        build_mjpeg_auth(url, auth);
        if (obn::tls::ssl_write_all(ssl, auth, sizeof(auth)) != 0) {
            log_at(LL_ERROR, kNoLogger, nullptr,
                   "dshow: MJPEG auth write failed");
            obn::tls::close_tls(&fd, &ssl);
            return;
        }

        std::vector<std::uint8_t> jpeg;
        constexpr std::size_t kMaxFrame = 4u * 1024u * 1024u;
        while (!worker_stop_.load(std::memory_order_acquire)) {
            std::uint8_t hdr[16];
            int rc = obn::tls::ssl_read_full(ssl, hdr, sizeof(hdr));
            if (rc != 0) {
                log_at(LL_INFO, kNoLogger, nullptr,
                       "dshow: MJPEG header read rc=%d -> ending stream", rc);
                break;
            }
            auto u32 = [&](std::size_t off) -> std::uint32_t {
                return  static_cast<std::uint32_t>(hdr[off + 0]) |
                       (static_cast<std::uint32_t>(hdr[off + 1]) <<  8) |
                       (static_cast<std::uint32_t>(hdr[off + 2]) << 16) |
                       (static_cast<std::uint32_t>(hdr[off + 3]) << 24);
            };
            std::uint32_t payload_size = u32(0);
            std::uint32_t flags        = u32(8);
            if (payload_size == 0 || payload_size > kMaxFrame) {
                log_at(LL_WARN, kNoLogger, nullptr,
                       "dshow: MJPEG bogus payload_size=%u", payload_size);
                break;
            }
            jpeg.resize(payload_size);
            rc = obn::tls::ssl_read_full(ssl, jpeg.data(), payload_size);
            if (rc != 0) {
                log_at(LL_INFO, kNoLogger, nullptr,
                       "dshow: MJPEG payload read rc=%d", rc);
                break;
            }
            if (payload_size < 4 ||
                jpeg[0] != 0xFF || jpeg[1] != 0xD8 ||
                jpeg[payload_size - 2] != 0xFF ||
                jpeg[payload_size - 1] != 0xD9) {
                log_at(LL_WARN, kNoLogger, nullptr,
                       "dshow: MJPEG magic mismatch size=%u",
                       static_cast<unsigned>(payload_size));
                continue;
            }
            // See note in the RTSP branch: never gate pushes on
            // State_Running -- wmp keeps the graph in Paused waiting
            // for the first sample.

            IMemAllocator* alloc = nullptr;
            IMemInputPin*  input = nullptr;
            borrow_targets(&alloc, &input);
            if (alloc && input) {
                HRESULT hr = push_sample_into(alloc, input,
                                              jpeg.data(), jpeg.size(),
                                              now_dt_100ns(), true,
                                              pushed == 0,
                                              666666 /*~15fps placeholder*/);
                if (FAILED(hr)) {
                    log_at(LL_WARN, kNoLogger, nullptr,
                           "dshow: MJPEG push failed hr=0x%08lx flags=%u",
                           static_cast<unsigned long>(hr), flags);
                }
                ++pushed;
                if ((pushed & 0x1F) == 0) {
                    log_at(LL_DEBUG, kNoLogger, nullptr,
                           "dshow: MJPEG pushed %llu samples (last=%uB)",
                           static_cast<unsigned long long>(pushed),
                           static_cast<unsigned>(payload_size));
                }
            }
            if (alloc) alloc->Release();
            if (input) input->Release();
        }
        obn::tls::close_tls(&fd, &ssl);
    }

    log_at(LL_INFO, kNoLogger, nullptr,
           "dshow: worker exiting (pushed=%llu)",
           static_cast<unsigned long long>(pushed));
}

// ============================================================================
// IClassFactory + DllGetClassObject / DllCanUnloadNow
// ============================================================================

class BambuSourceClassFactory : public IClassFactory {
public:
    BambuSourceClassFactory() : ref_(1) { module_lock(); }
    ~BambuSourceClassFactory() { module_unlock(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return static_cast<ULONG>(ref_.fetch_add(1, std::memory_order_acq_rel) + 1);
    }
    ULONG STDMETHODCALLTYPE Release() override
    {
        long n = ref_.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (n == 0) delete this;
        return static_cast<ULONG>(n);
    }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* pUnkOuter, REFIID riid,
                                             void** ppv) override
    {
        log_at(LL_INFO, kNoLogger, nullptr,
            "dshow: ClassFactory::CreateInstance riid=%s outer=%p",
            iid_to_string(riid), pUnkOuter);
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (pUnkOuter) {
            log_at(LL_WARN, kNoLogger, nullptr,
                "dshow: CreateInstance -> CLASS_E_NOAGGREGATION");
            return CLASS_E_NOAGGREGATION;
        }
        BambuSourceFilter* filter = nullptr;
        try {
            filter = new BambuSourceFilter();
        } catch (const std::exception& e) {
            log_at(LL_ERROR, kNoLogger, nullptr,
                "dshow: BambuSourceFilter ctor threw: %s", e.what());
            return E_OUTOFMEMORY;
        } catch (...) {
            log_at(LL_ERROR, kNoLogger, nullptr,
                "dshow: BambuSourceFilter ctor threw unknown exception");
            return E_UNEXPECTED;
        }
        HRESULT hr = filter->QueryInterface(riid, ppv);
        filter->Release();
        log_at(LL_INFO, kNoLogger, nullptr,
            "dshow: CreateInstance -> hr=0x%08lx ppv=%p",
            static_cast<unsigned long>(hr), *ppv);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) override
    {
        log_at(LL_DEBUG, kNoLogger, nullptr,
            "dshow: ClassFactory::LockServer(%s)", fLock ? "TRUE" : "FALSE");
        if (fLock) module_lock(); else module_unlock();
        return S_OK;
    }

private:
    std::atomic<long> ref_;
};

} // anonymous namespace

// ============================================================================
// COM in-proc server entry points
// ============================================================================

// Exports done via stubs/BambuSource.def; these definitions are plain
// extern "C" + WINAPI to match the prototypes in <objbase.h> /
// <combaseapi.h>. Adding __declspec(dllexport) here would clash with
// the system header's dllimport-less prototype ("different linkage").
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    obn::source::log_at(obn::source::LL_INFO, kNoLogger, nullptr,
        "dshow: DllGetClassObject clsid=%s riid=%s",
        iid_to_string(rclsid), iid_to_string(riid));
    if (!ppv) return E_POINTER;
    *ppv = nullptr;
    if (rclsid != CLSID_BambuSource) {
        obn::source::log_at(obn::source::LL_WARN, kNoLogger, nullptr,
            "dshow: DllGetClassObject -> CLASS_E_CLASSNOTAVAILABLE (not our CLSID)");
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    auto* cf = new BambuSourceClassFactory();
    HRESULT hr = cf->QueryInterface(riid, ppv);
    cf->Release();
    obn::source::log_at(obn::source::LL_INFO, kNoLogger, nullptr,
        "dshow: DllGetClassObject -> hr=0x%08lx ppv=%p",
        static_cast<unsigned long>(hr), *ppv);
    return hr;
}

STDAPI DllCanUnloadNow()
{
    long lc = g_lock_count.load(std::memory_order_acquire);
    obn::source::log_at(obn::source::LL_DEBUG, kNoLogger, nullptr,
        "dshow: DllCanUnloadNow lock_count=%ld", lc);
    return (lc == 0) ? S_OK : S_FALSE;
}

// ============================================================================
// DllRegisterServer / DllUnregisterServer
// ============================================================================

namespace {

bool clsid_to_string(const GUID& g, wchar_t* out, std::size_t out_chars)
{
    return ::StringFromGUID2(g, out, static_cast<int>(out_chars)) != 0;
}

LSTATUS reg_set_default_w(HKEY parent, const wchar_t* subkey, const wchar_t* value)
{
    HKEY k = nullptr;
    LSTATUS rc = ::RegCreateKeyExW(parent, subkey, 0, nullptr, 0, KEY_WRITE,
                                   nullptr, &k, nullptr);
    if (rc != ERROR_SUCCESS) return rc;
    DWORD bytes = static_cast<DWORD>((std::wcslen(value) + 1) * sizeof(wchar_t));
    rc = ::RegSetValueExW(k, nullptr, 0, REG_SZ,
                          reinterpret_cast<const BYTE*>(value), bytes);
    ::RegCloseKey(k);
    return rc;
}

LSTATUS reg_set_named_w(HKEY parent, const wchar_t* subkey, const wchar_t* name,
                        const wchar_t* value)
{
    HKEY k = nullptr;
    LSTATUS rc = ::RegCreateKeyExW(parent, subkey, 0, nullptr, 0, KEY_WRITE,
                                   nullptr, &k, nullptr);
    if (rc != ERROR_SUCCESS) return rc;
    DWORD bytes = static_cast<DWORD>((std::wcslen(value) + 1) * sizeof(wchar_t));
    rc = ::RegSetValueExW(k, name, 0, REG_SZ,
                          reinterpret_cast<const BYTE*>(value), bytes);
    ::RegCloseKey(k);
    return rc;
}

void reg_delete_tree(HKEY parent, const wchar_t* subkey)
{
    ::RegDeleteTreeW(parent, subkey);
}

} // anonymous namespace

STDAPI DllRegisterServer()
{
    if (!g_module) return SELFREG_E_CLASS;

    wchar_t module_path[MAX_PATH] = {0};
    if (::GetModuleFileNameW(g_module, module_path, MAX_PATH) == 0)
        return HRESULT_FROM_WIN32(::GetLastError());

    wchar_t clsid_str[64] = {0};
    if (!clsid_to_string(CLSID_BambuSource, clsid_str,
                         sizeof(clsid_str) / sizeof(clsid_str[0])))
        return E_FAIL;

    // CLSID\{...}\(Default) = "Bambu Source Filter"
    wchar_t key[256];
    std::swprintf(key, sizeof(key) / sizeof(key[0]),
                  L"SOFTWARE\\Classes\\CLSID\\%ls", clsid_str);
    if (reg_set_default_w(HKEY_CURRENT_USER, key, kFilterName) != ERROR_SUCCESS)
        return SELFREG_E_CLASS;

    // CLSID\{...}\InprocServer32\(Default) = <module path>
    //                            ThreadingModel = "Both"
    wchar_t inproc_key[256];
    std::swprintf(inproc_key, sizeof(inproc_key) / sizeof(inproc_key[0]),
                  L"SOFTWARE\\Classes\\CLSID\\%ls\\InprocServer32", clsid_str);
    if (reg_set_default_w(HKEY_CURRENT_USER, inproc_key, module_path) != ERROR_SUCCESS)
        return SELFREG_E_CLASS;
    if (reg_set_named_w(HKEY_CURRENT_USER, inproc_key, L"ThreadingModel", L"Both")
        != ERROR_SUCCESS)
        return SELFREG_E_CLASS;

    // bambu URI scheme handler.
    if (reg_set_default_w(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\bambu",
                          L"URL:Bambu Source") != ERROR_SUCCESS)
        return SELFREG_E_CLASS;
    if (reg_set_named_w(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\bambu",
                        L"URL Protocol", L"") != ERROR_SUCCESS)
        return SELFREG_E_CLASS;
    if (reg_set_default_w(HKEY_CURRENT_USER,
                          L"SOFTWARE\\Classes\\bambu\\Source Filter",
                          clsid_str) != ERROR_SUCCESS)
        return SELFREG_E_CLASS;

    return S_OK;
}

STDAPI DllUnregisterServer()
{
    wchar_t clsid_str[64] = {0};
    if (!clsid_to_string(CLSID_BambuSource, clsid_str,
                         sizeof(clsid_str) / sizeof(clsid_str[0])))
        return E_FAIL;

    wchar_t key[256];
    std::swprintf(key, sizeof(key) / sizeof(key[0]),
                  L"SOFTWARE\\Classes\\CLSID\\%ls", clsid_str);
    reg_delete_tree(HKEY_CURRENT_USER, key);
    reg_delete_tree(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\bambu");
    return S_OK;
}

// ============================================================================
// DllMain
// ============================================================================

extern "C" BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID)
{
    // DllMain runs under the OS loader lock. NEVER touch the obn
    // logger here: log_at()'s very first call lazily opens the
    // mirror file (fopen + GetEnvironmentVariable + path resolution),
    // and CRT IO under the loader lock is documented to deadlock or,
    // worse, trigger the /GS guard with a STATUS_STACK_BUFFER_OVERRUN
    // when the loader calls DllRegisterServer right after attach. We
    // observed exactly that with regsvr32. The first dshow: log line
    // appears in DllGetClassObject instead.
    if (reason == DLL_PROCESS_ATTACH) {
        g_module = hinst;
        ::DisableThreadLibraryCalls(hinst);
    }
    return TRUE;
}

#endif // _WIN32
