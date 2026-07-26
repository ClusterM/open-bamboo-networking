## 9. The `libBambuSource` library

This second module is the one Studio talks to whenever the user opens a printer's **camera live view** or the **on-printer file browser** (under "Device" → "SD Card / USB"). It has nothing in common with `bambu_networking` apart from packaging — different symbol prefix (`Bambu_*`), different loader, different per-platform back-ends. Bambu's stock shipment puts it at the same `<data_dir>/plugins/` path as the main networking plugin, but a missing or stub `libBambuSource` does not stop Studio from starting; only camera/file-browser features get disabled.

Reverse-engineered from the upstream BambuStudio tree (see **Source citations** in [§0](00-intro.md)). OrcaSlicer keeps the same logic under the same file names except the `dlopen` helper: Orca names it `BBLNetworkPlugin::get_source_module()` in [BBLNetworkPlugin.cpp:286-325](https://github.com/SoftFever/OrcaSlicer/blob/11fdb472d6193312bc6c78b7703ad2c1222502b7/src/slic3r/Utils/BBLNetworkPlugin.cpp#L286-L325) (Orca tree only — that file does not exist in BambuStudio).

### 9.1. Loading and discovery

Bambu Studio resolves `libBambuSource` lazily, on the first time a camera or file-browser tab is shown:

Source: [NetworkAgent.cpp:529-580](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/NetworkAgent.cpp#L529-L580)

```cpp
#if defined(_MSC_VER) || defined(_WIN32)
HMODULE NetworkAgent::get_bambu_source_entry()
#else
void* NetworkAgent::get_bambu_source_entry()
#endif
{
    if ((source_module) || (!networking_module))
        return source_module;

    std::string library;
    std::string data_dir_str = data_dir();
    boost::filesystem::path data_dir_path(data_dir_str);
    auto plugin_folder = data_dir_path / "plugins";

#if defined(_MSC_VER) || defined(_WIN32)
    library = plugin_folder.string() + "/" + std::string(BAMBU_SOURCE_LIBRARY) + ".dll";
    ...
    source_module = LoadLibrary(lib_wstr);
    ...
#else
#if defined(__WXMAC__)
    library = plugin_folder.string() + "/" + std::string("lib") + std::string(BAMBU_SOURCE_LIBRARY) + ".dylib";
#else
    library = plugin_folder.string() + "/" + std::string("lib") + std::string(BAMBU_SOURCE_LIBRARY) + ".so";
#endif
    source_module = dlopen(library.c_str(), RTLD_LAZY);
#endif

    return source_module;
}
```

So the resolved file names are:

| Platform | Path |
|----------|------|
| Windows  | `<data_dir>\plugins\BambuSource.dll` |
| macOS    | `<data_dir>/plugins/libBambuSource.dylib` |
| Linux    | `<data_dir>/plugins/libBambuSource.so` |

Notable side effects:

- The function early-returns `nullptr` when `networking_module == nullptr`, so `libBambuSource` is **never** loaded standalone — `bambu_networking` must be loaded first.
- There is no signature check on this module, no version-prefix gate, no fall-back to `<data_dir>/plugins/backup/`. Studio either gets a non-null module, fishes out C symbols via `dlsym`/`GetProcAddress` (§9.2), and never touches it again, or it falls back to a `Fake_Bambu_Create` stub (§9.2) and the whole feature surface is disabled.
- The single public accessor is `Slic3r::NetworkAgent::get_bambu_source_entry()` ([NetworkAgent.cpp:529-580](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/NetworkAgent.cpp#L529-L580)); the camera UI and the file browser both call it when they need this library.

### 9.2. C ABI surface (`Bambu_*`)

The header lives at [BambuTunnel.h](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/BambuTunnel.h) and ships **both** as a static-link header (`#define BAMBU_DYNAMIC` off) and as a dlopen function-pointer table (`BAMBU_DYNAMIC` on, `typedef struct __BambuLib { ... } BambuLib`). Studio uses the dlopen path: `PrinterFileSystem.cpp` defines

```cpp
class PrinterFileSystem : ..., BambuLib { ... };
```

i.e. it inherits the function-pointer table directly into the file-browser object. The pointers are wired up by `StaticBambuLib`:

Source: [PrinterFileSystem.cpp:1840-1879](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.cpp#L1840-L1879)

```cpp
StaticBambuLib &StaticBambuLib::get(BambuLib *copy)
{
    static StaticBambuLib lib;

    if (lib.Bambu_Create)
        return lib;

    if (!module) {
        module = Slic3r::NetworkAgent::get_bambu_source_entry();
    }

    GET_FUNC(Bambu_Create);
    GET_FUNC(Bambu_Open);
    GET_FUNC(Bambu_StartStream);
    GET_FUNC(Bambu_StartStreamEx);
    GET_FUNC(Bambu_GetStreamCount);
    GET_FUNC(Bambu_GetStreamInfo);
    GET_FUNC(Bambu_SendMessage);
    GET_FUNC(Bambu_ReadSample);
    GET_FUNC(Bambu_Close);
    GET_FUNC(Bambu_Destroy);
    GET_FUNC(Bambu_SetLogger);
    GET_FUNC(Bambu_FreeLogMsg);
    GET_FUNC(Bambu_Deinit);

    if (!lib.Bambu_Create) {
        lib.Bambu_Create = Fake_Bambu_Create;
        ...
    }
    return lib;
}
```

`Fake_Bambu_Create` (`PrinterFileSystem.cpp:71`) returns `-2`, which propagates as `m_last_error` and surfaces in the UI as "library missing".

The full set of symbols Studio looks up — declared in `BambuTunnel.h`, sorted by consumer — is:

| Symbol | Signature | Used by |
|--------|-----------|---------|
| `Bambu_Init` | `int (void)` | one-shot global init (rarely called — observed shipping libs do nothing here) |
| `Bambu_Deinit` | `void (void)` | one-shot global teardown; called once on agent reset (`StaticBambuLib::release()`) |
| `Bambu_Create` | `int (Bambu_Tunnel*, const char* url)` | every tunnel |
| `Bambu_Destroy` | `void (Bambu_Tunnel)` | every tunnel |
| `Bambu_SetLogger` | `void (Bambu_Tunnel, Logger, void* ctx)` | every tunnel |
| `Bambu_Open` | `int (Bambu_Tunnel)` | every tunnel; returns `Bambu_would_block` until ready |
| `Bambu_Close` | `void (Bambu_Tunnel)` | every tunnel |
| `Bambu_StartStream` | `int (Bambu_Tunnel, bool video)` | camera (legacy entry point) |
| `Bambu_StartStreamEx` | `int (Bambu_Tunnel, int type)` | camera + file-browser; `type = CTRL_TYPE = 0x3001` switches the tunnel into JSON-RPC mode (§9.5) |
| `Bambu_GetStreamCount` / `Bambu_GetStreamInfo` | `int (...)` | camera; describe the video / audio tracks once `StartStream` has succeeded |
| `Bambu_GetDuration` / `Bambu_Seek` | `unsigned long (...) / int (...)` | declared but not exercised on a live LAN stream |
| `Bambu_ReadSample` | `int (Bambu_Tunnel, Bambu_Sample*)` | camera (one MJPG / H.264 access unit per call) **and** file-browser (one JSON response per call) |
| `Bambu_SendMessage` | `int (Bambu_Tunnel, int ctrl, const char* data, int len)` | file-browser only — sends a CTRL JSON request (§9.5) |
| `Bambu_RecvMessage` | `int (Bambu_Tunnel, int* ctrl, char* data, int* len)` | declared but not actually called by Studio for either feature |
| `Bambu_GetLastErrorMsg` | `const char* (void)` | error-reporting fallback |
| `Bambu_FreeLogMsg` | `void (const tchar* msg)` | log-callback companion |

`Bambu_Tunnel` is an opaque pointer; `Bambu_Sample`, `Bambu_StreamInfo` and the `Bambu_Error` enum are defined in `BambuTunnel.h:36-110`. The relevant error values are:

```cpp
typedef enum {
    Bambu_success      = 0,
    Bambu_stream_end   = 1,
    Bambu_would_block  = 2,
    Bambu_buffer_limit = 3,
} Bambu_Error;
```

Negative return values are treated as fatal (the caller calls `Bambu_Close` + `Bambu_Destroy` and surfaces the code).

> ABI footgun (same as `bambu_networking`): even though every entry point is `extern "C"`, several signatures hand `Bambu_Sample` / `Bambu_StreamInfo` structs by value or by pointer. The plugin must therefore be built with the same C compiler ABI Studio was built with. There is no `std::*` at the boundary here, so cross-toolchain mixing is somewhat safer than for `bambu_networking`, but `tchar` (`wchar_t` on Windows, `char` elsewhere) and the calling convention still need to match.

### 9.3. URL formats Studio passes into `Bambu_Create`

Studio's two consumers each build their own URL.

#### 9.3.1. Camera live view

Built in `MediaPlayCtrl::Play` ([MediaPlayCtrl.cpp:444-455](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/MediaPlayCtrl.cpp#L444-L455)) and `MediaPlayCtrl::ToggleStream` (`...:551-559`):

Source: [MediaPlayCtrl.cpp:444-455](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/MediaPlayCtrl.cpp#L444-L455)

```cpp
        std::string url;
        if (m_lan_proto == MachineObject::LVL_Local)
            url = "bambu:///local/" + m_lan_ip + ".?port=6000&user=" + m_lan_user + "&passwd=" + m_lan_passwd;
        else if (m_lan_proto == MachineObject::LVL_Rtsps)
            url = "bambu:///rtsps___" + m_lan_user + ":" + m_lan_passwd + "@" + m_lan_ip + "/streaming/live/1?proto=rtsps";
        else if (m_lan_proto == MachineObject::LVL_Rtsp)
            url = "bambu:///rtsp___"  + m_lan_user + ":" + m_lan_passwd + "@" + m_lan_ip + "/streaming/live/1?proto=rtsp";
        url += "&device=" + m_machine;
        url += "&net_ver=" + agent_version;
        url += "&dev_ver=" + m_dev_ver;
        url += "&cli_id=" + wxGetApp().app_config->get("slicer_uuid");
        url += "&cli_ver=" + std::string(SLIC3R_VERSION);
```

So the three accepted forms are:

| Form | Used by | Wire protocol |
|------|---------|---------------|
| `bambu:///local/<ip>.?port=6000&user=<u>&passwd=<p>&...` | A1 / A1 mini / P1 / P1P | TLS over TCP/6000, 80-byte auth packet, then 16-byte framed JPEG samples |
| `bambu:///rtsps___<u>:<p>@<ip>/streaming/live/1?proto=rtsps&...` | X1 / X1C / X1E / P1S / P2S / H-series | RTSP over TLS on port 322 |
| `bambu:///rtsp___<u>:<p>@<ip>/streaming/live/1?proto=rtsp&...` | development / unencrypted variant | plain RTSP |

The trailing query parameters (`device`, `net_ver`, `dev_ver`, `cli_id`, `cli_ver`, plus optional `dump_h264=<FILE*>` / `dump_info=<FILE*>` for `internal_developer_mode`) are pure metadata — printers only authenticate on `user`/`passwd`, the rest is for analytics and debugging.

#### 9.3.2. File browser

Built in `PrinterFileSystem::Reconnect` via `MediaFilePanel`. Studio uses the same **URL shape** as the MJPEG camera (`bambu:///local/<ip>.?port=6000&user=<u>&passwd=<p>&...`) — same TCP port — but stock `libBambuSource` instantiates **`BambuTunnelLocal`** for LAN file browsing, **not** the MJPEG 80-byte auth path from [`video.md`](https://github.com/Doridian/OpenBambuAPI/blob/master/video.md). After `Bambu_Open` (TLS only) Studio calls `Bambu_StartStreamEx(tunnel, 0x3001)`, which runs a multi-step wire handshake ([§6.4](06.04-port-6000.md)) before any `LIST_INFO` JSON appears on the wire. On printers that lack `StartStreamEx` (older firmwares), Studio falls back to `Bambu_StartStream(tunnel, false)` (`PrinterFileSystem.cpp:1747-1748`).

### 9.4. Per-platform camera back-end (the critical part)

This used to be the section where the three platforms diverged sharply, with **Windows** routing the camera through a DirectShow source filter inside `BambuSource.dll`. **That changed upstream in BambuStudio commit `94d91be60` ("NEW: reimpl wxMediaCtrl from ffmpeg", June 2024)**, which introduced [wxMediaCtrl3.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl3.cpp), [wxMediaCtrl3.h](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl3.h). Studio's `MediaPlayCtrl` was migrated to `wxMediaCtrl3` as part of the same series, and from that point on **Windows Studio uses the `Bambu_*` C ABI directly**, exactly like Linux: `wxMediaCtrl3::PlayThread` calls `Bambu_Create` → `Bambu_Open` → `Bambu_StartStream` → `Bambu_ReadSample`, then decodes each access unit with FFmpeg via `AVVideoDecoder` and blits the resulting `wxBitmap` into a plain `wxWindow`.

`wxMediaCtrl2.{cpp,h}` is still in the BambuStudio tree and still has the Windows DirectShow stub from before the migration. It is no longer instantiated by Studio. The OrcaSlicer fork has not picked up the FFmpeg-based widget — it still uses `wxMediaCtrl2` and therefore still requires the DirectShow filter on Windows.

So the matrix is now:

| Slicer / version | Linux | Windows | macOS |
|---|---|---|---|
| **BambuStudio** post `94d91be60` (≈ v01.10+ / current `v02.06.x`) | `wxMediaCtrl3` → `Bambu_*` C ABI → `AVVideoDecoder` (FFmpeg) → wxWindow | **same**: `wxMediaCtrl3` → `Bambu_*` C ABI → `AVVideoDecoder` → wxWindow | `wxMediaCtrl2.mm` → Objective-C `BambuPlayer` class via `dlsym` |
| **BambuStudio** pre-`94d91be60` and **OrcaSlicer (current)** | `wxMediaCtrl2` → `gstbambusrc` (statically linked into Studio) → `bambulib_get()` → `Bambu_*` C ABI | `wxMediaCtrl2` → `wxMediaCtrl::Load(wxURI("bambu:..."))` → wxWidgets DirectShow backend → COM source filter (CLSID `{233E64FB-…}`) inside `BambuSource.dll` | `wxMediaCtrl2.mm` → Objective-C `BambuPlayer` |

Observed requirements from Studio source (camera back-end):

- A portable C-ABI implementation of `libBambuSource` covers **all three platforms** when the user runs current BambuStudio. The Windows DirectShow filter is no longer on the hot path.
- For OrcaSlicer (and any pre-`94d91be60` Studio install) the Windows DirectShow filter is still required: without `CLSID {233E64FB-…}` registered against the `bambu:` URL scheme, Orca cannot play the camera at all and falls into the "BambuSource has not correctly been registered" dialog.
- macOS still additionally requires an Objective-C `BambuPlayer` class inside the dylib regardless of Studio version; that path was not touched by the FFmpeg migration.

The subsections below describe each back-end. §9.4.1 (Linux gstbambusrc) and §9.4.3 (macOS BambuPlayer) are unchanged. §9.4.2 (Windows DirectShow) is now an Orca-only / legacy-Studio path. §9.4.4 documents the new `wxMediaCtrl3` flow that current Studio actually uses on Windows.

#### 9.4.1. Linux: `gstbambusrc` baked into Studio

`wxMediaCtrl2::wxMediaCtrl2()` ([wxMediaCtrl2.cpp:42-52](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl2.cpp#L42-L52), in the `__LINUX__` branch) registers a custom GStreamer element after the underlying `wxMediaCtrl` has spun up its own playbin:

Source: [wxMediaCtrl2.cpp:42-52](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl2.cpp#L42-L52)

```cpp
#ifdef __LINUX__
    auto playbin = reinterpret_cast<wxGStreamerMediaBackend *>(m_imp)->m_playbin;
    GstElement* video_sink = nullptr;
    for (const char* sink_name : {"ximagesink", "xvimagesink"}) {
        ...
    }
    g_object_set (G_OBJECT (playbin),
                  "audio-sink", NULL,
                  "video-sink", video_sink,
                   NULL);
    ...
    gstbambusrc_register();
    ...
#endif
```

`gstbambusrc_register` lives in [gstbambusrc.c](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/gstbambusrc.c) — it is **statically linked into Studio's binary** (no plugin search path involved). The element handles the `bambu://` URI scheme; internally it calls the generic accessor `bambulib_get()`, which in turn returns the same `StaticBambuLib` pointer table used by the file browser:

Source: [gstbambusrc.c:67](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/gstbambusrc.c#L67)

```cpp
BambuLib *bambulib_get();
```

Source: [PrinterFileSystem.cpp:1895-1896](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.cpp#L1895-L1896)

```cpp
extern "C" BambuLib *bambulib_get() {
    return &StaticBambuLib::get(); }
```

So on Linux the camera flow is:

1. `MediaPlayCtrl::Play` → `m_media_ctrl->Load(wxURI("bambu:///..."))`.
2. wxGStreamerMediaBackend builds the standard playbin with `bambusrc` as the source element.
3. `bambusrc` calls `BAMBULIB(Bambu_Create)(..., url)` etc., i.e. the C ABI from `libBambuSource.so`.
4. For MJPG streams the source emits JPEG access units; the playbin attaches `jpegdec ! videoconvert ! ximagesink`. For RTSPS streams the source emits raw H.264 byte stream and the playbin attaches `h264parse ! avdec_h264 / openh264dec ! videoconvert ! ximagesink`. Either way the slicer-side pipeline does the decode.

i.e. **on Linux the C ABI is sufficient**. No Linux-specific code needs to live inside `libBambuSource.so`.

#### 9.4.2. Windows (Orca / legacy Studio): DirectShow filter, separate library

Note: this is the path **OrcaSlicer** and pre-`94d91be60` BambuStudio take on Windows. Current upstream BambuStudio (`wxMediaCtrl3`, see §9.4.4) bypasses DirectShow entirely and goes straight through the `Bambu_*` C ABI like Linux does.

`wxMediaCtrl2::Load` (the Windows branch) drops `wxURI("bambu:...")` into `wxMediaCtrl::Load`, which uses wxWidgets's `wxMediaBackendDirectShow`. wxWidgets resolves the URL by looking up `HKCR\bambu\Source Filter` in the registry to find the CLSID that handles `bambu:` URLs, then `CoCreateInstance`s that CLSID and asks the resulting filter to load the URL via `IFileSourceFilter::Load`. Studio expects a custom **DirectShow source filter** to be COM-registered against the URL scheme `bambu:`:

Source: [wxMediaCtrl2.cpp:94-138](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl2.cpp#L94-L138)

```cpp
#define CLSID_BAMBU_SOURCE L"{233E64FB-2041-4A6C-AFAB-FF9BCF83E7AA}"
...
        wxRegKey key11(wxRegKey::HKCU, L"SOFTWARE\\Classes\\CLSID\\" CLSID_BAMBU_SOURCE L"\\InProcServer32");
        wxRegKey key12(wxRegKey::HKCR, L"CLSID\\" CLSID_BAMBU_SOURCE L"\\InProcServer32");
        wxString path = key11.Exists() ? key11.QueryDefaultValue()
                                       : key12.Exists() ? key12.QueryDefaultValue() : wxString{};
        wxRegKey key2(wxRegKey::HKCR, "bambu");
        wxString clsid;
        if (key2.Exists())
            key2.QueryRawValue("Source Filter", clsid);
        ...
        auto dll_path = data_dir_path / "plugins" / "BambuSource.dll";
        if (path.empty() || !wxFile::Exists(path) || clsid != CLSID_BAMBU_SOURCE) {
            if (boost::filesystem::exists(dll_path)) {
                ... regsvr32 /q /s "<dll_path>" ...
            }
        }
```

Concretely:

- `BambuSource.dll` must export `DllRegisterServer` / `DllUnregisterServer`, register `CLSID_BAMBU_SOURCE = {233E64FB-2041-4A6C-AFAB-FF9BCF83E7AA}` with `InprocServer32 = <path-to-BambuSource.dll>`, and register itself as the `Source Filter` for the `bambu:` protocol under `HKCR\bambu`.
- The actual filter must implement `IBaseFilter` + `IFileSourceFilter` and produce video samples on its output pin.
- For Orca / legacy Studio, the C ABI from §9.2 is **not used** for camera output — it is exclusively the file browser path. The DirectShow filter is a separate code path inside the same DLL.

Practical consequence (Orca / legacy Studio only): stock `BambuSource.dll` must expose a DirectShow source filter registered against `bambu:` for camera playback; the C ABI alone covers the file browser on Windows.

Stock filter internals are closed source. Studio-side contract inferred from `wxMediaCtrl2` / wxWidgets (Orca / legacy Studio):

1. **`wxURI` normalises `bambu:///rtsps___…` to `bambu://rtsps___…`** before calling `IFileSourceFilter::Load`. The triple-slash form is what `MediaPlayCtrl::load()` produces (no host, path = `/rtsps___user:pwd@ip/...`), but wxURI's "authority is empty" canonicaliser interprets `rtsps___user:pwd` as userinfo and `ip` as host, then re-emits the URI with a single `//`. A parser keyed strictly off `bambu:///rtsps___` will reject every Orca camera URL with `E_INVALIDARG`. Accept any number of `/` characters after `bambu:` (1, 2, or 3).
2. **DirectShow graphs stay in `Paused` until the first sample arrives.** wxMediaCtrl2 / wmp keeps the filter graph in `State_Paused` until the renderer receives its first sample (which triggers the transition to `State_Running`). A source filter that gates `IMemInputPin::Receive` on `State_Running` deadlocks playback.

#### 9.4.3. macOS: Objective-C `BambuPlayer` class inside the dylib

On macOS Studio does **not** use wxMediaCtrl's GStreamer/AVFoundation back-end. Instead, `wxMediaCtrl2.mm` reaches directly into `libBambuSource.dylib` and looks up an Objective-C class by the synthetic name `OBJC_CLASS_$_BambuPlayer`:

Source: [wxMediaCtrl2.mm:245-269](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl2.mm#L245-L269)

```cpp
void wxMediaCtrl2::create_player()
{
    auto module = Slic3r::NetworkAgent::get_bambu_source_entry();
    if (!module) {
        BOOST_LOG_TRIVIAL(info) << __FUNCTION__ << "Network plugin not ready currently!";
        return;
    }
    Class cls = (__bridge Class) dlsym(module, "OBJC_CLASS_$_BambuPlayer");
    if (cls == nullptr) {
        m_error = -2;
        return;
    }
    NSView * imageView = (NSView *) GetHandle();
    BambuPlayer * player = [cls alloc];
    [player initWithImageView: imageView];
    [player setLogger: bambu_log withContext: this];
    m_player = player;
}
```

The expected interface is documented in [BambuPlayer.h:36-58](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/BambuPlayer/BambuPlayer.h#L36-L58):

Source: [BambuPlayer.h:36-58](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/BambuPlayer/BambuPlayer.h#L36-L58)

```cpp
@interface BambuPlayer : NSObject

+ (void) initialize;

- (instancetype) initWithDisplayLayer: (AVSampleBufferDisplayLayer*) layer;
- (instancetype) initWithImageView: (NSView*) view;
- (int) open: (char const *) url;
- (NSSize) videoSize;
- (int) play;
- (void) stop;
- (void) close;

- (void) setLogger: (void (*)(void const * context, int level, char const * msg)) logger withContext: (void const *) context;

@end
```

Studio drives it from `wxMediaCtrl2::Load` / `Play` / `Stop` (`wxMediaCtrl2.mm:87-141`):

- `Load(url)` → `[player close]` then `m_error = [player open: url.BuildURI().ToUTF8()]`.
- `Play()` → `[player play]`, marks state as `wxMEDIASTATE_PLAYING`, posts `wxEVT_MEDIA_STATECHANGED`.
- `Stop()` → `[player close]`, posts `wxMEDIASTATE_STOPPED`.
- `GetVideoSize()` → `[player videoSize]`.

Failure mode if the symbol is missing: `m_error = -2`, `m_player = nullptr`. Subsequent `Load` / `Play` calls log `create_player failed currently!` and return without ever transitioning out of `MEDIASTATE_LOADING`. The user sees an **infinite "Loading…" spinner** in the camera tab, *not* the "Player is malfunctioning" dialog — the latter is reserved for `m_failed_code == 2`, which only fires after a state transition that never happens here. (`MediaPlayCtrl.cpp:29-36, 415-428`.)

This is the reason a C-ABI-only `libBambuSource.dylib` build (no Objective-C `BambuPlayer` class) is enough for the Mac file browser but produces an indefinite loading state in the Mac camera tab. To make the camera tab work on macOS the dylib must additionally export an Objective-C class symbol `OBJC_CLASS_$_BambuPlayer` whose interface matches `BambuPlayer.h` above.

#### 9.4.4. Windows (current Studio): `wxMediaCtrl3` + FFmpeg, C ABI directly

In commit `94d91be60` ("NEW: reimpl wxMediaCtrl from ffmpeg"), upstream BambuStudio replaced the platform-specific `wxMediaCtrl2` widget with `wxMediaCtrl3`, a self-contained widget that:

1. Inherits from `BambuLib` (the `StaticBambuLib` shim from `PrinterFileSystem.cpp`) so it can call every `Bambu_*` symbol directly without going through any wxWidgets media backend.
2. Owns a single play-thread (`PlayThread`) that walks the entire `Bambu_*` lifecycle — `Bambu_Create` → `Bambu_SetLogger` → `Bambu_Open` → spin on `Bambu_StartStream(true)` until it stops returning `Bambu_would_block` → `Bambu_GetStreamInfo` → loop on `Bambu_ReadSample` → `Bambu_Close` / `Bambu_Destroy` — exactly the way Linux's `gstbambusrc` does.
3. Decodes each access unit with FFmpeg via the new `AVVideoDecoder` helper, packages it into a `wxBitmap` (Windows) or `wxImage` (Linux), pushes it through a small ring buffer (`m_frame_buffer`), and renders it from a wxTimer onto a plain `wxWindow`.

Cross-references in the BambuStudio tree:

- [wxMediaCtrl3.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl3.cpp), [wxMediaCtrl3.h](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl3.h) — the widget itself and the play-thread (`wxMediaCtrl3::PlayThread` at `wxMediaCtrl3.cpp:260-405`).
- [AVVideoDecoder.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/AVVideoDecoder.cpp), [AVVideoDecoder.h](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/AVVideoDecoder.h) — wraps FFmpeg's `avcodec_send_packet` / `avcodec_receive_frame` and hands the raw planes back as a wxBitmap or wxImage.
- [MediaPlayCtrl.cpp:67](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/MediaPlayCtrl.cpp#L67) — the constructor takes `wxMediaCtrl3 *media_ctrl`, replacing the old `wxMediaCtrl2 *` from earlier revisions.

On **current Windows BambuStudio** the camera reaches `libBambuSource` through the same C-ABI surface as Linux. The Windows logger callback expects `wchar_t const*` strings (the `tchar` typedef in `BambuTunnel.h`); POSIX builds use `char const*` (UTF-8).

Studio's `wxMediaCtrl3` does **not** consult the registry, does **not** call `CoCreateInstance`, and does **not** require the DirectShow filter to be registered. On Windows, current BambuStudio uses only the `Bambu_*` C ABI for camera playback; OrcaSlicer and pre-`94d91be60` Studio still require the DirectShow filter to be registered (`regsvr32 /s BambuSource.dll`). Stock `BambuSource.dll` is therefore expected to export both surfaces on Windows.

#### 9.4.5. Recap

| Slicer | Platform | Camera back-end | What `libBambuSource` must provide |
|--------|----------|-----------------|------------------------------------|
| BambuStudio post-`94d91be60` (current) | Linux | `wxMediaCtrl3` → `Bambu_*` C ABI → FFmpeg → wxWindow | The `Bambu_*` C ABI (§9.2) only |
| BambuStudio post-`94d91be60` (current) | Windows | `wxMediaCtrl3` → `Bambu_*` C ABI → FFmpeg → wxWindow | The `Bambu_*` C ABI (§9.2) only |
| BambuStudio post-`94d91be60` (current) | macOS | `wxMediaCtrl2.mm` → `dlsym(libBambuSource.dylib, "OBJC_CLASS_$_BambuPlayer")` *(`wxMediaCtrl3` was not adopted on macOS — the platform still goes through the Objective-C class)* | Both the `Bambu_*` C ABI **and** the Objective-C `BambuPlayer` class |
| OrcaSlicer (current) and BambuStudio pre-`94d91be60` | Linux | `wxMediaCtrl2` → `gstbambusrc` (statically linked into Studio) → `bambulib_get()` → `Bambu_*` C ABI | The `Bambu_*` C ABI (§9.2) only |
| OrcaSlicer (current) and BambuStudio pre-`94d91be60` | Windows | `wxMediaCtrl2` → `wxMediaCtrl::Load` → wxWidgets DirectShow backend → COM source filter (CLSID `{233E64FB-…}`) inside `BambuSource.dll` | A DirectShow `IBaseFilter`/`IFileSourceFilter` implementation registered against `bambu:`. The `Bambu_*` C ABI is **not** used for video; only for the file browser |
| OrcaSlicer (current) and BambuStudio pre-`94d91be60` | macOS | same as current Studio (Objective-C `BambuPlayer`) | same |

In every case the file-browser path uses **only** the `Bambu_*` C ABI plus the CTRL JSON wire protocol described next.

### 9.5. CTRL mode (file-browser RPC over the camera tunnel)

When Studio opens a file browser, it uses the same `Bambu_Create` / `Bambu_Open` URL as the LAN camera, then calls `Bambu_StartStreamEx(tunnel, CTRL_TYPE = 0x3001)`:

Source: [PrinterFileSystem.h:32](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.h#L32)

```cpp
    static const int CTRL_TYPE     = 0x3001;
```

On LAN, stock `libBambuSource` routes this through **`BambuTunnelLocal`** (`createBambuTunnelLocal` in the plugin binary): `Bambu_Open` is TLS connect only; `Bambu_StartStreamEx(0x3001)` sends the subchannel login + `mtype` 12291 setup frames documented in [§6.4](06.04-port-6000.md). Only after that handshake completes does the tunnel accept framed CTRL JSON (`mtype` 12289) for `LIST_INFO` / `SUB_FILE` / …

Source: [PrinterFileSystem.cpp:1756-1771](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.cpp#L1756-L1771)

```cpp
                do{
                    ret = Bambu_StartStreamEx ? Bambu_StartStreamEx(tunnel, CTRL_TYPE) : Bambu_StartStream(tunnel, false);
                    if (ret == Bambu_would_block)
                        boost::this_thread::sleep(boost::posix_time::milliseconds(100));

                     auto now = boost::posix_time::microsec_clock::universal_time();
                    if (now - start_time > timeout) {
                        BOOST_LOG_TRIVIAL(warning) << "StartStream timeout after 5 seconds.";
                        break;
                    }
                } while (ret == Bambu_would_block && !m_stopped);
```

After this, the tunnel is no longer a media bytestream — it is a bidirectional JSON-RPC pipe. Studio:

- enqueues outgoing requests with `Bambu_SendMessage(tunnel, CTRL_TYPE, json_text, len)`;
- polls for responses with `Bambu_ReadSample(tunnel, &sample)` exactly as for video — except `sample.buffer` now holds a JSON document optionally followed by a binary payload (e.g. a thumbnail blob).

Both run on a dedicated worker thread inside `PrinterFileSystem::Reconnect` / `RunRequests` ([PrinterFileSystem.cpp:1567-1606](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.cpp#L1567-L1606)).

#### 9.5.1. Where the printer-side bytes actually come from

From Studio's perspective the file browser is JSON over the `Bambu_*` ABI (`Bambu_SendMessage` / `Bambu_ReadSample`). **Stock `libBambuSource`** forwards that traffic to printer firmware over a long-lived **TLS :6000** socket (`BambuTunnelLocal` + `LocalTunnel_*` + `tutk_third_SSL_*` inside the plugin):

| Channel | Endpoint | Direction | Carries |
|---------|----------|-----------|---------|
| CTRL / file data | TLS over TCP/**6000** (opened by `Bambu_Open`, kept open) | PC ↔ printer firmware | Subchannel-framed bytes ([§6.4](06.04-port-6000.md)): login, `StartStreamEx` setup, then JSON RPC + optional binary blobs |

**Evidence (P2S, May 2026).** LAN capture while using stock Studio Device → Files (Wireshark filter `ip.addr==<printer> && tcp.port != 8883`):

- **External** tab (empty list): small request/response exchange on :6000 only.
- **Internal** tab (timelapse list + JPEG previews): ~66 KiB server→client on :6000 only.
- **Zero packets on FTPS :990** during the same session.

Payload on :6000 is TLS application data (opaque in Wireshark unless decrypted). The **on-wire framing** is documented in [§6.4](06.04-port-6000.md) (reverse-engineered May 2026 from stock `libBambuSource.so` + live probes against P2S).

**Multiple clients.** Unlike an earlier working assumption, the printer **does allow several simultaneous TLS :6000 sessions** (verified with two independent REPL connections while Studio also had Files open). There is no exclusive lock on the port.

**Do not conflate `:6000` with FTPS `:990`.** Print/upload paths that touch either port on P2S:

| Use | Library | When | Upload transport |
|-----|---------|------|------------------|
| Device → Files browse (external USB) | `libBambuSource` (`:6000`) | File browser tab | N/A (lists/downloads only) |
| **`verify_job` preflight** | `libbambu_networking` | `PrintJob` LAN preflight; optional before Send to Printer | Tiny FTPS `STOR verify_job` only |
| Legacy Send-to-Printer fallback | `libbambu_networking` | `SendJob` when `!is_support_brtc` | Full `.3mf` over FTPS `STOR` — not used on P2S |
| Hybrid / fake “with record” | `libbambu_networking` | `start_local_print_with_record` | FTPS `STOR` + `ftp://` PATCH, then **full S3** + https PATCH; `/my/task` `lan_file`; printer prints **S3** ([§11.2](11.02-cloud-upload.md)) — not a real LAN print |
| Pure LAN model (P2S stock) | `libbambu_networking` | `start_local_print` | Full `.3mf` over **`:6000`**; MQTT URL `brtc://emmc/…` ([§11.2.2](11.02-cloud-upload.md)) |

Stock **Send to Printer → cache** on P2S: **`verify_job` FTPS probe (optional) + `:6000` chunked upload** — not a full FTPS model transfer.

**Do not conflate with MJPEG auth.** The 80-byte `0x3000` auth block in [`video.md`](https://github.com/Doridian/OpenBambuAPI/blob/master/video.md) applies to **MJPEG live view on A1 / P1 / P1P** (`BambuTunnelLocal` is still used on some paths, but the camera stream uses different post-auth bytes). Sending that 80-byte packet on a P2S file-browser session yields a 24-byte `0x0003013f` ack and the peer closes — it is the wrong handshake.

Internal timelapse **recording** during print (`task_timelapse_use_internal` → MQTT `project_file` `"cfg":"4"`) is handled by **`libbambu_networking`**, not the file-browser CTRL path documented here.

#### 9.5.1.1. The `:6000` protocol (`BambuTunnelLocal` wire)

Canonical LAN/TUTK framing, login, `StartStreamEx` setup, and `FILE_UPLOAD` / `FILE_DOWNLOAD` wire flows: **[§6.4](06.04-port-6000.md)**. This subsection only notes that file-browser CTRL and `ft_*` share that wire; ABI JSON before framing is below.

#### 9.5.2. ABI / Studio-side JSON: `Bambu_SendMessage` payload

This is the JSON **inside** `libBambuSource` before the plugin adds `"mtype":12289` and the §9.5.1.1 frame header for the LAN wire.

The serialiser is in `PrinterFileSystem::SendRequest` ([PrinterFileSystem.cpp:1439-1478](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.cpp#L1439-L1478)):

Source: [PrinterFileSystem.cpp:1439-1478](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.cpp#L1439-L1478)

```cpp
boost::uint32_t PrinterFileSystem::SendRequest(int type, json const &req, callback_t2 const &callback,const std::string& param)
{
    ...
    boost::uint32_t seq  = m_sequence + m_callbacks.size();
    json root;
    root["cmdtype"] = type;
    root["sequence"] = seq;
    root["req"] = req;
    std::ostringstream oss;
    oss << root;

    if (!param.empty()) {
        oss << "\n\n";
        oss << param;
    }
    auto               msg = oss.str();
    boost::unique_lock l(m_mutex);
    m_messages.push_back(msg);
    m_callbacks.push_back(callback);
    ...
}
```

Concrete shape:

```text
{"cmdtype":<int>,"sequence":<u32>,"req":{...command-specific...}}\n\n<optional binary param>
```

Notes:

- `cmdtype` is one of the `LIST_INFO`/`SUB_FILE`/`FILE_DEL`/`FILE_DOWNLOAD`/`FILE_UPLOAD`/`REQUEST_MEDIA_ABILITY`/`TASK_CANCEL` constants (§9.6).
- `sequence` is a monotonically increasing per-tunnel counter; the plugin echoes it in every response so Studio can match callbacks to requests.
- The optional `\n\n<param>` tail carries an inline binary blob. In practice Studio uses this only for the file-upload command; on the response side the plugin uses the same `\n\n<binary>` convention to deliver thumbnail bytes to Studio.

#### 9.5.3. ABI / Studio-side JSON: response envelope

The plugin returns each response as a `Bambu_Sample` whose `buffer` is the same `json\n\n[blob]` envelope. Studio's parser is `PrinterFileSystem::HandleResponse` (`PrinterFileSystem.cpp:1598+`):

```text
{"sequence":<u32>,"result":<int>,...command-specific result fields...}\n\n<optional binary>
```

`result` is an integer in the error-code enum from `PrinterFileSystem.h:48-72`:

| Value | Meaning |
|------:|---------|
| 0 | `SUCCESS` |
| 1 | `CONTINUE` (used by streaming responses, e.g. progressive download) |
| 2 | `ERROR_JSON` (malformed request) |
| 3 | `ERROR_PIPE` |
| 4 | `ERROR_CANCEL` |
| 5 | `ERROR_RES_BUSY` |
| 6 | `ERROR_TIME_OUT` |
| 10 | `FILE_NO_EXIST` |
| 11 | `FILE_NAME_INVALID` |
| 12 | `FILE_SIZE_ERR` |
| 13 | `FILE_OPEN_ERR` |
| 14 | `FILE_READ_WRITE_ERR` |
| 15 | `FILE_CHECK_ERR` |
| 16 | `FILE_TYPE_ERR` |
| 17 | `STORAGE_UNAVAILABLE` |
| 18 | `API_VERSION_UNSUPPORT` |
| 19 | `FILE_EXIST` |
| 20 | `STORAGE_SPACE_NOT_ENOUGH` |
| 21 | `FILE_CREATE_ERR` |
| 22 | `FILE_WRITE_ERR` |
| 23 | `MD5_COMPARE_ERR` |
| 24 | `FILE_RENAME_ERR` |
| 25 | `SEND_ERR` |

Asynchronous notifications (printer-initiated, no preceding `Bambu_SendMessage`) carry a `cmdtype` in the `NOTIFY_FIRST..NOTIFY_FIRST+N` range and are dispatched through `PrinterFileSystem::InstallNotify`.

### 9.6. CTRL command reference

This is the per-command `req`/response detail for the command set; the transport, framing, handshake and multi-frame flows are in the canonical `:6000` protocol reference ([§6.4](06.04-port-6000.md)). The full set of `cmdtype` values is in `PrinterFileSystem.h:34-45`:

Source: [PrinterFileSystem.h:34-45](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.h#L34-L45)

```cpp
    enum {
        LIST_INFO             = 0x0001,
        SUB_FILE              = 0x0002,
        FILE_DEL              = 0x0003,
        FILE_DOWNLOAD         = 0x0004,
        FILE_UPLOAD           = 0x0005,
        REQUEST_MEDIA_ABILITY = 0x0007,
        NOTIFY_FIRST          = 0x0100,
        LIST_CHANGE_NOTIFY    = 0x0100,
        LIST_RESYNC_NOTIFY    = 0x0101,
        TASK_CANCEL           = 0x1000
    };
```

Per-command request shape (the `req` object — line numbers for the assemblers in `PrinterFileSystem.cpp`):

| Cmd | Hex | Origin | `req` fields | Stock plugin maps to |
|-----|----:|--------|--------------|----------------------|
| `LIST_INFO` | `0x0001` | `BuildFileList` (`...:160-175`) | `{ notify, type, storage }` (`type` ∈ {`timelapse`,`video`,`model`}) | :6000 firmware wire; honours `storage` (Internal vs External) |
| `SUB_FILE` | `0x0002` | thumbnail / partial fetch (`...:500-540`) | `{ path, name, offset, size, ... }` | :6000 firmware wire |
| `FILE_DEL` | `0x0003` | `DeleteFiles` (`...:776-799`) | `{ paths: [...] }` or `{ path, file }` | :6000 firmware wire |
| `FILE_DOWNLOAD` | `0x0004` | `DownloadFiles` (`...:811-829`) | `{ path, file }` (or `mem:/<idx>` for in-memory thumbnails) | :6000 firmware wire |
| `FILE_UPLOAD` | `0x0005` | **Chunked** (§8.14.2): init `{type,storage,path,total}` → N× `{frag_id,offset,size[,file_md5]}` + binary; **or** legacy one-shot `{path,file,size,md5,…}` + binary (P2S: one-shot fails for large files) | :6000 firmware wire; Send to Printer uses `ft_*` in `libbambu_networking`, not `libBambuSource` |
| `REQUEST_MEDIA_ABILITY` | `0x0007` | media abilities probe (`...:1228-1240`) | `{}` | static answer from stock plugin / firmware |
| `TASK_CANCEL` | `0x1000` | `CancelRequests` (`...:1469-1483`) | `{ tasks: [seq, seq, ...] }` | cancel in-flight work on the :6000 session |
| `LIST_CHANGE_NOTIFY` | `0x0100` | printer-initiated | "the file list changed, please refresh" | re-emits `LIST_INFO` to Studio |
| `LIST_RESYNC_NOTIFY` | `0x0101` | printer-initiated | "the printer reset its file index" | full re-fetch |

On P2S, stock file-browser bytes stay on :6000 only (§9.5.1); wire framing in [§6.4](06.04-port-6000.md).

#### 9.6.1. Storage selection (`req.storage`)

Studio's `LIST_INFO` requests carry a **`storage`** field when the printer reports internal timelapse support (`is_support_internal_timelapse` from MQTT `print.fun`):

| `req.storage` | Studio UI tab | Stock behaviour (P2S, inferred) |
|---------------|---------------|----------------------------------|
| absent or `""` | **External** | :6000 wire → external volume (USB when mounted) |
| `"internal"` | **Internal** (eMMC timelapses) | :6000 wire → internal volume |

Older Studio builds also used logical labels **`sdcard`** / **`usb`** in `REQUEST_MEDIA_ABILITY` replies and some `LIST_INFO` requests.

#### 9.6.1.1. Observed FTPS filesystem layout (LAN probe)

FTPS :990 is a **separate** service from the stock file browser (§9.5.1). Layout below is from direct `CWD`/`LIST` probes — relevant for **`verify_job` preflight** (§8.14.3) and legacy LAN print `STOR`. **Not** used for P2S Device → Files (native `:6000`) or Send-to-Printer cache upload (`:6000` `ft_*`, §8.14.2).

**P2S (May 2026):**

| USB state | FTPS root (`LIST /`) | `/timelapse` | eMMC / internal paths (`/emmc`, `/internal`, …) |
|-----------|----------------------|--------------|--------------------------------------------------|
| USB inserted | USB stick contents | exists (often empty) | `CWD` → `550` |
| USB removed | **0 entries** | `CWD` → `550` | `CWD` → `550` |

Internal timelapse files visible in stock Studio's **Internal** tab are **not** reachable through this FTPS view on P2S.

FTPS storage layout on other printer families has **not** been probed for this document.

#### 9.6.2. The tunnel keeps Studio requests sequenced

There are no concurrent CTRL requests on the same tunnel: `PrinterFileSystem::RunRequests` serialises everything on the worker thread, holding `m_mutex` between `Bambu_SendMessage` and the matching `Bambu_ReadSample`. Stock `libBambuSource` forwards each request/response pair over its single :6000 socket in that order.

**`ft_*` is different.** Send to Printer (`libbambu_networking.so`) opens its **own** TLS `:6000` session and may run **`cmd_type=7` ability** then **`cmd_type=5` upload** back-to-back on the same socket without re-handshaking. Clients must drain stale framed JSON and match `cmdtype` + `sequence` on every reply (§8.14.2). Do not assume the strict request/response pairing of the file-browser worker thread applies verbatim to `ft_*`.

#### 9.6.3. FTPS dialect quirks

Implicit TLS `:990`, PASV/data-TLS ordering, and related dialect notes: **[§6.3](06.03-ftps.md)**. Proxy for ordinary FTP clients: [`tools/bambu_ftp_proxy.py`](../tools/bambu_ftp_proxy.py). Layout probe notes remain in §9.6.1.1 above.

### 9.7. Lifetime, error propagation and reconnect

A few practical contracts that the Studio code path enforces but does not document:

- **Tunnel ownership**. Studio creates one tunnel per UI tab. The camera tab and the file-browser tab live on different `Bambu_Tunnel` handles even though they target the same printer IP. The plugin must not share state across them.
- **`Bambu_would_block` is not an error**. Both `Bambu_Open` and `Bambu_StartStream*` are expected to be polled (`PrinterFileSystem.cpp:1747-1758`, `gstbambusrc.c` does the same). Studio retries with a 100 ms backoff for up to 3-5 seconds, then gives up.
- **`Bambu_ReadSample` controls the wakeup cadence**. On the file-browser tunnel the worker calls `Bambu_ReadSample` with no separate condvar — it relies on the plugin returning `Bambu_would_block` instead of blocking forever. A plugin that blocks indefinitely freezes the tab.
- **Negative return values are fatal**. Anything outside `{0, Bambu_stream_end, Bambu_would_block, Bambu_buffer_limit}` makes Studio call `Bambu_Close` + `Bambu_Destroy` and try to re-open the tunnel from scratch. (`PrinterFileSystem.cpp:1577-1593`.)
- **Logger callback is signal-safe**. `Bambu_SetLogger` is invoked from arbitrary threads; the receiving callback inside Studio (`bambu_log` in `wxMediaCtrl3.cpp` for current Windows/Linux Studio, `bambu_log` in `wxMediaCtrl2.mm` for macOS, `DumpLog` in `PrinterFileSystem.cpp` for the file browser everywhere) is wrapped to be reentrant. The plugin must not assume the callback runs on a particular thread. On Windows the logger receives `wchar_t const*` strings (a UTF-16 buffer), on POSIX it receives `char const*` (UTF-8); the plugin must allocate accordingly because Studio frees each message with `Bambu_FreeLogMsg`.
- **Race between `Bambu_Close` and a streaming reader**. Studio assumes that once `Bambu_Close` returns it is safe to also call `Bambu_Destroy`, even if another thread was blocked inside `Bambu_ReadSample` a microsecond earlier. A correct plugin must therefore either gracefully unblock the reader (via `shutdown(SHUT_RDWR)` on the underlying socket, etc.) or serialise the two; failing to do so manifests as a use-after-free during reconnect.

### 9.8. Map of `libBambuSource`-related source locations

| Topic | File:lines |
|-------|------------|
| C ABI declarations / function-pointer table | [BambuTunnel.h](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/BambuTunnel.h) |
| Loader (`StaticBambuLib`) | [PrinterFileSystem.cpp:1840-1879](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.cpp#L1840-L1879) |
| `dlopen`/`LoadLibrary` of `libBambuSource` | [NetworkAgent.cpp:529-580](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/NetworkAgent.cpp#L529-L580) |
| Public accessor `get_bambu_source_entry` | [NetworkAgent.cpp:529-580](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/NetworkAgent.cpp#L529-L580) |
| Linux/Windows camera widget — current Studio (FFmpeg-based) | [wxMediaCtrl3.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl3.cpp), [wxMediaCtrl3.h](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl3.h), [AVVideoDecoder.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/AVVideoDecoder.cpp), [AVVideoDecoder.h](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/AVVideoDecoder.h) |
| Linux camera back-end (gstbambusrc, used by Orca / legacy Studio) | [gstbambusrc.c](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/gstbambusrc.c), `gstbambusrc.h` |
| Windows camera back-end (DirectShow filter, COM CLSID — Orca / legacy Studio only) | [wxMediaCtrl2.cpp:55-138](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl2.cpp#L55-L138) |
| macOS camera (`BambuPlayer` Objective-C) | [wxMediaCtrl2.mm:245-289](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl2.mm#L245-L289), [BambuPlayer.h](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/BambuPlayer/BambuPlayer.h) |
| Camera URL formats (`bambu:///local/`, `rtsps___`, `rtsp___`) | [MediaPlayCtrl.cpp:444-455](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/MediaPlayCtrl.cpp#L444-L455), [MediaPlayCtrl.cpp:742-760](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/MediaPlayCtrl.cpp#L742-L760) |
| File-browser `CTRL_TYPE` constant | [PrinterFileSystem.h:32](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.h#L32) |
| File-browser command codes (`LIST_INFO` etc.) | [PrinterFileSystem.h:34-45](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.h#L34-L45) |
| File-browser error codes | [PrinterFileSystem.h:48-72](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.h#L48-L72) |
| CTRL JSON envelope (`cmdtype`/`sequence`/`req`) | [PrinterFileSystem.cpp:1439-1478](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.cpp#L1439-L1478) |
| CTRL response dispatch | [PrinterFileSystem.cpp:1567-1606](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.cpp#L1567-L1606) |
| Camera UI panel and state machine | [MediaPlayCtrl.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/MediaPlayCtrl.cpp) |

---

