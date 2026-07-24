## 7. The `libBambuSource` library

This second module is the one Studio talks to whenever the user opens a printer's **camera live view** or the **on-printer file browser** (under "Device" → "SD Card / USB"). It has nothing in common with `bambu_networking` apart from packaging — different symbol prefix (`Bambu_*`), different loader, different per-platform back-ends. Bambu's stock shipment puts it at the same `<data_dir>/plugins/` path as the main networking plugin, but a missing or stub `libBambuSource` does not stop Studio from starting; only camera/file-browser features get disabled.

Reverse-engineered from the upstream BambuStudio tree (see **Source path convention** at the top). OrcaSlicer keeps the same logic under the same file names except the `dlopen` helper: Orca names it `BBLNetworkPlugin::get_source_module()` in `src/slic3r/Utils/BBLNetworkPlugin.cpp` (Orca tree only — that file does not exist in BambuStudio).

### 7.1. Loading and discovery

Bambu Studio resolves `libBambuSource` lazily, on the first time a camera or file-browser tab is shown:

```523:575:src/slic3r/Utils/NetworkAgent.cpp
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
- There is no signature check on this module, no version-prefix gate, no fall-back to `<data_dir>/plugins/backup/`. Studio either gets a non-null module, fishes out C symbols via `dlsym`/`GetProcAddress` (§7.2), and never touches it again, or it falls back to a `Fake_Bambu_Create` stub (§7.2) and the whole feature surface is disabled.
- The single public accessor is `Slic3r::NetworkAgent::get_bambu_source_entry()` (`src/slic3r/Utils/NetworkAgent.cpp:523-575`); the camera UI and the file browser both call it when they need this library.

### 7.2. C ABI surface (`Bambu_*`)

The header lives at `src/slic3r/GUI/Printer/BambuTunnel.h` and ships **both** as a static-link header (`#define BAMBU_DYNAMIC` off) and as a dlopen function-pointer table (`BAMBU_DYNAMIC` on, `typedef struct __BambuLib { ... } BambuLib`). Studio uses the dlopen path: `PrinterFileSystem.cpp` defines

```cpp
class PrinterFileSystem : ..., BambuLib { ... };
```

i.e. it inherits the function-pointer table directly into the file-browser object. The pointers are wired up by `StaticBambuLib`:

```1831:1867:src/slic3r/GUI/Printer/PrinterFileSystem.cpp
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
| `Bambu_StartStreamEx` | `int (Bambu_Tunnel, int type)` | camera + file-browser; `type = CTRL_TYPE = 0x3001` switches the tunnel into JSON-RPC mode (§7.5) |
| `Bambu_GetStreamCount` / `Bambu_GetStreamInfo` | `int (...)` | camera; describe the video / audio tracks once `StartStream` has succeeded |
| `Bambu_GetDuration` / `Bambu_Seek` | `unsigned long (...) / int (...)` | declared but not exercised on a live LAN stream |
| `Bambu_ReadSample` | `int (Bambu_Tunnel, Bambu_Sample*)` | camera (one MJPG / H.264 access unit per call) **and** file-browser (one JSON response per call) |
| `Bambu_SendMessage` | `int (Bambu_Tunnel, int ctrl, const char* data, int len)` | file-browser only — sends a CTRL JSON request (§7.5) |
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

### 7.3. URL formats Studio passes into `Bambu_Create`

Studio's two consumers each build their own URL.

#### 7.3.1. Camera live view

Built in `MediaPlayCtrl::Play` (`src/slic3r/GUI/MediaPlayCtrl.cpp:307-318`) and `MediaPlayCtrl::ToggleStream` (`...:551-559`):

```307:318:src/slic3r/GUI/MediaPlayCtrl.cpp
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

#### 7.3.2. File browser

Built in `PrinterFileSystem::Reconnect` via `MediaFilePanel`. Studio uses the same **URL shape** as the MJPEG camera (`bambu:///local/<ip>.?port=6000&user=<u>&passwd=<p>&...`) — same TCP port — but stock `libBambuSource` instantiates **`BambuTunnelLocal`** for LAN file browsing, **not** the MJPEG 80-byte auth path from [`video.md`](https://github.com/Doridian/OpenBambuAPI/blob/master/video.md). After `Bambu_Open` (TLS only) Studio calls `Bambu_StartStreamEx(tunnel, 0x3001)`, which runs a multi-step wire handshake (§7.5.1.1) before any `LIST_INFO` JSON appears on the wire. On printers that lack `StartStreamEx` (older firmwares), Studio falls back to `Bambu_StartStream(tunnel, false)` (`PrinterFileSystem.cpp:1747-1748`).

### 7.4. Per-platform camera back-end (the critical part)

This used to be the section where the three platforms diverged sharply, with **Windows** routing the camera through a DirectShow source filter inside `BambuSource.dll`. **That changed upstream in BambuStudio commit `94d91be60` ("NEW: reimpl wxMediaCtrl from ffmpeg", June 2024)**, which introduced `src/slic3r/GUI/wxMediaCtrl3.{cpp,h}`. Studio's `MediaPlayCtrl` was migrated to `wxMediaCtrl3` as part of the same series, and from that point on **Windows Studio uses the `Bambu_*` C ABI directly**, exactly like Linux: `wxMediaCtrl3::PlayThread` calls `Bambu_Create` → `Bambu_Open` → `Bambu_StartStream` → `Bambu_ReadSample`, then decodes each access unit with FFmpeg via `AVVideoDecoder` and blits the resulting `wxBitmap` into a plain `wxWindow`.

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

The subsections below describe each back-end. §7.4.1 (Linux gstbambusrc) and §7.4.3 (macOS BambuPlayer) are unchanged. §7.4.2 (Windows DirectShow) is now an Orca-only / legacy-Studio path. §7.4.4 documents the new `wxMediaCtrl3` flow that current Studio actually uses on Windows.

#### 7.4.1. Linux: `gstbambusrc` baked into Studio

`wxMediaCtrl2::wxMediaCtrl2()` (`src/slic3r/GUI/wxMediaCtrl2.cpp:44-68`, in the `__LINUX__` branch) registers a custom GStreamer element after the underlying `wxMediaCtrl` has spun up its own playbin:

```44:68:src/slic3r/GUI/wxMediaCtrl2.cpp
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

`gstbambusrc_register` lives in `src/slic3r/GUI/Printer/gstbambusrc.c` — it is **statically linked into Studio's binary** (no plugin search path involved). The element handles the `bambu://` URI scheme; internally it calls the generic accessor `bambulib_get()`, which in turn returns the same `StaticBambuLib` pointer table used by the file browser:

```67:67:src/slic3r/GUI/Printer/gstbambusrc.c
BambuLib *bambulib_get();
```

```1883:1884:src/slic3r/GUI/Printer/PrinterFileSystem.cpp
extern "C" BambuLib *bambulib_get() {
    return &StaticBambuLib::get(); }
```

So on Linux the camera flow is:

1. `MediaPlayCtrl::Play` → `m_media_ctrl->Load(wxURI("bambu:///..."))`.
2. wxGStreamerMediaBackend builds the standard playbin with `bambusrc` as the source element.
3. `bambusrc` calls `BAMBULIB(Bambu_Create)(..., url)` etc., i.e. the C ABI from `libBambuSource.so`.
4. For MJPG streams the source emits JPEG access units; the playbin attaches `jpegdec ! videoconvert ! ximagesink`. For RTSPS streams the source emits raw H.264 byte stream and the playbin attaches `h264parse ! avdec_h264 / openh264dec ! videoconvert ! ximagesink`. Either way the slicer-side pipeline does the decode.

i.e. **on Linux the C ABI is sufficient**. No Linux-specific code needs to live inside `libBambuSource.so`.

#### 7.4.2. Windows (Orca / legacy Studio): DirectShow filter, separate library

Note: this is the path **OrcaSlicer** and pre-`94d91be60` BambuStudio take on Windows. Current upstream BambuStudio (`wxMediaCtrl3`, see §7.4.4) bypasses DirectShow entirely and goes straight through the `Bambu_*` C ABI like Linux does.

`wxMediaCtrl2::Load` (the Windows branch) drops `wxURI("bambu:...")` into `wxMediaCtrl::Load`, which uses wxWidgets's `wxMediaBackendDirectShow`. wxWidgets resolves the URL by looking up `HKCR\bambu\Source Filter` in the registry to find the CLSID that handles `bambu:` URLs, then `CoCreateInstance`s that CLSID and asks the resulting filter to load the URL via `IFileSourceFilter::Load`. Studio expects a custom **DirectShow source filter** to be COM-registered against the URL scheme `bambu:`:

```95:138:src/slic3r/GUI/wxMediaCtrl2.cpp
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
- For Orca / legacy Studio, the C ABI from §7.2 is **not used** for camera output — it is exclusively the file browser path. The DirectShow filter is a separate code path inside the same DLL.

Practical consequence (Orca / legacy Studio only): stock `BambuSource.dll` must expose a DirectShow source filter registered against `bambu:` for camera playback; the C ABI alone covers the file browser on Windows.

Stock filter internals are closed source. Studio-side contract inferred from `wxMediaCtrl2` / wxWidgets (Orca / legacy Studio):

1. **`wxURI` normalises `bambu:///rtsps___…` to `bambu://rtsps___…`** before calling `IFileSourceFilter::Load`. The triple-slash form is what `MediaPlayCtrl::load()` produces (no host, path = `/rtsps___user:pwd@ip/...`), but wxURI's "authority is empty" canonicaliser interprets `rtsps___user:pwd` as userinfo and `ip` as host, then re-emits the URI with a single `//`. A parser keyed strictly off `bambu:///rtsps___` will reject every Orca camera URL with `E_INVALIDARG`. Accept any number of `/` characters after `bambu:` (1, 2, or 3).
2. **DirectShow graphs stay in `Paused` until the first sample arrives.** wxMediaCtrl2 / wmp keeps the filter graph in `State_Paused` until the renderer receives its first sample (which triggers the transition to `State_Running`). A source filter that gates `IMemInputPin::Receive` on `State_Running` deadlocks playback.

#### 7.4.3. macOS: Objective-C `BambuPlayer` class inside the dylib

On macOS Studio does **not** use wxMediaCtrl's GStreamer/AVFoundation back-end. Instead, `wxMediaCtrl2.mm` reaches directly into `libBambuSource.dylib` and looks up an Objective-C class by the synthetic name `OBJC_CLASS_$_BambuPlayer`:

```67:85:src/slic3r/GUI/wxMediaCtrl2.mm
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

The expected interface is documented in `src/slic3r/GUI/BambuPlayer/BambuPlayer.h:14-28`:

```14:28:src/slic3r/GUI/BambuPlayer/BambuPlayer.h
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

#### 7.4.4. Windows (current Studio): `wxMediaCtrl3` + FFmpeg, C ABI directly

In commit `94d91be60` ("NEW: reimpl wxMediaCtrl from ffmpeg"), upstream BambuStudio replaced the platform-specific `wxMediaCtrl2` widget with `wxMediaCtrl3`, a self-contained widget that:

1. Inherits from `BambuLib` (the `StaticBambuLib` shim from `PrinterFileSystem.cpp`) so it can call every `Bambu_*` symbol directly without going through any wxWidgets media backend.
2. Owns a single play-thread (`PlayThread`) that walks the entire `Bambu_*` lifecycle — `Bambu_Create` → `Bambu_SetLogger` → `Bambu_Open` → spin on `Bambu_StartStream(true)` until it stops returning `Bambu_would_block` → `Bambu_GetStreamInfo` → loop on `Bambu_ReadSample` → `Bambu_Close` / `Bambu_Destroy` — exactly the way Linux's `gstbambusrc` does.
3. Decodes each access unit with FFmpeg via the new `AVVideoDecoder` helper, packages it into a `wxBitmap` (Windows) or `wxImage` (Linux), pushes it through a small ring buffer (`m_frame_buffer`), and renders it from a wxTimer onto a plain `wxWindow`.

Cross-references in the BambuStudio tree:

- `src/slic3r/GUI/wxMediaCtrl3.{cpp,h}` — the widget itself and the play-thread (`wxMediaCtrl3::PlayThread` at `wxMediaCtrl3.cpp:260-405`).
- `src/slic3r/GUI/AVVideoDecoder.{cpp,h}` — wraps FFmpeg's `avcodec_send_packet` / `avcodec_receive_frame` and hands the raw planes back as a wxBitmap or wxImage.
- `src/slic3r/GUI/MediaPlayCtrl.cpp:49` — the constructor takes `wxMediaCtrl3 *media_ctrl`, replacing the old `wxMediaCtrl2 *` from earlier revisions.

On **current Windows BambuStudio** the camera reaches `libBambuSource` through the same C-ABI surface as Linux. The Windows logger callback expects `wchar_t const*` strings (the `tchar` typedef in `BambuTunnel.h`); POSIX builds use `char const*` (UTF-8).

Studio's `wxMediaCtrl3` does **not** consult the registry, does **not** call `CoCreateInstance`, and does **not** require the DirectShow filter to be registered. On Windows, current BambuStudio uses only the `Bambu_*` C ABI for camera playback; OrcaSlicer and pre-`94d91be60` Studio still require the DirectShow filter to be registered (`regsvr32 /s BambuSource.dll`). Stock `BambuSource.dll` is therefore expected to export both surfaces on Windows.

#### 7.4.5. Recap

| Slicer | Platform | Camera back-end | What `libBambuSource` must provide |
|--------|----------|-----------------|------------------------------------|
| BambuStudio post-`94d91be60` (current) | Linux | `wxMediaCtrl3` → `Bambu_*` C ABI → FFmpeg → wxWindow | The `Bambu_*` C ABI (§7.2) only |
| BambuStudio post-`94d91be60` (current) | Windows | `wxMediaCtrl3` → `Bambu_*` C ABI → FFmpeg → wxWindow | The `Bambu_*` C ABI (§7.2) only |
| BambuStudio post-`94d91be60` (current) | macOS | `wxMediaCtrl2.mm` → `dlsym(libBambuSource.dylib, "OBJC_CLASS_$_BambuPlayer")` *(`wxMediaCtrl3` was not adopted on macOS — the platform still goes through the Objective-C class)* | Both the `Bambu_*` C ABI **and** the Objective-C `BambuPlayer` class |
| OrcaSlicer (current) and BambuStudio pre-`94d91be60` | Linux | `wxMediaCtrl2` → `gstbambusrc` (statically linked into Studio) → `bambulib_get()` → `Bambu_*` C ABI | The `Bambu_*` C ABI (§7.2) only |
| OrcaSlicer (current) and BambuStudio pre-`94d91be60` | Windows | `wxMediaCtrl2` → `wxMediaCtrl::Load` → wxWidgets DirectShow backend → COM source filter (CLSID `{233E64FB-…}`) inside `BambuSource.dll` | A DirectShow `IBaseFilter`/`IFileSourceFilter` implementation registered against `bambu:`. The `Bambu_*` C ABI is **not** used for video; only for the file browser |
| OrcaSlicer (current) and BambuStudio pre-`94d91be60` | macOS | same as current Studio (Objective-C `BambuPlayer`) | same |

In every case the file-browser path uses **only** the `Bambu_*` C ABI plus the CTRL JSON wire protocol described next.

### 7.5. CTRL mode (file-browser RPC over the camera tunnel)

When Studio opens a file browser, it uses the same `Bambu_Create` / `Bambu_Open` URL as the LAN camera, then calls `Bambu_StartStreamEx(tunnel, CTRL_TYPE = 0x3001)`:

```32:32:src/slic3r/GUI/Printer/PrinterFileSystem.h
    static const int CTRL_TYPE     = 0x3001;
```

On LAN, stock `libBambuSource` routes this through **`BambuTunnelLocal`** (`createBambuTunnelLocal` in the plugin binary): `Bambu_Open` is TLS connect only; `Bambu_StartStreamEx(0x3001)` sends the subchannel login + `mtype` 12291 setup frames documented in §7.5.1.1. Only after that handshake completes does the tunnel accept framed CTRL JSON (`mtype` 12289) for `LIST_INFO` / `SUB_FILE` / …

```1747:1758:src/slic3r/GUI/Printer/PrinterFileSystem.cpp
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

Both run on a dedicated worker thread inside `PrinterFileSystem::Reconnect` / `RunRequests` (`src/slic3r/GUI/Printer/PrinterFileSystem.cpp:1567-1595`).

#### 7.5.1. Where the printer-side bytes actually come from

From Studio's perspective the file browser is JSON over the `Bambu_*` ABI (`Bambu_SendMessage` / `Bambu_ReadSample`). **Stock `libBambuSource`** forwards that traffic to printer firmware over a long-lived **TLS :6000** socket (`BambuTunnelLocal` + `LocalTunnel_*` + `tutk_third_SSL_*` inside the plugin):

| Channel | Endpoint | Direction | Carries |
|---------|----------|-----------|---------|
| CTRL / file data | TLS over TCP/**6000** (opened by `Bambu_Open`, kept open) | PC ↔ printer firmware | Subchannel-framed bytes (§7.5.1.1): login, `StartStreamEx` setup, then JSON RPC + optional binary blobs |

**Evidence (P2S, May 2026).** LAN capture while using stock Studio Device → Files (Wireshark filter `ip.addr==<printer> && tcp.port != 8883`):

- **External** tab (empty list): small request/response exchange on :6000 only.
- **Internal** tab (timelapse list + JPEG previews): ~66 KiB server→client on :6000 only.
- **Zero packets on FTPS :990** during the same session.

Payload on :6000 is TLS application data (opaque in Wireshark unless decrypted). The **on-wire framing** is documented in §7.5.1.1 (reverse-engineered May 2026 from stock `libBambuSource.so` + live probes against P2S).

**Multiple clients.** Unlike an earlier working assumption, the printer **does allow several simultaneous TLS :6000 sessions** (verified with two independent REPL connections while Studio also had Files open). There is no exclusive lock on the port.

**Do not conflate `:6000` with FTPS `:990`.** Print/upload paths that touch either port on P2S:

| Use | Library | When | Upload transport |
|-----|---------|------|------------------|
| Device → Files browse (external USB) | `libBambuSource` (`:6000`) | File browser tab | N/A (lists/downloads only) |
| **`verify_job` preflight** | `libbambu_networking` | `PrintJob` LAN preflight; optional before Send to Printer | Tiny FTPS `STOR verify_job` only |
| Legacy Send-to-Printer fallback | `libbambu_networking` | `SendJob` when `!is_support_brtc` | Full `.3mf` over FTPS `STOR` — not used on P2S |
| Hybrid / fake “with record” | `libbambu_networking` | `start_local_print_with_record` | FTPS `STOR` + `ftp://` PATCH, then **full S3** + https PATCH; `/my/task` `lan_file`; printer prints **S3** (§6.8.1) — not a real LAN print |
| Pure LAN model (P2S stock) | `libbambu_networking` | `start_local_print` | Full `.3mf` over **`:6000`**; MQTT URL `brtc://emmc/…` (§6.8.1.2) |

Stock **Send to Printer → cache** on P2S: **`verify_job` FTPS probe (optional) + `:6000` chunked upload** — not a full FTPS model transfer.

**Do not conflate with MJPEG auth.** The 80-byte `0x3000` auth block in [`video.md`](https://github.com/Doridian/OpenBambuAPI/blob/master/video.md) applies to **MJPEG live view on A1 / P1 / P1P** (`BambuTunnelLocal` is still used on some paths, but the camera stream uses different post-auth bytes). Sending that 80-byte packet on a P2S file-browser session yields a 24-byte `0x0003013f` ack and the peer closes — it is the wrong handshake.

Internal timelapse **recording** during print (`task_timelapse_use_internal` → MQTT `project_file` `"cfg":"4"`) is handled by **`libbambu_networking`**, not the file-browser CTRL path documented here.

#### 7.5.1.1. The `:6000` protocol (`BambuTunnelLocal` wire) — canonical reference

This is the single canonical description of the printer's `:6000` LAN service (reverse-engineered on **P2S**, May 2026; likely shared across models that expose `bambu:///local/...:6000`). It is the same wire for **both** consumers that use it: the **file-browser CTRL** path in `libBambuSource.so` (Device → Files, `BambuTunnelLocal`, *not* the cloud TUTK UID path `BambuTunnelTutk` / `IOTC_Connect_ByUIDEx`) and the **file-transfer** path (`ft_*` model upload, ABI mapping in §6.14). The framing, handshake and command set below apply to both; the ABI-specific bits live in §6.14, and the per-command `req`/response shapes in §7.6/§7.5.3.

**Transport and login.** TCP `:6000`, **implicit TLS** immediately after connect (leaf cert `CN=<serial>`, same LAN-TLS policy as §6.1.1). The application-layer login uses `user="bblp"` + the 8-character access code (the same code used for FTPS `:990` and the LAN MQTT password). The printer allows **several simultaneous `:6000` TLS sessions** — there is no exclusive lock on the port.

**Stack:**

```text
TCP :6000
  └─ TLS (implicit; OpenSSL — tutk_third_SSL_connect wrapper in libBambuSource)
       └─ subchannel 0x01  login
       └─ subchannel 0x02  StartStreamEx setup + all CTRL JSON / binary
```

**Common frame header** (16 bytes, little-endian, sent as its own `tutk_third_SSL_write` followed by a second write for the payload when `payload_len > 0`):

| Offset | Field | Notes |
|--------|-------|-------|
| 0–3 | `payload_len` | Byte length of payload **following** this header (may be `0`) |
| 4–7 | `magic` | `0xNNMM013f` — see table below (`NN` = subchannel, byte at offset 6; byte at offset 7 = direction) |
| 8–11 | `seq` | Monotonic per-session counter (stock seeds from `rand()` in `BambuTunnelLocal::open`) |
| 12–15 | reserved | `0` |

**Magic values observed:**

| Value (LE u32) | Direction | Subchannel | Purpose |
|----------------|-----------|------------|---------|
| `0x0101013f` | client → printer | `0x01` | Login |
| `0x0001013f` | printer → client | `0x01` | Login ack (typically 4 zero bytes) |
| `0x0102013f` | client → printer | `0x02` | CTRL setup + RPC |
| `0x0002013f` | printer → client | `0x02` | CTRL replies / streaming data |

Byte at offset **7** of the magic distinguishes client (`0x01`) vs server (`0x00`) frames. Subchannel is byte at offset **6** (`0x01` login, `0x02` CTRL).

**Session bootstrap** (matches `BambuTunnelLocal::start(0x3001)` in stock `libBambuSource.so`):

1. **`Bambu_Open`** — `LocalTunnel_Open`: TCP connect + TLS handshake. **No** 80-byte `0x3000` auth on this path.

2. **Subchannel `0x01` login** — header (`payload_len = 16`, magic `0x0101013f`) + 16-byte payload:
   - bytes 0–7: username, ASCII, NUL-padded (Studio sends `"bblp"`)
   - bytes 8–15: LAN access code, ASCII, NUL-padded (8 chars from printer screen)

3. **Subchannel `0x02` `StartStreamEx` setup** — one JSON object (stock `snprintf` format in the plugin), sent with magic `0x0102013f`:

```json
{"sequence":0,"mtype":12291,"req":{"t_av":1,"mtype":12289,"peer_t":3,"pid":"<clientId>","ver":"<cli_ver>"}}
```

   - Outer `mtype` **12291** = `0x3003` (setup)
   - Inner `req.mtype` **12289** = `0x3001` (= Studio's `CTRL_TYPE`)
   - `pid` / `ver` come from URL query params `cli_id` / `cli_ver` when present; stock falls back to an 8-char id derived from the session counter

   Printer replies with a short JSON ack, e.g. `{"mtype":12291,"sequence":0,"result":0,"reply":{}}`.

4. **Subchannel `0x02` RPC** — each `Bambu_SendMessage` JSON body is wrapped for the wire as:

```json
{"mtype":12289,"cmdtype":1,"sequence":1,"req":{...}}
```

   i.e. the Studio-side object from §7.5.2 gains a leading `"mtype":12289,` (+14 bytes) before framing. Large replies (e.g. `SUB_FILE` thumbnails) append `\n\n` + binary **inside the payload** after the JSON; stock `Bambu_ReadSample` returns the combined buffer to Studio unchanged.

**Frida / packet-capture caveat.** Hooking the TLS write primitive **after** Device → Files is already open shows **only step 4** (16-byte header + ~100–200 B JSON). Steps 1–3 (login + `StartStreamEx` setup) happen during `Bambu_Open` / `Bambu_StartStreamEx` before browsing, so a full capture must attach before the browser opens, or drive the socket directly with [`tools/bambu6000_repl.py`](../tools/bambu6000_repl.py) (which performs login + setup itself, so the whole handshake is under your control).

**RE tooling in this repo (how to reproduce the wire).** These scripts drive / observe the `:6000` protocol directly and were used to reverse-engineer everything above:

| Tool | Role | Typical use |
|------|------|-------------|
| [`tools/bambu6000_repl.py`](../tools/bambu6000_repl.py) | Interactive TLS `:6000` client; performs login + `mtype` 12291 setup, then auto-frames each JSON line you type | `python3 tools/bambu6000_repl.py <ip> <access_code>` then type e.g. `{"cmdtype":1,"req":{"api_version":2,"notify":"DETAIL","type":"timelapse"}}`; `/ability`, `/upload <file> emmc`, `/download mem:/26 out.jpg` are built-in helpers |
| [`tools/bambu6000_ftp_proxy.py`](../tools/bambu6000_ftp_proxy.py) | Plain-FTP ↔ `:6000` bridge (default `127.0.0.1:2122`); virtual `/external/*` and `/internal/*` trees map to `LIST_INFO` / `FILE_DOWNLOAD` / upload / delete | Point any FTP client at `ftp://127.0.0.1:2122` to browse/pull printer files without speaking the raw framing |
| [`tools/repl_upload_sweep.py`](../tools/repl_upload_sweep.py) | Batch regression: repeated pipeline uploads, optional delete, same-session stress | Confirms the chunked pipeline is stable across many uploads on one session |
| [`tools/upload_experiments.py`](../tools/upload_experiments.py) | Matrix of upload wire variants (one-shot, per-chunk ACK, md5/separator permutations) | How the "P2S rejects one-shot / requires pipelined chunks" facts above were established |
| [`tools/tutk_ssl_log.js`](../tools/tutk_ssl_log.js) + [`tools/frida_tutk_attach.sh`](../tools/frida_tutk_attach.sh) | Frida hooks on stock `libBambuSource.so` (`Bambu_SendMessage`, `Bambu_ReadSample`, `tutk_third_SSL_*`) | Attach *before* opening Device → Files to capture the login + setup frames that a late hook misses |

**Example `LIST_INFO` round-trip** (External timelapse, after handshake):

```text
C→P  hdr(101, 0x0102013f) + {"mtype":12289,"cmdtype":1,"sequence":1,"req":{"api_version":2,"notify":"DETAIL","type":"timelapse"}}
P→C  hdr(310, 0x0002013f) + {"cmdtype":1,"mtype":12289,"reply":{"file_lists":[...]},"result":0,"sequence":1}
```

**Command set (`cmdtype`).** Every RPC carries a `cmdtype` selecting the operation. The enum and the per-command `req` field shapes are tabulated in §7.6; every reply carries a `result` integer from the error enum in §7.5.3. The commands whose *wire flow* is more than a single request/response are detailed below.

**`FILE_UPLOAD` (5) — chunked pipeline.** Large model uploads (multi-MB `.3mf`) use a two-phase, pipelined flow (a single one-shot `{path,file,size,md5}` + whole file is **rejected** by P2S firmware for large files — connection reset / `-9203`):

```text
# Phase 1 — init (JSON only)
C→P  {"cmdtype":5,"sequence":N,"req":{"type":"model","storage":"emmc","path":"<name>.3mf","total":<bytes>}}
P→C  {"cmdtype":5,"sequence":N,"result":1,"reply":{"chunk_size":255,"offset":0}}    # result 1 = CONTINUE

# Phase 2 — data fragments (same sequence N, increasing frag_id); file_md5 on the LAST chunk
C→P  {"mtype":12289,"cmdtype":5,"sequence":N,"req":{"frag_id":0,"offset":0,"size":261120}}  + "\n\n" + <261120 bytes>
     …
C→P  {"cmdtype":5,"sequence":N,"req":{"frag_id":K,"offset":…,"size":…,"file_md5":"<hex>"}} + "\n\n" + <tail bytes>
P→C  {"cmdtype":5,"sequence":N,"result":0}                                                  # 0 = SUCCESS
```

Two protocol details that are easy to miss:

- **`chunk_size` in the init reply is in kibibytes, not bytes.** `"chunk_size":255` means ~255 KiB per fragment, i.e. each `size` on the wire is `chunk_size * 1024` (except the final, shorter tail).
- **The connection is full-duplex during Phase 2.** While the client is still writing fragment bodies, the printer emits progress/interim reply frames on the same socket. The client **must keep draining** those frames as it sends; if it only writes and never reads, the peer's send buffer backs up and the printer **resets the connection** mid-upload.

**`FILE_DOWNLOAD` (4) — mem preview.** In-memory thumbnails/previews are addressed as `mem:/<idx>`; the wire request is `{"cmdtype":4,"sequence":N,"req":{"path":"mem:/26","offset":0}}` (no `is_mem_file` on the wire). The reply streams the JPEG in fragments carrying `frag_id` / `offset` / `size` / `total`, with `file_md5` on the final fragment (`result:0`).

**`REQUEST_MEDIA_ABILITY` (7) — storage probe.** `{"cmdtype":7,"sequence":N,"req":{"peer":"studio","api_version":<v>}}` returns a JSON **array of storage labels** the printer can write, e.g. `["emmc","udisk"]` on P2S. Observed `api_version` values differ by firmware/client (2 or 3); `peer` identifies the requesting side.

**Storage labels.** The `storage` value in `FILE_UPLOAD`/`LIST_INFO` and the array from `REQUEST_MEDIA_ABILITY` use the labels `emmc` / `udisk` (physical volumes, current firmware) and, on older builds/logical views, `sdcard` / `usb` / `internal` / `external`. The label selects *where the file is written*; the print-start `url` scheme (§6.8.2) later selects *how firmware locates* it.

**Session semantics and scope.**

- The **file-browser CTRL** consumer keeps one request in flight at a time (serialised on a worker thread): strict request → response pairing, `sequence` echoed back to match callbacks.
- The **`ft_*` file-transfer** consumer keeps one session open across a `cmdtype=7` ability probe and a `cmdtype=5` upload back-to-back **without re-handshaking**, and does not assume strict pairing: a client must **drain or filter stale framed JSON** left from a prior command and **match replies on `cmdtype` + `sequence`**, not on a bare `result:0`.
- Do **not** conflate `:6000` with two neighbouring services: **FTPS `:990`** (a separate implicit-TLS FTP daemon, §7.6.1.1) and the **MJPEG `0x3000` 80-byte auth block** used for A1/P1 live view — sending that block on a `:6000` file session yields a 24-byte `0x0003013f` ack and the peer closes.

#### 7.5.2. ABI / Studio-side JSON: `Bambu_SendMessage` payload

This is the JSON **inside** `libBambuSource` before the plugin adds `"mtype":12289` and the §7.5.1.1 frame header for the LAN wire.

The serialiser is in `PrinterFileSystem::SendRequest` (`src/slic3r/GUI/Printer/PrinterFileSystem.cpp:1431-1458`):

```1431:1458:src/slic3r/GUI/Printer/PrinterFileSystem.cpp
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

- `cmdtype` is one of the `LIST_INFO`/`SUB_FILE`/`FILE_DEL`/`FILE_DOWNLOAD`/`FILE_UPLOAD`/`REQUEST_MEDIA_ABILITY`/`TASK_CANCEL` constants (§7.6).
- `sequence` is a monotonically increasing per-tunnel counter; the plugin echoes it in every response so Studio can match callbacks to requests.
- The optional `\n\n<param>` tail carries an inline binary blob. In practice Studio uses this only for the file-upload command; on the response side the plugin uses the same `\n\n<binary>` convention to deliver thumbnail bytes to Studio.

#### 7.5.3. ABI / Studio-side JSON: response envelope

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

### 7.6. CTRL command reference

This is the per-command `req`/response detail for the command set; the transport, framing, handshake and multi-frame flows are in the canonical `:6000` protocol reference (§7.5.1.1). The full set of `cmdtype` values is in `PrinterFileSystem.h:34-45`:

```34:45:src/slic3r/GUI/Printer/PrinterFileSystem.h
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
| `FILE_UPLOAD` | `0x0005` | **Chunked** (§6.14.2): init `{type,storage,path,total}` → N× `{frag_id,offset,size[,file_md5]}` + binary; **or** legacy one-shot `{path,file,size,md5,…}` + binary (P2S: one-shot fails for large files) | :6000 firmware wire; Send to Printer uses `ft_*` in `libbambu_networking`, not `libBambuSource` |
| `REQUEST_MEDIA_ABILITY` | `0x0007` | media abilities probe (`...:1228-1240`) | `{}` | static answer from stock plugin / firmware |
| `TASK_CANCEL` | `0x1000` | `CancelRequests` (`...:1469-1483`) | `{ tasks: [seq, seq, ...] }` | cancel in-flight work on the :6000 session |
| `LIST_CHANGE_NOTIFY` | `0x0100` | printer-initiated | "the file list changed, please refresh" | re-emits `LIST_INFO` to Studio |
| `LIST_RESYNC_NOTIFY` | `0x0101` | printer-initiated | "the printer reset its file index" | full re-fetch |

On P2S, stock file-browser bytes stay on :6000 only (§7.5.1); wire framing in §7.5.1.1.

#### 7.6.1. Storage selection (`req.storage`)

Studio's `LIST_INFO` requests carry a **`storage`** field when the printer reports internal timelapse support (`is_support_internal_timelapse` from MQTT `print.fun`):

| `req.storage` | Studio UI tab | Stock behaviour (P2S, inferred) |
|---------------|---------------|----------------------------------|
| absent or `""` | **External** | :6000 wire → external volume (USB when mounted) |
| `"internal"` | **Internal** (eMMC timelapses) | :6000 wire → internal volume |

Older Studio builds also used logical labels **`sdcard`** / **`usb`** in `REQUEST_MEDIA_ABILITY` replies and some `LIST_INFO` requests.

#### 7.6.1.1. Observed FTPS filesystem layout (LAN probe)

FTPS :990 is a **separate** service from the stock file browser (§7.5.1). Layout below is from direct `CWD`/`LIST` probes — relevant for **`verify_job` preflight** (§6.14.3) and legacy LAN print `STOR`. **Not** used for P2S Device → Files (native `:6000`) or Send-to-Printer cache upload (`:6000` `ft_*`, §6.14.2).

**P2S (May 2026):**

| USB state | FTPS root (`LIST /`) | `/timelapse` | eMMC / internal paths (`/emmc`, `/internal`, …) |
|-----------|----------------------|--------------|--------------------------------------------------|
| USB inserted | USB stick contents | exists (often empty) | `CWD` → `550` |
| USB removed | **0 entries** | `CWD` → `550` | `CWD` → `550` |

Internal timelapse files visible in stock Studio's **Internal** tab are **not** reachable through this FTPS view on P2S.

FTPS storage layout on other printer families has **not** been probed for this document.

#### 7.6.2. The tunnel keeps Studio requests sequenced

There are no concurrent CTRL requests on the same tunnel: `PrinterFileSystem::RunRequests` serialises everything on the worker thread, holding `m_mutex` between `Bambu_SendMessage` and the matching `Bambu_ReadSample`. Stock `libBambuSource` forwards each request/response pair over its single :6000 socket in that order.

**`ft_*` is different.** Send to Printer (`libbambu_networking.so`) opens its **own** TLS `:6000` session and may run **`cmd_type=7` ability** then **`cmd_type=5` upload** back-to-back on the same socket without re-handshaking. Clients must drain stale framed JSON and match `cmdtype` + `sequence` on every reply (§6.14.2). Do not assume the strict request/response pairing of the file-browser worker thread applies verbatim to `ft_*`.

#### 7.6.3. FTPS dialect quirks

Bambu firmware ships a stripped-down vsftpd / busybox-ftpd hybrid (the exact image varies across O1S / X1 / P1 / P2S / A-series) that deviates from RFC 959 / 4217 in several ways. None of these quirks appear in Studio source; the list below is from LAN probes against printer firmware:

- **Implicit TLS, TCP/990.** The TLS handshake starts immediately after the TCP `connect()`; there is no `AUTH TLS` upgrade dance. A plaintext FTP client that opens 990 and waits for a `220` banner gets nothing — the server is already in TLS mode.
- **Device cert CN = serial, no SAN.** The leaf certificate uses `CN=<serial>` (e.g. `22E8BJ610801473`) with **no** DNS/IP SAN entries. Clients connect by LAN IP but must verify hostname against the serial. On observed N7/P2S firmware the printer sends **only that leaf** in TLS; issuer is `BBL Device CA N7-V2`, which is **not** present in Studio's `printer.cer` bundle (v02.07) — see §6.1.1. **Stock plugin LAN TLS policy is unknown** — do not assume it skips verification.
- **Login is `USER bblp` + `PASS <printer-access-code>`.** The 8-character code shown on the printer screen is the FTPS password. There is no anonymous mode, and no other usernames are accepted.
- **Mandatory post-login sequence.** After `230` the client *must* issue `TYPE I` → `PBSZ 0` → `PROT P` in that order before any data-channel command. Skipping `PROT P` (or sending it before `PBSZ`) makes the next `PASV` reply `425`/`431` depending on firmware.
- **PASV only — `PORT` is not implemented.** The daemon either ignores `PORT` outright or replies `500 Unknown command`. Active mode is not negotiable.
- **PASV replies with a bogus IP.** The first four digits of the `(h1,h2,h3,h4,p1,p2)` tuple cannot be trusted: most firmwares advertise `0.0.0.0`, some leak a private printer-side address (`192.168.x.x` from the firmware's internal namespace) that is not reachable from the LAN. **Always discard those four octets and reconnect the data socket to the same host the control connection is on.**
- **Delayed TLS handshake on the data channel.** This is the single biggest gotcha. The wire order for a STOR/RETR/LIST is:
  1. send `PASV`, parse the reply, TCP-connect to the printer's data port (still plaintext);
  2. send the data command (`STOR foo` / `LIST` / …) on the control;
  3. wait for the `150` reply;
  4. **only now** start the TLS handshake on the data socket;
  5. transfer payload bytes;
  6. close (or `SSL_shutdown`) the data socket;
  7. read the `226`/`250` final reply on control.

  If the client tries to TLS-handshake right after the TCP connect (the order most generic FTPS libraries follow), the daemon never starts its half of the handshake and the connection hangs until the data timeout.
- **Data-channel TLS session reuse.** Bambu's current vsftpd build accepts data sockets without session reuse, but several adjacent FTPS forks (pureftpd hardened, newer vsftpd with `require_ssl_reuse=YES`) refuse otherwise. Safe to always opt in: pull the control session via `SSL_get1_session()` and bind it to the data SSL with `SSL_set_session()` before `SSL_connect()`.
- **`MLSD` is not implemented.** `FEAT` does *not* list `MLSD`, and an explicit `MLSD` call returns `500 Unknown command` on every observed firmware (O1S / X1 / P1 / P2S / A1). Use `LIST` exclusively. The output is plain `ls -l` with two date variants and timestamps in the printer's *local* time without a timezone hint:
  ```text
  -rwxr-xr-x  1 0 0     12345 Oct 21 12:34 name        # recent (HH:MM, year implicit)
  -rwxr-xr-x  1 0 0  98765432 Oct 21  2020 name        # old / future (year explicit, no HH:MM)
  ```
- **`NLST` is unreliable.** Some firmwares return clean filenames; others return the full `ls -l` block, and a few reply `502`. Treat `NLST` as a hint only and always be prepared to fall back to `LIST` + parse-and-extract-name.
- **No `MKD` / `RMD` / `APPE` / `REST` / `RNFR` / `RNTO` / `MDTM`.** Either the command is not wired up (response: `502 Command not implemented`) or it is gated off (response: `550`). In particular: you cannot create a directory over FTPS, and you cannot resume an interrupted `STOR` — Studio's "upload retry" flow re-uploads from byte 0. `SIZE` *is* implemented (`213 <bytes>`), `DELE` is implemented, `CWD` works, `PWD` is hit-and-miss across firmwares.
- **Idle timeout ≈ 5 minutes.** The control connection is torn down silently (no `421 Timeout` first) once it has been idle for roughly 5 minutes. The simplest fix is a reconnect-on-stale retry on the next request.
- **Strictly serial commands.** Pipelining or concurrent commands on the same control connection is not safe — the daemon can desynchronise its reply queue. Always wait for the previous reply (or, for data commands, the closing `226`) before sending the next command.
- **Only the bare command set is implemented.** From RFC 959 Bambu firmware reliably implements: `USER`, `PASS`, `TYPE` (`I` only — `A` is accepted but `STOR` of an ASCII file still ships the bytes verbatim), `PBSZ`, `PROT`, `PASV`, `LIST`, `RETR`, `STOR`, `DELE`, `SIZE`, `CWD`, `CDUP`, `PWD` (sometimes), `NOOP`, `QUIT`. Everything else is best-effort or missing.

### 7.7. Lifetime, error propagation and reconnect

A few practical contracts that the Studio code path enforces but does not document:

- **Tunnel ownership**. Studio creates one tunnel per UI tab. The camera tab and the file-browser tab live on different `Bambu_Tunnel` handles even though they target the same printer IP. The plugin must not share state across them.
- **`Bambu_would_block` is not an error**. Both `Bambu_Open` and `Bambu_StartStream*` are expected to be polled (`PrinterFileSystem.cpp:1747-1758`, `gstbambusrc.c` does the same). Studio retries with a 100 ms backoff for up to 3-5 seconds, then gives up.
- **`Bambu_ReadSample` controls the wakeup cadence**. On the file-browser tunnel the worker calls `Bambu_ReadSample` with no separate condvar — it relies on the plugin returning `Bambu_would_block` instead of blocking forever. A plugin that blocks indefinitely freezes the tab.
- **Negative return values are fatal**. Anything outside `{0, Bambu_stream_end, Bambu_would_block, Bambu_buffer_limit}` makes Studio call `Bambu_Close` + `Bambu_Destroy` and try to re-open the tunnel from scratch. (`PrinterFileSystem.cpp:1577-1593`.)
- **Logger callback is signal-safe**. `Bambu_SetLogger` is invoked from arbitrary threads; the receiving callback inside Studio (`bambu_log` in `wxMediaCtrl3.cpp` for current Windows/Linux Studio, `bambu_log` in `wxMediaCtrl2.mm` for macOS, `DumpLog` in `PrinterFileSystem.cpp` for the file browser everywhere) is wrapped to be reentrant. The plugin must not assume the callback runs on a particular thread. On Windows the logger receives `wchar_t const*` strings (a UTF-16 buffer), on POSIX it receives `char const*` (UTF-8); the plugin must allocate accordingly because Studio frees each message with `Bambu_FreeLogMsg`.
- **Race between `Bambu_Close` and a streaming reader**. Studio assumes that once `Bambu_Close` returns it is safe to also call `Bambu_Destroy`, even if another thread was blocked inside `Bambu_ReadSample` a microsecond earlier. A correct plugin must therefore either gracefully unblock the reader (via `shutdown(SHUT_RDWR)` on the underlying socket, etc.) or serialise the two; failing to do so manifests as a use-after-free during reconnect.

### 7.8. Map of `libBambuSource`-related source locations

| Topic | File:lines |
|-------|------------|
| C ABI declarations / function-pointer table | `src/slic3r/GUI/Printer/BambuTunnel.h` |
| Loader (`StaticBambuLib`) | `src/slic3r/GUI/Printer/PrinterFileSystem.cpp:1831-1877` |
| `dlopen`/`LoadLibrary` of `libBambuSource` | `src/slic3r/Utils/NetworkAgent.cpp:523-575` |
| Public accessor `get_bambu_source_entry` | `src/slic3r/Utils/NetworkAgent.cpp:523-575` |
| Linux/Windows camera widget — current Studio (FFmpeg-based) | `src/slic3r/GUI/wxMediaCtrl3.{cpp,h}`, `AVVideoDecoder.{cpp,h}` |
| Linux camera back-end (gstbambusrc, used by Orca / legacy Studio) | `src/slic3r/GUI/Printer/gstbambusrc.c`, `gstbambusrc.h` |
| Windows camera back-end (DirectShow filter, COM CLSID — Orca / legacy Studio only) | `src/slic3r/GUI/wxMediaCtrl2.cpp:71-138` |
| macOS camera (`BambuPlayer` Objective-C) | `src/slic3r/GUI/wxMediaCtrl2.mm:67-141`, `BambuPlayer/BambuPlayer.h` |
| Camera URL formats (`bambu:///local/`, `rtsps___`, `rtsp___`) | `src/slic3r/GUI/MediaPlayCtrl.cpp:307-318, 551-559` |
| File-browser `CTRL_TYPE` constant | `src/slic3r/GUI/Printer/PrinterFileSystem.h:32` |
| File-browser command codes (`LIST_INFO` etc.) | `src/slic3r/GUI/Printer/PrinterFileSystem.h:34-45` |
| File-browser error codes | `src/slic3r/GUI/Printer/PrinterFileSystem.h:48-72` |
| CTRL JSON envelope (`cmdtype`/`sequence`/`req`) | `src/slic3r/GUI/Printer/PrinterFileSystem.cpp:1431-1458` |
| CTRL response dispatch | `src/slic3r/GUI/Printer/PrinterFileSystem.cpp:1567-1596` |
| Camera UI panel and state machine | `src/slic3r/GUI/MediaPlayCtrl.cpp` |

---

