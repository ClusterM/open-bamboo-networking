## 9. The `libBambuSource` ABI contract

Second plugin module Studio loads for **camera live view** and the **on-printer file browser** (Device → SD Card / USB). Different symbol prefix (`Bambu_*`), different loader, and different per-platform camera back-ends from `bambu_networking`. Shipped next to the networking plugin under `<data_dir>/plugins/`; a missing or stub `libBambuSource` does not stop Studio from starting — only camera / file-browser features fail.

Reverse-engineered from the upstream BambuStudio tree (see **Source citations** in [§0](00-intro.md)). OrcaSlicer keeps the same logic under the same file names except the `dlopen` helper: `BBLNetworkPlugin::get_source_module()` in [BBLNetworkPlugin.cpp:286-325](https://github.com/SoftFever/OrcaSlicer/blob/11fdb472d6193312bc6c78b7703ad2c1222502b7/src/slic3r/Utils/BBLNetworkPlugin.cpp#L286-L325) (Orca-only).

Neighbors: TLS `:6000` wire ([§6.4](06.04-port-6000.md)); RTSP(S) ([§6.5](06.05-rtsp.md)); FTPS dialect ([§6.3](06.03-ftps.md)); cloud camera URL mint ([§8.11](08.11-camera.md)); Send-to-Printer `ft_*` ([§8.14](08.14-file-transfer.md)).


| Section | File |
| --- | --- |
| 9.1 Loading and discovery | [09.01-loading.md](09.01-loading.md) |
| 9.2 C ABI (`Bambu_*`) | [09.02-abi.md](09.02-abi.md) |
| 9.3 URL formats | [09.03-urls.md](09.03-urls.md) |
| 9.4 Camera back-ends | [09.04-camera-backends.md](09.04-camera-backends.md) |
| 9.5 CTRL mode (file-browser RPC) | [09.05-ctrl.md](09.05-ctrl.md) |
| 9.6 CTRL command reference | [09.06-commands.md](09.06-commands.md) |


### Lifetime, error propagation and reconnect

Practical contracts Studio enforces but does not document:

- **Tunnel ownership.** One tunnel per UI tab. Camera and file-browser use different `Bambu_Tunnel` handles even for the same printer IP — do not share connection state across them.
- **`Bambu_would_block` is not an error.** `Bambu_Open` and `Bambu_StartStream*` are polled (`PrinterFileSystem.cpp:1747-1758`; `gstbambusrc` same). Studio retries ~100 ms for 3–5 s, then gives up.
- **`Bambu_ReadSample` controls wakeup.** File-browser worker has no separate condvar — it relies on `Bambu_would_block` instead of blocking forever. An indefinite block freezes the tab.
- **Negative returns are fatal.** Outside `{0, Bambu_stream_end, Bambu_would_block, Bambu_buffer_limit}` → `Bambu_Close` + `Bambu_Destroy` and reconnect (`PrinterFileSystem.cpp:1577-1593`).
- **Logger callback is reentrant.** Invoked from arbitrary threads; Studio wrappers (`bambu_log` / `DumpLog`) are reentrant. Windows logger uses `wchar_t const*` (`tchar`); POSIX uses UTF-8 `char const*`. Studio frees each message with `Bambu_FreeLogMsg`.
- **Close vs reader race.** Once `Bambu_Close` returns, Studio may call `Bambu_Destroy` even if another thread was in `Bambu_ReadSample`. Unblock the reader (e.g. `shutdown(SHUT_RDWR)`) or serialise — otherwise use-after-free on reconnect.


### Map of `libBambuSource`-related source locations

| Topic | File:lines |
|-------|------------|
| C ABI declarations / function-pointer table | [BambuTunnel.h](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/BambuTunnel.h) |
| Loader (`StaticBambuLib`) | [PrinterFileSystem.cpp:1840-1879](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.cpp#L1840-L1879) |
| `dlopen` / `LoadLibrary` | [NetworkAgent.cpp:529-580](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/NetworkAgent.cpp#L529-L580) |
| Linux/Windows camera widget — current Studio (FFmpeg) | [wxMediaCtrl3.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl3.cpp), [AVVideoDecoder.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/AVVideoDecoder.cpp) |
| Linux camera (gstbambusrc — Orca / legacy) | [gstbambusrc.c](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/gstbambusrc.c) |
| Windows DirectShow (Orca / legacy) | [wxMediaCtrl2.cpp:55-138](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl2.cpp#L55-L138) |
| macOS `BambuPlayer` | [wxMediaCtrl2.mm:245-289](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/wxMediaCtrl2.mm#L245-L289), [BambuPlayer.h](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/BambuPlayer/BambuPlayer.h) |
| Camera URL formats | [MediaPlayCtrl.cpp:444-455](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/MediaPlayCtrl.cpp#L444-L455) |
| File-browser `CTRL_TYPE` / cmdtypes / result codes | [PrinterFileSystem.h:32-72](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.h#L32-L72) |
| CTRL JSON envelope / response dispatch | [PrinterFileSystem.cpp:1439-1478](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.cpp#L1439-L1478), [L1567-1606](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Printer/PrinterFileSystem.cpp#L1567-L1606) |
| Camera UI state machine | [MediaPlayCtrl.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/MediaPlayCtrl.cpp) |
