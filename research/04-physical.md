## 4. What the plugin is, physically

It is a plain native dynamic library with C exports. The calling convention is `cdecl` on Windows (`FT_CALL __cdecl` in `FileTransferUtils.hpp:15`) and the standard System V AMD64 ABI on Linux/macOS.

- The main module is **`bambu_networking`** — it implements the entire networking API (`bambu_network_*`) and the file-transfer ABI (`ft_*`). **Both symbol sets live in the same library**: immediately after loading, `NetworkAgent::initialize_network_module` calls `InitFTModule(networking_module)` ([NetworkAgent.cpp:272](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/NetworkAgent.cpp#L272)).
- Optional companion modules Studio knows how to pick up:
  - `BambuSource` — the wrapper for the printer camera stream. Loaded separately through `NetworkAgent::get_bambu_source_entry()` ([NetworkAgent.cpp:529-580](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/NetworkAgent.cpp#L529-L580)); if it fails to load, `m_networking_compatible = false` is set and the user sees "please update the plugin" ([GUI_App.cpp:3639](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp#L3639)).
  - `live555` — the classic RTSP library used internally by `BambuSource`. Studio never calls it directly but requires it to be present in the OTA cache (see § 3.3).

The ZIP is usually a few MiB. Studio imposes no formal size limit; `install_plugin` simply extracts every file through `miniz` (`mz_zip_…`).

No `plugins.json`/`manifest.xml` inside the archive is required. After extraction Studio only reads:
- the library itself — via `LoadLibrary`/`dlopen`;
- `network_plugins.json` **in the OTA cache** (not in the installed folder);
- the symbol `bambu_network_get_version` to determine the version.

---

