## 1. Architecture overview

Bambu Studio is a wxWidgets/C++ application. All networking code (Bambu Lab cloud, MQTT/SSDP to printers, print/upload jobs, authentication, OSS, tracking, and so on) lives in a separate **dynamically-loaded library** (`.dll` / `.so` / `.dylib`). Studio talks to it through a single C ABI whose symbols all start with `bambu_network_…`.

Key players:

| Role | Source |
|------|--------|
| C ABI declarations (`dlsym` typedefs) | `src/slic3r/Utils/NetworkAgent.hpp` |
| Symbol resolver and method wrappers | `src/slic3r/Utils/NetworkAgent.cpp` |
| Shared protocol structures / constants | `src/slic3r/Utils/bambu_networking.hpp` |
| `ft_*` File Transfer ABI | `src/slic3r/Utils/FileTransferUtils.{hpp,cpp}` |
| Module signature verification | `src/slic3r/Utils/CertificateVerify.{hpp,cpp}` |
| Lifecycle (URL, download, install, version) | `src/slic3r/GUI/GUI_App.cpp` |
| OTA synchronization | `src/slic3r/Utils/PresetUpdater.cpp` |
| UI job "download & install" | `src/slic3r/GUI/Jobs/UpgradeNetworkJob.{hpp,cpp}` |
| **`libBambuSource` C ABI** (`Bambu_*`) | `src/slic3r/GUI/Printer/BambuTunnel.h` |
| **`libBambuSource` loader / shim** | `src/slic3r/GUI/Printer/PrinterFileSystem.cpp` (`StaticBambuLib`) |
| **GStreamer source element (Linux only)** | `src/slic3r/GUI/Printer/gstbambusrc.{c,h}` |
| **macOS native player wrapper** | `src/slic3r/GUI/wxMediaCtrl2.mm`, `src/slic3r/GUI/BambuPlayer/BambuPlayer.h` |
| **Linux wxMediaCtrl shim (gstbambusrc registration)** | `src/slic3r/GUI/wxMediaCtrl2.{cpp,h}` (`__LINUX__` branch) |
| **Windows / Linux camera widget — Studio (current)** | `src/slic3r/GUI/wxMediaCtrl3.{cpp,h}` (BambuStudio commit `94d91be60`, June 2024). Drives `Bambu_*` C ABI directly + decodes via `AVVideoDecoder` (FFmpeg). |
| **Windows / Linux camera widget — Orca (and pre-`94d91be6` Studio)** | `src/slic3r/GUI/wxMediaCtrl2.{cpp,h}` Windows branch. Drives wxWidgets DirectShow backend → `bambu:` URL scheme → CLSID `{233E64FB-…}` source filter |
| **Camera UI panel** | `src/slic3r/GUI/MediaPlayCtrl.{cpp,h}` |
| **File browser UI / CTRL protocol consumer** | `src/slic3r/GUI/Printer/PrinterFileSystem.{cpp,h}`, `src/slic3r/GUI/MediaFilePanel.{cpp,h}` |

> Note: the code occasionally refers to two further libraries, **`BambuSource`** and **`live555`**. These are the camera/player and the RTSP stack; they are fetched and installed through the exact same mechanism and live next to the main library. The "Network Plugin" contract proper is `bambu_networking`, but a usable Studio installation ALSO needs a working `libBambuSource` for the camera live view *and* the printer file browser. The `libBambuSource` ABI is its own beast (different symbol prefix `Bambu_*`, different loader, per-platform back-ends) — it is documented separately in **§7**.

The current Studio version pinned in sources (tag `v02.06.00.51`) is `SLIC3R_VERSION = "02.06.00.51"` (`version.inc`); the expected agent version is `BAMBU_NETWORK_AGENT_VERSION = "02.06.00.50"` (`src/slic3r/Utils/bambu_networking.hpp:100`).

---

