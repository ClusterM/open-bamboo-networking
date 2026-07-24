## 9. Map of key source locations

| Topic | File:lines |
|-------|------------|
| Timelapse storage preflight (`ipcam_get_media_info`) | `src/slic3r/GUI/DeviceManager.cpp:2067-2074, 3548-3553` |
| PA calibration commands (`extrusion_cali_*`, `flowrate_*`) | `src/slic3r/GUI/DeviceManager.cpp:1744-2090`, `src/slic3r/GUI/DeviceCore/DevCalib.cpp:45-324` |
| AMS MQTT commands (`ams_*`, `print_option`) | `src/slic3r/GUI/DeviceManager.cpp:1537-1775`, `src/slic3r/GUI/DeviceCore/DevFilaSystemCtrl.cpp:11-57` |
| AMS status / tray indexing | `src/slic3r/GUI/DeviceCore/DevFilaSystem.cpp:344-385, 522-555` |
| `PACalibResult` / `FlowRatioCalibResult` schemas | `src/libslic3r/Calib.hpp:114-181`, `src/slic3r/GUI/DeviceCore/DevCalib.cpp:54-80` |
| Resolution of all 100+ symbols | `src/slic3r/Utils/NetworkAgent.cpp:279-382` |
| API typedefs | `src/slic3r/Utils/NetworkAgent.hpp:10-115` |
| Name constants | `src/slic3r/Utils/bambu_networking.hpp:97-100` |
| Error codes | `src/slic3r/Utils/bambu_networking.hpp:13-94` |
| Print-job stage enum + `PrintParams` | `src/slic3r/Utils/bambu_networking.hpp:152-241` |
| Studio print orchestration (decision tree) | `src/slic3r/GUI/Jobs/PrintJob.cpp:149-624` |
| Upload-only job (`SendJob`) | `src/slic3r/GUI/Jobs/SendJob.cpp:111-347` |
| Select-machine dialog → `PrintJob` | `src/slic3r/GUI/SelectMachine.cpp:2931-3157` |
| Send-to-Printer dialog → `ft_*` | `src/slic3r/GUI/SendToPrinter.cpp:1700-1995` |
| `NetworkAgent` wrappers for `start_*` | `src/slic3r/Utils/NetworkAgent.cpp:1363-1425` |
| Data structures | `src/slic3r/Utils/bambu_networking.hpp:180-275` |
| `InitFTModule` / `UnloadFTModule` | `src/slic3r/Utils/FileTransferUtils.hpp:239-253` |
| `ft_*` symbol resolution | `src/slic3r/Utils/FileTransferUtils.cpp:12-37` |
| Signature verification | `src/slic3r/Utils/CertificateVerify.cpp:289-300` |
| Signature bypass | `app_config → ignore_module_cert`; `src/slic3r/GUI/GUI_App.cpp:3423` |
| Request URL | `src/slic3r/GUI/GUI_App.cpp:1469-1556` |
| Plugin download | `src/slic3r/GUI/GUI_App.cpp:1573-1761` |
| Extraction / installation | `src/slic3r/GUI/GUI_App.cpp:1763-1912` |
| Version check | `src/slic3r/GUI/GUI_App.cpp:1982-1998` |
| Restart networking | `src/slic3r/GUI/GUI_App.cpp:1914-1957` |
| Removal | `src/slic3r/GUI/GUI_App.cpp:1959-1973` |
| OTA copy-in | `src/slic3r/GUI/GUI_App.cpp:3359-3419` |
| Agent initialization | `src/slic3r/GUI/GUI_App.cpp:3421-3519` |
| OTA `sync_plugins` | `src/slic3r/Utils/PresetUpdater.cpp:1165-1253` |
| `sync_resources` (shared engine) | `src/slic3r/Utils/PresetUpdater.cpp:561-737` |
| OTA cache validation | `src/slic3r/Utils/PresetUpdater.cpp:1131-1163` |
| UI install job | `src/slic3r/GUI/Jobs/UpgradeNetworkJob.cpp:16-146` |
| "Downloading Bambu Network Plug-in" dialog | `src/slic3r/GUI/DownloadProgressDialog.cpp` |
| `libBambuSource` C ABI | `src/slic3r/GUI/Printer/BambuTunnel.h` |
| `libBambuSource` loader | `src/slic3r/GUI/Printer/PrinterFileSystem.cpp:1831-1877` |
| `libBambuSource` `dlopen`/`LoadLibrary` | `src/slic3r/Utils/NetworkAgent.cpp:523-575` |
| Camera URL formats | `src/slic3r/GUI/MediaPlayCtrl.cpp:307-318, 551-559` |
| File-browser CTRL command set | `src/slic3r/GUI/Printer/PrinterFileSystem.h:32-72` |
| File-browser CTRL JSON envelope | `src/slic3r/GUI/Printer/PrinterFileSystem.cpp:1431-1458` |
| Linux camera back-end (gstbambusrc — Orca / legacy Studio) | `src/slic3r/GUI/Printer/gstbambusrc.{c,h}` |
| Windows / Linux camera widget — current Studio (FFmpeg, C ABI) | `src/slic3r/GUI/wxMediaCtrl3.{cpp,h}`, `AVVideoDecoder.{cpp,h}` |
| Windows camera back-end (DirectShow CLSID — Orca / legacy Studio only) | `src/slic3r/GUI/wxMediaCtrl2.cpp:71-138` |
| macOS camera (`BambuPlayer` Objective-C class) | `src/slic3r/GUI/wxMediaCtrl2.mm:67-141`, `BambuPlayer/BambuPlayer.h` |

---

