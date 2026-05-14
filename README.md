# Open Bambu Networking

Open-source drop-in replacement for Bambu Studio's proprietary `bambu_networking`
plugin.

## Table of contents

- [Why this project exists](#why-this-project-exists)
- [Supported platforms](#supported-platforms)
- [Supported Bambu Studio versions (ABI versions)](#supported-bambu-studio-versions-abi-versions)
- [Developer Mode requirement](#developer-mode-requirement)
- [What works and what's not](#what-works-and-whats-not)
  - [TL;DR: what is **not** implemented](#tldr-what-is-not-implemented)
  - [More details](#more-details)
    - [Basics (model-independent)](#basics-model-independent)
    - [Printing](#printing)
    - [Camera liveview](#camera-liveview)
    - [File browser (Device → Files)](#file-browser-device--files)
    - [Status / Device tab](#status--device-tab)
  - [Workaround reference](#workaround-reference)
  - [Cloud sign-in](#cloud-sign-in)
- [How to build](#how-to-build)
  - [Linux](#linux)
    - [Prerequisites](#prerequisites-linux)
    - [Linux: configure, build and install](#linux-configure-build-and-install)
    - [`./configure` options](#configure-options)
  - [Windows](#windows)
    - [Prerequisites](#prerequisites-windows)
    - [Windows: configure, build and install](#windows-configure-build-and-install)
- [Manual installation](#manual-installation)
- [Logging](#logging)
  - [`libBambuSource.so` logging](#libbambusourceso-logging)
- [License](#license)
- [Support the Developer and the Project](#support-the-developer-and-the-project)

## Why this project exists

[Bambu Studio](https://github.com/bambulab/BambuStudio) is an excellent
open-source slicer, but every piece of code that actually talks to a
Bambu Lab printer — LAN discovery, MQTT telemetry, file transfer,
camera, OTA, cloud — lives in a closed-source shared library
(`libbambu_networking.so`, shipped as a "Network Plugin" Studio
downloads on first start). There's nothing inherently wrong with a
cloud product; the problem is the implementation:

- **The stock plugin ships an unaligned atomic that triggers the
kernel's `split_lock` detector on every modern Intel CPU.** Startup
stalls for 25-60 seconds while the kernel walks each trap; every
Device-tab click hits it again. The workaround
(`sysctl kernel.split_lock_mitigate=0`) degrades system-wide
performance and still misbehaves in LAN-only mode. Reported to Bambu
over a year ago and still open:
[bambulab/BambuStudio#8605](https://github.com/bambulab/BambuStudio/issues/8605).
- **No ARM or non-x86_64 build.** The plugin is only published as
Linux x86_64 (plus Windows and macOS). You can't use Studio or any
third-party tool that reuses the plugin on a Raspberry Pi, an
Ampere workstation, or any other aarch64 / riscv host, even though
the rest of Studio builds cleanly.
- **Cloud chatter on every action, even in LAN-only mode.** Even when
the printer is sitting on the same subnet as Studio in Developer
Mode, the stock plugin keeps reaching out to
`api.bambulab.com` / MakerWorld for things like bind status and
task metadata. That's extra latency on every click, a hard
dependency on the account infrastructure being up, and a
surveillance footprint a lot of users didn't opt in to.

This project is a drop-in replacement for that library: same `dlsym`
ABI, same file name, same install location, but open source,
aligned-atomic-clean, cross-architecture-buildable, and strictly
LAN-first (the cloud is only ever contacted for sign-in, so that
Studio's preset sync works — the rest is straight to the printer).

Protocol knowledge comes from
[OpenBambuAPI](https://github.com/Doridian/OpenBambuAPI) and the
reference implementations in
[bambulabs_api](https://github.com/acse-ci223/bambulabs_api) and
[ha_bambu_lab](https://github.com/greghesp/ha-bambulab); everything
else is reverse-engineered from MITM captures of the stock plugin.

Everything we have been able to establish about how the stock network
plugin is integrated, validated, and invoked — including the full C ABI
and related wire behaviour — is collected in
[NETWORK_PLUGIN.md](NETWORK_PLUGIN.md).

Please note:

**This project has been built entirely through the author's enthusiasm, with a tremendous personal investment of time, effort, and financial resources. If this work helps you, please consider supporting its further development in the [Support the Developer and the Project](#support-the-developer-and-the-project) section.**

## Supported platforms

- Linux x86_64 (primary target).
- Linux aarch64 (primary target).
- Windows x64 (experimental).
- macOS (very experimental, works partially).

## Supported Bambu Studio versions (ABI versions)

- Bambu Studio **02.03.00**._xx_
- Bambu Studio **02.03.01**._xx_
- Bambu Studio **02.04.00**._xx_
- Bambu Studio **02.05.00**._xx_
- Bambu Studio **02.05.01**._xx_
- Bambu Studio **02.05.02**._xx_
- Bambu Studio **02.05.03**._xx_
- Bambu Studio **02.06.00**._xx_
- Bambu Studio **02.06.01**._xx_

Compatibility with plugin ABI depends on the first three numbers in the version number, e.g.
any Bambu Studio v**02**.**03**.**04**._xx_ is compatible with any plugin with a version v**02**.**03**.**04**._xx_.

Orca Slicer lets you select plugin versions directly.

## Developer Mode requirement

Recent (2024+) printer firmware cryptographically verifies every MQTT command
it receives when the printer is paired with the Bambu cloud. The verification
uses a per-installation RSA key that the stock plugin ships as obfuscated data
and which we do not reproduce. Symptom on the printer screen when an unsigned
command arrives:

```
MQTT Command verification failed
err_code: 84033543
```

To use this plugin, put the printer in **Developer Mode**:

1. On the printer: Nut icon -> Settings -> LAN Only Mode -> enable "LAN Only", "LAN Only liveview" and "Developer mode".
2. In Bambu Studio: Device -> Connect via LAN with access code.

In this mode the printer skips MQTT verification and accepts plain LAN
commands. All LAN features of the plugin (discovery, telemetry, printing,
filename browsing, file transfer, camera) work normally.

Non-developer / hybrid / cloud-only modes are **only partially
implemented** and remain **severely limited**: the plugin can still
sign you into the cloud, fetch presets, and show telemetry, but **you
cannot reliably start a print** — the printer expects MQTT commands to
carry the stock plugin's RSA signature, which we do not ship. Without
Developer Mode every `print` / `project_file` / similar command is
rejected (`err_code: 84033543`). Fully replicating that signing chain
is out of scope for an open-source project. MakerWorld task history is
likewise out of scope.

## What works and what's not

### TL;DR: what is **not** implemented

- Printing in non-developer mode
- MakerWorld integration
- Stock **`ft_*` / FileTransfer** port-6000 JSON framer (replaced by an FTPS
  fastpath in `libbambu_networking.so`; see
  [STATUS.md § 6.14](STATUS.md#614-file-transfer-abi-ft_)). **Device → Files**
  is implemented in `libBambuSource.so` — see
  [STATUS.md — PrinterFileSystem (MediaFilePanel)](STATUS.md#printerfilesystem-mediafilepanel).
- Old printer models like A1 are not tested

### More details

The author only owns a **P2S**, so the "Tested" column in the table
below usually means it works 100% on **P2S**. 

**Community help is essential.** If you use another printer model or
CPU architecture, please try the plugin and open an issue:
[https://github.com/ClusterM/open-bambu-networking/issues](https://github.com/ClusterM/open-bambu-networking/issues)
with what works, what fails, and your firmware / OS / Studio version —
that is how we turn "not tested" into documented reality. Bug reports,
regressions, and small compatibility notes all belong in
**[Issues](https://github.com/ClusterM/open-bambu-networking/issues)**.

The tables below are a feature-level view. For an ABI-level view —
every single function Studio resolves from the plugin, with per-symbol
implementation status and notes — see [STATUS.md](STATUS.md).

Legend:

| Mark | Meaning                                                                                                      |
| ---- | ------------------------------------------------------------------------------------------------------------ |
| ✅   | Implemented and working on the listed models. "Tested" column says where the author has physically verified. |
| ⚠️   | Partial / soft-fails / needs a prerequisite (see Notes).                                                     |
| ❌   | Not implemented (see [TL;DR: what is **not** implemented](#tldr-what-is-not-implemented) for scope rationale). |

The **Impl** column distinguishes:

- **Native** — the plugin speaks the same wire protocol the stock
`bambu_networking.so` does. Drop-in behaviour.
- **Workaround** — the plugin reaches the same user-visible outcome
over a different transport. Listed individually in
[Workaround reference](#workaround-reference) below; all of them
can be compiled out together with `-DOBN_ENABLE_WORKAROUNDS=OFF`.
- **Passthrough** — the plugin just forwards MQTT / REST payloads;
Studio does the work.

#### Basics (model-independent)

| Feature                              | Status | Impl                | Notes                                                                                                                                                                |
| ------------------------------------ | ------ | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SSDP discovery (LAN)                 | ✅     | Native              | Multicast listener on `239.255.255.250:1990` + Studio `on_server_connected`_.                                                                                        |
| LAN MQTT telemetry                   | ✅     | Native              | TLS to `mqtts://<ip>:8883`, user `bblp`, pass = access code.                                                                                                         |
| Cloud MQTT telemetry                 | ✅     | Native              | TLS to `us.mqtt.bambulab.com:8883`. Runs in parallel with LAN when signed in; not exercised during LAN-focused testing.                                              |
| Cloud login / ticket flow            | ✅     | Native              | Browser → `localhost` callback → `POST /user-service/user/ticket/<T>`. Session persisted to `obn.auth.json`.                                                         |
| User presets sync / profile / avatar | ✅     | Native              | List / create / update / delete works                                                                                                                                |
| MQTT command signing                 | ❌     | —                   | Stock plugin carries per-install RSA keys we don't reproduce. Workaround for the user: enable Developer Mode on the printer (all LAN commands bypass signing there). |

#### Printing

| Feature                                    | Status             | Impl        | Notes                                                                                                                                                                                                                       |
| ------------------------------------------ | ------------------ | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LAN print (FTPS + MQTT, Dev Mode)          | ✅ (tested on P2S) | Native      | FTPS upload and `{"print":{"command":"project_file",...}}` command on LAN MQTT.                                                                                                                                             |
| "Send to Printer" dialog (`ft_*`)          | ✅ (tested on P2S) | Workaround  | `ft_*` C ABI served over FTPS (`OBN_FT_FTPS_FASTPATH`, ON by default); stock uses a proprietary port-6000 tunnel. With `OFF` Studio falls back to its internal FTP path — same file, same place, less UI polish.            |
| Cloud 3MF upload to S3                     | ✅                 | Native      | 6-step upload sequence reversed from MITM of the stock plugin.                                                                                                                                                              |
| `create_task` (MakerWorld entry)           | ⚠️                 | ❌          | Soft-fails — logs 4xx, keeps going with `task_id="0"`. Printing works; MakerWorld history and timelapse-on-printer cloud flags don't. See [TL;DR: what is **not** implemented](#tldr-what-is-not-implemented) (MakerWorld). |
| "Print from Device" (`start_sdcard_print`) | ✅ (tested on P2S) | Workaround  | Stock plugin: cloud REST endpoint we can't sign. Ours: publish `project_file` on LAN MQTT for a file already on the printer.                                                                                                |
| AMS telemetry / mapping                    | ✅                 | Passthrough | Studio consumes `push_status` directly.                                                                                                                                                                                     |
| Nozzle mapping / multi-extruder            | ✅ (not tested)    | Passthrough | Plugin puts nozzle mapping data into JSON but the author has no such printer to test.                                                                                                                                       |

#### Camera liveview

Camera protocol differs by model (see the hardware matrix). Both paths
share the same `libBambuSource.so` tunnel API towards Studio; the
difference is what happens inside.

| Feature                                 | Applies to                        | Status             | Impl   | Notes                                                                                                                                             |
| --------------------------------------- | --------------------------------- | ------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| MJPEG over TLS, port 6000               | A1, A1 mini                       | ✅ (not tested)    | Native | Same TCP-over-TLS stream the stock plugin consumes. The author has no such printer to test.                                                       |
| RTSPS → H.264 byte-stream, port 322     | P1S, X1 (all), P2S, H-series, X2D | ✅ (tested on P2S) | Native | Same wire format the stock plugin uses: raw H.264 Annex-B byte-stream out via `Bambu_ReadSample`; the slicer's vendored `gstbambusrc` decodes it. |
| Cloud camera (TUTK / Agora p2p)         | any printer out of LAN            | ❌                 | ❌     | Proprietary libraries.                                                                                                                            |

#### File browser (Device → Files)

Plugin always uses FTPS; the stock port-6000 CTRL framer to the printer is
not reimplemented. Behaviour, `ipcam.file` injection, and `ft_*` fastpath
details: [STATUS.md § 6.14](STATUS.md#614-file-transfer-abi-ft_) and
[STATUS.md — PrinterFileSystem (MediaFilePanel)](STATUS.md#printerfilesystem-mediafilepanel).

| Feature                                       | Status             | Impl       | Notes                                                                                                                                                                       |
| --------------------------------------------- | ------------------ | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| List files (LIST_INFO)                        | ✅ (tested on P2S) | Workaround | FTPS `LIST` (Bambu firmware does not implement `MLSD`); stock port-6000 CTRL protocol not reimplemented.                                                                    |
| Download from storage                         | ✅ (tested on P2S) | Workaround | Streaming FTPS `RETR` with 256 KB `CONTINUE` chunks.                                                                                                                        |
| Delete from storage                           | ✅ (tested on P2S) | Workaround | FTPS `DELE` per path.                                                                                                                                                       |
| 3MF plate thumbnails (`Metadata/plate_*.png`) | ⚠️                 | Workaround | Opens the archive via FTPS `RETR`, inflates the plate PNG with zlib. Flaky on very large archives.                                                                          |
| Timelapse / video thumbnails                  | ✅ (tested on P2S) | Workaround | Sidecar `<stem>.jpg` over FTPS; P2S may omit sidecars — see [STATUS.md](STATUS.md#printerfilesystem-mediafilepanel).                                                        |

#### Status / Device tab

| Feature                                     | Applies to | Status             | Impl        | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------- | ---------- | ------------------ | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Current-print thumbnail cover               | All models | ✅ (tested on P2S) | Mixed       | Covers both runtime paths: **(a)** LAN-only prints where `project_id=profile_id=subtask_id="0"` — the plugin rewrites those to synthetic `"lan-<fnv>"` ids on every `push_status` (workaround, pushes Studio off its SD-card placeholder branch); **(b)** cloud-initiated subtasks whose real ids are still attached after unbinding — here the plugin answers `get_subtask_info(<real_id>)` instead of routing through Bambu's CDN (regular stock replacement). Both paths share the same backend: localhost HTTP server pulls `/cache/<subtask>.gcode.3mf` over FTPS, unpacks `Metadata/plate_N.png`, serves it as `thumbnail.url = http://127.0.0.1:<port>/cover/…`. Same image HA uses. **Linux only: requires `[patches/bambustudio-statuspanel-thumbnail.patch](patches/bambustudio-statuspanel-thumbnail.patch)` applied to Studio** — `wxStaticBitmap` under wxGTK doesn't fire `wxEVT_PAINT` on `Bind()`'d handlers, so `PrintingTaskPanel::paint()` never runs and neither the LAN cover nor stock cloud covers ever show. |
| Firmware version panel (Device → Update)    | All models | ✅ (tested on P2S) | Mixed       | `bambu_network_get_printer_firmware` re-synthesises the "firmware list" Studio expects from the MQTT frames the printer already sends (`info.module[]` replies + `push_status.upgrade_state.new_ver_list`). That populates the Update tab with current per-module versions (OTA, AMS, AHB, …), stock-style. When the printer advertises a newer version the "current → new" arrow and the green "update available" badge appear.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Firmware Release Notes dialog               | All models | ✅ (tested on P2S) | Workaround  | Shown when a new version is advertised. Description text is synthesised locally with a link to the model-specific page on [bambulab.com/support/firmware-download](https://bambulab.com/en/support/firmware-download/all); we can't reach Bambu's cloud changelog API without login. If no new version is advertised the dialog is empty — which matches stock behaviour in the same situation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Start firmware update (Update button)       | All models | ✅ (tested on P2S) | Passthrough | Button publishes `{"upgrade":{"command":"upgrade_confirm"}}` on LAN MQTT. The printer already knows which OTA package it advertised and downloads it from Bambu's CDN itself — the plugin doesn't need to supply a URL.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Flash an arbitrary version (version picker) | —          | ❌                 | —           | Stock plugin lets you pick any older/newer OTA from Bambu's cloud catalogue; that catalogue is auth-gated and we don't have cloud signing. Only the printer-advertised version is flashable.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

### Workaround reference

Everything marked **Workaround** in the table above is a deliberate
non-stock path chosen to get a Developer-Mode printer usable without
the proprietary secrets the stock plugin carries. All of them are
gated behind one CMake flag, `-DOBN_ENABLE_WORKAROUNDS` (default
`ON`). Build with `=OFF` if you want a strict drop-in that only
exposes the native paths from the feature tables above — Studio
will transparently lose the affected features (Send greys out on P2S,
file browser stays empty on Dev-Mode printers, "Print from Device"
errors out with "start_sdcard_print disabled", RTSPS liveview refuses
to open, etc.), but nothing half-done runs at runtime.

| Workaround                                                     | What the stock plugin does                                                                                                                                                                                                                                                                                                                                                                                                                           | What we do                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Why this is acceptable                                                                                                                                                                                                                                                                                                                                                                                            | Trade-offs                                                                                                                                                                                                                                                                                                                               |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `home_flag` SDCARD-bits rewrite                                | Printer reports its real `SdcardState` from the hardware. On P2S / A-series firmware without an SD slot the bits read `NO_SDCARD`.                                                                                                                                                                                                                                                                                                                   | On every LAN `push_status` we check bits [8:9]. If they are `00` (NO_SDCARD) and `ipcam` is present we flip them to `01` (HAS_SDCARD_NORMAL) in-place on the JSON text. `ABNORMAL` / `READONLY` and printers that already have the bit are passed through untouched.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | We *can* read/write the USB stick over FTPS on P2S, so from Studio's workflow POV the storage exists and is healthy — the bit is lying.                                                                                                                                                                                                                                                                           | If a real "SD card missing" ever reports as `NO_SDCARD` on P1/A1 the UI would mistakenly enable Send; in practice those printers have a real slot and use the ABNORMAL code path instead.                                                                                                                                                |
| `ipcam.file` block injection                                   | Firmware with a file browser advertises `ipcam.file = {"local":"local",…}`; Studio keys the MediaFilePanel off that.                                                                                                                                                                                                                                                                                                                                 | When the printer omits the block we inject `{"local":"local","remote":"none","model_download":"enabled"}` into the ipcam object. Present blocks pass through unchanged.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Without this Studio short-circuits MediaFilePanel with "Browsing file in storage is not supported in current firmware" and never calls `Bambu_StartStreamEx(CTRL_TYPE)` on us.                                                                                                                                                                                                                                    | The plugin advertises file-browser capability even for firmware revisions where it doesn't exist natively; the opposite side (our CTRL bridge) is all FTPS so it still works.                                                                                                                                                            |
| PrinterFileSystem CTRL bridge                                  | Port-6000 proprietary CTRL protocol served by the stock `libBambuSource.so`: Bambu-framed binary JSON and per-command media blobs.                                                                                                                                                                                                                                                                                                                   | In our `libBambuSource.so` a worker thread per tunnel answers `LIST_INFO` / `SUB_FILE` / `FILE_DOWNLOAD` / `FILE_DEL` / `REQUEST_MEDIA_ABILITY` / `TASK_CANCEL` by translating each into FTPS (`LIST`, `RETR`, `DELE`) on the same TLS endpoint we use for LAN print uploads.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | FTPS is universal across Bambu LAN firmware and survives Developer Mode. The CTRL protocol isn't documented anywhere we've found.                                                                                                                                                                                                                                                                                 | `FILE_UPLOAD` is not implemented (Studio uses `ft_`* for uploads anyway). `SUB_FILE` re-downloads the whole `.3mf` for every thumbnail / metadata request: OK on LAN, wasteful vs. a native CTRL channel that could stream entries.                                                                                                      |
| 3MF thumbnail extraction                                       | Stock CTRL protocol likely streams just the requested entry out of the `.3mf` on the printer.                                                                                                                                                                                                                                                                                                                                                        | We fetch the whole archive into memory, parse the central directory, and `inflate` the target PNG (`Metadata/plate_1.png` / `plate_no_light_1.png`) or a requested entry with zlib raw-deflate.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | No external ZIP dependency; archives fit in RAM for any reasonable print job.                                                                                                                                                                                                                                                                                                                                     | Large models (~10+ MB) hit the wire once per thumbnail tile. Parser is minimal — compressed entries only via DEFLATE; we don't handle stored-with-encryption or ZIP64.                                                                                                                                                                   |
| Camera liveview (RTSPS)                                        | Stock `libBambuSource.so` does the RTSP/RTSPS handshake on port 322 (live555-based) and hands raw H.264 byte-stream back through `Bambu_ReadSample`; the slicer's `gstbambusrc` then decodes it.                                                                                                                                                                                                                                                     | Same thing with our own RTSP client (`stubs/rtsp_client.cpp` — TLS + Basic/Digest auth + RTP/TCP-interleaved depacketisation, FU-A / STAP-A reassembly, GET_PARAMETER keepalive) and an Annex-B passthrough worker (`stubs/rtsp_passthrough.cpp`) that re-prefixes SPS/PPS in front of every IDR. The byte stream is the same one stock returns.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Owning the RTSP layer ourselves drops the live555 dependency and keeps the plugin self-contained.                                                                                                                                                                                                                                                                                                                 | Single H.264 video track, baseline/main profile, no audio. Reconnect on stream drop is "tear down + re-`Bambu_Open`", same as stock.                                                                                                                                                                                                     |
| `start_sdcard_print` over LAN MQTT                             | Stock plugin hits a cloud REST endpoint (`start_sdcard_print`) that signs and relays the command via the cloud tunnel.                                                                                                                                                                                                                                                                                                                               | We publish `{"print":{"command":"project_file", "url":"ftp://<path>", …}}` directly on the active LAN MQTT session.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | The cloud endpoint requires MakerWorld signing we don't reproduce, and Developer Mode printers have no cloud route to receive it on anyway. LAN MQTT is what the firmware actually consumes.                                                                                                                                                                                                                      | No cloud task record. `task_id` / `subtask_id` / `project_id` are all `0`, which a very old firmware could refuse if it ever validates them (none observed).                                                                                                                                                                             |
| Cross-device user preset sync                                  | Stock plugin's `get_setting_list2` only fetches metadata (`setting_id`, `name`, `update_time`, …) from `GET /v1/iot-service/api/slicer/setting`, assuming the matching preset body is already present on disk under `<config_dir>/user/<uid>/`. On a fresh machine the list walk produces a `setting_id` with no `setting` map to merge in, so `PresetCollection::load_user_preset()` silently skips every cloud preset and your profiles disappear. | For each preset the Studio-provided `CheckFn` flags as needed, we additionally issue `GET /v1/iot-service/api/slicer/setting/<setting_id>` to pull the full `setting` payload, then inject `user_id` (not returned by the server) and convert `update_time` from `"YYYY-MM-DD HH:MM:SS"` into the unix-seconds string `load_user_preset()` expects. The resulting flat `values_map` is handed to Studio exactly where it would expect one from a local file.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Studio's loader path and the cloud endpoint both exist; the stock plugin simply never connects the two. The extra `GET /setting/<id>` per preset is the minimum RTT needed to survive a wiped local cache (on which the author got burnt while reverse-engineering this section).                                                                                                                                 | One HTTPS round-trip per synced preset on the first sync after a wipe (~100 KB response each). On a machine that already has the local files, Studio's `need_sync()` check short-circuits the download — same bandwidth as stock.                                                                                                        |
| Firmware info synthesis (`get_printer_firmware`)               | Stock plugin serves `GET /v1/iot-service/api/slicer/resource/printer/firmware?dev_id=…` against the Bambu cloud, returning a JSON envelope (current/new version per module + release notes + binary URL) that Studio's `UpgradePanel` and `ReleaseNoteDialog` render.                                                                                                                                                                                | The plugin doesn't call the cloud at all. Instead the agent maintains a `DeviceFw` cache keyed by `dev_id` that harvests versions from every MQTT frame the printer already sends: `info.command=get_version` replies (module array with `name`/`sw_ver`/`sn`/`loader_ver`) and `push_status.upgrade_state.new_ver_list`. `render_firmware_json(dev_id)` then emits the same envelope Studio expects — current versions populate the Update panel, advertised newer versions light up the "update available" banner, the description links to `bambulab.com/en/support/firmware-download/all`. The actual flash is a passthrough: Studio's "Update" button publishes `{"upgrade":{"command":"upgrade_confirm"}}` on LAN MQTT, and the printer fetches the binary from Bambu's CDN itself.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | The cloud firmware catalogue requires a signed request with an `accessToken` for a linked account and answers with HTML behind Cloudflare from an untrusted client (no stable public JSON). What we need (current version, advertised new version, a way to flash the advertised one) is already on the wire in plaintext via MQTT, so we re-synthesise the envelope locally.                                     | No cross-version history — you can only flash what the printer is currently advertising, not an older or a beta OTA from the cloud catalogue. Release Notes text is a short auto-generated stub with an external link, not the full changelog. No effect when no new version is advertised (Release Notes dialog empty — same as stock). |
| `ft_*` FTPS fastpath (`OBN_FT_FTPS_FASTPATH`, also default ON) | Port-6000 proprietary tunnel for the `FileTransfer` ABI (Send-to-Printer dialog + eMMC pre-flight + media-ability probes).                                                                                                                                                                                                                                                                                                                           | FTPS-backed `STOR` for uploads + `CWD /sdcard` / `CWD /usb` probe for media-ability answers. TUTK/Agora URLs still return `FT_EIO`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Same tunnel the LAN print path already uses; gives the richer dialog sequence (ability probe → storage picker → percent progress) without a new transport.                                                                                                                                                                                                                                                        | `emmc` is never advertised (Bambu firmware reserves it for system files). Fall-back path via Studio's internal FTP upload still puts the file in the same place if you turn this OFF. See [STATUS.md § 6.14](STATUS.md#614-file-transfer-abi-ft_).                                                                                         |
| Current-print thumbnail cover                                  | Stock plugin gets `project_id`/`profile_id`/`subtask_id` back from the cloud task it created, and `get_subtask_info` returns a `thumbnail.url` served out of Bambu's CDN.                                                                                                                                                                                                                                                                            | Two runtime paths share the same backend: **(a)** LAN-only prints whose ids come through as `"0"` — `MachineObject::is_sdcard_printing()` would otherwise route the Device-panel thumbnail to a static SD-card placeholder, so we rewrite the zeros to synthetic `"lan-<fnv>"` ids on every `push_status` (this part is the workaround). **(b)** Cloud-initiated subtasks that still carry their real numeric ids (e.g. after unbinding a cloud-paired printer) — Studio calls `get_subtask_info(<real_id>)` exactly like it would against stock; we just serve that ourselves instead of the CDN. Both paths land in the same backend: a single-thread HTTP server on `127.0.0.1:<random>`, FTPS-download of `/cache/<subtask>.gcode.3mf`, unpack `Metadata/plate_N.png` via zlib raw-inflate and serve as `image/png` behind the URL we return from `get_subtask_info`. On Linux this additionally requires `[patches/bambustudio-statuspanel-thumbnail.patch](patches/bambustudio-statuspanel-thumbnail.patch)` against Studio: `PrintingTaskPanel::set_thumbnail_img` relies on a custom `wxEVT_PAINT` handler which `wxStaticBitmap` doesn't dispatch under wxGTK (native `GtkImage` wrapper), so without the patch no cover — LAN or cloud — ever becomes visible on screen. | wxWebRequest on libsoup3 / Linux rejects `file://` URLs; a loopback HTTP server is the minimum that still uses the same code path cloud thumbnails take. File is cached under `temp_directory_path()/obn-covers/` so reprint requests don't re-download the archive. `/cache/` is the drop-zone for both `start_local_print_with_record` and the printer's own cloud-download, so one lookup covers both origins. | Extra 2-20 MB FTPS `RETR` once per print, a socket listener on loopback for the lifetime of the plugin, and a 15 s wait budget inside the HTTP server while the FTPS worker is still fetching. If the .3mf is gone from `/cache/` the server returns 503 → Studio falls back to its broken-image icon (clickable to retry).              |

The first four rows are gated by `OBN_ENABLE_WORKAROUNDS`; the last three — firmware info synthesis, cross-device preset sync, and the thumbnail cover — always run, because they either cannot cause runtime regressions vs. stock behaviour (there is no stock path at all under Developer Mode) or the stock behaviour they replace is silent data loss rather than a graceful degradation. The `ft_`* fastpath has its own flag because stock-compatible builds may want to keep Send-to-Printer's UI progress working while turning everything else off. The RTSPS camera path is **not** gated — it produces the same byte-stream stock does.

### Cloud sign-in

Even though every print path is local, the plugin still implements
Bambu's cloud account login. The reason is that Studio's UI and preset
machinery are heavily wired to a logged-in `user_id`: without a session
a number of features quietly degrade. With a session they behave as
they did under the stock plugin.

**What login gives you:**

After sign-in, Studio may show a **Synchronization** dialog asking
whether to pull personal data from Bambu Cloud. The stock UI lists
exactly three categories — the same ones the account machinery is built
around:

1. **Process presets** (print / process profiles)
2. **Filament presets**
3. **Printer presets** (machine profiles)

> **Note:** To sync custom filaments to the printer so they show up in its filament menu, temporarily
> disable LAN-only mode and bind the printer to Bambu Cloud. Afterward, you can turn LAN-only mode and
> Developer Mode back on.

**Running without sign-in** is fully supported: go straight to 
"Device → Connect via LAN with access code",
and LAN printing / camera / discovery / FTPS all work. You'll just
lose the Studio features in the second list above.

## How to build

### Linux

#### Prerequisites (Linux)

You need **CMake ≥ 3.20**, a **C++17** compiler, **pkg-config**, and development
headers for everything the project links against:

| Component                           | Debian / Ubuntu packages                                                                             | Fedora-style packages                                                             |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Toolchain                           | `build-essential`, `cmake`, `pkg-config`                                                             | `gcc-c++`, `cmake`, `pkgconf-pkg-config`                                          |
| MQTT / JSON / HTTP / TLS / zlib     | `libmosquitto-dev`, `libcjson-dev`, `uthash-dev`, `libcurl4-openssl-dev`, `libssl-dev`, `zlib1g-dev` | `mosquitto-devel`, `uthash-devel`, `libcurl-devel`, `openssl-devel`, `zlib-devel` |

> Note  
> `libcjson-dev` and `uthash-dev` are required for `--vendor-mosquitto` option only (see below).

One-shot install examples:

```sh
# Debian / Ubuntu
sudo apt install build-essential cmake pkg-config \
  libmosquitto-dev libcjson-dev uthash-dev libcurl4-openssl-dev libssl-dev zlib1g-dev
```

```sh
# Fedora
sudo dnf install gcc-c++ cmake pkgconf-pkg-config \
  mosquitto-devel cjson-devel uthash-devel libcurl-devel openssl-devel zlib-devel
```

#### Linux: configure, build and install

From the repository root, the usual three commands:

```sh
./configure
make
make install
```

For Orca Slicer (it uses the same binaries; only the installation process is different):
```
./configure --client-type=orca_slicer
make
make install
```

No `sudo` needed — the default install prefix is inside your home directory.

That's it. `./configure` is a thin wrapper around CMake that writes the build
tree into `build/` and by default this script autodetects the Bambu Studio version
and the config location, then picks sensible defaults for a typical user.

`make install` runs the automated install. For the manual steps (copy paths, conf keys), see [Manual installation](#manual-installation) below.

`make uninstall` walks the install manifest and removes whatever was put
down; `make clean` / `make distclean` drop build artefacts; `make test`
runs the smoke tests via `ctest`.

#### `./configure` options

`./configure --help` prints the full list; the most useful ones:

| Flag                      | Default                                                        | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--client-type=TYPE`      | `bambu_studio`                                                 | Which slicer the plugin is being installed for: `bambu_studio` or `orca_slicer`. Drives the default `--prefix`, the auto-detected version source and the installation procedure                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `--prefix=DIR`            | per-client native config dir on Linux, with a Flatpak fallback | Where `make install` copies the shared objects and the OTA manifest. For both clients, `./configure` prefers the native config dir and only falls back to the Flatpak config dir when the native one is missing AND the Flatpak one exists: Studio: `~/.config/BambuStudio` → `~/.var/app/com.bambulab.BambuStudio/config/BambuStudio/`. Orca: `~/.config/OrcaSlicer` → `~/.var/app/com.orcaslicer.OrcaSlicer/config/OrcaSlicer/`. When this does not point at one of the two known dirs for the selected `--client-type`, the conf-file patch is skipped automatically — you are clearly building into a staging tree.                                                                                     |
| `--build-type=TYPE`       | `Release`                                                      | `Release`, `Debug`, `RelWithDebInfo`, `MinSizeRel`. Maps to `-DCMAKE_BUILD_TYPE=…`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `--with-version=VER`      | auto (see **Version auto-detection** below)                    | Overrides automatic `OBN_VERSION`. The slicer compares only the **first 8 characters** (`MAJOR.MINOR.PATCH`), so e.g. AppImage `v02.05.02.51` wants `02.05.02.*`. Maps to `-DOBN_VERSION=…`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `--disable-workarounds`   | enabled                                                        | Master switch for every non-stock code path (see [Workaround reference](#workaround-reference)): `home_flag` / `ipcam.file` rewrites, PrinterFileSystem FTPS bridge in `libBambuSource.so`, `start_sdcard_print` over LAN MQTT. With this passed the plugin is a strict drop-in — same wire protocols, nothing else. Studio transparently loses every workaround-backed feature (the LAN file browser stays empty, Send greys out on P2S, and so on) but nothing half-done runs at runtime. Maps to `-DOBN_ENABLE_WORKAROUNDS=OFF`. Note: the RTSPS camera path is **not** gated by this flag — passthrough is the same behaviour the stock plugin ships.                                                   |
| `--disable-ftps-fastpath` | enabled                                                        | Stub out the `ft_*` C ABI; Studio will fall back to its internal FTP send path. Both modes land the file in the same place on the printer — see [STATUS.md § 6.14](STATUS.md#614-file-transfer-abi-ft_) for the trade-offs. Orthogonal to `--disable-workarounds`. Maps to `-DOBN_FT_FTPS_FASTPATH=OFF`.                                                                                                                                                                                                                                                                                                                                                                                                    |
| `--enable-tests`          | disabled                                                       | Build `probe_plugin`, `ftps_parse_test`, and `*_live_test` smoke tests. Default is off for regular user builds; CI enables it explicitly. Maps to `-DOBN_BUILD_TESTS=ON`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `--no-conf-patch`         | patch enabled                                                  | Do not edit the slicer's conf file (`BambuStudio.conf` / `OrcaSlicer.conf`) during `make install`. Handy when you want to inspect it yourself first or if you manage it through some other means. Maps to `-DOBN_PATCH_CLIENT_CONF=OFF`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `--build-dir=DIR`         | `build`                                                        | Where CMake writes its build tree. Only relevant if you want to keep several builds side by side.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `--cmake-arg=ARG`         | none                                                           | Pass an arbitrary flag through to CMake (e.g. `--cmake-arg=-GNinja`). Repeatable.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

**Version auto-detection** (omit `--with-version`):

- **Bambu Studio** — baseline comes from the slicer’s own build id: the `"version"` field inside the `"app"` object of `<prefix>/BambuStudio.conf` (written after you launch Studio at least once). That is the tag Studio and its bundled agent advertise; the plugin must match the **first eight characters** (`MAJOR.MINOR.PATCH`).
- **Orca Slicer** — baseline comes from `"network_plugin_version"` in the `"app"` object of `<prefix>/OrcaSlicer.conf`, because Orca tracks plugin ABI separately from the Orca app version. If that key is still missing (fresh Orca install, no plugin installed yet), both scripts fall back to **`02.03.00`**.

The detected `W.X.Y.Z` or `W.X.Y` is turned into a **four-component** `OBN_VERSION` with the **last component set to `99`** (e.g. `02.06.01.55` → `02.06.01.99`, `02.03.00` → `02.03.00.99`) so the replacement plugin always wins the “newer than the bundled agent” check.

`./configure --help` also lists less common flags (including Mosquitto linking
options). Driving **CMake** directly works the same way; see `OBN_`* and
other cache variables in `CMakeLists.txt`.

### Windows

Bambu Studio for Windows is a 64-bit MSVC build (Visual Studio 2019, see
`3rd_party/BambuStudio/build_win.bat`). The plugin ABI passes
`std::string`, `std::map` and `std::function` across the DLL boundary, so
**the plugin must be built with the same compiler and STL Studio uses** —
i.e. MSVC from Visual Studio 2019 (toolset v142). MinGW or any libstdc++
flavour will silently mangle types and crash on the first `bambu_network_*`
call. C++ libraries (OpenSSL, libcurl, zlib, libmosquitto) come from
[vcpkg](https://github.com/microsoft/vcpkg) in manifest mode (`vcpkg.json`).

#### Prerequisites (Windows)

- Visual Studio 2019 with the *Desktop development with C++* workload
  (toolset v142). Newer toolsets *may* work but the std::string layout
  across the DLL boundary is not guaranteed.
- CMake ≥ 3.20 (the one bundled with VS 2019 works).
- vcpkg checked out somewhere on disk; export `VCPKG_ROOT` so PowerShell
  can find it. The vcpkg shipped with Visual Studio 2022 (under
  `…\VC\vcpkg\`) works as well — `vcpkg.json` pins a `builtin-baseline`
  SHA so modern, strict-manifest vcpkg installations are happy out of
  the box.

#### Windows: configure, build and install

Recommended path through the supplied PowerShell wrapper (mirrors the POSIX
`./configure`):

For Bambu Studio:
```powershell
$env:VCPKG_ROOT = "C:\path\to\vcpkg"
.\configure.ps1
cmake --build   build --config Release
cmake --install build --config Release
```

For Orca Slicer:
```powershell
$env:VCPKG_ROOT = "C:\path\to\vcpkg"
.\configure.ps1 -ClientType orca_slicer
cmake --build   build --config Release
cmake --install build --config Release
```

The wrapper's full option list is `Get-Help .\configure.ps1 -Detailed`; the
useful ones:

| Flag                                  | Default                                    | Equivalent `./configure` flag                           |
| ------------------------------------- | ------------------------------------------ | ------------------------------------------------------- |
| `-ClientType bambu_studio`            | `bambu_studio`                             | `--client-type=bambu_studio` (or `orca_slicer`)         |
| `-Prefix C:\Foo\BambuStudio`          | `%APPDATA%\<client>`                       | `--prefix=DIR`                                          |
| `-WithVersion 02.06.01.99`            | auto-detected (see below)                  | `--with-version=VER`                                    |
| `-EnableTests:$true`                  | `$false`                                   | `--enable-tests` (builds `probe_plugin.exe` on Windows) |
| `-PatchConf:$false`                   | `$true`                                    | `--no-conf-patch`                                       |

Windows-only options (no POSIX `./configure` equivalent — MSVC + vcpkg path only):

| Flag                                  | Default                                    | What it does                                                                                                                                                                                                                                                                                                                                                                                 |
| ------------------------------------- | ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-VcpkgTriplet x64-windows-static-md` | static deps + dynamic CRT (matches Studio) | Selects the **vcpkg triplet** CMake uses (`VCPKG_TARGET_TRIPLET`): which variants of OpenSSL, zlib, curl, mosquitto, etc. get linked. The default **static libs + `/MD` runtime** matches typical Bambu Studio builds so you do not mix CRT modes across the DLL boundary. Use **`x64-windows`** if you want **shared** vcpkg DLLs (often quicker rebuilds, different deployment trade-off). |
| `-VcpkgRoot C:\vcpkg`                 | `$env:VCPKG_ROOT`                          | **Path to your vcpkg checkout.** The script feeds CMake `…/scripts/buildsystems/vcpkg.cmake` from here so manifest mode can resolve `vcpkg.json`. Set the env var globally or pass this when vcpkg lives outside `%VCPKG_ROOT%` / you use several trees.                                                                                                                                     |
| `-RegisterDShowFilter:$false`         | `$true`                                    | When **on** (default), `cmake --install` runs **`regsvr32`** on `BambuSource.dll` so the **DirectShow** source filter is **COM-registered** — needed for **Orca / `wxMediaCtrl2` / Windows Media Player** camera playback. Turn **off** for portable or staged installs, CI, or if you register the DLL yourself (`regsvr32 /s` / `/u`) after copying plugins by hand.                       |

**Version auto-detection** (omit `-WithVersion`; same intent as Linux, different primary source):

- **Bambu Studio** — `configure.ps1` first tries the **installed application binary**, not the conf file alone. It scans the **Add/Remove Programs** uninstall registry (`HKLM\…\Uninstall`, `HKLM\…\Wow6432Node\…\Uninstall`, `HKCU\…\Uninstall`) for an entry whose **DisplayName** is **`Bambu Studio`**, resolves the real **`bambu-studio.exe`** from **`DisplayIcon`** (or **`InstallLocation`** + `bambu-studio.exe`), and reads the PE **`FileVersion`** string. That matches what Studio uses internally as **`SLIC3R_VERSION`** and what the About box shows. Only if that path fails does it fall back to the **`"version"`** field under **`"app"`** in **`<Prefix>\BambuStudio.conf`** (default prefix is **`%APPDATA%\BambuStudio`**). The binary wins when both exist because the conf can **lag the `.exe`** after a patch, and Studio’s plugin gate compares against the **running build**, not the stale JSON line — picking only the conf can make Studio reject the DLL every launch. If **neither** `FileVersion` nor conf **`version`** is available, the script **errors** and asks for **`-WithVersion`** (same “no silent guess” idea as Linux).
- **Orca Slicer** — the same registry walk for **DisplayName `OrcaSlicer`**, then **`FileVersion`** of the Orca executable; if that fails, **`"network_plugin_version"`** under **`"app"`** in **`<Prefix>\OrcaSlicer.conf`**. If that key is still absent (never installed a plugin), fall back to **`02.03.00`** — the newest network version Orca advertises upstream (see **`AVAILABLE_NETWORK_VERSIONS`** in Orca’s `bambu_networking.hpp`), so a pristine Orca profile still configures. When **FileVersion** and the conf disagree, the script prints a note and keeps the **binary** value.

Identical to Linux: the chosen `W.X.Y.Z` or `W.X.Y` is normalized to **four** dotted components with the **last set to `99`** so the plugin passes the “newer than bundled agent” check.

Driving CMake directly is also fine:

```powershell
cmake -S . -B build -G "Visual Studio 16 2019" -A x64 `
    -DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake `
    -DVCPKG_TARGET_TRIPLET=x64-windows-static-md `
    -DOBN_VERSION=02.06.01.99 -DOBN_CLIENT_TYPE=bambu_studio
cmake --build   build --config Release
cmake --install build --config Release
```

`cmake --install` runs the automated install. For the manual steps (copy paths, conf keys), see [Manual installation](#manual-installation) below.

## Manual installation

First, copy the plugin binaries themselves: `*.so` on Linux and `*.dll` on Windows.
For both Bambu Studio and Orca Slicer, put them in the `plugins` directory under the application’s data / config directory:

  - `~/.config/<client_name>/plugins` — Linux
  - `~/.var/app/<namespace>/config/<client_name>/plugins` — Linux (Flatpak install)
  - `%APPDATA%\<client_name>\plugins` — Windows

Here `client_name` is `BambuStudio` or `OrcaSlicer`, and `namespace` is `com.bambulab.BambuStudio` or `com.orcaslicer.OrcaSlicer` respectively.

- **Bambu Studio:** also place `network_plugins.json` in `ota/plugins` (alongside the `plugins` directory).
- **Orca Slicer:** rename `libbambu_networking.so` (or `bambu_networking.dll` on Windows) so the filename includes the plugin version, e.g. `libbambu_networking_02.03.00.99.so`.

Then edit the configuration file.

**Bambu Studio** — `BambuStudio.conf` (under the `app` object):

  - set `"installed_networking"` to `"1"` (mark the plugin as installed)
  - set `"update_network_plugin"` to `"false"` (avoid auto-update replacing it with the stock plugin)
  - on **Windows** and **macOS**, set `ignore_module_cert` to `"1"` to skip publisher / certificate validation for the plugin

**Orca Slicer** — `OrcaSlicer.conf` (under the `app` object):

  - set `"installed_networking"` to `"true"`
  - set `"network_plugin_version"` to your built plugin version, e.g. `02.03.00.99`
  - set `"network_plugin_remind_later"` to `"true"` to suppress “newer plugin available” prompts
  - remove your plugin version from `"network_plugin_skipped_versions"` if it appears there

## Logging

The plugin writes a printf-style log of ABI calls and MQTT / FTPS /
HTTP activity. **Defaults:** severity **info**, output **only to stderr**
(the terminal that launched Bambu Studio). No log file is opened unless
you opt in — this keeps disk noise down for everyday use.

**Where it goes.**

- **Default:** stderr only (`OBN_LOG_STDERR=1`), each line prefixed with
`[obn]` so it is easy to grep apart from Bambu Studio’s own stderr.
- **File next to the slicer's data directory:** set `OBN_LOG_TO_FILE=1`
to append to `<data_dir>/obn.log`, where `data_dir` is the path the
slicer passes to `bambu_network_create_agent`. Typical paths:
`~/.config/BambuStudio/obn.log` (Linux Studio),
`~/.config/OrcaSlicer/obn.log` (Linux Orca),
`%APPDATA%\BambuStudio\obn.log` (Windows Studio),
`%APPDATA%\OrcaSlicer\obn.log` (Windows Orca). The mirror file for
`BambuSource.dll` (`obn-bambusource.log`) follows the same dispatch:
it auto-detects the host slicer from the DLL's own install path so
Studio and Orca never share a log file.
- **Explicit path:** set `OBN_LOG_FILE` to an absolute path. Use
`/dev/null` to disable the file sink while keeping stderr. An empty
`OBN_LOG_FILE=` means “no file from env” (stderr only unless
`OBN_LOG_TO_FILE=1`).

**Log levels.** `trace < debug < info < warn < error < off`. The default
is **info**. Use `debug` or `trace` when diagnosing issues (`trace` adds
per-MQTT-frame and per-FTPS-command noise).

**Configuration via environment variables** (read once, on first log
call — export them *before* launching Studio):

| Variable          | Default   | Effect                                                                                                                                       |
| ----------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `OBN_LOG_LEVEL`   | `info`    | Threshold: `trace`, `debug`, `info`, `warn`, `error`, `off`.                                                                                 |
| `OBN_LOG_STDERR`  | `1`       | When `1`, copy every line to stderr with an `[obn]` prefix. Set to `0` to suppress the console copy (only useful together with a file sink). |
| `OBN_LOG_TO_FILE` | *(unset)* | Set to `1`/`true`/`yes` to append to `<data_dir>/obn.log` after Studio passes `data_dir`. Ignored if `OBN_LOG_FILE` is set.                  |
| `OBN_LOG_FILE`    | *(unset)* | Absolute path to a log file. Creates the file sink when non-empty.                                                                           |

Example — default behaviour (info to terminal only):

```sh
bambu-studio
```

Example — persistent file next to Studio data, no stderr spam:

```sh
OBN_LOG_TO_FILE=1 OBN_LOG_LEVEL=info OBN_LOG_STDERR=0 bambu-studio
```

Example — full wire-level trace to a dedicated file:

```sh
OBN_LOG_LEVEL=trace OBN_LOG_FILE=/tmp/obn-session.log bambu-studio
```

**Line format:**

On stderr, each line starts with `[obn]`, then:

```
YYYY-mm-dd HH:MM:SS.uuuuuu [LVL] [tid] file.cpp:line func_name: message
```

The file sink (if any) omits the `[obn]` prefix — the file is plugin-only.

where `tid` is the OS thread id — useful to correlate MQTT
background-thread activity with Studio main-thread ABI calls.

**Secrets — be careful before sharing a log.** The plugin does *not*
currently auto-redact secrets. At `debug` and `trace` levels the log
can contain: printer access codes (MQTT password), session bearer /
refresh tokens from `obn.auth.json`, raw MQTT `push_status` payloads
(which include serial numbers and filament metadata), FTPS file
paths, and device IPs. Before pasting a log into a bug report, grep
out `access_code`, `Bearer`, `accessToken`, `refreshToken`,
`password`, and your printer's serial / WAN IP. (Tightening this up
into a proper redacting logger is on the TODO list.)

### `libBambuSource.so` logging

`libBambuSource.so` is `dlopen`'d separately from the main plugin and
runs inside the camera / file-browser code path that the slicer's media
widget drives. It keeps its own log mirror so you can see RTSP / TLS
failures even when the parent slicer process funnels its log somewhere
unhelpful.

| Variable                     | Default                                                                                                                                                                                          | Effect                                                                                                                                                                |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OBN_BAMBUSOURCE_LOG_LEVEL`  | `info`                                                                                                                                                                                           | `trace` / `debug` / `info` / `warn` / `error` / `off`. Filters both the file mirror and the callback the slicer gets.                                                 |
| `OBN_BAMBUSOURCE_LOG_FILE`   | Linux: first writable of `$XDG_STATE_HOME/bambu-studio/obn-bambusource.log`, `$HOME/.local/state/bambu-studio/obn-bambusource.log`, `/tmp/obn-bambusource.log`. Windows: first writable of `<host slicer's data dir>\obn-bambusource.log` (i.e. `%APPDATA%\BambuStudio\obn-bambusource.log` when loaded by Bambu Studio, `%APPDATA%\OrcaSlicer\obn-bambusource.log` when loaded by OrcaSlicer — auto-detected from the DLL's own install path), then `%LOCALAPPDATA%\BambuStudio\obn-bambusource.log`, then `%TEMP%\obn-bambusource.log`. | Absolute path to the file mirror, or `off` / `none` / empty / `0` to disable, or `stderr` / `-` to route to stderr instead of a file.                                 |

The mirror file rolls every line through `[level]` plus a timestamp.
Lines are tagged with `rtsp:` (handshake / DESCRIBE / SETUP / PLAY),
`rtsp_passthrough:` (the worker that hands the byte stream to
gstbambusrc on Linux), and on Windows also `dshow:` (the DirectShow
filter's connection / sample pump). If you see no video despite a
successful `rtsp: PLAY ok` the issue is slicer-side: on Linux, missing
GStreamer H.264 decoder (`gstreamer1.0-plugins-bad` /
`gstreamer1.0-libav`); on Windows, missing H.264 MFT (Media Feature
Pack on N/KN editions).

## License

MIT — see [LICENSE](LICENSE).

## Support the Developer and the Project

- [GitHub Sponsors](https://github.com/sponsors/ClusterM)
- [Patreon](https://www.patreon.com/c/ClusterMeerkat)
- [Buy Me A Coffee](https://www.buymeacoffee.com/cluster)
- [Sber](https://messenger.online.sberbank.ru/sl/Lnb2OLE4JsyiEhQgC)
- [Donation Alerts](https://www.donationalerts.com/r/clustermeerkat)
- [Boosty](https://boosty.to/cluster)
