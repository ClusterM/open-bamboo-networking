# Open Bamboo Networking

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
- macOS (very experimental, works partially, not documented yet).

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
- Internal storage file browser/operations

### More details

The author only owns a **P2S**, so the "Tested" column in the table
below usually means it works 100% on **P2S**. 

**Community help is essential.** If you use another printer model or
CPU architecture, please try the plugin and open an issue:
[https://github.com/ClusterM/open-bamboo-networking/issues](https://github.com/ClusterM/open-bamboo-networking/issues)
with what works, what fails, and your firmware / OS / Studio version —
that is how we turn "not tested" into documented reality. Bug reports,
regressions, and small compatibility notes all belong in
**[Issues](https://github.com/ClusterM/open-bamboo-networking/issues)**.

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
| "Send to Printer" dialog (`ft_*`)          | ✅ (tested on P2S) | Native    | `ft_*` over TLS :6000 — upload `cmd_type=5`, ability `7`, Printer Preview `cmd_type=4` (`mem:/26`). See [STATUS.md §6.14](STATUS.md#614-file-transfer-abi-ft_). |
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

**Default (stock parity):** `libBambuSource.so` opens TLS **:6000**, runs the BambuTunnelLocal handshake (`StartStreamEx` / `mtype` 12291), then **forwards** Studio's CTRL JSON (`LIST_INFO`, `SUB_FILE`, `FILE_DOWNLOAD`, …) to printer firmware — same wire as stock. See [NETWORK_PLUGIN.md §7.5.1](NETWORK_PLUGIN.md#751-where-the-printer-side-bytes-actually-come-from).

**3MF model thumbnails in the browser:** Studio sends **`SUB_FILE`** (`cmdtype=2`). Typical shapes:
- `req.paths`: `["/path/model.gcode.3mf#thumbnail"]` — firmware returns `Metadata/plate_N.png` bytes (or sidecar `.jpg` for timelapses).
- `req.zip=true` — whole `.3mf` archive in chunks for FetchModel.

Our plugin does not parse thumbnails locally on this path; firmware (or stock passthrough) serves the blob.

**Legacy fallback:** `OBN_CTRL_FTPS_FALLBACK=1` re-enables the old in-process FTPS translator (external USB only). Not used in normal builds.

| Feature | Status | Notes |
| --- | :--: | --- |
| Browse / download / delete | ✅ (P2S) | Native `:6000` passthrough when fallback off |
| `SUB_FILE` / `.3mf` plate thumbnails | ✅ | Stock wire; `#thumbnail` in path |
| Internal eMMC tab (`storage=internal`) | ⚠️ | Depends on firmware + native :6000 (same as stock) |
| FTPS fallback | ⚠️ | Env-only; external USB; see [STATUS.md](STATUS.md#printerfilesystem-mediafilepanel) |

#### Status / Device tab

| Feature                                     | Applies to | Status             | Impl        | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------- | ---------- | ------------------ | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Current-print thumbnail cover               | All models | ✅ (tested on P2S) | Workaround  | LAN prints with zero ids → synthetic `lan-<fnv>` + `get_subtask_info` → loopback HTTP. Backend: **`SUB_FILE` on TLS :6000** (`/cache/<subtask>.gcode.3mf#thumbnail`). **Linux:** needs [`patches/bambustudio-statuspanel-thumbnail.patch`](patches/bambustudio-statuspanel-thumbnail.patch). |
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
| `ipcam.file` block injection                                   | Firmware with a file browser advertises `ipcam.file = {"local":"local",…}`; Studio keys the MediaFilePanel off that.                                                                                                                                                                                                                                                                                                                                 | When the printer omits the block we inject `{"local":"local","remote":"none","model_download":"enabled"}` into the ipcam object. Present blocks pass through unchanged.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Without this Studio short-circuits MediaFilePanel and never opens the `:6000` CTRL tunnel.                                                                                                                                                                                                                                    | Does not change firmware; only unblocks Studio UI on P2S/A-class MQTT. |
| Device → Files (`libBambuSource`)                              | Stock keeps TLS :6000 open and forwards CTRL JSON to firmware.                                                                                                                                                                                                                                                                                                                                                                                          | **Default:** same — native BambuTunnelLocal passthrough (`start_native_ctrl_handshake`). **Optional:** `OBN_CTRL_FTPS_FALLBACK=1` maps CTRL to FTPS (legacy, external USB only).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Matches stock wire on the default path.                                                                                                                                                                                                                                                                                                                                                                           | FTPS fallback is for regression/debug only; not the normal P2S path.                                                                                                                                                                                                                      |
| 3MF thumbnails in file browser                                 | Firmware handles `SUB_FILE` (`path#thumbnail` or zip mode) over :6000.                                                                                                                                                                                                                                                                                                                                                                                | Default path: passthrough — no local ZIP parse. FTPS fallback extracts PNG client-side (legacy).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Same as stock when passthrough is active.                                                                                                                                                                                                                                                                                                                                                                         | FTPS fallback only when env set.                                                                                                                                                                                                                                   |
| Camera liveview (RTSPS)                                        | Stock `libBambuSource.so` does the RTSP/RTSPS handshake on port 322 (live555-based) and hands raw H.264 byte-stream back through `Bambu_ReadSample`; the slicer's `gstbambusrc` then decodes it.                                                                                                                                                                                                                                                     | Same thing with our own RTSP client (`stubs/rtsp_client.cpp` — TLS + Basic/Digest auth + RTP/TCP-interleaved depacketisation, FU-A / STAP-A reassembly, GET_PARAMETER keepalive) and an Annex-B passthrough worker (`stubs/rtsp_passthrough.cpp`) that re-prefixes SPS/PPS in front of every IDR. The byte stream is the same one stock returns.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Owning the RTSP layer ourselves drops the live555 dependency and keeps the plugin self-contained.                                                                                                                                                                                                                                                                                                                 | Single H.264 video track, baseline/main profile, no audio. Reconnect on stream drop is "tear down + re-`Bambu_Open`", same as stock.                                                                                                                                                                                                     |
| `start_sdcard_print` over LAN MQTT                             | Stock plugin hits a cloud REST endpoint (`start_sdcard_print`) that signs and relays the command via the cloud tunnel.                                                                                                                                                                                                                                                                                                                               | We publish `{"print":{"command":"project_file", "url":"file:///<path>", …}}` directly on the active LAN MQTT session.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | The cloud endpoint requires MakerWorld signing we don't reproduce, and Developer Mode printers have no cloud route to receive it on anyway. LAN MQTT is what the firmware actually consumes.                                                                                                                                                                                                                      | No cloud task record. `task_id` / `subtask_id` / `project_id` are all `0`, which a very old firmware could refuse if it ever validates them (none observed).                                                                                                                                                                             |
| Cross-device user preset sync                                  | Stock plugin's `get_setting_list2` only fetches metadata (`setting_id`, `name`, `update_time`, …) from `GET /v1/iot-service/api/slicer/setting`, assuming the matching preset body is already present on disk under `<config_dir>/user/<uid>/`. On a fresh machine the list walk produces a `setting_id` with no `setting` map to merge in, so `PresetCollection::load_user_preset()` silently skips every cloud preset and your profiles disappear. | For each preset the Studio-provided `CheckFn` flags as needed, we additionally issue `GET /v1/iot-service/api/slicer/setting/<setting_id>` to pull the full `setting` payload, then inject `user_id` (not returned by the server) and convert `update_time` from `"YYYY-MM-DD HH:MM:SS"` into the unix-seconds string `load_user_preset()` expects. The resulting flat `values_map` is handed to Studio exactly where it would expect one from a local file.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Studio's loader path and the cloud endpoint both exist; the stock plugin simply never connects the two. The extra `GET /setting/<id>` per preset is the minimum RTT needed to survive a wiped local cache (on which the author got burnt while reverse-engineering this section).                                                                                                                                 | One HTTPS round-trip per synced preset on the first sync after a wipe (~100 KB response each). On a machine that already has the local files, Studio's `need_sync()` check short-circuits the download — same bandwidth as stock.                                                                                                        |
| Firmware info synthesis (`get_printer_firmware`)               | Stock plugin serves `GET /v1/iot-service/api/slicer/resource/printer/firmware?dev_id=…` against the Bambu cloud, returning a JSON envelope (current/new version per module + release notes + binary URL) that Studio's `UpgradePanel` and `ReleaseNoteDialog` render.                                                                                                                                                                                | The plugin doesn't call the cloud at all. Instead the agent maintains a `DeviceFw` cache keyed by `dev_id` that harvests versions from every MQTT frame the printer already sends: `info.command=get_version` replies (module array with `name`/`sw_ver`/`sn`/`loader_ver`) and `push_status.upgrade_state.new_ver_list`. `render_firmware_json(dev_id)` then emits the same envelope Studio expects — current versions populate the Update panel, advertised newer versions light up the "update available" banner, the description links to `bambulab.com/en/support/firmware-download/all`. The actual flash is a passthrough: Studio's "Update" button publishes `{"upgrade":{"command":"upgrade_confirm"}}` on LAN MQTT, and the printer fetches the binary from Bambu's CDN itself.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | The cloud firmware catalogue requires a signed request with an `accessToken` for a linked account and answers with HTML behind Cloudflare from an untrusted client (no stable public JSON). What we need (current version, advertised new version, a way to flash the advertised one) is already on the wire in plaintext via MQTT, so we re-synthesise the envelope locally.                                     | No cross-version history — you can only flash what the printer is currently advertising, not an older or a beta OTA from the cloud catalogue. Release Notes text is a short auto-generated stub with an external link, not the full changelog. No effect when no new version is advertised (Release Notes dialog empty — same as stock). |
| `ft_*` over TLS :6000 | Port-6000 BambuTunnelLocal for Send-to-Printer, eMMC preflight, LAN print upload, and **Printer Preview** (`cmd_type=4` / `mem:/26`). | Native `:6000` wire (`tunnel_upload.cpp` + `abi_ft.cpp`): chunked upload §6.14.2, mem download §6.14.4. | Same BambuTunnelLocal framing as stock `ft_*`. | Shared with `start_local_print` when `try_emmc_print`. Legacy printers without `:6000` use Studio `SendJob` → FTPS. [STATUS.md §6.14](STATUS.md#614-file-transfer-abi-ft_). |
| Current-print thumbnail cover                                  | Stock plugin gets `project_id`/`profile_id`/`subtask_id` from cloud tasks; `get_subtask_info` returns CDN `thumbnail.url`.                                                                                                                                                                                                                                                                            | **(a)** LAN prints with zero ids → rewrite to synthetic `lan-<fnv>` on `push_status`. **(b)** Real cloud subtask ids after unbind → same `get_subtask_info` hook. Backend: loopback HTTP + **`SUB_FILE` on :6000** (`/cache/*.gcode.3mf#thumbnail`). Linux needs [`patches/bambustudio-statuspanel-thumbnail.patch`](patches/bambustudio-statuspanel-thumbnail.patch). | wxWebRequest rejects `file://`; loopback HTTP mirrors cloud path. Cache under `obn-covers/`. | One SUB_FILE per print; 503 if `/cache/` file gone.              |

**Gated by `OBN_ENABLE_WORKAROUNDS`:** rows 1–2 (MQTT UI hints), in-print cover (MQTT id rewrite + `get_subtask_info`), `start_sdcard_print` LAN MQTT. **Always on:** firmware info synthesis, preset sync, `ft_*`/`:6000`, native file-browser passthrough, RTSPS. **`start_sdcard_print` cloud bypass** may get its own flag later.

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
| MQTT / HTTP / TLS / zlib              | `git`, `uthash-dev`, `libcurl4-openssl-dev`, `libssl-dev`, `zlib1g-dev` | `git`, `uthash-devel`, `libcurl-devel`, `openssl-devel`, `zlib-devel` |

> Note  
> libmosquitto is **always vendored** via FetchContent at configure time (needs `git` + network). `uthash-dev` supplies `utlist.h`; cJSON is bundled automatically.

One-shot install examples:

```sh
# Debian / Ubuntu
sudo apt install build-essential cmake pkg-config git \
  uthash-dev libcurl4-openssl-dev libssl-dev zlib1g-dev
```

```sh
# Fedora
sudo dnf install gcc-c++ cmake pkgconf-pkg-config git \
  uthash-devel libcurl-devel openssl-devel zlib-devel
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
| `--disable-workarounds`   | enabled                                                        | MQTT `home_flag` / `ipcam.file` rewrites; in-print cover (`get_subtask_info` + `cover_cache`); `start_sdcard_print` LAN MQTT instead of signed cloud REST; optional `OBN_CTRL_FTPS_FALLBACK` FTPS file browser. Does **not** disable `ft_*`/`:6000`, native file-browser passthrough, RTSPS, firmware info, or preset sync. Maps to `-DOBN_ENABLE_WORKAROUNDS=OFF`. |
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
call. C++ libraries (OpenSSL, libcurl, zlib) come from
[vcpkg](https://github.com/microsoft/vcpkg) in manifest mode (`vcpkg.json`).
libmosquitto is always vendored via FetchContent (same as Linux).

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

GNU Affero General Public License v3.0 (AGPL-3.0) — see [LICENSE](LICENSE).

## Support the Developer and the Project

- [GitHub Sponsors](https://github.com/sponsors/ClusterM)
- [Patreon](https://www.patreon.com/c/ClusterMeerkat)
- [Buy Me A Coffee](https://www.buymeacoffee.com/cluster)
- [Sber](https://messenger.online.sberbank.ru/sl/Lnb2OLE4JsyiEhQgC)
- [Donation Alerts](https://www.donationalerts.com/r/clustermeerkat)
- [Boosty](https://boosty.to/cluster)
