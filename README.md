# Open Bamboo Networking

Open-source drop-in replacement for Bambu Studio's proprietary `bambu_networking`
plugin.

## Table of contents

- [Downloads](#downloads)
- [Installation](#installation)
- [Why this project exists](#why-this-project-exists)
- [Supported platforms](#supported-platforms)
- [Supported slicers](#supported-slicers)
- [Two ways to run](#two-ways-to-run)
  - [Option A: Developer Mode](#option-a-developer-mode)
  - [Option B: cloud mode without Developer Mode](#option-b-cloud-mode-without-developer-mode)
- [What works and what's not](#what-works-and-whats-not)
  - [TL;DR: what is **not** implemented](#tldr-what-is-not-implemented)
  - [More details](#more-details)
    - [Basics (model-independent)](#basics-model-independent)
    - [Printing](#printing)
    - [Camera liveview](#camera-liveview)
    - [Status / Device tab](#status-device-tab)
  - [Cloud sign-in in Developer or LAN-only mode](#cloud-sign-in-in-developer-or-lan-only-mode)
- [Building from source](#building-from-source)
- [Configuration file](#configuration-file)
- [Logging](#logging)
  - [`libBambuSource.so` logging](#libbambusourceso-logging)
- [Known issues](#known-issues)
- [License](#license)
- [Support the Developer and the Project](#support-the-developer-and-the-project)

## Downloads

Pre-built plugin binaries are available for all supported platforms.

**Stable releases:** [GitHub Releases](https://github.com/ClusterM/open-bamboo-networking/releases)
— tested and tagged versions recommended for general use.

**Interim builds:** [GitHub Pages](https://clusterm.github.io/open-bamboo-networking/)
— automatically built from the latest commit on the main branch. These
builds may include new features and bug fixes ahead of the next release, but
they can also be unstable, contain incomplete functionality, or introduce
breaking changes that will be revised before the next stable release. Use them
if you want the cutting edge and are comfortable reporting issues.

## Installation

Every release / interim archive ships with an interactive installer, so you do
**not** need to build anything. Download the archive for your platform, unpack
it, and run the bundled installer:

| Platform | Archive | Installer |
| --- | --- | --- |
| Linux (x86_64 / aarch64) | `obn-linux-*.tar.gz` | `chmod +x install.sh && ./install.sh` |
| Windows (x64 / ARM64) | `obn-windows-*.zip` | double-click `install.bat`, or `.\install.ps1` in PowerShell |
| macOS (Apple Silicon / Intel) | `obn-macos-*.tar.gz` | double-click `install.command` in Finder, or `./install.sh` |

Close the slicer before running the installer. After installing, launch it
again and (optionally) tune the plugin via [`obn.conf`](#configuration-file).

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
- **No ARM or non-x86_64 build.** The stock plugin is published for
x86_64 only. You can't use Studio or any third-party tool that reuses
the plugin on a Raspberry Pi, an Ampere workstation, or any other
aarch64 host, even though the rest of Studio builds cleanly. (This
project additionally builds for Linux aarch64 and Windows ARM64 — see
[Supported platforms](#supported-platforms).)
- **Cloud chatter on every action, even in LAN-only mode.** Even when
the printer is sitting on the same subnet as Studio in Developer
Mode, the stock plugin keeps reaching out to
`api.bambulab.com` / MakerWorld for things like bind status and
task metadata. That's extra latency on every click, a hard
dependency on the account infrastructure being up, and a
surveillance footprint a lot of users didn't opt in to.

This project is a drop-in replacement for that library: same `dlsym`
ABI, same file name, same install location, but open source,
aligned-atomic-clean, cross-architecture-buildable, and LAN-first **by
default** (`block_cloud = 1`: the cloud is only contacted for sign-in
and preset sync, the rest goes straight to the printer). The cloud path
is there when you deliberately opt in — see
[Option B](#option-b-cloud-mode-without-developer-mode).

Protocol knowledge comes from
[OpenBambuAPI](https://github.com/Doridian/OpenBambuAPI) and the
reference implementations in
[bambulabs_api](https://github.com/acse-ci223/bambulabs_api) and
[ha_bambu_lab](https://github.com/greghesp/ha-bambulab); everything
else is reverse-engineered from MITM captures of the stock plugin.

Everything we have been able to establish about how the stock network
plugin is integrated, validated, and invoked — including the full C ABI
and related wire behaviour — is collected in
[research/INDEX.md](research/INDEX.md).

Please note:

**This project has been built entirely through the author's enthusiasm, with a tremendous personal investment of time, effort, and financial resources. If this work helps you, please consider supporting its further development in the [Support the Developer and the Project](#support-the-developer-and-the-project) section.**

## Supported platforms

- Linux x86_64 (primary target).
- Linux aarch64 (primary target).
- Windows x64 (primary target).
- Windows ARM64 (experimental, no video).
- macOS ARM64 (experimental).
- macOS x64 (experimental).

All of these are built and smoke-tested in CI for every supported ABI.

## Supported slicers

The same plugin binary drives both **Bambu Studio** and **Orca Slicer** — they
consume the same C ABI — and the installer handles the per-client conventions
for you. But they are not equal targets.

**Bambu Studio — primary target.** Development and testing happen here first;
every feature is verified against Studio. Supported ABI series:

- Bambu Studio **02.03.00**._xx_
- Bambu Studio **02.03.01**._xx_
- Bambu Studio **02.04.00**._xx_
- Bambu Studio **02.05.00**._xx_
- Bambu Studio **02.05.01**._xx_
- Bambu Studio **02.05.02**._xx_
- Bambu Studio **02.05.03**._xx_
- Bambu Studio **02.06.00**._xx_
- Bambu Studio **02.06.01**._xx_
- Bambu Studio **02.07.00**._xx_
- Bambu Studio **02.07.01**._xx_
- Bambu Studio **02.08.00**._xx_
- Bambu Studio **02.08.01**._xx_
- Bambu Studio **02.08.02**._xx_

Compatibility with plugin ABI depends on the first three numbers in the version number, e.g.
any Bambu Studio v**02**.**03**.**04**._xx_ is compatible with any plugin with a version v**02**.**03**.**04**._xx_.

**Orca Slicer — supported, with caveats.** Orca tracks the plugin ABI
separately from its own app version, so the installer always installs the
**`02.03.00`** series and patches `network_plugin_version` in `OrcaSlicer.conf`
to match — you do not have to pick a version in Preferences. That is the series
Orca has shipped since **Orca Slicer v2.3.2**; earlier releases ask for
`02.01.01`, which this project does not build, so v2.3.2 is the minimum. The
library file name must carry the version (`libbambu_networking_<ver>.so`), which
the installer also handles. Expect these differences from Studio:

- **No current-print thumbnail.** Orca routes `get_subtask_info` through its
  own `OrcaCloudServiceAgent` stub instead of the plugin, so the Device panel
  shows a placeholder cover. This needs a patch to Orca itself and cannot be
  fixed plugin-side (see [Known issues](#known-issues)).
- **MQTT reconnect churn.** Orca tears down and re-establishes the MQTT
  session after every print, causing a 5-30 s delay on printers with few MQTT
  slots — which is why `mqtt_keep_connection` defaults to `1`.
- **Camera on Windows needs the DirectShow filter.** Orca plays video through
  `wxMediaCtrl2` / DirectShow, so `BambuSource.dll` must be registered with
  `regsvr32` (the installer offers to do this). Bambu Studio does not need it.

## Two ways to run

Recent (2024+) printer firmware cryptographically verifies every MQTT command
it receives while the printer is paired with the Bambu cloud. The verification
uses a per-installation RSA key that the stock plugin ships as obfuscated data.
There are two ways to work with that, and they trade convenience against how
much of the cloud you keep.

### Option A: Developer Mode

This is the **simple path, and it is enough for most people.** The printer is
switched into Developer Mode, which turns MQTT command verification off, so the
plugin can drive it over the LAN with no signing keys at all.

1. On the printer screen, enable LAN-only mode and Developer mode. Bambu places these toggles in different submenus depending on the model and firmware — look for options named along the lines of "LAN Only", "LAN Only liveview", and "Developer mode". Examples:
   - **P2S**: Nut icon -> Settings -> **LAN Only Mode**
   - **P1S**: Nut icon -> **WLAN**
2. In Bambu Studio: Device -> Connect via LAN with access code.

In this mode the printer skips MQTT verification and accepts plain LAN
commands. All LAN features of the plugin (discovery, telemetry, printing,
file browsing, file transfer, camera) work normally.

**What Developer Mode costs you:**

- **No cloud print dispatch — you can only start prints while on the same
  network as the printer.** This is solvable but more work to set up: run a VPN
  (e.g. WireGuard / Tailscale) back into your home network, or port-forward
  `8883` / `990` / `6000` / `322` to the printer and set `override_lan_ip = 1`
  so the camera and file browser also use the reachable address.
- **No cloud print records:** MakerWorld print history and model ratings are
  not written for LAN prints.
- Cloud camera and cloud file browsing are unavailable — but those are not
  implemented in either mode (LAN only, see below).

### Option B: cloud mode without Developer Mode

Starting with v2.0.0 the plugin can also drive a **cloud-paired printer with
verification left ON** — no Developer Mode. This keeps the cloud features
(cloud print dispatch, print history, MakerWorld) but is meant for advanced
users, because it requires private slicer credentials that this project does
**not** distribute.

Two things are needed:

**1. Bambu's slicer credentials, which you provide yourself.** Put
`slicer_cert.pem`, `slicer_key.pem` and `slicer_crl.pem` in the plugin's config
directory (or point at them with `slicer_cert_pem` / `slicer_key_pem` /
`slicer_crl_pem` in [`obn.conf`](#configuration-file)). The plugin uses the key
to sign MQTT `print` commands and to install its app certificate on the printer.
**These are private credentials. This project does not ship them and gives no
instructions on obtaining them** — you have to find or extract them yourself,
and you alone are responsible for ensuring your use complies with the
applicable terms and law.

**2. Two settings in [`obn.conf`](#configuration-file).** Set `block_cloud = 0`
(the default `1` blocks cloud printing outright) and
`client_name = BambuStudio` (the honest default client name is rejected by the
cloud print API with HTTP 403).

With that in place you get signed MQTT commands, on-printer app-certificate
install, cloud print dispatch, print history and MakerWorld — without touching
Developer Mode.

**What the default `cloud_print = cloud_only` actually uploads.** Even in this
mode the model itself normally stays on your network: for a print with a cloud
record the plugin sends the `.3mf` straight to the printer over LAN FTPS, and
only the *record* goes to Bambu — a project entry, a task entry
(`mode=lan_file`) and a small config `.3mf` that print history uses for its
thumbnails. That record is exactly what buys you the cloud extras: print
history in Studio and Handy, and the ability to rate models on MakerWorld. The
full model is uploaded to Bambu's servers only when Studio dispatches a pure
cloud print (`start_print`), e.g. for a printer that is not reachable on your
LAN.

**You can limit even that:** set `cloud_print = try_lan_first` or `lan_only` to
print over the LAN without writing a cloud record at all, and
`cloud_hide_history = 1` to hide the cloud print history in Studio.

If you run **neither** Developer Mode **nor** valid credentials, the printer
rejects every `print` / `project_file` command and shows on its screen:

```
MQTT Command verification failed
err_code: 84033543
```

## What works and what's not

### TL;DR: what is **not** implemented

- **Camera live view over the cloud** (TUTK / Agora p2p) — video works on the
  LAN only.
- **File operations over the cloud** — browsing / download / delete work over
  the LAN only (`:6000` / FTPS).
- **Go Live** and **HMS photo snapshot** — both are cloud-only and need the
  proprietary SDK.

Two things that used to be listed here now work with caveats:

- **Printing without Developer Mode** works if you supply your own slicer
  credentials — see [Option B](#option-b-cloud-mode-without-developer-mode).
- **MakerWorld** (print history, model ratings, task list) works in cloud mode;
  see the [Printing](#printing) table and
  [Option B](#option-b-cloud-mode-without-developer-mode).

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
| 🔒   | Implemented, but only works with proprietary Bambu secrets you supply yourself (see [Option B](#option-b-cloud-mode-without-developer-mode)). |
| ❌   | Not implemented (see [TL;DR: what is **not** implemented](#tldr-what-is-not-implemented) for scope rationale). |

The **Impl** column distinguishes:

- **Native** — the plugin speaks the same wire protocol the stock
`bambu_networking.so` does. Drop-in behaviour.
- **Alternative** — the plugin reaches the same user-visible outcome
over a different transport (e.g. LAN MQTT instead of cloud REST).
- **Passthrough** — the plugin just forwards MQTT / REST payloads;
Studio does the work.

#### Basics (model-independent)

| Feature                              | Status | Impl                | Notes                                                                                                                                                                |
| ------------------------------------ | ------ | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SSDP discovery (LAN)                 | ✅     | Native              | UDP `:2021` NOTIFY listener + Studio `on_server_connected`_.                                                                                        |
| LAN MQTT telemetry                   | ✅     | Native              | TLS to `mqtts://<ip>:8883`, user `bblp`, pass = access code.                                                                                                         |
| Cloud MQTT telemetry                 | ✅     | Native              | TLS to `us.mqtt.bambulab.com:8883`. Runs in parallel with LAN when signed in; not exercised during LAN-focused testing.                                              |
| Cloud login / ticket flow            | ✅     | Native              | Browser → `localhost` callback → `POST /user-service/user/ticket/<T>`. Session persisted to `obn.auth.json`.                                                         |
| User presets sync / profile / avatar | ✅     | Native              | List / create / update / delete works                                                                                                                                |
| Filament Manager (cloud spool catalogue) | ✅ | Native              | Studio's spool tab (Studio 02.06.01+). All CRUD endpoints plus the bulk AMS sync added in ABI 02.08.01 and the AMS slot bind/unbind added in ABI 02.08.02 (new in v2.0.0). Needs cloud sign-in; works under the default `block_cloud = 1`. |
| MQTT command signing                 | 🔒     | Native              | (new in v2.0.0) Signs `print` commands (RSA-PKCS#1 v1.5 + SHA-256) and installs the app cert on the printer **when you supply your own `slicer_key.pem` / `slicer_cert.pem`** — see [Option B](#option-b-cloud-mode-without-developer-mode). Without those keys nothing is signed; use Developer Mode instead. |

#### Printing

| Feature                                    | Status             | Impl        | Notes                                                                                                                                                                                                                       |
| ------------------------------------------ | ------------------ | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LAN print (FTPS + MQTT, Dev Mode)          | ✅ (tested on P2S) | Native      | FTPS upload and `{"print":{"command":"project_file",...}}` command on LAN MQTT.                                                                                                                                             |
| "Send to Printer" dialog (`ft_*`)          | ✅ (tested on P2S) | Native    | `ft_*` over TLS :6000 — upload `cmd_type=5`, ability `7`, Printer Preview `cmd_type=4` (`mem:/26`). See [STATUS.md §8.14](STATUS.md#814-file-transfer-abi-ft_). |
| Cloud 3MF upload to S3                     | ✅                 | Native      | 6-step upload sequence reversed from MITM of the stock plugin.                                                                                                                                                              |
| Cloud print dispatch (`start_print`)       | ⚠️                 | Native      | (new in v2.0.0) Full cloud pipeline: `POST /user/project` → presigned S3 upload → `POST /my/task`. Requires `block_cloud = 0`, `client_name = BambuStudio`, cloud login, and (on a verified printer) your own `slicer_key.pem`. Governed by `cloud_print` (see [Configuration file](#configuration-file)). |
| `create_task` (MakerWorld entry)           | ⚠️                 | Native      | (new in v2.0.0) Writes the MakerWorld task/print-history record as part of the cloud print flow. Needs `client_name = BambuStudio` (otherwise `POST /my/task` → HTTP 403). Not written for pure LAN prints (`try_lan_first` / `lan_only`). |
| "Print from Device" (`start_sdcard_print`) | ✅ (tested on P2S) | Alternative | Stock plugin: cloud REST endpoint we can't sign. Ours: publish `project_file` on LAN MQTT for a file already on the printer.                                                                                                |
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

#### Status / Device tab

| Feature                                     | Applies to | Status             | Impl        | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------- | ---------- | ------------------ | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Current-print thumbnail cover               | All models | ✅ (tested on P2S) | Alternative | LAN prints with zero ids → synthetic `lan-<fnv>` + `get_subtask_info` → loopback HTTP. Backend: **`SUB_FILE` on TLS :6000** (`/cache/<subtask>.gcode.3mf#thumbnail`). **Linux:** needs [`patches/bambustudio-statuspanel-thumbnail.patch`](patches/bambustudio-statuspanel-thumbnail.patch). |
| Firmware version panel (Device → Update)    | All models | ✅ (tested on P2S) | Mixed       | `bambu_network_get_printer_firmware` re-synthesises the "firmware list" Studio expects from the MQTT frames the printer already sends (`info.module[]` replies + `push_status.upgrade_state.new_ver_list`). That populates the Update tab with current per-module versions (OTA, AMS, AHB, …), stock-style. When the printer advertises a newer version the "current → new" arrow and the green "update available" badge appear.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Firmware Release Notes dialog               | All models | ✅ (tested on P2S) | Alternative | Shown when a new version is advertised. Description text is synthesised locally with a link to the model-specific page on [bambulab.com/support/firmware-download](https://bambulab.com/en/support/firmware-download/all); we can't reach Bambu's cloud changelog API without login. If no new version is advertised the dialog is empty — which matches stock behaviour in the same situation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Start firmware update (Update button)       | All models | ✅ (tested on P2S) | Passthrough | Button publishes `{"upgrade":{"command":"upgrade_confirm"}}` on LAN MQTT. The printer already knows which OTA package it advertised and downloads it from Bambu's CDN itself — the plugin doesn't need to supply a URL.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

### Cloud sign-in in Developer or LAN-only mode

Signing in to your Bambu account is worth doing even when every print goes over
the LAN. Studio's UI and preset machinery are heavily wired to a logged-in
`user_id`, so without a session several features quietly degrade; with one they
behave as they did under the stock plugin. Signing in does **not** move your
printing to the cloud: in the default configuration (`block_cloud = 1`) the
session is used for account-level REST only — background cloud connections and
cloud printing stay blocked. Enabling those is
[Option B](#option-b-cloud-mode-without-developer-mode).

**What login gives you:**

After sign-in, Studio may show a **Synchronization** dialog asking
whether to pull personal data from Bambu Cloud. The stock UI lists
exactly three categories — the same ones the account machinery is built
around:

1. **Process presets** (print / process profiles)
2. **Filament presets**
3. **Printer presets** (machine profiles)

It also unlocks the **Filament Manager** tab (Bambu Studio 02.06.01 and newer),
the cloud spool catalogue where Studio tracks every spool you own — RFID,
vendor, type, remaining weight, AMS slot binding. The plugin implements all of
its endpoints, including the bulk AMS sync added in ABI 02.08.01 and the AMS
slot bind/unbind added in ABI 02.08.02, so the tab works as it does with the
stock plugin.

Bind/unbind and cloud print history remain available too; history and MakerWorld
records are only written for cloud prints, so a Developer-Mode LAN print leaves
no trace there.

> **Note:** To sync custom filaments to the printer so they show up in its filament menu, temporarily
> disable LAN-only mode and bind the printer to Bambu Cloud. Afterward, you can turn LAN-only mode and
> Developer Mode back on.

**Running without sign-in** is fully supported: go straight to 
"Device → Connect via LAN with access code",
and LAN printing / camera / discovery / FTPS all work. You'll just
lose the Studio features in the list above (and, obviously, anything
cloud-side such as print history / MakerWorld).

## Building from source

Most users should install a pre-built archive (see [Installation](#installation))
instead of building. If you are developing, packaging for a distribution, or
targeting a platform / ABI we do not ship binaries for, the full build and
manual-installation guide lives in **[BUILDING.md](BUILDING.md)**.

It covers prerequisites, all `./configure` / `configure.ps1` options, version
auto-detection, and the [manual installation](BUILDING.md#manual-installation)
steps.

## Configuration file

Advanced users can fine-tune the plugin's behavior through a
configuration file. Available options include logging, cloud endpoint
overrides, file transfer mode selection, and a number of low-level
tweaks that modify MQTT traffic between the slicer and the printer —
use those with caution, as they change what the slicer sees and may
cause unexpected UI behavior if misconfigured.

Persistent plugin settings live in **`<data_dir>/obn.conf`**, where
`data_dir` is the slicer's configuration directory:

- `~/.config/BambuStudio/` (Linux Bambu Studio)
- `~/.config/OrcaSlicer/` (Linux Orca Slicer)
- `%APPDATA%\BambuStudio\` (Windows Bambu Studio)
- `%APPDATA%\OrcaSlicer\` (Windows Orca Slicer)

On first launch, if the file is missing, the plugin creates a template
with every key and its default value.

**Format:** INI-like `key = value` lines. Lines starting with `#` are comments;
`##` section headers are comments too.
Spaces around `=` are optional.

**Logging** (see also [Logging](#logging); env vars override these):

| Key | Default | Effect |
| --- | --- | --- |
| `log_level` | `info` | Log threshold: `trace`, `debug`, `info`, `warn`, `error`, `off`. Overridden by `OBN_LOG_LEVEL`. |
| `log_stderr` | `1` | When `1`, copy every line to stderr with an `[obn]` prefix. Overridden by `OBN_LOG_STDERR`. |
| `log_to_file` | `0` | When `1`, append to `<data_dir>/obn.log`. Overridden by `OBN_LOG_TO_FILE`. |
| `log_file` | *(empty)* | Absolute path to a log file. Overridden by `OBN_LOG_FILE`. |
| `bambusource_log_level` | `info` | Log threshold for BambuSource (camera/file-browser library). Overridden by `OBN_BAMBUSOURCE_LOG_LEVEL`. |
| `bambusource_log_stderr` | `1` | Copy BambuSource log lines to stderr with `[obn-bs]` prefix. Overridden by `OBN_BAMBUSOURCE_LOG_STDERR`. |
| `bambusource_log_to_file` | `0` | When `1`, append to `<data_dir>/obn-bambusource.log`. Overridden by `OBN_BAMBUSOURCE_LOG_TO_FILE`. |
| `bambusource_log_file` | *(empty)* | Explicit log file path for BambuSource. Overridden by `OBN_BAMBUSOURCE_LOG_FILE`. |

**LAN networking:**

| Key | Default | Effect |
| --- | --- | --- |
| `lan_tls_skip_verify` | `0` | Skip TLS certificate verification for LAN MQTT/FTPS connections. |
| `override_lan_ip` | `0` | Replace the printer's self-reported LAN IP in push_status with the IP used in connect_printer. Enable for NAT / port-forwarding setups where the printer advertises its internal address. |
| `mqtt_keep_connection` | `1` | Keep the MQTT connection alive across the slicer's internal disconnect/reconnect cycles (e.g. after sending a print job). Avoids 5-30s reconnection delays on printers with limited MQTT session slots. Useful for Orca Slicer. |

**Print behaviour & file transfer:**

| Key | Default | Effect |
| --- | --- | --- |
| `force_ftps` | `0` | Force FTPS (port 990) for file transfer instead of the native TLS :6000 protocol. Thumbnails, timelapse files, and internal storage (eMMC) browsing are not available in this mode. Useful when the printer's :6000 file browser is broken (e.g. some A1 firmware versions). |
| `disable_camera_preview` | `0` | Disable the annoying static "Printer Preview" JPEG snapshot (mem:/N over TLS :6000) shown in the device panel when live view is off. |
| `force_timelapse_external` | `0` | Always save timelapse to external storage (USB/SD), ignoring the Internal/External toggle in the print dialog (Studio defaults to internal). |

**MQTT push_status patches** (all off by default; enable only if your model needs it):

| Key | Default | Effect |
| --- | --- | --- |
| `patch_mqtt_home_flag` | `0` | Rewrite home_flag SD-card bits from NO_SDCARD to HAS_SDCARD. Useful on some A-series where Studio greys out storage UI even though USB storage works. |
| `patch_mqtt_ipcam_file` | `0` | Inject `ipcam.file` block into push_status when firmware omits it. Without this, Studio may refuse to open the file browser on some models. |
| `patch_mqtt_internal_storage` | `0` | Set the internal storage capability bit so Studio shows the eMMC tab in the file browser. Firmware often omits this bit even when :6000/FTPS lists eMMC, and browsing internal memory may still be slow or unreliable (e.g. on P2S). |

**Cloud endpoints** (change only for CN accounts or a dev host):

| Key | Default | Effect |
| --- | --- | --- |
| `cloud_global_api_host` | `https://api.bambulab.com` | REST API base for non-CN accounts. |
| `cloud_global_web_host` | `https://bambulab.com` | Web portal base for sign-in / bind UI (non-CN). |
| `cloud_global_mqtt_host` | `us.mqtt.bambulab.com` | Cloud MQTT broker hostname (non-CN). |
| `cloud_cn_api_host` | `https://api.bambulab.cn` | REST API base for CN accounts. |
| `cloud_cn_web_host` | `https://bambulab.cn` | Web portal base for sign-in / bind UI (CN). |
| `cloud_cn_mqtt_host` | `cn.mqtt.bambulab.com` | Cloud MQTT broker hostname (CN). |
| `cloud_mqtt_port` | `8883` | Cloud MQTT broker port (both regions). |

**Cloud mode**, privacy and slicer credentials (see [Option B](#option-b-cloud-mode-without-developer-mode); the `slicer_*` keys matter only for cloud mode on a verified printer):

| Key | Default | Effect |
| --- | --- | --- |
| `block_cloud` | `1` | Block background cloud MQTT/REST connections **and cloud printing**. Login, preset sync, Filament Manager and bind/unbind are still allowed. Set to `0` to enable the cloud MQTT session and any `cloud_print` mode. |
| `cloud_print` | `cloud_only` | (new in v2.0.0) How a print is sent when cloud mode is on. `cloud_only`: write a cloud print record (history / MakerWorld); the model itself still goes to the printer over your LAN when possible, and is uploaded to Bambu only if the printer is not reachable locally. `try_lan_first`: print entirely over the LAN with no cloud record, falling back to a cloud print only if that fails. `lan_only`: always local, never upload. |
| `cloud_hide_history` | `0` | (new in v2.0.0) Return an empty task list so the Bambu Studio home page shows no cloud print history. Handy with the true-LAN `cloud_print` modes. |
| `slicer_cert_pem` | *(empty)* | (new in v2.0.0) Path to the slicer certificate (PEM). Empty = look for `slicer_cert.pem` in the config directory. |
| `slicer_key_pem` | *(empty)* | (new in v2.0.0) Path to the slicer private key (PEM) used to sign print commands. Empty = look for `slicer_key.pem` in the config directory. |
| `slicer_crl_pem` | *(empty)* | (new in v2.0.0) Path to the certificate revocation list (PEM). Empty = look for `slicer_crl.pem` in the config directory. |
| `client_name` | `OpenBambooNetworking` | (new in v2.0.0) Name the plugin presents to Bambu's cloud. Cloud printing only accepts the stock name `BambuStudio`; leave the default and it is refused. Set to `BambuStudio` for cloud mode. |

**These credential files are private and are not shipped with this project;
you must obtain them yourself and are responsible for complying with the
applicable terms and law.**

Typical paths: `~/.config/BambuStudio/obn.conf`, `~/.config/OrcaSlicer/obn.conf`,
`%APPDATA%\BambuStudio\obn.conf`, `%APPDATA%\OrcaSlicer\obn.conf`. You do not
have to guess — the installer prints the exact path for your slicer when it
finishes.

## Logging

The plugin writes a printf-style log of ABI calls and MQTT / FTPS /
HTTP activity. **Defaults:** severity **info**, output **only to stderr**
(the terminal that launched Bambu Studio). No log file is opened unless
you opt in — this keeps disk noise down for everyday use.

Most logging options can also be set in [`obn.conf`](#configuration-file)
(`log_level`, `log_stderr`, `log_to_file`, `log_file`); env vars override
the file when both are present.

**Where it goes.**

- **Default:** stderr only (`OBN_LOG_STDERR=1`), each line prefixed with
`[obn]` so it is easy to grep apart from Bambu Studio’s own stderr.
- **File next to the slicer's data directory:** set `OBN_LOG_TO_FILE=1` or
`log_to_file = 1` in `obn.conf` to append to `<data_dir>/obn.log`, where
`data_dir` is the path the slicer passes to `bambu_network_create_agent`.
Typical paths:
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

**Configuration via environment variables** (read once at plugin init;
export them *before* launching Studio. Same keys exist in `obn.conf`; env
wins when both are set):

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

`libBambuSource.so` is a separate library that handles the camera
liveview and file browser. Its logging follows the same pattern as the
main plugin: **stderr by default, file on demand**. All settings below
can be set in `obn.conf`; environment variables override them when set.

| `obn.conf` key                 | Env override                     | Default   | Effect |
| ------------------------------ | -------------------------------- | --------- | ------ |
| `bambusource_log_level`        | `OBN_BAMBUSOURCE_LOG_LEVEL`      | `info`    | `trace` / `debug` / `info` / `warn` / `error` / `off`. |
| `bambusource_log_stderr`       | `OBN_BAMBUSOURCE_LOG_STDERR`     | `1`       | When `1`, copy every line to stderr with an `[obn-bs]` prefix. |
| `bambusource_log_to_file`      | `OBN_BAMBUSOURCE_LOG_TO_FILE`    | `0`       | When `1`, append to `<data_dir>/obn-bambusource.log`. |
| `bambusource_log_file`         | `OBN_BAMBUSOURCE_LOG_FILE`       | *(empty)* | Explicit path; `off`/`none`/`0` to disable, `stderr`/`-` for stderr. |

The log file rolls every line through `[level]` plus a timestamp.
Lines are tagged with `rtsp:` (handshake / DESCRIBE / SETUP / PLAY),
`rtsp_passthrough:` (the worker that hands the byte stream to
gstbambusrc on Linux), and on Windows also `dshow:` (the DirectShow
filter's connection / sample pump). If you see no video despite a
successful `rtsp: PLAY ok` the issue is slicer-side: on Linux, missing
GStreamer H.264 decoder (`gstreamer1.0-plugins-bad` /
`gstreamer1.0-libav`); on Windows, missing H.264 MFT (Media Feature
Pack on N/KN editions).

## Known issues

- **No current-print thumbnail in Orca Slicer.** The plugin provides
  the model cover during printing via `bambu_network_get_subtask_info`,
  but Orca Slicer routes that call through its own `OrcaCloudServiceAgent`
  (a stub returning empty JSON) instead of `BBLCloudServiceAgent` which
  delegates to the plugin. The thumbnail URL never reaches the UI, so the
  Device panel shows a placeholder. This cannot be fixed on the plugin
  side; a patch to Orca Slicer is needed. Works correctly in Bambu Studio.
  (Also listed under [Supported slicers](#supported-slicers).)

## License

GNU Affero General Public License v3.0 (AGPL-3.0) — see [LICENSE](LICENSE).

## Support the Developer and the Project

- [GitHub Sponsors](https://github.com/sponsors/ClusterM)
- [Patreon](https://www.patreon.com/c/ClusterMeerkat)
- [Buy Me A Coffee](https://www.buymeacoffee.com/cluster)
- [Sber](https://messenger.online.sberbank.ru/sl/Lnb2OLE4JsyiEhQgC)
- [Donation Alerts](https://www.donationalerts.com/r/clustermeerkat)
- [Boosty](https://boosty.to/cluster)
