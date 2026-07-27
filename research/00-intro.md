# Bambu Studio Network Plugin — full reference

This document describes how Bambu Studio integrates with its proprietary **Network Plugin** (`bambu_networking`) — where it is downloaded from, where it is installed, how it is validated, and the exact C ABI contract it must implement. The goal is to document how the plugin is integrated, loaded, validated and invoked, based purely on the Bambu Studio source code.

The reference is derived from three independent sources, none of them involving binary disassembly:

1. A read-through of the upstream [bambulab/BambuStudio](https://github.com/bambulab/BambuStudio) (and the closely related [SoftFever/OrcaSlicer](https://github.com/SoftFever/OrcaSlicer)) trees — every Studio-side claim in this document is backed by a concrete file and line range in those sources.
2. **MITM captures** of the stock `libbambu_networking.so` against `api.bambulab.com`, MakerWorld and the printer's LAN MQTT / FTPS / RTSPS endpoints, used to reverse the wire format the closed-source `bambu_networking` binary actually produces (HTTPS bodies, MQTT JSON envelopes, FTPS dialect quirks, etc.).
3. **Cross-ABI matrix runs** against the stock plugin in versions `02.05.00` … `02.06.01` to track how a given `BBL::PrintParams` value is rendered onto the LAN MQTT `print:project_file` payload, and how that mapping shifts as fields are added to `PrintParams` over time.

Where a claim originates from MITM or matrix runs rather than Studio source it is marked accordingly (see "Evidence" tags in [§8.10.1](08.10-http.md) and the per-field tables in [§12.1](12.01-project-file.md)). Behaviour that has not been confirmed against either source is flagged as such.

**Source citations:** Studio-side file links are GitHub permalinks into [bambulab/BambuStudio](https://github.com/bambulab/BambuStudio) at [`12f17b06f4f537f9c03162d08bb70cf733c42839`](https://github.com/bambulab/BambuStudio/commit/12f17b06f4f537f9c03162d08bb70cf733c42839) (2026-07-26). Orca-only paths use [SoftFever/OrcaSlicer](https://github.com/SoftFever/OrcaSlicer) at [`11fdb472d6193312bc6c78b7703ad2c1222502b7`](https://github.com/SoftFever/OrcaSlicer/commit/11fdb472d6193312bc6c78b7703ad2c1222502b7). Those trees are **not** vendored here (`3rd_party/` is gitignored local tooling). Camera-widget / Windows back-end divergences are called out inline (§9.4).

## Summary

Key facts about the stock Bambu Network Plugin:

- **Download source**: `https://api.bambulab.com/v1/iot-service/api/slicer/resource?slicer/plugins/cloud=<MAJOR.MINOR.PATCH.00>` (or the regional `.cn` / dev / QA endpoints), which returns a JSON manifest pointing at a ZIP.
- **Install layout**: the binary ends up at `<data_dir>/plugins/{bambu_networking,BambuSource,live555}.{dll|so|dylib}`; OTA staging in `<data_dir>/ota/plugins/` must hold all three libraries plus `network_plugins.json` or the cache is treated as incomplete.
- **Version gate**: Studio compares only the first 8 characters of `bambu_network_get_version()` against `SLIC3R_VERSION`; everything beyond that is build metadata.
- **Signature gate**: Authenticode publisher match on Windows, Developer Team ID match on macOS; on Linux the check is a no-op. `ignore_module_cert` in `AppConfig` disables it on Windows/macOS.
- **ABI surface**: roughly 100 `bambu_network_*` entry points using C linkage but `std::string` / `std::vector` / `std::map` / `std::function` at the boundary — tightly coupled to Studio's libstdc++/libc++ ABI — plus a separate, pure-C `ft_*` tunnel/job bus (`ft_abi_version() == 1`) that ships in the same `.so`/`.dll`.
- **Initialization contract**: a deterministic call sequence `create_agent → set_config_dir → init_log → set_cert_file → set_extra_http_header → set_on_*_fn(…) → set_country_code → start` in `GUI_App::on_init_network`, then `start_discovery` later from `post_init` / `restart_networking`, with `QueueOnMainFn` as the only safe way back to the GUI thread.
- **Notable Studio quirks observed during reverse engineering**: the `bambu_network_get_user_nickanme` symbol name is misspelled in the real ABI, and Studio `dlsym`s `get_my_token` via `"bambu_network_get_my_token"` but casts the pointer to `func_get_my_profile` (same signature) — a compatible plugin must export both symbols with matching signatures.
- **Second library, second contract**: camera live view and the on-printer file browser go through a *separate* library `libBambuSource` (different symbol prefix `Bambu_*`, different loader, no signature gate, no version gate). It exposes a small C ABI (`Bambu_Create` / `Bambu_Open` / `Bambu_StartStreamEx` / `Bambu_SendMessage` / `Bambu_ReadSample` / …) plus, on macOS only, an Objective-C class `BambuPlayer` resolved through `dlsym(libBambuSource.dylib, "OBJC_CLASS_$_BambuPlayer")` inside `wxMediaCtrl2.mm`. The camera widget that consumes this ABI varies by slicer: current BambuStudio (commit `94d91be60`+, June 2024) uses `wxMediaCtrl3` which calls `Bambu_*` directly and decodes via FFmpeg on **both** Linux and Windows; OrcaSlicer and pre-`94d91be60` Studio still use the older `wxMediaCtrl2` which routes Linux through the `gstbambusrc` GStreamer element baked into the Studio binary and Windows through a DirectShow source filter registered against the `bambu:` URI scheme (CLSID `{233E64FB-…}`). The file browser uses the same camera tunnel (TLS over TCP/6000) but switches it into JSON-RPC mode via `Bambu_StartStreamEx(tunnel, CTRL_TYPE = 0x3001)`; **stock Device → Files traffic on P2S stays on that :6000 socket** for lists, thumbnails, and downloads (§9.5.1). FTPS on TCP/990 is a separate printer service (§9.6.3) used for LAN print uploads and the `ft_*` ABI — not for stock file browsing on P2S. See **§9** for the full ABI, wire format and per-platform back-ends.

---

