# STATUS — ABI coverage of `open-bambu-networking`

This document tracks how each symbol listed in [NETWORK_PLUGIN.md § 6](NETWORK_PLUGIN.md#6-the-full-c-abi-contract) is handled by this open-source plugin. Top-level `##` headings group related surfaces; **subsection numbers (`### 6._n_`) match the same §6._n_ titles in the reference** so you can jump between the two documents. Everything that talks to Bambu’s cloud over **HTTPS** (and the closely related **cloud MQTT** session in §6.3) is rolled into one block, **Cloud & HTTP APIs**, with subsections below it.

## Legend

| Mark | Meaning |
| :--: | --- |
| ✅ | Implemented the same way as the stock plugin (behavioural parity with the symbols Studio calls). |
| ❌ | Not implemented. Either returns a hard error or silently answers with an empty payload so Studio's UI degrades gracefully. The exact mode is noted per row. |
| 🔒 | Cannot be implemented without proprietary secrets (per-install RSA signing keys, TUTK / Agora SDK). |
| ⚠️ | Implemented with limitations — the happy path works, but some user-visible behaviour is degraded vs. stock. |
| 🔒⚠️ | Partial: the secret-protected path is not possible, but the remaining path (typically LAN under Developer Mode) is functional. |
| ✨ | Implemented via a workaround — end result matches stock behaviour but over a different transport or by synthesising the response locally. |
| ❓ | Exported for binary compatibility but not currently resolved by Bambu Studio, so behaviour against real Studio code cannot be verified. Body is a minimal stub. |

> Note on `❌`: some of these return `BAMBU_NETWORK_SUCCESS` with an empty payload rather than an error code. This is intentional — the corresponding feature is not wired to any remote backend, and returning success with empty data is what keeps Studio from showing error dialogs for features that are simply unused in this plugin. The "what is actually returned" is stated per row in the Notes column.

---

## Supported slicers

The same plugin binary works under both **Bambu Studio** and **Orca Slicer** — they consume the same C ABI documented below. The build system handles client-specific install conventions via `./configure --client-type=bambu_studio | orca_slicer` (Studio is the default). Per-client differences:

| Aspect | Bambu Studio | Orca Slicer |
| --- | --- | --- |
| Default install prefix (Linux) | `~/.config/BambuStudio` | `~/.config/OrcaSlicer` (or the Flatpak config dir if it exists) |
| `.so` file name on disk | `libbambu_networking.so` (fixed) | `libbambu_networking_<network_plugin_version>.so` |
| `network_plugins.json` OTA manifest | Installed under `ota/plugins/`; Studio reads it as a persistent manifest | Not installed — Orca only writes it as a transient OTA artefact |
| Conf-file patch (`make install`) | `BambuStudio.conf`: `installed_networking="1"`, `update_network_plugin="false"` | `OrcaSlicer.conf`: `installed_networking="true"`, `network_plugin_version="<OBN_VERSION>"`, `network_plugin_remind_later="true"`, `<OBN_VERSION>` stripped from `network_plugin_skipped_versions` |

See [README — Installing for Orca Slicer](README.md#installing-for-orca-slicer) for the full setup story.

---

## 6.1. Initialization and lifecycle

Source: [src/abi_meta.cpp](src/abi_meta.cpp), [src/abi_lifecycle.cpp](src/abi_lifecycle.cpp).

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_check_debug_consistent` | ✅ | Always returns `true`. A single release-mode `.so` is expected to satisfy both Studio build flavours. |
| `bambu_network_get_version` | ✅ | Returns `OBN_VERSION_STRING`, auto-detected at configure time from `<prefix>/BambuStudio.conf` (or `--with-version=…`). First 8 characters are kept in sync with shipped `SLIC3R_VERSION` to pass the compatibility gate. |
| `bambu_network_create_agent` | ✅ | Allocates the internal agent and bootstraps logging from the supplied `log_dir`. |
| `bambu_network_destroy_agent` | ✅ | Deletes the agent instance. |
| `bambu_network_init_log` | ✅ | No-op here: log sinks are configured inside `create_agent`, before the first log line. |
| `bambu_network_set_config_dir` | ✅ | Stored on the agent; used for auth cache and transient state. |
| `bambu_network_set_cert_file` | ✅ | Studio's embedded CA bundle (`slicer_base64.cer`) is loaded and reused as the HTTPS/MQTTS trust store. |
| `bambu_network_set_country_code` | ✅ | Stored; drives cloud region selection (`api_host`, `web_host`). |
| `bambu_network_start` | ✅ | Starts worker threads. If a cached session is present the plugin also kicks off `connect_cloud()` here — the stock call chain normally goes through `EVT_USER_LOGIN_HANDLE`, but that cascade can silently stall for cached sign-ins; starting from `start()` guarantees cloud MQTT gets initiated. |

---

## 6.2. Callbacks (registration)

Source: [src/abi_callbacks.cpp](src/abi_callbacks.cpp). All entries are thin `std::function` setters stored on the agent.

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_set_on_ssdp_msg_fn` | ✅ | Fired on each SSDP `NOTIFY`. |
| `bambu_network_set_on_user_login_fn` | ✅ | Fired on sign-in / sign-out transitions. |
| `bambu_network_set_on_printer_connected_fn` | ✅ | Fired when the LAN MQTT broker accepts a connection. |
| `bambu_network_set_on_server_connected_fn` | ✅ | Fired when the cloud MQTT broker accepts a connection. |
| `bambu_network_set_on_http_error_fn` | ✅ | Fired on unexpected HTTP status codes from cloud REST calls. |
| `bambu_network_set_get_country_code_fn` | ✅ | Pulled by the agent whenever a cloud request needs the current region. |
| `bambu_network_set_on_subscribe_failure_fn` | ✅ | Fired when an MQTT topic subscription is rejected. |
| `bambu_network_set_on_message_fn` | ✅ | Cloud-side push frames. |
| `bambu_network_set_on_user_message_fn` | ✅ | Cloud-side user-channel frames. |
| `bambu_network_set_on_local_connect_fn` | ✅ | LAN MQTT session state. |
| `bambu_network_set_on_local_message_fn` | ✅ | LAN-side push frames. |
| `bambu_network_set_queue_on_main_fn` | ✅ | Used for every wxWidgets-touching callback dispatch. |
| `bambu_network_set_server_callback` | ✅ | Generic cloud error channel. |

---

## Cloud & HTTP APIs

Subsections use the same **§6._n_** numbers as [NETWORK_PLUGIN.md § 6](NETWORK_PLUGIN.md#6-the-full-c-abi-contract). **§6.3** is cloud **MQTT** (TLS to the broker), not REST on `api.bambulab.*`, but it shares the same logged-in session, region, and callback wiring as the HTTPS calls below.

### 6.3. Cloud — connection and subscriptions

Source: [src/abi_cloud.cpp](src/abi_cloud.cpp).

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_connect_server` | ✅ | Opens cloud MQTT over TLS using the cached user session. |
| `bambu_network_is_server_connected` | ✅ | Reports the current cloud MQTT session state. |
| `bambu_network_refresh_connection` | ✅ | Called on Studio's ~1 Hz device-refresh tick; delegates to the agent which decides whether a reconnect is actually needed. |
| `bambu_network_start_subscribe` | ✅ | No-op, matching stock semantics: the "module" argument is a keepalive hint rather than an MQTT topic, and stock does not map it to an explicit subscription either. |
| `bambu_network_stop_subscribe` | ✅ | Same as above. |
| `bambu_network_add_subscribe` | ✅ | Buffers the requested device set; applies on current or next `CONNACK`. |
| `bambu_network_del_subscribe` | ✅ | Unsubscribes individual `device/<id>/report` topics. |
| `bambu_network_enable_multi_machine` | ✅ | No-op: multi-machine mode only toggles Studio's UI; there is no plugin-side state tied to it. |
| `bambu_network_send_message` | ✅ | LAN-first routing: tries the LAN MQTT session for the target `dev_id`; falls back to cloud MQTT when no LAN session matches. |

### 6.5. Authentication and user

Source: [src/abi_user.cpp](src/abi_user.cpp).

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_change_user` | ✅ | Empty / `{}` user_info clears the session (Studio's logout path); otherwise parses the envelope and applies it. |
| `bambu_network_is_user_login` | ✅ | Polled on every sidebar repaint; returns the current session state. |
| `bambu_network_user_logout` | ✅ | Clears the agent session. |
| `bambu_network_get_user_id` | ✅ | Returned from the agent's session snapshot. |
| `bambu_network_get_user_name` | ✅ | Returned from the agent's session snapshot. |
| `bambu_network_get_user_avatar` | ✅ | Returned from the agent's session snapshot. |
| `bambu_network_get_user_nickanme` | ✅ | The stock typo is preserved on purpose — Studio resolves the symbol by that exact name. Falls back to `user_name` when `nick_name` is empty. |
| `bambu_network_build_login_cmd` | ✅ | Emits the stock-shape `{"command":"studio_userlogin", …}` envelope the Studio WebViews listen for. |
| `bambu_network_build_logout_cmd` | ✅ | Emits the mirror envelope `{"command":"studio_useroffline", …}`. |
| `bambu_network_build_login_info` | ✅ | Reuses the `userlogin` envelope; that is what `WebViewPanel::SendLoginInfo` forwards to the currently visible WebView. |
| `bambu_network_get_my_profile` | ✅ | Issues the cloud `GET /v1/user-service/my/profile` call. Note Studio's known bug: this symbol is also resolved under the name `get_my_token_ptr`, so both paths must share an identical signature — which they do. |
| `bambu_network_get_my_token` | ✅ | Exchanges a browser-login ticket for an access token (`POST /user-service/user/ticket/<T>`). |
| `bambu_network_get_user_info` | ✅ | Returns the numeric user id. Uses `stoll` + narrowing cast because cloud user ids are 32-bit unsigned and would overflow `std::stoi`. |

### 6.6. Binding / bind

Source: [src/abi_bind.cpp](src/abi_bind.cpp).

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_ping_bind` | ✅ | Cloud `/iot-service/api/ping-bind` call. |
| `bambu_network_bind_detect` | ✅ | Waits up to 4.5 s for an SSDP `NOTIFY` on UDP 2021 to learn the printer identity — same as stock, since the ABI provides no access code here either. |
| `bambu_network_bind` | ✅ | LAN → cloud bind flow; reports progress through `OnUpdateStatusFn`. |
| `bambu_network_unbind` | ✅ | Cloud unbind call. |
| `bambu_network_request_bind_ticket` | ✅ | Requests the WebView SSO ticket used by the browser bind flow. |
| `bambu_network_query_bind_status` | ✅ | Cloud bind-status query. |
| `bambu_network_report_consent` | ❌ | No-op (returns `SUCCESS`). No consent-collection endpoint is exposed by this plugin. |

### 6.7. Printer selection and metadata

Sources: [src/abi_user.cpp](src/abi_user.cpp), [src/abi_bind.cpp](src/abi_bind.cpp), [src/abi_http.cpp](src/abi_http.cpp).

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_get_bambulab_host` | ✅ | Returns the region-appropriate portal host (ends with `/`, as stock does). |
| `bambu_network_get_user_selected_machine` | ✅ | Agent-side selection state. |
| `bambu_network_set_user_selected_machine` | ✅ | Agent-side selection state. |
| `bambu_network_modify_printer_name` | ✅ | Cloud rename call. |
| `bambu_network_get_printer_firmware` | ✨ | Stock calls Bambu's cloud firmware catalogue. This plugin re-synthesises the JSON envelope locally from the MQTT frames the printer already sends (`info.command=get_version` replies and `push_status.upgrade_state.new_ver_list`). That populates the Update panel and lights up the "update available" badge without any cloud roundtrip. The "Update" button itself is a plain LAN MQTT passthrough; the printer fetches the binary from Bambu's CDN directly. Trade-off: no cross-version history — only the advertised version is flashable. |

### 6.9. User presets

Source: [src/abi_presets.cpp](src/abi_presets.cpp), [src/cloud_presets.cpp](src/cloud_presets.cpp). Full CRUD against Bambu's `api.bambulab.com/v1/iot-service/api/slicer/setting` endpoint, using only the user's bearer token (the stock `X-BBL-*` fingerprint headers aren't required by the server).

This implementation goes a step beyond the stock plugin. Studio's original `bambu_networking.so` only retrieves metadata (`setting_id`, `name`, `update_time`, …) from `GET /setting`, assuming the actual preset bodies are present on disk — so wiping the local preset directory permanently loses cloud-stored configs on that machine. We additionally call `GET /setting/<id>` for every preset Studio's `CheckFn` asks us to sync, and feed the full flattened config into `get_user_presets()` so true cross-device sync works even on a fresh install.

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_get_user_presets` | ✅ | Drains the cache populated by the preceding `get_setting_list2` call into Studio's `map<name, values_map>`. |
| `bambu_network_request_setting_id` | ✅ | `POST /slicer/setting` with `{name, type, version, base_id, filament_id, setting:{…}}`. Returns the new `PPUS/PFUS/PMUS` id, refreshes `values_map["updated_time"]`, and surfaces server `code` (e.g. `"14"` = preset limit) into `values_map["code"]` so Studio's limit handling keeps working. |
| `bambu_network_put_setting` | ✅ | `PATCH /slicer/setting/<id>` with the same body shape as create. Refreshes `values_map["updated_time"]`. |
| `bambu_network_get_setting_list` | ✅ | Full sync (no filter): lists all user presets, downloads every body, caches for `get_user_presets`. |
| `bambu_network_get_setting_list2` | ✨ | Stock plugin only lists metadata and relies on local files. We additionally `GET /slicer/setting/<id>` for presets the Studio-provided `CheckFn` flags as needed, so cross-device sync actually delivers the content. |
| `bambu_network_delete_setting` | ✅ | `DELETE /slicer/setting/<id>`; server-side idempotent (missing id still returns 200). |

### 6.10. HTTP / service

Source: [src/abi_http.cpp](src/abi_http.cpp).

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_get_studio_info_url` | ❌ | Returns an empty string — no Studio-side "news" banner is served. |
| `bambu_network_set_extra_http_header` | ✅ | Stored on the agent and applied to every outbound HTTPS request. |
| `bambu_network_get_my_message` | ❌ | Returns `SUCCESS` with empty body; Studio shows an empty inbox. |
| `bambu_network_check_user_task_report` | ❌ | Returns `SUCCESS` with `task_id=0, printable=false`. |
| `bambu_network_get_user_print_info` | ✅ | Fetches `/v1/iot-service/api/user/bind`, remaps field names (`name` → `dev_name`, `online` → `dev_online`, `print_status` → `task_status`) so Studio's `DeviceManager::parse_user_print_info` finds everything, and implicitly subscribes to `device/<id>/report` for each returned device (matching stock push-delivery behaviour). |
| `bambu_network_get_user_tasks` | ❌ | Returns `SUCCESS` with empty body; no MakerWorld task history is served. |
| `bambu_network_get_task_plate_index` | ❌ | Returns `SUCCESS` with `plate_index=-1`. |
| `bambu_network_get_subtask_info` | ✨ | LAN-only prints arrive with `project_id=profile_id=subtask_id="0"`; the agent rewrites those to synthetic `"lan-<fnv>"` ids on `push_status`, and this call resolves them — the reply carries a `thumbnail.url` pointing at the plugin's loopback HTTP cover server, which serves `Metadata/plate_N.png` unpacked from the `.3mf` in the printer's `/cache/`. Cloud-style subtask ids fall through unchanged. Guarded by `OBN_ENABLE_WORKAROUNDS`. |
| `bambu_network_get_slice_info` | ❌ | Returns `SUCCESS` with empty body. |

### 6.15. Filament Manager (cloud spool catalogue)

Source: [src/abi_filament.cpp](src/abi_filament.cpp), [src/cloud_filament.cpp](src/cloud_filament.cpp). All five endpoints are fully reverse-engineered from a MITM dump of the stock `02.06.01.50` plugin (see [NETWORK_PLUGIN.md § 6.15](NETWORK_PLUGIN.md#615-filament-manager-cloud-spool-catalogue)).

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_get_filament_spools` | ✅ | `GET /v1/design-user-service/my/filament/v2?offset=…&limit=…[&category=…&status=…&ids=…&RFIDs=…]`. Response body (`{"hits":[…]}`) is forwarded verbatim to Studio. |
| `bambu_network_create_filament_spool` | ✅ | `POST /v1/design-user-service/my/filament/v2`. Request body is forwarded verbatim from Studio (CreateFilamentV2Req JSON). Server responds with `{}` — Studio re-lists afterwards to learn the assigned `id`. |
| `bambu_network_update_filament_spool` | ✅ | `PUT /v1/design-user-service/my/filament/v2`. Body must always include `id` (int64) and `filamentName`; Studio assembles and forwards this. Response (`{"filamentV2":{…}}`) is returned in `http_body`. |
| `bambu_network_delete_filament_spools` | ✅ | `DELETE /v1/design-user-service/my/filament/v2/batch` with body `{"ids":[…],"RFIDs":[…]}` built from `FilamentDeleteParams`. Server responds with `{}`. |
| `bambu_network_get_filament_config` | ✅ | `GET /v1/design-user-service/filament/config`. Returns the ~11 KB catalogue of known filament vendors/types/ids that Studio uses to populate the "Add spool" form pickers. |

---

## 6.4. Local printer connection (LAN)

Source: [src/abi_lan.cpp](src/abi_lan.cpp).

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_connect_printer` | ✅ | Opens a LAN MQTT session (TLS to `mqtts://<ip>:8883`, user `bblp`, password = access code). |
| `bambu_network_disconnect_printer` | ✅ | Tears the LAN MQTT session down. |
| `bambu_network_send_message_to_printer` | ✅ | Publishes on the active LAN MQTT session; payload is log-redacted. |
| `bambu_network_update_cert` | ✅ | No-op: the CA bundle is loaded once in `set_cert_file` and re-used for the lifetime of the agent. |
| `bambu_network_install_device_cert` | ✅ | Per-device TLS material is installed on the agent the first time it is seen; subsequent calls are deduplicated. |
| `bambu_network_start_discovery` | ✅ | Starts the SSDP multicast listener on `239.255.255.250:1990`. |

---

## 6.8. Submitting a print job

Source: [src/abi_print.cpp](src/abi_print.cpp).

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_start_print` | 🔒⚠️ | Pure cloud path: Studio publishes a signed MQTT command to the cloud-paired printer. The required per-install RSA signing keys are not reproducible, so the command is rejected with `84033543 "MQTT Command verification failed"`. Works only against a printer with Developer Mode enabled, where signature validation is skipped and the command arrives via LAN MQTT. |
| `bambu_network_start_local_print_with_record` | ⚠️ | LAN print runs normally; the cloud `create_task` step for MakerWorld history soft-fails (logged at WARN) and the job proceeds with `task_id="0"`. Net effect: print works, MakerWorld job history and the timelapse-on-printer cloud flags are unavailable. |
| `bambu_network_start_send_gcode_to_sdcard` | ✅ | LAN FTPS upload to the printer's storage mount. |
| `bambu_network_start_local_print` | ✅ | LAN-only: FTPS upload + `{"print":{"command":"project_file", …}}` on LAN MQTT. |
| `bambu_network_start_sdcard_print` | ✨ | Stock hits a signed cloud REST endpoint. This plugin publishes `{"print":{"command":"project_file", "url":"ftp://<path>", …}}` directly on LAN MQTT for a file already resident on the printer. No cloud task record is produced. |

`project_file` wire format covers everything the firmware actually parses: `sequence_id`, `command`, `param`, `project_id`, `profile_id`, `task_id`, `subtask_id`, `subtask_name`, `file`, `url`, `md5`, `bed_type`, `bed_leveling`, `flow_cali`, `vibration_cali`, `layer_inspect`, `timelapse`, `use_ams`, `ams_mapping`, `ams_mapping2`, `nozzle_mapping` (multi-extruder only), `auto_bed_leveling`, `nozzle_offset_cali`, `extrude_cali_manual_mode`, `cfg`, `extrude_cali_flag`. **As of the cross-ABI `tools/plugin_runner` matrix the LAN `project_file` payload we generate is byte-identical (only `sequence_id` differs, by design — it's a wall-clock counter) to what the stock libbambu_networking.so emits for the same `PrintParams`** across `02.05.00` -> `02.06.01` and the variants we tried (default, AMS on, timelapse off, alternate bed types, PA cali manual mode, auto-flow-cali). `cfg` is a string-encoded bitmask we drive from `task_timelapse_use_internal` (bit 2 = use internal storage); other bits emit `0` in every captured stock frame so far. `extrude_cali_flag` is the wire mirror of `auto_flow_cali` (1/0) — confirmed the same way. `ams_mapping2` is emitted unconditionally as `[]` when AMS isn't in use, mirroring stock. The 3mf is uploaded to the **FTPS root** (not `/cache/`, which was an earlier guess), and `print.md5` is computed locally from the file because Studio leaves `params.ftp_file_md5` empty. We deliberately omit the stock plugin's `header` / `url_enc` envelope (RSA-signed and RSA-OAEP-encrypted with a per-install device cert key) — Developer Mode disables signature verification, which is our supported deployment. See [NETWORK_PLUGIN §6.8.2](NETWORK_PLUGIN.md#682-the-mqtt-project_file-command-wire-format) for the full per-field reference and the full cross-ABI / per-overlay matrix.

---

## 6.11. Camera

Source: [src/abi_camera.cpp](src/abi_camera.cpp).

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_get_camera_url` | 🔒 | Stock returns a `bambu:///tutk?...` URL that cannot be minted without the proprietary TUTK / Agora SDK. Callback is invoked with an empty string; Studio drives itself into its normal "connection failed" path. LAN camera never reaches this entry point — `MediaPlayCtrl` takes the native LAN branch served by `libBambuSource` directly. |
| `bambu_network_get_camera_url_for_golive` | 🔒 | Same as above, for the Go-Live flow. |
| `bambu_network_get_hms_snapshot` | 🔒 | HMS photo snapshot is cloud-only and requires the same SDK. Callback is invoked with `("", -1)`. |

---

## 6.12. MakerWorld / Mall

Source: [src/abi_makerworld.cpp](src/abi_makerworld.cpp). MakerWorld has no open specification; this group degrades Studio's Mall UI gracefully rather than implementing any of the proprietary endpoints.

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_get_design_staffpick` | ❌ | Callback receives `{"list":[],"total":0}`. Studio renders an empty staff-pick carousel. |
| `bambu_network_start_publish` | ❌ | Returns `ERR_INVALID_RESULT`; publishing to MakerWorld is not supported. |
| `bambu_network_get_model_publish_url` | ❌ | Returns `https://makerworld.com/` as a safe default; stock serves the per-account upload endpoint. |
| `bambu_network_get_subtask` | ❌ | Returns `SUCCESS` without invoking the callback. Invoking it with a fake `BBLModelTask*` would crash Studio — `StatusPanel::update_model_info` dereferences the pointer unconditionally. |
| `bambu_network_get_model_mall_home_url` | ❌ | Returns `https://makerworld.com/` as a safe default. |
| `bambu_network_get_model_mall_detail_url` | ❌ | Returns `https://makerworld.com/models/<id>` as a safe default. |
| `bambu_network_put_model_mall_rating` | ❌ | Returns `ERR_INVALID_RESULT`; no rating submission backend. |
| `bambu_network_get_oss_config` | ❌ | Returns `ERR_INVALID_RESULT`; no OSS credentials are minted. |
| `bambu_network_put_rating_picture_oss` | ❌ | Returns `ERR_INVALID_RESULT`. |
| `bambu_network_get_model_mall_rating` | ❌ | Returns `ERR_INVALID_RESULT`. |
| `bambu_network_get_mw_user_preference` | ❌ | Callback receives `{"recommendStatus":0}`. The exact field name and type are load-bearing: Studio's JSON-to-int conversion throws through a queued lambda on a `null` here and aborts the process via `wxApp::OnUnhandledException`. |
| `bambu_network_get_mw_user_4ulist` | ❌ | Callback receives `{"list":[],"total":0}`. |

### ABI-compat shims

These symbols are exported by the real plugin, and by this one for binary compatibility, but current Bambu Studio does not resolve them via `dlsym`/`GetProcAddress`. Their runtime behaviour against live Studio code cannot therefore be verified against the stock plugin.

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_check_user_report` | ❓ | Stub: returns `SUCCESS` with `printable=false`. |
| `bambu_network_del_rating_picture_oss` | ❓ | Stub: returns `SUCCESS`, clears out-path and error fields. |
| `bambu_network_get_model_instance_id` | ❓ | Stub: returns `ERR_GET_INSTANCE_ID_FAILED`. |
| `bambu_network_get_model_rating_id` | ❓ | Stub: returns `ERR_GET_RATING_ID_FAILED`. |

---

## 6.13. Tracking / telemetry

Source: [src/abi_track.cpp](src/abi_track.cpp). Telemetry is intentionally not forwarded anywhere; all entry points are privacy-preserving no-ops.

| Function | Status | Notes |
| --- | :--: | --- |
| `bambu_network_track_enable` | ❌ | No-op; returns `SUCCESS`. |
| `bambu_network_track_remove_files` | ❌ | No-op; returns `SUCCESS`. |
| `bambu_network_track_event` | ❌ | No-op; returns `SUCCESS`. |
| `bambu_network_track_header` | ❌ | No-op; returns `SUCCESS`. |
| `bambu_network_track_update_property` | ❌ | No-op; returns `SUCCESS`. |
| `bambu_network_track_get_property` | ❌ | No-op; clears `value` and returns `SUCCESS`. |

---

## 6.14. File Transfer ABI (`ft_*`)

Source: [src/abi_ft.cpp](src/abi_ft.cpp).

Statuses below assume `OBN_FT_FTPS_FASTPATH=ON` (the default). With it `OFF`, every active entry point collapses into a polite-failure stub (`FT_EIO`) and Studio transparently falls back to its internal FTP send path (`bambu_network_start_send_gcode_to_sdcard`). The file ends up in the same place; the UI just skips the storage-ability probe and per-percent progress from the fast path.

For `bambu:///local/*` URLs the fast path serves the whole `ft_*` bus over FTPS (port 990) — `CWD /sdcard` / `CWD /usb` probes satisfy `cmd_type=7` (media ability), and `STOR` satisfies `cmd_type=5` (upload). Cloud / TUTK URLs return `FT_EIO`; that proprietary transport is out of scope.

| Function | Status | Notes |
| --- | :--: | --- |
| `ft_abi_version` | ✅ | Returns `1`, matching Studio's expected `abi_required`. |
| `ft_free` | ✅ | No-op (handles are owned by the plugin). |
| `ft_job_result_destroy` | ✅ | No-op. |
| `ft_job_msg_destroy` | ✅ | No-op. |
| `ft_tunnel_create` | ✨ | Parses `bambu:///local/<ip>?port=…&user=…&passwd=…` into a LAN descriptor; non-local URLs fall through to the stub path. |
| `ft_tunnel_retain` | ✅ | Refcount. |
| `ft_tunnel_release` | ✅ | Refcount. |
| `ft_tunnel_set_status_cb` | ✅ | Stored on the tunnel. |
| `ft_tunnel_start_connect` | ✨ | LAN: synchronously establishes the FTPS control channel (sub-second on LAN) and fires the callback. Non-LAN: fires a synthetic `FT_EIO` immediately so Studio's state machine never hangs. |
| `ft_tunnel_sync_connect` | ✨ | LAN: same FTPS handshake. Non-LAN: returns `FT_EIO`. |
| `ft_tunnel_shutdown` | ✅ | Tears down the FTPS control channel and flags the tunnel as shut down. |
| `ft_job_create` | ✅ | Parses `cmd_type` / `dest_storage` / `dest_name` / `file_path` out of the params JSON. |
| `ft_job_retain` | ✅ | Refcount. |
| `ft_job_release` | ✅ | Refcount. |
| `ft_job_set_result_cb` | ✅ | Stored on the job. |
| `ft_job_set_msg_cb` | ✅ | Stored on the job; progress is pushed through it from the STOR loop. |
| `ft_tunnel_start_job` | ✨ | LAN: spawns a worker thread that dispatches on `cmd_type` (media-ability probe, STOR upload with percent progress). Non-LAN: delivers a synthetic `FT_EIO` result. |
| `ft_job_get_result` | ✅ | Blocks with timeout on the job's condition variable; returns `FT_ETIMEOUT` on timeout, the job result otherwise. |
| `ft_job_cancel` | ✅ | Sets an atomic flag observed by the STOR progress callback; the upload aborts cleanly with `FT_ECANCELLED`. |
| `ft_job_try_get_msg` | ❌ | Always returns `FT_EIO`. Progress messages are pushed through `msg_cb` rather than polled, matching how Studio actually consumes them. |
| `ft_job_get_msg` | ❌ | Always returns `FT_EIO`, same reason as above. |

---

## Cross-reference

| Reference | Location |
| --- | --- |
| ABI contract (canonical function list) | [NETWORK_PLUGIN.md § 6](NETWORK_PLUGIN.md#6-the-full-c-abi-contract) |
| Common cloud HTTPS transport (hosts, bearer, response envelopes) | [NETWORK_PLUGIN.md § 6.10.1](NETWORK_PLUGIN.md#6101-common-cloud-transport) |
| Filament Manager REST shapes (MITM) | [NETWORK_PLUGIN.md § 6.15](NETWORK_PLUGIN.md#615-filament-manager-cloud-spool-catalogue) |
| Feature-level status tables (per-model) | [README.md](README.md) |
| Workaround rationale | [README.md § Workaround reference](README.md#workaround-reference) |
