# Cloud REST parity audit

Goal: make the open plugin's api.bambulab.com REST traffic byte-identical to the
closed-source Bambu network plugin. Captured live via MITM of the genuine plugin
(Studio bridge fork) on 2026-07-13/14. Version pair on the wire was
**agent 02.07.00.50 / client 02.07.00.55**, which matches `slicer_plugin_versions.hpp`
exactly — the version table is validated against real traffic.

## Header pattern per endpoint (genuine capture)

`CID` = X-BBL-Client-ID present. `CT` = Content-Type present.

| Method | Endpoint | CID | CT | Notes |
|--------|----------|-----|----|----|
| GET  | /iot-service/api/user/print            | varies | ✓ | saw both with & without CID (incl. `?force=true` variant) |
| GET  | /user-service/my/tasks?limit&offset&status | ✓ | ✓ | notification/task list poll |
| GET  | /user-service/my/task/{id}             | ✓ | ✗ | task detail |
| GET  | /iot-service/api/user/task/{id}        | ✓ | ✗ | task detail (iot) |
| GET  | /design-user-service/my/filament/v2?offset&limit | ✓ | ✓ | filament list |
| PUT  | /design-user-service/my/filament/v2    | ✓ | ✓ | filament edit; body below |
| GET  | /design-user-service/filament/config   | ✓ | ✓ | |
| GET  | /iot-service/api/user/applications/{t}/cert | ✗ | ✗ | get_app_cert — neither |
| POST | /user-service/user/consent             | ✓ | ✓ | |
| GET  | /iot-service/api/slicer/resource       | ✗ | ✗ | plugin-store lookup (public) |
| GET  | /design-service/my/design/recommend    | ✓ | ✓ | |
| GET  | /design-user-service/my/preference     | ✗ | ✓ | |
| GET  | /operation-service/makerlabhomepage    | ✗ | ✓ | |
| GET  | /v1/analysis-st/tag/                    | ✗ | ✗ | |

**X-BBL-Client-ID is non-deterministic.** The same endpoint (`/user/print`) was seen
both with and without it. Exact CID replication is therefore not achievable; the open
plugin picks one valid observed variant per endpoint. Content-Type presence, by contrast,
is deterministic per endpoint.

### PUT /filament/v2 body (edit)
```
{"color":"#001489","colors":["#001489"],"filamentName":"PETG Basic","id":1114804,"note":"..."}
```
Compact JSON, keys alphabetical, partial update (only changed/identifying fields).

## OSS call-site conformance

| File | Endpoint(s) | Flags | vs genuine |
|------|-------------|-------|-----------|
| cloud_filament.cpp | filament/config, filament/v2 | (cid,ct)=(T,T) | ✓ match (list/config GET keep CT — was erasing it, **fixed**; caught by the wire-compliance harness, tests/wire-fixtures/) |
| abi_http.cpp | user/print, user/bind | (F,T) | ✓ user/print is a valid variant |
| cloud_presets.cpp list/get_full | slicer/setting GET | (T,F) | not yet capture-verified |
| cloud_presets.cpp create/update/delete | slicer/setting | (T,T) | not yet capture-verified |
| cloud_auth.cpp profile/ticket/refresh | my/profile, ticket, refreshtoken | (F,T) pre-auth | reasonable; ticket not captured |
| cloud_auth.cpp get_app_cert (#if 0) | applications/{t}/cert | (F,F) | ✓ match |
| cloud_print.cpp (FIXED) | project/notification/upload/my-task | now delegates to identity_headers | fixed below |

## Fix applied this pass

`cloud_print.cpp::bbl_headers()` was a stale local helper that:
- set `X-BBL-Client-Name: OpenBambooNetworking` (a self-identifying fingerprint tell)
- used `Accept` (capital) instead of genuine lowercase `accept`
- hardcoded a static `:obn0` client-id suffix instead of the per-request hex
- omitted X-BBL-Client-Version, -Device-ID, -OS-Version, -Agent-Version, -Executable-Env

Now delegates to `obn::bbl::identity_headers(token, uid, /*cid*/true, /*ct*/true)` so the
print-pipeline requests carry the identical stock set/values/casing. GET stages still
erase Content-Type at the call site.

## Live login + settings-sync capture (2026-07-14) — CONFIRMED byte-identical

Captured a full logout→login→cloud-settings-sync against the genuine plugin (hostname-
scoped MITM: only `api.bambulab.com` is remapped to a loopback sentinel and intercepted;
`bambulab.com`/`makerworld.com` reach the real server so the login webview's TLS passes).

- **`POST /user-service/user/ticket/{ticket}`** (ticket→token): full X-BBL block, **no**
  X-BBL-Client-ID, **no** Authorization (pre-auth), `accept`, `Content-Type`; body
  `{"ticket":"<t>"}`. Matches `cloud_auth.cpp::login_with_ticket` header-for-header. ✓
- **`GET /user-service/my/profile`**: full block, Authorization, **no** CID, Content-Type.
  Matches `get_profile(token,"",false,true)`. ✓
- **`GET /iot-service/api/slicer/setting?version=<host>&public=false`** (preset list) and
  **`GET /iot-service/api/slicer/setting/{id}`** (per-preset, ids `PFUS…`=filament /
  `PPUS…`=process): both **CID present, NO Content-Type**, Authorization. Matches
  `cloud_presets.cpp` list/get_full `(cid=true, ct=false)`. ✓ The `version` value
  (`2.7.0.2`) is host-supplied and forwarded verbatim — no plugin-side synthesis.
  Settings sync is a read-only pull (list + N per-id GETs); **no writes** are emitted by
  the sync, so create/update/delete flags remain inferred, not capture-verified.

  The `version` param = the release's `resources/profiles/BBL.json` `"version"` with
  leading zeros stripped (`Semver::to_string`), i.e. BambuStudio's
  `preset_bundle->get_vendor_profile_version(BBL_BUNDLE).to_string()` at
  `GUI_App.cpp` `get_setting_list2(version, …)`. It is NOT the app/plugin version.
  Recovered per release from each tag's BBL.json and added to
  `slicer_plugin_versions.hpp` as a 4th `sync` column + `sync_version()` accessor;
  `cloud_presets.cpp::list()` now falls back to it when the host supplies none:

  Full table (slicer tag / plugin build / sync). Plugin build recovered from
  `GET /slicer/resource?slicer/plugins/cloud=<MAJOR.MINOR.PATCH>.00 -> resources[].version`
  (validated: 02.07.00→…50, 02.05.03→…63). Covers OSS's supported floor of 02.03.00.xx.

  | line | slicer | plugin (agent) | sync |
  |------|--------|----------------|------|
  | 02.03.00 | 02.03.00.70 | 02.03.00.62 | 2.3.0.2 |
  | 02.03.01 | 02.03.01.51 | 02.03.01.52 | 2.3.0.4 |
  | 02.04.00 | 02.04.00.70 | 02.04.00.79 | 2.4.0.1 |
  | 02.05.01 | 02.05.01.58 | 02.05.01.52 | 2.5.0.15 |
  | 02.05.02 | 02.05.02.51 | 02.05.02.58 | 2.5.0.15 |
  | 02.05.03 | 02.05.03.62 | 02.05.03.63 | 2.5.0.18 |
  | 02.06.00 | 02.06.00.51 | 02.06.00.50 | 2.6.0.1 |
  | 02.06.01 | 02.06.01.55 | 02.06.01.50 | 2.6.0.3 |
  | 02.07.00 | 02.07.00.55 | 02.07.00.50 | 2.7.0.2 (capture-confirmed) |
  | 02.07.01 | 02.07.01.62 | 02.07.01.51 | 2.7.0.8 |
  | 02.08.00 | 02.08.00.50 | 02.08.00.51 | 2.8.0.1 |

## OrcaSlicer masquerade (default-on, env-overridable)

`identity_headers()` presents the stock BambuStudio identity by default, and the block
wins over any X-BBL-* the host sets via set_extra_http_header — so a non-Bambu host
(OrcaSlicer) is indistinguishable to the cloud without host cooperation.

**Versions are governed by one switch, `OBN_ALLOW_VERSION_OVERRIDES` (default false).**
They never come from the environment. When false, all versions — X-BBL-Client-Version,
X-BBL-Agent-Version, User-Agent version, and the `/slicer/setting?version=` bundle — come
from the version table for the release line, and the host slicer's own versions are
ignored. When set (`1`/`true`/`yes`/`on`), the plugin obeys the host's versions instead:
the sync bundle version it passes to `list()`, and the X-BBL-Client-Version /
X-BBL-Agent-Version / User-Agent it supplies via set_extra_http_header (those win the
overlay in `agent.cpp`).

Non-version identity fields remain individually env-tunable (names/OS, not versions):

| env var | overrides | default |
|---------|-----------|---------|
| `BBL_CLIENT_NAME`    | X-BBL-Client-Name          | BambuStudio |
| `BBL_CLIENT_TYPE`    | X-BBL-Client-Type + client-id prefix | slicer |
| `BBL_UA_PRODUCT`     | User-Agent product token (not the version) | bambu_network_agent |
| `BBL_OS_TYPE` / `BBL_OS_VERSION` / `BBL_DEVICE_ID` / `BBL_LANGUAGE` / `BBL_EXEC_INFO` | resp. X-BBL-* | stock |

### New endpoint discovered: `POST /iot-service/api/user/ttcode`
Device tunnel-code request (camera/remote), body
`{"dev_id":"…","dev_version":"…","protocols":["tutk","agora"]}`. Not implemented in OSS.
Notable for the **device-auth header family** it carries (real-world shape):
- `x-bbl-app-certification-id: CN=<serial>.bambulab.com:<hex>`
- `x-bbl-device-security-sign: <base64 RSA signature>`
- `user-id: <uid>` (lowercase header)
Useful reference for `bind_cloud.cpp` / device-security-sign work; the endpoint itself is
tunnel/camera plumbing, likely out of scope for cloud REST parity.

## Preset WRITE endpoints (2026-07-14) — CONFIRMED

Triggered live by save-as / save-in-place / delete of a throwaway preset (sync thread
pushes within ~2s once logged in; both test presets deleted afterwards). All match OSS
`cloud_presets.cpp`:

- **create** `POST /iot-service/api/slicer/setting` — CID + Content-Type + Auth. Body
  `{"base_id","name","public":false,"setting":{…diffed values + inherits/ids/updated_time},"type","version"}`.
  (OSS emits the same keys; JSON key order differs but is irrelevant to the server.) ✓
- **update** `PATCH /iot-service/api/slicer/setting/{id}` — CID + Content-Type + Auth. Body
  `{"base_id","name","setting":{…},"version"}` — **no `type`, no `public`**. OSS was
  emitting `type` on PATCH when present in the values map; **fixed** to omit it. ✓
- **delete** `DELETE /iot-service/api/slicer/setting/{id}` — CID, **no Content-Type**, no
  body. OSS `del()` does `hdrs.erase("Content-Type")`. ✓

`version` inside the write body is the same sync bundle version (`2.7.0.2`). Preset ids are
`PPUS…` (process) / `PFUS…` (filament).

## Device endpoints (2026-07-14)

- **`GET /iot-service/api/user/device/version?dev_id=<sn>`** — CID + Content-Type + Auth,
  no body. Fires on the Device→Update page / device switch. Matches OSS `bind_cloud.cpp`
  `(cid=true, ct=true)`. ✓
- **`PATCH /iot-service/api/user/device/info`** (rename) — CID + Content-Type + Auth, body
  `{"dev_id":"<sn>","dev_name":"<name>"}`. Captured by renaming a printer via the Device
  selector's edit-pencil and renaming back. OSS `modify_printer_name` is a **perfect match**
  (same method, URL, body keys, header flags). ✓

## Web-SSO / bind ticket (2026-07-14) — CONFIRMED + FIXED

Triggered by opening a MakerWorld model page. The genuine plugin's `request_bind_ticket`
is a single **`GET /v1/user-service/user/ticket`** (no body; CID + Content-Type + Auth) —
the response ticket is put in the browser SSO link. OSS `request_web_sso_ticket()` was
POSTing three *guessed* wrong paths (`/user/ticket/web`, `/user/web-ticket`,
`/user/slicer/ticket`) and only falling back to the correct GET last — **fixed** to issue
the single GET, matching the stock plugin (the three 404-ing POSTs were a fingerprint tell).

A follow-up **`POST /v1/user-service/my/ticket/{ticket}`** (body `{"ticket":"…"}`, CID + CT
+ Auth, carrying plugin X-BBL headers so it's the plugin, not the webview) fires right
after. Role not yet pinned down (ticket activation/exchange); needs one more capture before
wiring — noted, not implemented.

## Token refresh (2026-07-14) — request format captured; success NOT observed

Forced by editing the conf's `expires_in` to near-now and restarting (conf is AES-128-ECB,
zero-padded, key `i4crL3LESLnWapLS`; the plugin refreshes on startup when the token looks
near-expiry). Genuine request captured: **`POST /v1/user-service/user/refreshtoken`**,
**pre-auth** (no Authorization, no X-BBL-Client-ID), full X-BBL block, `Content-Type`, body
`{"refreshToken":"<t>"}`. Request shape **matches OSS `cloud_auth.cpp::refresh_token`**.

**Key finding — the genuine plugin's refresh 401s against this endpoint, every time.**
Logged statuses: **32/32 `POST /user-service/user/refreshtoken` → 401**
(`{"code":401,"error":"The client must authenticate itself..."}`) across both trick runs —
with fresh, valid refresh tokens from *both* a browser-SSO login (RT0) and a 2FA login
(RT2), 401 from the first attempt (not "consumed after one use"). Correcting an earlier
misread: both `expires_in`-trick runs 401'd the refresh (the post-restart 200s were just
the still-valid access token, since only the conf expiry was faked) — hence the logouts.

**It is NOT a MITM/fingerprint problem.** The pre-auth ticket exchange
(`POST /user/ticket/{t}`) returns **200 through the same mitmdump proxy** (twice, at login).
So a pre-auth endpoint works fine through the interceptor; the refresh 401 is specific to
that endpoint/token. (This retracts an earlier JA4/fingerprint theory.)

Open question — one of:
1. `/v1/user-service/user/refreshtoken` with body `{"refreshToken":…}` is **not** the real
   refresh mechanism (wrong path/auth/body) → then **OSS `cloud_auth.cpp::refresh_token` is
   actually wrong**, not merely format-matching. The request *shape* matches what BambuStudio
   sends, but BambuStudio's own refresh fails here too.
2. BambuStudio has **no working silent refresh** and just re-prompts login on expiry
   (consistent with the "Login information expired. Please login again." dialog we saw).
3. Refresh needs a session element we didn't capture (e.g. a Cloudflare clearance cookie the
   long-running plugin normally holds).

Consequences:
- **Fixed-vs-sliding expiry unanswered** (never observed a successful refresh; tokens are
  opaque, not JWTs).
- **OSS refresh is unverified end-to-end** — don't treat it as "confirmed correct"; the
  endpoint may be wrong, or refresh may be a non-feature. Needs real-server verification.
- Refresh appears **single-use/rotating** where it works, but that was inferred, not seen
  succeed here.

## Print pipeline (2026-07-14) — CONFIRMED (real cloud print to H2S, cancelled pre-Layer-1)

Sent a sliced benchy to the H2S ("cloud service" send), captured the full pipeline, then
Stopped on-printer at 0% during heat/filament-change. All calls 200; POST/PUT/PATCH carry
CID+CT, GETs CID/no-CT. Sequence (matches OSS `cloud_print.cpp` `[A]…[I]`):

1. `POST /project` — `{"name":"3DBenchy"}` → project_id
2. `PUT /notification` — `{"upload":{"origin_file_name":".<pid>.1_config.3mf","ticket":"uploader_<uid>_<...>"}}`
3. `GET /notification?action=upload&ticket=…` (polled until ready)
4. `PATCH /project/{id}` — `{"profile_id","profile_print_3mf":[{"md5","plate_idx":1,"url":"ftp://…gcode.3mf"}]}` (placeholder url)
5. **`GET /my/setting`** — NEW, not in OSS (mid-pipeline; user print settings)
6. `GET /upload?models=<modelId>_<profileId>_<plate>.3mf` → presigned S3 url
7. `PATCH /project/{id}` — same shape, real `https://s3…amazonaws.com/…` url
8. `POST /my/task` — full create_task body (below)
9. `GET /my/task/{id}` — status poll

**create_task body validated field-for-field against OSS** (same fields, same order):
`amsDetailMapping, amsMapping, amsMapping2, autoBedLeveling, bedLeveling, bedType, cfg,
cover, deviceId, extrudeCaliFlag, extrudeCaliManualMode, filamentSettingIds, flowCali,
layerInspect, mode, modelId, nozzleInfos, nozzleOffsetCali, oriModelId, oriProfileId,
plateIndex, profileId, sequence_id, timelapse, title, useAms, vibrationCali`. Confirms the
original create_task work: **`oriModelId:""`, `oriProfileId:0` for a local (no-DesignModelId)
file**; `bedType:"eng_plate"`; amsDetailMapping[0]=`{ams:1,filamentId:"GFN99",filamentType:"PA",
nozzleId:1,sourceColor,targetColor}`.

Note: despite the "Sending through cloud service" UI, the task `mode` was **`lan_file`**
(printer is LAN-reachable) — the file uploaded to S3 but delivery is LAN. A pure
`cloud_file` would need the printer's LAN blocked (the user's firewall idea).

`GET /my/setting` gap — **now added** to OSS `cloud_print.cpp` (`fetch_my_setting`, between
the first PATCH and the upload; keeps Content-Type unlike other pipeline GETs; non-fatal).

### lan_file vs cloud_file (2026-07-14) — verified by a second print with the printer's LAN blocked

Sent the same benchy to H2S again with `iptables OUTPUT -d 192.168.1.209 DROP` on the host,
forcing cloud delivery, then Stopped on-printer (the **cloud Stop works with LAN blocked**).

- **create_task body: identical except `"mode"`** — `lan_file` → **`cloud_file`**. Every other
  field the same (amsDetailMapping/amsMapping/amsMapping2, bedType, deviceId, oriModelId:"" /
  oriProfileId:0, all cali flags). (`title`/`modelId`/`profileId` differ only incidentally —
  per-upload ids / how the model was loaded, not lan-vs-cloud.)
- **Pipeline is leaner for cloud_file:**
  - lan: `POST project → PUT/GET notification → PATCH project (ftp:// placeholder) →
    GET /my/setting → GET upload → PATCH project (S3) → POST my/task → polls`
  - cloud: `POST project → PUT/GET notification → GET upload → PATCH project (S3) →
    POST my/task → polls`
  - i.e. cloud **skips the ftp-placeholder PATCH and the `GET /my/setting`**, and does a single
    PATCH. So the ftp PATCH + `/my/setting` are **lan-flow-specific**.

Implication: OSS implements the lan-with-record flow, so the two-PATCH + `/my/setting`
sequence (now including the added `fetch_my_setting`) is correct for its use. A pure
cloud_file print would use the shorter sequence — worth branching only if OSS adds a
cloud-delivery mode. Functionally the server accepts either; only `mode` drives delivery.

### Multi-filament / multi-AMS + dual-nozzle create_task (2026-07-14)

To broaden the `start_print` wire fixtures, two more genuine prints were captured (a 20mm box
with a colour change at layer 47, so it uses two filaments; cancelled before layer 1):

- **H2S, single nozzle, two DIFFERENT AMS units.** Filament 1 = PAHT-CF on the 4-slot AMS
  (slot A3), filament 2 = ASA on the AMS-HT unit. The AMS-HT surfaces as **`ams`/`amsId` 128**:
  `amsMapping [2,128]`, `amsMapping2 [{amsId:0,slotId:2},{amsId:128,slotId:0}]`. Both entries
  carry `nozzleId:1` and `nozzleInfos` is `[]` (single-nozzle machine).
- **H2D, dual nozzle, one filament per nozzle.** Left AMS (B-series) is **`amsId 1`** feeding
  the left nozzle (`nozzleId 1`), right AMS (A-series) is **`amsId 0`** feeding the right nozzle
  (`nozzleId 0`): `amsMapping [5,3]`, `amsMapping2 [{amsId:1,slotId:1},{amsId:0,slotId:3}]`,
  per-filament `nozzleId` 1 and 0, and the dual-nozzle signature **`nozzleInfos` with two
  entries** (`{diameter:0.4,flowSize:"standard_flow",id:1,type:null}` and `…id:0…`).
  `bedType:"textured_plate"`.

Both are `mode:lan_file` (cloud_lan). The OSS `build_task_body` reproduces all of this from
`PrintParams` (`ams_mapping` → amsMapping, `ams_mapping2` → amsMapping2, `ams_mapping_info` →
amsDetailMapping, `nozzles_info` → nozzleInfos) — asserted exactly by the wire-compliance harness
(`tests/wire-fixtures/.../cloud_lan/{h2s,h2d}/start_print`).

### The two LAN delivery legs (FTPS + MQTT) — captured from a live H2D (2026-07-14)

`lan_file` delivery adds two printer-direct legs the api-scoped MITM never saw. Captured directly:

- **FTPS upload (before create_task).** Implicit FTPS on **:990**, printer runs **vsFTPd 3.0.5**,
  auth `USER bblp` / `PASS <access_code>`. Real control sequence: `220 (vsFTPd 3.0.5)` /
  `USER→331` / `PASS→230` / `PBSZ 0→200` / `PROT P→200` / `PWD→257` / `PASV→227 (h1..p2)`
  (curl uses EPSV→229; the OSS uses PASV) / `TYPE I→200` / `STOR /<name>→150` / `226 Transfer
  complete`. The 3mf is STOR'd to the FTP **root** (`/box20.gcode.3mf`).
- **MQTT project_file (after create_task).** Topic `device/<serial>/request`, payload
  `{"print":{"command":"project_file","param":"Metadata/plate_N.gcode","url":"ftp://…",
  "md5":…,subtask_name,project/profile/task_id,…}}`. Fire-and-forget (QoS0). The **LAN channel
  carries the cleartext `url`** (the printer fetches from its own storage over the local url) —
  there is **no `url_enc`**; the RSA-encrypted `url_enc` is the **cloud-channel** path (S3 https
  url, encrypted to the printer pubkey).

**Finding:** on a **cloud-bound** printer the *genuine* plugin sends `project_file` over the
**cloud MQTT**, not the LAN `device/<serial>/request` topic — the LAN MQTT only carried
`get_version` / `pushall` / the `app_cert_install` security handshake + status `/report`. The OSS
(and BambuBridge) instead publish `project_file` straight to `device/<serial>/request`, which the
printer accepts (the LAN command topic took the version/security commands fine). So the OSS's LAN
transport differs from the cloud-bound genuine plugin's but is a valid path the firmware honours.

Both legs are now exercised end-to-end by the harness against faithful in-process mocks
(`tests/lan_mocks.hpp`, modelled on the above): the FTPS `STOR` is asserted to carry the whole
sliced 3mf (md5), and the `project_file` publish is asserted on the right topic with a cleartext
`ftp://` url.

## Not yet captured (need targeted triggers)

- `POST /user/bind` — out of scope (mutates account by binding a printer).
- Token refresh — see above; genuine plugin's own refresh 401s, unverified end-to-end.
- Pure `cloud_file` print mode — needs LAN to the printer blocked.

## Device-control commands (MQTT) + signing (2026-07-14/15)

Device-control commands are published to `device/<serial>/request`. Two classes:

- **Signed** — any payload whose top-level key is `"print"`: the plugin RSA-SHA256 signs the sorted
  print body with the slicer key (`maybe_sign`) into
  `{"header":{"cert_id","payload_len","sign_alg":"RSA_SHA256","sign_string","sign_ver":"v1.0"},"print":{…}}`.
  Captured (H2D): `ams_filament_drying` (ams_id, temp, duration, mode 1=start/0=stop, filament),
  `set_bed_temp` {temp}, `set_ctt` {ctt_val} (chamber; <40°C auto-reverts to 0),
  `ams_filament_setting` {tray_color, tray_type, tray_info_idx, setting_id, nozzle_temp_min/max, ams_id,
  slot_id, tray_id} (+ a follow-up signed `extrusion_cali_sel`).
- **Verbatim** — non-`print` payloads: chamber light `{"system":{"command":"ledctrl","led_node":
  "chamber_light"/"chamber_light2","led_mode":"on"/"off",…}}` is forwarded unsigned (H2 has two light nodes).

The H2S publishes these **AMS-HT** unit commands under `ams_id 128/129` (the single-slot high-temp AMS
is a separate unit). Note: for a cloud-bound H2S, BambuStudio routed drying over **cloud** MQTT, not the LAN
`device/<serial>/request` topic (the H2D used LAN).

**Signing validated end-to-end**: `tools/obn_send_command` (built on the OSS) sent signed
`ams_filament_setting` over LAN and over cloud (with the printer's LAN firewalled off) — the printers
**accepted** both (a bad signature is rejected "mqtt message verify failed"). The wire-compliance harness
(`flow: device_command`) verifies the same offline by cryptographically checking the OSS's signature against
a test slicer key.

## Storage / media listing (FTPS LIST)

Printer storage is listed over FTPS (vsFTPd 3.0.5): `220 / USER / PASS / PWD 257 / PASV(or EPSV) / TYPE A /
LIST 150 / 226`. **Models** (`*.gcode.3mf`) are in the FTP root and `/cache`; **timelapse videos** (`*.mp4`)
and their `/timelapse/thumbnail` are in `/timelapse`. Public storage API: the `ft_*` file-transfer ABI (`src/abi_ft.cpp`) only does download/upload/
media-ability -- it CANNOT list. The Device->Storage listing is the libBambuSource CTRL channel
(`Bambu_SendMessage 0x3001 {"cmdtype":1,"type":"model"/"timelapse"/"video","storage":""}`) ->
`ftps_handle_list_info` -> `obn::ftps::Client::list_entries`, which issues FTPS `LIST` and parses the
vsFTPd `ls -l` lines into `{name,size,mtime,is_dir}` and returns `{"reply":{"file_lists":[{name,path,
size,time,date}]}}`. **Bug found + fixed:** the FTPS bridge `ensure_ftp` (stubs/BambuSource.cpp)
hardcoded port 990 and ignored the `OBN_LAN_FTP_PORT` test seam -> added the same override as
print_job.cpp so the LIST path is now mockable. Harness: `flow: storage_list` drives `list_entries`
against FtpsMock (LIST responder) and asserts the parsed name/size.
