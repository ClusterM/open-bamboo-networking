# Wire fixtures — genuine-plugin contract traces

Golden, ordered traces of what the **stock** Bambu network plugin (BambuStudio) sends on the
wire. They are the contract the OSS library must reproduce; the future test harness replays
each flow against the OSS code and asserts the emitted messages match.

See **[FORMAT.md](FORMAT.md)** for the `flow.json` schema and matching rules.

## Tree
```
<os>/<network_plugin_version>/<channel>/<printer_model>/<flow>/flow.json
```

## Channels
- `cloud` — cloud-bound printer, cloud delivery (`mode=cloud_file`), printer not LAN-reachable.
- `cloud_lan` — cloud-bound printer delivering over LAN (`mode=lan_file`); still runs the whole
  api.bambulab.com project/task pipeline (creates the MakerWorld record). This is what our two
  "lan-side" runs actually were.
- `lan` — pure LAN-only / unbound printer: no cloud pipeline at all (different, shorter flow). Not yet captured.

Account/user flows that aren't tied to a printer use `channel: cloud`, `printer_model: account`
(they're cloud-only).

### Device-command flows (`flow: device_command`)

MQTT device-control commands published to `device/<serial>/request` (lights, AMS drying, bed/chamber
temp, filament-slot edit). The fixture's `driver` carries the raw `command_json` and a `signed` flag;
the harness sends it via `send_message_to_printer` against a `MqttBrokerMock` and asserts what the OSS
published. For a `"print"`-envelope command the OSS RSA-SHA256 **signs** the sorted print body with the
slicer key (`maybe_sign`) into `{"header":{cert_id,sign_alg,sign_string,sign_ver},"print":{…}}` — the
harness **cryptographically verifies** that signature against a test slicer public key (proving the
signing without a real printer). A `"system"` command (`ledctrl`) is asserted forwarded **verbatim**.
Captured on the H2D: `light` (unsigned), `ams_drying`, `bed_temp`, `chamber_temp`, `filament_setting`
(all signed). H2S adds `ams_drying` + `ams_ht_drying` (the single-slot AMS-HT is a separate unit,
`ams_id 128`).

### Storage-list flow (`flow: storage_list`)

Device → Storage listing over FTPS. (Note: the `ft_*` file-transfer ABI can only download/upload/
media-ability — it can't list; the real listing path is the libBambuSource CTRL channel
`{cmdtype:1,type:model}` → `ftps_handle_list_info` → `obn::ftps::Client::list_entries`.) The harness
drives `list_entries` directly against `FtpsMock`: it issues FTPS `LIST` and parses the vsFTPd
`ls -l` lines into `{name,size,mtime,is_dir}`. The fixture's `driver` supplies the raw `listing`
(the bytes the printer sends) and `expect_files` (name+size to assert). Captured on the H2S:
`storage_list` (models `*.gcode.3mf` + a timelapse `*.mp4`).

### CTRL-channel storage-list flow (`flow: ctrl_storage_list`)

The same listing driven **end to end through the shipped `libBambuSource.so` `Bambu_*` ABI** — the
exact path Studio/Orca use. The harness `dlopen`s the real `.so` and runs `Bambu_Open` →
`Bambu_StartStreamEx(0x3001)` → `Bambu_SendMessage(0x3001, {cmdtype:1,req:{type:model}})` →
`Bambu_ReadSample`. Two in-process mocks stand in for the printer: a `NativeTunnelMock` answers the
native `:6000` TLS **BambuTunnelLocal handshake** (LOGIN→ack, SETUP→reply) so the channel reaches
`ctrl_mode`, and `FtpsMock` serves the `LIST` once the `force_ftps` bridge dispatches it. The test
asserts the returned `reply.file_lists` (name+size) and that `keep_for_type(model)` filters the
`.mp4`/dir out of a model listing. Captured on the H2S: `ctrl_storage_list`.

## Captured so far
| os | plugin | channel | model | flow | notes |
|----|--------|---------|-------|------|-------|
| linux | 02.07.00.50 | cloud     | account | login            | `POST /user/ticket/{t}` → `GET /my/profile`; token-less CID; credential/2FA is web-side |
| linux | 02.07.00.50 | cloud     | account | preset_sync      | list `GET /slicer/setting?version=…&public=false` + per-id `GET` (CID, no CT) |
| linux | 02.07.00.50 | cloud     | account | preset_write     | create POST / update PATCH (no `type`/`public`) / delete DELETE (no CT) |
| linux | 02.07.00.50 | cloud     | account | filament_manager | `GET filament/config` + `GET my/filament/v2` + edit `PUT my/filament/v2` (all CID+CT) |
| linux | 02.07.00.50 | cloud_lan | h2s     | start_print      | single nozzle, 2 filaments on 2 different AMS units (amsMapping `[2,128]`); `mode=lan_file` |
| linux | 02.07.00.50 | cloud_lan | h2d     | start_print      | DUAL nozzle, one filament per nozzle; `nozzleInfos` ×2, per-filament `nozzleId`; `mode=lan_file` |
| linux | 02.07.00.50 | cloud     | h2s     | start_print      | pure-cloud `mode=cloud_file` (derived from the cloud_lan H2S capture; only `mode` differs) |
| linux | 02.07.00.50 | cloud     | a1      | start_print      | A1 single-nozzle **single-AMS** 2-filament, genuine pure-cloud (`mode=cloud_file`, LAN firewalled so the printer downloads from S3); A1 defaults (bedLeveling/flowCali true) |
| linux | 02.07.00.50 | cloud_lan | h2s     | storage_list      | FTPS `LIST` → vsFTPd `ls -l` parse (`list_entries`); models `*.gcode.3mf` + timelapse `*.mp4` |
| linux | 02.07.00.50 | cloud_lan | h2s     | ctrl_storage_list | full `libBambuSource` CTRL ABI: `:6000` handshake mock + FTPS bridge; `type=model` filter |
| linux | 02.07.00.50 | lan       | h2s     | ssdp_discovery    | genuine NOTIFY on UDP :2021; `parse` → device-info JSON + live `Discovery` listener |
| linux | 02.07.00.50 | lan       | h2d     | ssdp_discovery    | as H2S, dual-nozzle O1D model |
| linux | 02.07.00.50 | lan       | a1      | ssdp_discovery    | A1 firmware variant: uppercase `HOST` :1900, `DevSignal`, no `NTS`/`DevInf` |

**Diffing the two start_print traces** shows the entire cloud_lan-vs-cloud contract delta: the
`ftp://`-placeholder PATCH and `GET /my/setting` are cloud_lan-only, and `create_task.mode` flips
`lan_file`↔`cloud_file` (all other create_task fields identical).

## To extend
- **More flows** (same os/version/model): `login`, `refresh`, `preset_sync` (create/update/delete),
  `bind`, `web_sso_ticket`, `filament_edit`. We have raw captures for most of these in this
  session's `/tmp/http_all.jsonl`-style logs and in `../../CLOUD_REST_PARITY.md`.
- **More models**: `h2d` (dual-nozzle → `nozzleId`/grouping differs), `a1` (no AMS variants).
- **More plugin versions / OS**: `windows`/`macos` change the `X-BBL-OS-*` identity and paths;
  older plugin versions may reorder or omit headers — a new leaf documents exactly what changes.
- **MQTT**: the schema carries `protocol:"mqtt"` (see the placeholder step [J] in each start_print
  trace). The `device_command` flow already drives a `MqttBrokerMock`; extend with report/status
  subscribe traces. **SSDP is done** (`ssdp_discovery`, live `Discovery` listener over loopback).

## Harness (built)
`../wire_compliance_test.cpp` — embeds a mock of api.bambulab.com, points the OSS at it,
drives each flow's OSS entry point, and asserts the emitted requests against `steps[]` per
FORMAT.md. One ctest per fixture:

```
cmake -S . -B build -DOBN_BUILD_TESTS=ON -DOBN_VERSION=02.07.00.99
ctest --test-dir build -R wire_ --output-on-failure
```

Drivers today (all green): `login`, `preset_sync`, `preset_write`, `filament_manager`,
`start_print`. The `start_print` driver reads a `driver` block from the fixture (the
`PrintParams` inputs), drives the full `run_cloud_print_job` HTTP pipeline against the mock, and
asserts the exact `create_task` body via `test_build_task_body` (so `mode=lan_file` and the ams
mapping arrays are checked precisely). Each `start_print` leaf ships the genuine sliced 3mf it
uploaded under `assets/` (md5 matches the captured PATCH).

`start_print` coverage: `cloud_lan/h2s` (single nozzle, two filaments on two different AMS units —
amsMapping `[2,128]`), `cloud_lan/h2d` (dual nozzle, one filament per nozzle — `nozzleInfos` with
two entries, per-filament `nozzleId`), and `cloud/h2s` (pure-cloud `mode=cloud_file`, derived).

The two `cloud_lan` flows run the **full `lan_file` pipeline end-to-end**, not just the HTTP legs:
after the api.bambulab.com calls the harness drives the OSS's real FTPS upload and MQTT publish
against in-process printer mocks (`tests/lan_mocks.hpp`), grounded in a live H2D capture — a
vsFTPd-style `FtpsMock` (asserts the full-file `STOR` md5) and a `MqttBrokerMock` (asserts the
`project_file` publish with a cleartext `ftp://` url). See FORMAT.md → "start_print specifics".

Already caught + fixed a real bug: the filament `list`/`config` GETs were dropping `Content-Type`.
