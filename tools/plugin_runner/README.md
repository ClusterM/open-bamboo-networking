# `plugin_runner` — stock-plugin shim for MQTT reverse engineering

`plugin_runner` is a tiny standalone CLI that pretends to be Bambu Studio
just enough to load any `libbambu_networking.so` (a specific upstream
release), drive its print entry points with a user-supplied
`BBL::PrintParams`, and let the real MQTT publish hit your printer. It
exists so we can diff the wire output of the **stock** plugin against
our own `open-bamboo-networking` build without firing up the whole IDE.

The wrapper script ([`tools/plugin_runner.sh`](../plugin_runner.sh)) is
the only thing humans should call. It picks the right ABI, builds the
C++ bridge against it, downloads the matching plugin from Bambu's CDN
(or reuses a cached copy), and exec's the binary with all your other
flags forwarded.

---

## 1. Install dependencies

Debian/Ubuntu:

```bash
sudo apt install build-essential cmake ninja-build pkg-config \
                 libcurl4-openssl-dev libminizip-dev libssl-dev \
                 nlohmann-json3-dev python3
```

`python3` is only used by the wrapper to parse the downloader's JSON
output (one tiny `python3 -c`); the C++ binary itself has no Python
dependency.

## 2. Layout

| File | Role |
| --- | --- |
| [`../plugin_runner.sh`](../plugin_runner.sh) | Bash wrapper, the only user-facing entry point |
| [`CMakeLists.txt`](CMakeLists.txt) | Standalone CMake project (independent of the top-level build) |
| [`main.cpp`](main.cpp) | CLI parsing, init order, callback wiring, action dispatch, completion wait |
| [`plugin_loader.{hpp,cpp}`](plugin_loader.hpp) | `dlopen` + `dlsym` for the ~30 entry points we use |
| [`print_params_io.{hpp,cpp}`](print_params_io.hpp) | JSON ↔ `BBL::PrintParams` (the `--params-json` schema) |
| [`plugin_downloader.{hpp,cpp}`](plugin_downloader.hpp) | `libcurl` + `minizip` against Bambu's `/slicer/resource` API |

Build artefacts land in `tools/plugin_runner/build-0xMMmmpp/` (one dir
per ABI). Plugin downloads are cached in
`~/.cache/obn-plugin-runner/<full-version>/libbambu_networking.so`
(override with `--cache-dir`).

## 3. CLI reference

### Wrapper-only flags

```
--abi MM.mm.pp            target ABI version          (required)
--plugin-path PATH        use this .so, skip download
--use-backup-fallback     also try ~/.config/BambuStudio/plugins/backup/
--force-download          ignore cache, refetch from CDN
--cache-dir DIR           override ~/.cache/obn-plugin-runner
```

### Forwarded to the C++ binary

```
--params-json FILE        BBL::PrintParams JSON (see §4 for the schema)
                          required for the print actions; ignored for
                          send_raw / none / http_probe / mw_probe
--action ACTION           send_gcode_to_sdcard | local_print
                          | sdcard_print | local_print_with_record
                          | cloud_print | send_raw | none | http_probe
                          | mw_probe | filament_probe
--gcode-3mf PATH          path to the *.gcode.3mf file Studio would have
                          generated; used as `filename` and `ftp_file`
                          fallbacks if your params JSON omits them
--dev-id ID               printer serial     (required except http_probe|mw_probe)
--dev-ip IP               printer LAN IP     (required except http_probe|mw_probe)
--access-code CODE        printer LAN access code (required except http_probe|mw_probe)
--country US              countries influence routing in some plugins
--use-ssl-mqtt 0|1        default 1; matches Studio's LAN flow
--cert-file PATH          override slicer_base64.cer location (best-effort)
--timeout SECONDS         max wait for PrintingStageFinished/ERROR (default 90)
--connect-settle-ms MS    *cap* on the wait for set_on_local_connect_fn
                          (status=ConnectStatusOk) before the publish
                          channel is considered ready. Default 800; bump
                          to 15000+ on slow handshakes (see §9).
--client-name NAME        X-BBL-Client-Name. Default OpenBambooNetworking.
                          POST /my/task answers 403 for anything other
                          than `BambuStudio`, so pass that when you need a
                          faithful stock cloud-print capture.
--cert-lan-only 0|1       lan_only argument for install_device_cert during
                          bring-up; Studio passes is_lan_mode_printer().
                          Default 1. A cloud-paired printer needs 0: only
                          that branch publishes app_cert_install and gets
                          printer_cert back, and without it every print:*
                          publish is rejected with -4030 (see §9).
--log-out PATH            also mirror every JSON event line to this file
--keep-tmpdir             leave the per-run /tmp/obn-plugin-runner-* alone
--fast-exit               flush logs then `_Exit(0)` instead of letting
                          destroy_agent drain its worker pool. Default ON
                          for `--action none` / `http_probe` / `mw_probe`,
                          OFF otherwise.
                          Stock plugins keep boost::asio / mqtt-cpp threads
                          alive past destroy_agent so a graceful shutdown
                          blocks ~60s; fast exit lets the kernel reap the
                          mapping.
--no-fast-exit            opposite, useful if you want destroy_agent to
                          flush a final status/event after the action.
--user-info JSON|@FILE    change_user payload. Studio
                          `{"data":{"token":…,"user":{…}}}` envelope, or
                          OBN `obn.auth.json` (auto-converted). Required
                          for `http_probe` / `mw_probe` / `filament_probe`.

# --action send_raw flags
--raw-json FILE                JSON payload to publish verbatim       (required)
--raw-qos N                    MQTT QoS (default 1)
--raw-flag N                   plugin-specific publish flag (default 0)
--raw-settle SECONDS           sleep after the last publish to let
                               local_message replies land (default 5)
--raw-repeat N                 publish the payload N times (default 1)
--raw-repeat-interval-s S      gap between repeats (default 5)

# --action http_probe / mw_probe flags (no printer; cloud HTTP only)
--task-id ID                   get_task_plate_index / get_subtask (default 1114566547)
--project-id ID                for get_slice_info
--profile-id ID                for get_slice_info (default 894049654)
--plate-index N                for get_slice_info (default 1)
--msg-type / --msg-after / --msg-limit
                               args for get_my_message (defaults 0 / 0 / 20)
--instance-id N                get_model_mall_rating (default 390100)
--design-id ID                 get_model_mall_detail_url (default 478834)
--mw-seed / --mw-limit         get_mw_user_4ulist (defaults 0 / 10)
--mw-put-rating                also call put_model_mall_rating (off by default)
--rating-id / --rating-score   for optional put

# --action filament_probe flags (no printer; cloud HTTP only)
--slot-dev-id ID               devId for sync_slot_mappings (default --dev-id)
--slot-ams-sn SN               amsSn of the tray
--slot-id N                    slotId — a decimal string ("0".."3")
--slot-spool-id N              spoolId — cloud spool id; 0 means unbind
--slot-rfid HEX                rfid — empty on unbind
--slot-ams-id N                amsId — AMS unit index
--slot-ams-type N              amsType — DevAmsType (0 EXT, 1 AMS, 2 Lite,
                               3 N3F, 4 N3S, 5 Lite-mixed)
--slot-mappings-json JSON|@F   full mappings array (or {"devId":…,
                               "mappings":[…]}), overrides the flags above;
                               the only way to send a batch or an empty array
--fil-sync-only                skip get_filament_spools, only run the syncs
```

`http_probe` calls `get_studio_info_url`, `get_my_message`, `check_user_task_report`,
`get_task_plate_index`, and `get_slice_info` after `change_user`.

`mw_probe` calls `get_subtask`, `get_model_mall_detail_url`, `get_model_mall_rating`,
`get_mw_user_preference`, `get_mw_user_4ulist` (and optionally `put_model_mall_rating`).

`filament_probe` calls `get_filament_spools` and `sync_slot_mappings` (the latter
needs `--abi 02.08.02` or newer). Studio drives `sync_slot_mappings` from the
Filament Manager AMS sync in two flavours: a *bind* carries `spoolId` + `rfid`,
an *unbind* zeroes both and keeps the pre-eject mount fields. Both hit
`POST /my/filament/v2/slot-mappings/sync` ([research §8.15](../../research/08.15-filament.md)).

`update_cert` calls `bambu_network_update_cert` (Studio `check_cert`) — no printer,
`--user-info` optional. Under MITM this is the shared app-cert fetch
`GET /v1/iot-service/api/user/applications/{enc_secret}/cert?aes256=…&ver=1`
([research §10.2](../../research/10.02-secrets.md)).

Capture stock HTTPS under mitmproxy:

```bash
HTTPS_PROXY=http://127.0.0.1:8888 HTTP_PROXY=http://127.0.0.1:8888 \
CURL_CA_BUNDLE=$HOME/.mitmproxy/mitmproxy-ca-cert.pem \
SSL_CERT_FILE=$HOME/.mitmproxy/mitmproxy-ca-cert.pem \
./tools/plugin_runner.sh --abi 02.08.01 \
  --plugin-path ~/.config/BambuStudio/plugins/libbambu_networking.so \
  --action mw_probe \
  --user-info @$HOME/.config/BambuStudio/obn.auth.json \
  --data-dir $HOME/.config/BambuStudio \
  --task-id 1114566547 --instance-id 390100
```

If the stock plugin ignores `HTTPS_PROXY`, use `SSLKEYLOGFILE` + Wireshark
or Frida SSL hooks (`tools/frida_ft_*`).

`plugin_runner --help` prints the same reference at any time.

## 4. PrintParams JSON

The flat JSON object is fed straight into `BBL::PrintParams`. The full
list of accepted keys (and their types) is the source of truth:
[`tools/plugin_runner/print_params_io.cpp`](print_params_io.cpp) —
`load_print_params_overrides()` walks `PrintParams` field-by-field with
typed setters. Missing keys keep `BBL::PrintParams{}` defaults; unknown
or wrong-typed keys log a `params_warning` event and are ignored.

A ready-to-edit reference covering every field this loader knows
about — including `ams_mapping*` JSON-array-as-string conventions,
default values from a real Studio session, and the `task_*` toggles
that map straight into the MQTT `project_file` payload — lives at
[`tools/plugin_runner/example.params.json`](example.params.json). Copy
it, point `filename` at your local 3mf, drop fields you don't want to
override, and pass the result via `--params-json`.

Minimal experiment that toggles just `task_timelapse_use_internal`:

```json
{
    "filename":                    "/path/to/your-job.gcode.3mf",
    "task_name":                   "obn-runner-test",
    "task_record_timelapse":       true,
    "task_timelapse_use_internal": true,
    "task_bed_type":               "auto"
}
```

`dev_id`, `dev_ip`, `username` (`bblp`), `password` (your
`--access-code`) and `use_ssl_for_mqtt` only fall back to their CLI
values when the JSON leaves them blank — encode them only if you want
to override the wrapper.

Version-gated keys are only accepted when the bridge is built for a new
enough `--abi`; passing one to an older ABI logs a `params_warning` and
skips it: `extruder_cali_manual_mode` (`02.04.00`),
`task_timelapse_use_internal` (`02.05.03`), `svc_context` (`02.07.01`),
`slicer_uid` (`02.08.01`), `queue_plate_id` (`02.08.02`).

## 5. Worked examples

> The examples below use the placeholders `<DEV_ID>` (15-character
> serial from the printer's *Settings → About* screen), `<PRINTER_IP>`
> (LAN IPv4 of the printer), and `<ACCESS_CODE>` (the 8-digit code
> under *Settings → Network → LAN-only mode*). Substitute your own
> values before running anything.

### Auto-download for ABI `02.05.03`

```bash
tools/plugin_runner.sh \
    --abi 02.05.03 \
    --params-json experiment.json \
    --action send_gcode_to_sdcard \
    --gcode-3mf /tmp/job.gcode.3mf \
    --dev-id  <DEV_ID> \
    --dev-ip  <PRINTER_IP> \
    --access-code <ACCESS_CODE> \
    --log-out /tmp/runner.jsonl
```

First call configures + builds `tools/plugin_runner/build-0x020503/`
(~10 s on a cold machine), fetches
`https://public-cdn.bblmw.com/.../linux_02.05.03.63.zip`, and caches
the extracted `.so` under `~/.cache/obn-plugin-runner/02.05.03.63/`.
Subsequent runs against the same ABI start in well under a second.

### Custom `.so` (e.g. an old build you have backed up)

```bash
tools/plugin_runner.sh \
    --abi 02.05.02 \
    --plugin-path ~/.config/BambuStudio/plugins/backup/libbambu_networking.so \
    --params-json experiment.json \
    --action local_print \
    --gcode-3mf /tmp/job.gcode.3mf \
    --dev-id <DEV_ID> --dev-ip <PRINTER_IP> --access-code <ACCESS_CODE>
```

`--plugin-path` skips the CDN; the wrapper still rebuilds the bridge
against `--abi 02.05.02` so the `PrintParams` layout matches the .so.

## 6. Diff workflow with an MQTT sniffer

The point of this tool is wire-level diffs, not "does it print". The
recommended pairing is one terminal sniffing MQTT against the printer
while another runs `plugin_runner.sh`:

Terminal A — subscribe to the printer's MQTT broker. Any MQTT client
with TLS support works; just point it at `mqtts://<PRINTER_IP>:8883`,
authenticate as `bblp` / `<ACCESS_CODE>`, and disable certificate
validation (the printer presents a self-signed cert with its serial as
CN, so chain validation will fail in any client that checks). A few
options:

- **GUI:** [MQTT Explorer](https://mqtt-explorer.com/) — open the app,
  add a connection with `Protocol: mqtts`, `Host: <PRINTER_IP>`,
  `Port: 8883`, `Username: bblp`, `Password: <ACCESS_CODE>`, and under
  *Advanced → Certificate validation* turn off "Validate certificate".
  Topic tree and per-topic diff are very handy for spotting which
  field actually changed between two runs.
- **CLI** (`mosquitto_sub` doesn't talk to a self-signed broker out of
  the box, so bridge the TLS with `socat` first):

  ```bash
  socat -d TCP-LISTEN:18883,bind=127.0.0.1,reuseaddr,fork \
           OPENSSL:<PRINTER_IP>:8883,verify=0,commonname=ignore &
  mosquitto_sub -h 127.0.0.1 -p 18883 \
      -u bblp -P <ACCESS_CODE> -t '#' -v -F '%I  %t  %p' \
    | tee /tmp/mqtt-stock.log
  ```

  Best for scripted diffs since the output is plain text.

Terminal B — run the stock plugin once with your override:

```bash
tools/plugin_runner.sh --abi 02.05.03 \
    --params-json experiment.json \
    --action send_gcode_to_sdcard --gcode-3mf job.gcode.3mf \
    --dev-id <DEV_ID> --dev-ip <PRINTER_IP> --access-code <ACCESS_CODE>
```

Then re-run the same job using our build in place of the stock plugin
and `diff` the captures. Anything that differs in the `project_file`
publish is something the override / `experiment.json` actually
changed; anything else is a wire bug in our plugin to investigate.

## 7. Operational notes

- `plugin_runner` writes one JSON line per plugin event (`local_message`,
  `update_status`, `local_connect`, …) to stdout; copy with `--log-out`.
- The bridge spawns no threads itself — every callback invocation
  happens on whichever worker thread the plugin called us back on.
  `set_queue_on_main_fn` is wired to inline-execute, which is fine for
  this LAN-only scope but would deadlock under a real UI loop.
- Cloud printing (`bambu_network_start_print`) is `--action cloud_print`.
  It needs `--user-info` for the bambu-cloud auth dance, and still needs
  `--dev-id`/`--dev-ip`/`--access-code`/`--cert-file`: the stock plugin
  gates its send stage on the device certificate and answers `-3140`
  `ENC_FLAG_NOT_READY` without a live LAN session. Unlike the LAN
  actions it uploads to S3 and dispatches via `POST /my/task` with
  `mode=cloud_file`, so the printer starts downloading on its own —
  pair it with `--auto-stop`.
- A `--timeout` exceeded run returns exit code `75` (`EX_TEMPFAIL`); a
  finished-but-failed action returns `1`; a clean success returns `0`.

## 7. Connect timing (`--connect-settle-ms`) and `-4030`

`connect_printer` is **asynchronous**: it returns `rc=0` immediately
and the actual TLS handshake + first MQTT subscribe happens on a
worker thread several seconds later (typically 5–6 s on a quiet
network). The `set_on_local_connect_fn` callback firing with
`status=ConnectStatusOk` is the **only** reliable signal that the LAN
publish channel is ready. Publishing earlier deterministically returns
`-4` (paho's `MQTTASYNC_DISCONNECTED`); the print actions surface that
as `update_status code=-4030 msg="send msg failed"` at the *Sending*
stage.

`plugin_runner` waits for that callback automatically and only then
proceeds. `--connect-settle-ms` is a *cap* on that wait, not a fixed
sleep — bump it (e.g. `--connect-settle-ms 20000`) only if your
printer is slow to handshake, otherwise the default 800 ms is fine
once the wait turns into an event-driven block. The matching log
event is `session_ready {got: true|false, cap_ms: N}` followed by a
`kickstart_pushall` (verbatim copy of Studio's
`MachineObject::command_request_push_all` payload, used both to mimic
Studio's `keep_alive` loop and as a smoke test for the publish
channel).

If your action still fails with `-4030` *after* `kickstart_pushall
rc=0`, the publish channel was healthy at action time — the failure
is happening **inside the plugin's print state machine**, not in the
MQTT layer. Use `--action send_raw` (§10) to bisect which payload the
printer actually rejects.

## 8. Raw publish (`--action send_raw`)

Direct call into `bambu_network_send_message_to_printer` with a
verbatim JSON file. Useful for replicating Studio's exact pre-print
command sequence, probing what the printer accepts, or stress-testing
the LAN MQTT session.

```bash
# pushall-as-a-keepalive: mimics Studio's MachineObject::command_request_push_all
echo '{"pushing":{"sequence_id":"0","command":"pushall","version":1,"push_target":1}}' \
    > /tmp/pushall.json

tools/plugin_runner.sh --abi 02.05.03 \
    --action send_raw --raw-json /tmp/pushall.json \
    --raw-repeat 6 --raw-repeat-interval-s 5 --raw-settle 2 \
    --dev-id <DEV_ID> --dev-ip <PRINTER_IP> --access-code <ACCESS_CODE> \
    --connect-settle-ms 15000 --fast-exit \
    --log-out /tmp/runner-raw.jsonl
```

Watch the `send_raw_rc` events: `rc=0` means the publish hit the wire
(the printer's reply, if any, lands as a `local_message`); `rc=-4`
means the LAN MQTT session is not actually up yet — increase
`--connect-settle-ms` or check certs. `--raw-repeat` plus a few-second
interval is the easiest way to confirm the session stays alive over
the lifetime of an action (e.g. across an FTPS upload).

## 9. Diagnostics: `--action none`

Use this to sanity-check the init/connect path without actually printing:

```bash
tools/plugin_runner.sh --abi 02.05.03 \
    --action none --timeout 6 \
    --dev-id <DEV_ID> --dev-ip <PRINTER_IP> --access-code <ACCESS_CODE> \
    --log-out /tmp/runner-diag.jsonl
```

A healthy run looks like (event _kinds_ in order):
`startup → plugin_loaded → data_dir → cert_resolved →
extra_http_header → agent_start (rc=0) → post_start_init →
change_user_clear (rc=0) → ssdp_msg → bind_detect →
connect_printer_call (rc=0) → local_connect (status=0) →
session_ready (got=true) → start_subscribe → kickstart_pushall (rc=0)
→ idle_done → shutdown`.

Things to watch for:

- `local_connect status=1` means the plugin's MQTT client failed to
  connect (printer rejected, TLS error, busy session). The most
  common cause is a missing `slicer_base64.cer` — the runner searches
  `$HOME/.config/BambuStudio/cert/`, `$HOME/BambuStudio/resources/cert/`
  and `/usr/share/BambuStudio/resources/cert/`; pass `--cert-file PATH`
  if yours lives elsewhere.
- `session_ready got=false` means the cap fired before the
  `local_connect` callback. Bump `--connect-settle-ms`.
- `kickstart_pushall rc!=0` after `session_ready got=true` is
  pathological — the publish channel reports ready but rejects the
  first message. Re-check the cert and that no other LAN client is
  holding the access code session.
- `agent_start` taking ~10 s on a cold cache is normal: the plugin
  initialises bambu-cloud TLS material even on the LAN-only path.
  Subsequent runs in the same process group are a few hundred ms.
- A missing `local_connect` event entirely after `connect_printer_call`
  generally means the plugin was loaded but never spun up its worker —
  most often because `set_on_local_connect_fn` was wired against the
  wrong typedef. Cross-check the typedefs in
  [`plugin_loader.hpp`](plugin_loader.hpp) against the
  `tools/abi_snapshot/v<MM.mm.pp>/NetworkAgent.hpp` snapshot for the
  ABI you're targeting.
