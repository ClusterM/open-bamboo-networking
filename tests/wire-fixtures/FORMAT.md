# Wire-fixture format (`obn-wire-flow/v1`)

Golden, ordered traces of what the **genuine** Bambu network plugin puts on the wire for a
given UI flow, observed from BambuStudio. They are the contract the OSS library must reproduce.

A future OSS change is "safe" if, replaying the same flow, it emits the **same ordered
sequence** of messages with matching method / path / query-shape / header set+order / body
shape (after substituting the per-run variables). Anything else is a regression to review.

## Directory layout

```
<os>/<network_plugin_version>/<channel>/<printer_model>/<flow>/flow.json
```
- `os`            — `linux` | `windows` | `macos` (identity + paths differ per OS)
- `network_plugin_version` — the `bambu_network_agent/<ver>` on the wire (e.g. `02.07.00.50`)
- `channel`       — how the job reaches the printer (device flows differ per channel):
    - `cloud`     — cloud delivery (`mode=cloud_file`); printer NOT LAN-reachable. Also the
                    channel for account/user flows (login, presets, filament) — all cloud-only.
    - `cloud_lan` — cloud-bound printer, LAN delivery (`mode=lan_file`); the full cloud
                    project/task record is still created (what the two captured traces below use for lan)
    - `lan`       — pure LAN-only (no cloud account / unbound); skips the api.bambulab.com
                    pipeline entirely — a different, much shorter flow (not yet captured)
- `printer_model` — `h2s`, `h2d`, `a1`, … for device flows; **`account`** for account/user
                    flows that aren't tied to a printer (`login`, `preset_sync`, `preset_write`,
                    `filament_manager`, `refresh`, …).
- `flow`          — `start_print`, `login`, `refresh`, `preset_sync`, `bind`, …

Same flow across OS / version / model / channel = a new leaf. Diffing two leaves shows
exactly which fields an implementation must vary (e.g. `mode`, `bedType`, OS headers).

## `flow.json` schema

```jsonc
{
  "schema": "obn-wire-flow/v1",
  "meta": { os, network_plugin_version, slicer_client_version, channel, printer_model,
            flow, source },

  // The fixed X-BBL identity block every api.bambulab.com request carries, in JA4H order.
  // Cloudflare fingerprints the SET + ORDER; the harness asserts both. Values marked
  // <dynamic:*> vary per session/request and are matched by kind, not literal.
  "identity_block": { order: [...header names...], values: { name: literal | "<dynamic:kind>" } },

  // Variables that flow through the trace. kind:
  //   input        - supplied by the caller (job name, plate index)
  //   session      - from the authenticated session (access_token, user_id, device_id)
  //   from_response- captured from an earlier step's response (json path)
  //   generated    - per-request (client-id hex suffix, timestamps, presigned urls)
  "vars": { name: { kind, ...locator, example } },

  // Ordered steps. protocol lets the same format carry mqtt/ssdp later.
  "steps": [
    {
      seq, id, protocol: "http"|"mqtt"|"ssdp", channel_only?: "lan"|"cloud",
      request: {
        method, host, path,
        query: null | { param: value|"{{var}}" },
        // header presence flags relative to identity_block:
        headers: { block:true, client_id:bool, content_type:bool, authorization:bool,
                   extra?: {name:value} },
        body_json?: { ...with "{{var}}" placeholders... },   // structural match, key order irrelevant
        body_raw?: "..."                                     // for non-JSON bodies
      },
      expect: { status: 200 },
      captures?: { var: "$.json.path" }   // seed vars for later steps
    }
  ]
}
```

### Matching rules (what the harness asserts)
1. **Order** — steps observed in `seq` order (barring documented retries/polls, marked `repeatable:true`).
2. **method + host + path** — exact (path with `{{var}}` segments substituted).
3. **query** — same key set; values literal or `{{var}}`-matched.
4. **headers** — the `identity_block` names present in the given order; `client_id` /
   `content_type` / `authorization` presence matches the flags. Non-identity extras (e.g.
   `x-bbl-app-certification-id`, `user-id`) matched explicitly.
5. **body** — JSON structural match: same keys, literal values equal, `{{var}}` present and
   type-correct. Key **order is not asserted** for bodies (servers don't care); it **is** for headers.
6. **expect.status** — the genuine response status (usually 200).

Steps with `channel_only` appear only for that channel (e.g. the `ftp://`-placeholder PATCH
and `GET /my/setting` are `lan`-only). `protocol:"mqtt"|"ssdp"` steps are placeholders for the
transports we haven't captured yet — schema is ready; fill from a broker/multicast capture.

Not every genuine call is on api.bambulab.com: the actual 3mf uploads are `PUT`s to
short-lived S3 presigned URLs (host varies), marked `host:"<presigned>"`; the api.bambulab.com observation (scoped to
api.bambulab.com) doesn't see their bodies, but they are part of the flow and the OSS emits them.

## Harness

Implemented in **`tests/wire_compliance_test.cpp`** (C++, no external deps). It embeds a
minimal HTTP mock of api.bambulab.com on a thread, points the OSS config at it
(`cloud_global_api_host`), seeds a session (`Agent::set_config_dir` + `apply_login_info`),
drives the matching OSS entry point for `meta.flow`, records every request the OSS emits, and
asserts them against `steps[]` per the rules above (reports the first divergence).

CMake registers one ctest per fixture (`wire_<os>_<ver>_<channel>_<model>_<flow>`). Flows
without a driver yet exit 77 → ctest **Skipped**. Run:

```
cmake -S . -B build -DOBN_BUILD_TESTS=ON -DOBN_VERSION=02.07.00.99
cmake --build build --target wire_compliance_test
ctest --test-dir build -R wire_ --output-on-failure
```

Drivers exist for `login`, `preset_sync`, `preset_write`, `filament_manager`, and `start_print`.
MQTT/SSDP assertion needs a mock broker / multicast responder (the schema already carries those steps).

### `start_print` specifics

A `start_print` fixture carries two extra pieces:
- a top-level **`driver`** block — the `BBL::PrintParams` inputs the harness feeds
  `run_cloud_print_job` (dev_id, ams_mapping / ams_mapping2 / ams_mapping_info, nozzles_info,
  bed type, cali flags, and `asset`/`config_asset` paths for the two 3mf uploads, resolved
  relative to the fixture dir). The genuine sliced 3mf lives under the leaf's `assets/`.
- **`"body_builder": true`** on the `create_task` step — the harness asserts that step's body via
  `obn::cloud_print::test_build_task_body(..., use_lan_channel = channel=="cloud_lan")` instead of
  the recorded HTTP body. This checks `mode` (`lan_file`/`cloud_file`) and the full
  amsMapping/amsMapping2/amsDetailMapping/nozzleInfos exactly.

For a **`cloud`** (pure cloud_file) fixture the HTTP pipeline is driven in cloud mode
(`use_lan_channel=false`) — no printer needed — and the `lan_file` create_task body is asserted
via `test_build_task_body`.

For a **`cloud_lan`** fixture the harness runs the *full* `lan_file` pipeline
(`use_lan_channel=true`) end-to-end against two extra in-process mocks in `tests/lan_mocks.hpp`,
both modelled on a real H2D's captured behaviour:
- `FtpsMock` — an implicit-FTPS server (vsFTPd-style: `220`/`USER`→`331`/`PASS`→`230`/`PBSZ`→`200`/
  `PROT P`→`200`/`PASV`→`227`/`STOR`→`150`→`226`, TLS control + TLS data channel). The harness
  asserts the printer received a `STOR` of the print-ready 3mf whose md5 equals the fixture's
  `ftp_file_md5` (i.e. the whole sliced file, byte-for-byte).
- `MqttBrokerMock` — a minimal MQTT 3.1.1 broker. The harness asserts the OSS published a
  `project_file` command to `device/<serial>/request` carrying the cleartext local fetch url
  (`ftp://<name>`). The LAN channel does NOT encrypt the url — `url_enc` is the cloud-channel path.
A self-signed cert seeds the printer's RSA pubkey (used by the cloud channel) and
`lan_tls_skip_verify=1` lets the OSS accept the mocks' cert. The FTP/MQTT ports
are redirected to the loopback mocks via the test-only `OBN_LAN_FTP_PORT` / `OBN_LAN_MQTT_PORT`
env seams (the OSS otherwise hardcodes the printer's 990/8883). The final publish is
fire-and-forget, so no printer response is needed.

This already paid off: it caught the OSS filament `list`/`config` GETs dropping `Content-Type`
(the stock plugin keeps it) — now fixed in `cloud_filament.cpp`.
