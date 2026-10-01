# openbu-mock harness (`tools/mock_harness/`)

Hardware-free integration harness for TEST-01: run **openbu-mock as an external
binary** (never vendored — no LICENSE upstream), drive
`tools/plugin_runner --action none` against it, and assert the
detect→connect→pushall event chain. This plan (04-01) establishes the fetch/build
spike, the environment record, and the gap analysis; later plans add the clean-room
sidecar and the single CI-able command.

## Usage

*(planned in 04-03: `run_harness.sh` — one documented command with a real exit
code; no GitHub workflow is added by this phase, `build.yml` stays untouched.)*

## Environment & spikes

Recorded 2026-09-30 (plan 04-01 Task 1), host = Windows + WSL Ubuntu, all
commands from the workspace root.

- **WSL deps:** `wsl -d Ubuntu -- bash -c 'command -v cmake ninja g++ pkg-config python3 git'`
  → all found **after** the one-time README §1 apt install
  (`build-essential cmake ninja-build pkg-config libcurl4-openssl-dev libminizip-dev nlohmann-json3-dev`),
  run as root via `wsl -u root` (user sudo requires a password). Asserts:
  `pkg-config --exists openssl` rc=0, `pkg-config --exists libcurl minizip` rc=0,
  `dpkg -s nlohmann-json3-dev` rc=0. `jq` deliberately **not** installed —
  `python3` is this project's JSON tool (research Standard Stack).
- **Docker:** client 29.8.0 present, daemon was stopped → started via
  `powershell.exe -Command "Start-Process 'C:\Program Files\Docker\Docker\Docker Desktop.exe'"`;
  `docker info` healthy after ~5 s. The WSL distro has **no native `docker`**
  (Docker Desktop WSL integration is off for Ubuntu) and the Windows daemon
  cannot mount `/mnt/...` drvfs paths, so `fetch_mock.sh` falls back to
  `docker.exe` (interop) with `/mnt/<drive>/…` → `<Drive>:/…` path translation.
- **BUILD_PATH: docker-golang** (D-04 preferred path; local-Go fallback never fired)
- **Pin:** `MOCK_PIN` = `e3db0ce7341f467e656cc860f1a0625c548a8f56` (openbu-mock
  `master` at research time; hard-asserted in `fetch_mock.sh` — drift is recorded,
  the pin is never auto-bumped).
  `git -C .cache/openbu-mock/src rev-parse HEAD` raw output:

  ```text
  e3db0ce7341f467e656cc860f1a0625c548a8f56
  ```

- **Build:** `golang:1.22` image, `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`,
  `go build -trimpath -ldflags="-s -w" -o /out/openbu-mock .` (mirrors upstream
  `build.sh`) → `.cache/openbu-mock/out/openbu-mock`, 4735128 bytes,
  `test -x` rc=0. Re-running `fetch_mock.sh` skips fetch+build (idempotent).
- **Native run (D-07 venue):** from `.cache/openbu-mock/run/` (cwd so
  `ca.pem`/`ca-key.pem` land in the gitignored run dir):
  `../out/openbu-mock -model P1S -access-code 12345678 -count 1 -debug > mock.log 2>&1 &`
  (D-05: single printer, minimal flags). Parsed identity →
  `.cache/openbu-mock/run/identity.env` (public fields only — no CA key material):

  ```text
  IP=192.168.2.177
  SERIAL=01P6953E514809E
  MODEL=P1S
  NAME=3DP-01P-09E
  CODE=12345678
  ```

- **TLS readiness:** `timeout 15 openssl s_client -connect 192.168.2.177:8883 -showcerts </dev/null`
  → `run/tls_dump.txt` contains issuer `CN=Virtual Printer CA` (6 matches), rc=0.
- **SSDP readiness:** `ss -ulnp | grep ':2021'` →
  `UNCONN 0 0 0.0.0.0:2021 0.0.0.0:* users:(("openbu-mock",pid=379,fd=3))`;
  `run/mock.log` has **zero** `SSDP: failed to listen` lines. Mock killed after
  each task (each task owns its processes).

OQ4 resolved: native WSL run of the built linux-amd64 binary; Docker used as compiler only (mock binds its detected IP - openbu-mock network.go:12-18, container -p mapping breaks it; research Alternatives table)

### OQ1 TLS-trust spike — plan 04-03 Task 1 (2026-10-01)

Driver: gitignored `.cache/openbu-mock/oq1_driver.sh` — mock started first
(the recorded OQ2 order) from `.cache/openbu-mock/run/` (fresh identity
parsed into `identity.env`), clean-room sidecar with the `identity.env`
serial/name and the OQ5 defaults, `openssl s_client -showcerts` dump of the
served chain, then `tools/plugin_runner.sh --abi 02.08.01 --action none
--timeout 6 --connect-settle-ms 15000 --cert-file … --log-out …`. Four
recorded attempts, one trust-anchor variant each:

| attempt | `slicer_base64.cer` content | `--cert-file` arg | `local_connect` |
| --- | --- | --- | --- |
| A — `spike-oq1.jsonl` | PEM copy of `ca.pem` | relative `.cache/openbu-mock/run/slicer_base64.cer` | `"status":1` |
| B — `spike-oq1-b.jsonl` | base64-DER re-encode (`openssl x509 -outform der \| base64 -w0`) | relative | `"status":1` |
| C — `spike-oq1-c.jsonl` | base64-DER (as B) | absolute path | `"status":1` |
| D — `spike-oq1-d.jsonl` | raw DER | relative | `"status":1` |

Every attempt: sidecar logged `detect: served id=…`, `bind_detect` returned
`rc:0 / result_msg:success`, `cert_resolved` fired
(`"filename":"slicer_base64.cer"`), `connect_printer_call rc:0` — then the
plugin aborted the MQTT/TLS handshake. Verbatim evidence (attempt A / B):

```text
{"_kind":"bind_detect","_t":"2026-10-01T00:15:34.227949Z","bind_state":"free","command":"detect","connect_type":"lan","dev_id":"01P953009C0D43A","dev_name":"3DP-01P-43A","model_id":"C12","rc":0,"result_msg":"success","version":"01.09.01.00"}
{"_kind":"local_connect","_t":"2026-10-01T00:15:34.434602Z","dev_id":"01P953009C0D43A","msg":"-1","status":1}
{"_kind":"local_connect","_t":"2026-10-01T00:18:01.978923Z","dev_id":"01P5136BA5239D1","msg":"-1","status":1}
mock -debug (run A): MQTT [192.168.2.177:22998]: TLS handshake failed: EOF
mock -debug (run A): MQTT [192.168.2.177:22998]: no additional bytes available after handshake failure (client closed connection)
openssl s_client -connect <IP>:8883 -CAfile ca.pem -verify_return_error: Verification: OK  (rc=0 — the same chain verifies with the same CA)
```

The mock's server-side first read of the handshake returns EOF (the stock
client closes before sending a ClientHello) in all four variants, so this is
a client-side abort during local SSL setup/verify, not a wire-level
mismatch; no OpenSSL verify text exists to paste — the plugin's own log is
encrypted (main.cpp:797-801). Run logs: `.cache/openbu-mock/run/
spike-oq1{,-b,-c,-d}.{jsonl,out,err}`, `mock-oq1.log`, `verify-oq1.txt`,
`tls_dump-oq1.txt`, `oq1-spike-summary.txt` (all gitignored).

OQ1 BLOCKED: local_connect {"_kind":"local_connect","_t":"2026-10-01T00:15:34.434602Z","dev_id":"01P953009C0D43A","msg":"-1","status":1} (attempt A, PEM ca.pem copy) and {"_kind":"local_connect","_t":"2026-10-01T00:18:01.978923Z","dev_id":"01P5136BA5239D1","msg":"-1","status":1} (attempt B, base64-DER re-encode), attempts C/D identical; mock -debug verbatim "TLS handshake failed: EOF" + "no additional bytes available after handshake failure (client closed connection)" (stock closed before ClientHello; plugin log encrypted so no OpenSSL verify text exists); openssl -CAfile ca.pem -verify_return_error on the same served chain: Verification: OK - stock rejected the mock CA in both formats; no mock-side patch without user sign-off (D-04/D-05 do not cover it)

### Spikes — Task 2, both SSDP startup orders (2026-09-30)

Driver: gitignored `.cache/openbu-mock/spike_driver.sh`; artifacts in
`.cache/openbu-mock/run/`. The connect chain is **evidence only** in this plan —
it is never judged pass/fail here (the `:3000` sidecar does not exist until
04-02, so `bind_detect` is expected to fail).

**Order A — mock first.** Mock started from `identity.env` exactly as in Task 1
(`../out/openbu-mock -model P1S -access-code 12345678 -count 1 -debug`), then
from the repo root:

```text
tools/plugin_runner.sh --abi 02.08.01 --action none --timeout 6 \
    --dev-id 01P142E6C031BC9 --dev-ip 192.168.2.177 --access-code 12345678 \
    --connect-settle-ms 15000 --log-out .cache/openbu-mock/run/spike-orderA.jsonl
```

stderr captured to `spike-orderA.err`; runner rc=0. Cold-run stderr is
preserved verbatim in `spike-orderA.cold.err` (the recorded spike was re-run
once after the identity-parser fix below; the warm re-run logs
`cache hit: …/02.08.01.53/libbambu_networking.so`). Cold run evidence (A5):

- per-ABI bridge build: `configuring plugin_runner under ABI=0x020801
  (.../tools/plugin_runner/build-0x020801)` → final `[2/2] Linking CXX
  executable plugin_runner` (hex build dir `tools/plugin_runner/build-0x020801`)
- CDN plugin-zip fetch: `plugin_runner.sh: downloading plugin for
  ABI=02.08.01 from api.bambulab.com...` → `plugin_runner.sh: downloaded plugin
  version=02.08.01.53 -> /home/santiago/.cache/obn-plugin-runner/02.08.01.53/libbambu_networking.so`
  (**no `could not resolve a plugin for ABI` — 02.08.01 resolved, the README-blessed
  02.05.03 fallback was never needed**)
- `spike-orderA.jsonl` (27 lines): `plugin_loaded` present (version 02.08.01.53),
  `agent_start` rc=0, `ssdp_msg` present (5 events), and

```text
bind_detect rc=-2 result_msg=publish login request failed
```

  verbatim (Gap-1 runtime evidence: nothing listens on `:3000` yet — research
  08.06:126). `kickstart_pushall rc=-4` (no local session without sidecar/cert —
  expected here).

OQ3 resolved: --abi 02.08.01 (hex build dir tools/plugin_runner/build-0x020801; CDN zip resolved first try — plugin version=02.08.01.53 from api.bambulab.com, fallback 02.05.03 not needed)

**Order B — runner first.** Runner started in the background with the identity
parsed from the Order-A run (serial/IP are regenerated on every mock start —
`identity.env` always reflects the most recent mock run, nothing is hardcoded),
waited for `agent_start`, then:

- `ss -ulnp | grep ':2021'` while the plugin is up alone →
  `UNCONN 0 0 0.0.0.0:2021 0.0.0.0:* users:(("plugin_runner",pid=462,fd=5))`
  (artifact `ssdp-orderB-plugin-up.txt`)
- mock then started → **survived**: `mock-orderB.log` contains zero
  `SSDP: failed to listen` (it would `log.Fatalf` there, ssdp.go:24-26), and
  after start `ss` shows **both** listeners simultaneously:
  `users:(("openbu-mock",pid=514,fd=3))` + `users:(("plugin_runner",pid=462,fd=5))`
  on `0.0.0.0:2021` (artifact `ssdp-orderB-after-mock.txt`)
- `spike-orderB.jsonl` (27 lines): `plugin_loaded` present, `agent_start` rc=0,
  `bind_detect rc=-2`, `ssdp_msg` ×5 — same chain shape as Order A; runner rc=0
- Order-B mock output goes to `mock-orderB.log` (kept separate so Task 1's
  readiness `mock.log` evidence is never overwritten)

OQ2 resolved: coexistence OK in both startup orders (ssdp_msg present in both orders; mock survived the runner-first bind with zero `SSDP: failed to listen`; both UDP :2021 listeners visible simultaneously — SO_REUSEADDR held, no Pitfall-2 cascade)

**Spike environment fixes (deviations, recorded):** the first bridge builds
failed on missing `libssl-dev` (`Could NOT find OpenSSL`) and missing `zlib.h`
(minizip header dep) — both installed from Ubuntu repos (`apt-get install
libssl-dev zlib1g-dev`), the stale half-configured `build-0x020801` was removed,
and the build then completed. `tools/plugin_runner.sh` in the working tree was
LF-normalized (autocrlf had left a CRLF shebang → `/usr/bin/env: 'bash\r':
No such file or directory`); `.gitattributes` now pins `eol=lf` for
`tools/plugin_runner.sh` and `tools/mock_harness/*.sh` so this cannot regress.
The spike driver's first version transposed SERIAL/MODEL while parsing the
mock's stdout table (the runner was invoked with `--dev-id P1S`); both orders
were **re-run after the fix** with the true runtime-parsed serial
(`01P142E6C031BC9`) — identical results (agent_start rc=0, bind_detect rc=-2,
ssdp_msg ×5, dual `:2021` coexistence), cold stderr kept as
`spike-orderA.cold.err` / `spike-orderB.cold.err`.


## Gap analysis

> **License constraint (read first).** openbu-mock has **no LICENSE** upstream
> (`"license": null`, GitHub API, 2026-09-30) — per INTERESTING_REPOS.md's
> license rule, unlicensed repos are **facts-only**. Consequences: this harness
> uses the mock as an **external binary only**; no openbu-mock source, patch
> diff, or derived code enters our trees; the clone and the generated
> `ca.pem`/`ca-key.pem` live only in the gitignored `.cache/openbu-mock/`
> (covered by subrepo `.gitignore` lines `.cache/` and `*.pem`); nothing from
> the clone is ever `git add -f`ed (REQUIREMENTS.md Out of Scope: vendoring
> unlicensed code; INTERESTING_REPOS.md line 6; research Pitfall 9).

OQ7 resolved: gap-analysis home = tools/mock_harness/README.md (lives beside the run evidence; INTERESTING_REPOS.md §4 cross-link deferred to Phase 5 EXT-01)

Source: INTERESTING_REPOS.md §4 (openbu-mock gap list). All source facts below
were read at pin `e3db0ce7341f467e656cc860f1a0625c548a8f56` (the `MOCK_PIN`
in `fetch_mock.sh`) — read-only, never copied.

### Gap 1 — no `:3000` login/detect responder

**Source-at-pin evidence:** there is no `:3000` listener anywhere in
openbu-mock — MQTT binds `p.IP:8883` (mqtt.go:197), SSDP binds
`239.255.255.250:2021` (ssdp.go:12-26), and the service startup table
(main.go:286-293) starts only those listeners. There is no TCP-3000 code at
all, so a sidecar on `:3000` can never conflict with the mock.

Probe (harness run): IP=192.168.2.177 2026-09-30T23:29:37Z (mock running as the :8883 control)

```text
$ timeout 2 bash -c '</dev/tcp/192.168.2.177/3000'
bash: connect: Connection refused
bash: line 1: /dev/tcp/192.168.2.177/3000: Connection refused
rc3000=1            <-- non-zero: nothing answers on :3000

$ timeout 2 bash -c '</dev/tcp/192.168.2.177/8883'
rc8883=0            <-- success: the mock's MQTT/TLS listener answers
```

**Impact on our connect path:**

- with nothing listening, stock gives up after ~9 s returning `-2` with
  `result_msg = "publish login request failed"`
  (research/08.06-bind.md:126); this plan's spikes captured exactly that,
  verbatim: `bind_detect rc=-2 result_msg=publish login request failed`
- our own client hard-fails on an empty `id`:
  `if (out.dev_id.empty()) { … return BAMBU_NETWORK_ERR_BIND_PARSE_LOGIN_REPORT_FAILED; }`
  (src/lan_bind_tcp.cpp:335-339)
- a conforming reply must satisfy the §8.6.2 field map
  (research/08.06-bind.md:113): `command`, `id`, `model`, `name`, `version`,
  `bind`, `connect` — the request frame is
  `{"login":{"command":"detect","sequence_id":"20000"}}` (A5 A5 … A7 A7 framing)
- a `login_report` FAILURE is the documented refusal variant for completeness
  (research/08.06-bind.md:115, OBN #38) — the harness never sends it
- the plugin gates the MQTT path on `bind_state`/`connect_type`
  (plugin_loader.hpp:239-243), so the sidecar's reply values decide whether
  LAN MQTT is even attempted (exact values are OQ5, locked in 04-02/04-03)

**planned treatment (D-01):** a clean-room detect sidecar authored in
`tools/mock_harness/` from the §8.6.2 facts above plus our own
`obn::lan_bind_tcp` codec (`encode_frame` / `drain_frames`) only — **zero bytes
read from openbu-mock** (facts-only license posture; no port conflict: the mock
has no `:3000` code at all).

Gap 1 decision: CLOSED (clean-room sidecar, D-01) - proven against the REAL
stock client on 2026-09-30 (plan 04-02 Task 1). Build:
`tools/mock_harness/build_responder.sh` →
`.cache/mock_harness/build-responder/detect_responder`; run: sidecar started
with the `identity.env` serial/name beside
`tools/plugin_runner.sh --abi 02.08.01 --action bind_detect --log-out .cache/openbu-mock/run/gap1_bind_detect.jsonl`.
Run evidence, verbatim from that JSONL:

```text
{"_kind":"bind_detect","_t":"2026-09-30T23:58:26.120022Z","bind_state":"free","command":"detect","connect_type":"lan","dev_id":"01P142E6C031BC9","dev_name":"3DP-01P-BC9","elapsed_ms":1008,"model_id":"C12","rc":0,"result_msg":"success","version":"01.09.01.00"}
```

The invocation's raw exit code was `rc=0` (the `bind_detect` action exits 0
iff `rc==0`, main.cpp:1458-1462), and the sidecar stdout
(`.cache/openbu-mock/run/detect.log`) shows it served the request:

```text
detect: served id=01P142E6C031BC9
```

(`dev_id` is the runtime-parsed `identity.env` `SERIAL` — nothing hardcoded.)

### Gap 2 — `sequence_id` echo for arbitrary commands

Evidence table pinned to `e3db0ce7341f467e656cc860f1a0625c548a8f56` (read from
source; no code reused):

| Command our chain publishes | Mock behavior at the pin | Reply carries request `sequence_id`? |
| --- | --- | --- |
| `pushing:pushall` (kickstart) | answered with `push_status`, but it carries `static "sequence_id":"0"` (state.go:291 via mqtt.go:482-491) | **No** |
| `info:get_version` (kickstart) | echoes the request value (state.go:699 via mqtt.go:493-514) | **Yes** — the one command that echoes |
| `system:get_access_code`, `security:app_cert_install` | fall through to the `unhandled command keys` log with **no reply** (mqtt.go:516-531) | **No reply at all** |
| QoS 1 PUBACK for all of the above | sent before topic dispatch (mqtt.go:456 area) | n/a — transport ack only |

Why the chain is expected to pass **without** a sequence-echo patch (the
evidence D-02 records):

1. the runner never matches responses — verbatim kickstart comment:
   *"…uniqueness only matters for response matching, which we don't do."*
   (tools/plugin_runner/main.cpp:1263-1266)
2. the chain gates are transport/session-level only (README §9 golden stream) —
   **D-08's ordered event chain is the pass contract** for this phase
3. the mock proactively publishes `push_status` on subscribe and every 5 s
   (mqtt.go:356-372), so keep-alive needs no echo
4. residual risk: a stock-internal wait on an unanswered command could stall
   something the chain surfaces as a timing anomaly — exactly what the
   recorded harness run must observe (D-03)

**planned treatment (D-02):** documented-first; escalate to a patch **only**
inside a gitignored local clone (never committed anywhere) on the OQ6 trigger
that 04-02 defines, with the upstream permission request opened in parallel.
The recorded run in 04-03 (D-08 chain) is the deciding evidence.

Gap 2 decision: DOCUMENTED (D-02) - final confirmation lands with 04-03's recorded detect->connect->pushall run

OQ6 trigger: the harness proves sequence-echo blocks detect->connect->pushall IFF (a) any D-08 chain element fails in a recorded run AND (b) the mock's -debug log shows 'unhandled command keys' for a command that failing element depends on (pushing:pushall | info:get_version | system:get_access_code | security:app_cert_install)

This is research OQ6's proposed criterion, stated here as the planner's
resolution so the documented-vs-patch decision in 04-03 is mechanical. The
escalation procedure if the trigger fires: any patch lives **only** inside the
gitignored `.cache/openbu-mock/src` clone; only its observed **behavior**
(never a diff or source) is recorded in our docs; an upstream
**permission request** is opened in parallel; nothing from the clone is ever
committed (D-02 verbatim constraints). Documented-first is the default today because
the source-at-pin evidence table above plus the runner's own comment that
response matching is not done (main.cpp:1263-1266, *"…uniqueness only matters
for response matching, which we don't do."*) make blocking unlikely — the
passing/failing 04-03 run is the deciding evidence per D-03.

OQ5 provisional: detect reply values bind=free, connect=lan, model=C12, name=<NAME from identity.env>, version=01.09.01.00, dev_cap=1, sequence_id=20000 (JSON number) - flagged assumption, resolution step: 04-03 locks them on the first bind_detect rc=0 + local_connect status=0 pair

Clean-room attestation: detect_responder.cpp derives solely from research/08.06-bind.md 8.6.2 and our obn::lan_bind_tcp/obn::json code - zero bytes read from openbu-mock (D-01)

### Out-of-scope mock gaps (documented, not worked)

FTPS/`990`, print-job/`project_file` flow, signing, strict single SUBSCRIBE
topic, and multi-printer `-count` support remain out of scope (CONTEXT Deferred
ideas) — recorded here so the gap census is complete.

