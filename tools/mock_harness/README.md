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
    --dev-id 01P533A160381E4 --dev-ip 192.168.2.177 --access-code 12345678 \
    --connect-settle-ms 15000 --log-out .cache/openbu-mock/run/spike-orderA.jsonl
```

stderr captured to `spike-orderA.err`; runner rc=0. Cold run evidence (A5):

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
  `UNCONN 0 0 0.0.0.0:2021 0.0.0.0:* users:(("plugin_runner",pid=649,fd=5))`
  (artifact `ssdp-orderB-plugin-up.txt`)
- mock then started → **survived**: `mock-orderB.log` contains zero
  `SSDP: failed to listen` (it would `log.Fatalf` there, ssdp.go:24-26), and
  after start `ss` shows **both** listeners simultaneously:
  `users:(("openbu-mock",pid=698,fd=3))` + `users:(("plugin_runner",pid=649,fd=5))`
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

*(OQ7 `## Gap analysis` lands below in Task 3.)*

## Gap analysis

*(planned in 04-01 Task 3 — both critical gaps against our connect path, with the
license constraint and the D-01/D-02 planned treatments.)*
