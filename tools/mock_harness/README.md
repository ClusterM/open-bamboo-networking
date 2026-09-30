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

*(OQ2/OQ3 spike lines land below in Task 2; `## Gap analysis` lands in Task 3.)*

## Gap analysis

*(planned in 04-01 Task 3 — both critical gaps against our connect path, with the
license constraint and the D-01/D-02 planned treatments.)*
