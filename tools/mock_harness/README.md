# openbu-mock harness (`tools/mock_harness/`)

Hardware-free regression net for our LAN connect path: run **openbu-mock as
an external binary** (never vendored — no LICENSE upstream), drive
`tools/plugin_runner --action none` against it with **our own build of
`libbambu_networking`**, and assert the ordered detect→connect→pushall event
chain.

## What this is, and what it is not

openbu-mock implements: SSDP discovery, MQTT over TLS on `:8883` with a real
`bblp` + access-code check, a status report, a camera stream on `:6000`, and
three commands (`pushall`, `get_version`, `ledctrl`). There is no FTPS, so no
upload and no printing; no `:3000` responder (that is our clean-room
sidecar); no cloud, no signing, no security flow, no `project_file`.

So this is a regression net for **our own handshake path** — discovery,
detect, TLS, auth, subscribe, publish — and nothing more. It is **not** a
source of protocol truth and must never be cited as one: the mock encodes
what we currently believe the firmware does, so when firmware changes it
will keep reporting PASS while being wrong. `research/` and captures from
real hardware stay the authority.

Nothing here is wired into CI: `.github/workflows/build.yml` is untouched
and these assertions do not run on any push. Wiring them in would need a
Linux runner with a Docker daemon, network access (the pinned mock build
pulls `golang:1.22`, and the stock-plugin path also downloads a plugin zip
from `api.bambulab.com`), and the apt toolchain listed below.

## Usage

From the repo root, in Linux/WSL bash:

```bash
# one-time: build this repo — the harness loads OUR build by default
./configure && cmake --build build
# one-time: install the apt dependencies (below)

tools/mock_harness/run_harness.sh
```

Flags and defaults (defaults are constants in `run_harness.sh`; this table
documents them — the script never parses this file):

| flag | default |
| --- | --- |
| `--abi MM.mm.pp` | first three components of `OBN_VERSION` in `build/CMakeCache.txt` (fallback `02.08.04`) |
| `--plugin-path PATH` | `build/libbambu_networking.so`, i.e. our own build; the stock plugin is opt-in: pass the CDN-cached `.so` explicitly, together with its `--abi` |
| `--model` | `P1S` |
| `--access-code` | `12345678` |
| `--timeout` | `6` |
| `--connect-settle-ms` | `15000` |
| `--log-out` | `.cache/openbu-mock/run/harness.jsonl` |
| `--ssdp {off,soft,hard}` | `hard` |

Exit-code contract: **`0` = chain passed, `1` = assertion failed** — the
runner's own `rc` (printed as `runner_rc=`) is informational only:
`--action none` exits 0 even when the flow failed, so the verdict comes
solely from `tools/mock_harness/assert_chain.py`, which prints
`PASS connect chain` or one `FAIL …` line per broken gate.

What one invocation does: preflight (`command -v cmake ninja g++ pkg-config
python3 git` plus `pkg-config --exists openssl libcurl minizip`, actionable
errors on failure) → `fetch_mock.sh` pinned fetch/build if
`.cache/openbu-mock/out/openbu-mock` is missing → `build_responder.sh` if
the sidecar is missing → start the mock (identity parsed from its stdout
table — serial/IP/code are never hardcoded) → copy the trust anchors
(`slicer_base64.cer` **and** `printer.cer` = PEM copies of `ca.pem`) →
start the `:3000` sidecar with that identity → readiness poll (`$IP:8883`
and `:3000`, else the mock log tail) → `tools/plugin_runner.sh --abi …
--plugin-path … --action none … --log-out …` → `assert_chain.py` verdict →
teardown (`trap` on EXIT/INT/TERM kills mock + sidecar) → **exit with the
assertion's code**.

Prerequisites (one-time):

```bash
sudo apt-get update && sudo apt-get install -y build-essential cmake ninja-build \
    pkg-config libcurl4-openssl-dev libminizip-dev nlohmann-json3-dev
```

A running Docker daemon is needed for the **first** fetch (the `golang:1.22`
build); later runs skip fetch+build when the binaries exist. `fetch_mock.sh`
pins openbu-mock at `MOCK_PIN` and hard-fails if upstream drifts — the pin is
never auto-bumped.

Artifacts (all gitignored): the `<--log-out>` JSONL transcript (+ `.out` /
`.err` runner capture), `.cache/openbu-mock/run/mock.log` (mock `-debug`),
`identity.env`, `detect.log` (sidecar stdout).

## Expected chain

Golden stream from `tools/plugin_runner/README.md` §9 (event _kinds_ in
order):

```text
startup → plugin_loaded → data_dir → cert_resolved →
extra_http_header → agent_start (rc=0) → post_start_init →
change_user_clear (rc=0) → ssdp_msg → bind_detect →
connect_printer_call (rc=0) → local_connect (status=0) →
session_ready (got=true) → start_subscribe → kickstart_pushall (rc=0)
→ idle_done → shutdown
```

of which `assert_chain.py` asserts, in order: `bind_detect rc=0 →
connect_printer_call rc=0 → local_connect status=0 → session_ready got=true
→ start_subscribe → kickstart_pushall rc=0 → idle_done`, plus `ssdp_msg`
under `--ssdp hard`. The default is `hard` because `ssdp_msg` was present in
every recorded run and both SSDP startup orders coexist cleanly on `:2021`
(zero `SSDP: failed to listen` from the mock in either order).

### The `:3000` sidecar

openbu-mock has no `:3000` listener at all — at the pin, MQTT binds
`p.IP:8883`, SSDP binds `239.255.255.250:2021`, and the startup table starts
only those two. The detect responder is therefore our own clean-room
`detect_responder.cpp`, authored from `research/08.06-bind.md` §8.6.2 plus
our `obn::lan_bind_tcp` codec — zero bytes read from openbu-mock (see the
license constraint below). It satisfies our parser in `src/lan_bind_tcp.cpp`
(field reads plus a hard failure on an empty `id`), and with nothing
listening stock gives up after ~9 s with `bind_detect rc=-2 result_msg =
"publish login request failed"`.

Without the sidecar the chain stops there: `bind_detect rc=-2`,
`kickstart_pushall rc=-4`.

### Trust anchors (observed behavior)

Stock's LAN TLS verify loads `printer.cer` from the same folder as the
resolved `slicer_base64.cer`, and the verify trust anchor is the **content
of `printer.cer`**. Without that file the client aborts before even sending
a ClientHello; with both files as PEM copies of the mock's `ca.pem`,
`local_connect status=0` and the full chain passes.

### Sequence echo

The mock answers `pushall` with a static `sequence_id`, echoes
`get_version`, and never replies to `get_access_code` /
`app_cert_install`. The chain passes without a patch because the runner does
not match responses (`tools/plugin_runner/main.cpp:1263-1266`) and the gates
are transport/session-level. Escalate to a mock patch only if a recorded run
fails **and** the mock's `-debug` log shows `unhandled command keys` for the
command that the failing gate depends on. Any such patch would live only
inside the gitignored clone, only its observed behavior (never a diff) would
be recorded here, and an upstream permission request would be opened in
parallel — nothing from the clone is ever committed.

## License constraint

openbu-mock has **no LICENSE** upstream (`"license": null`, GitHub API) —
unlicensed repos are facts-only here. The mock is an **external binary
only**: no openbu-mock source, patch diff, or derived code enters our trees;
the clone and the generated `ca.pem`/`ca-key.pem` live only in the gitignored
`.cache/openbu-mock/`; nothing from the clone is ever `git add`ed (vendoring
unlicensed code is out of scope for this repo).

## Out of scope

FTPS/`990`, the print-job/`project_file` flow, signing, a strict single
SUBSCRIBE topic, and multi-printer `-count` support are not covered —
recorded here so the gap census is complete.
