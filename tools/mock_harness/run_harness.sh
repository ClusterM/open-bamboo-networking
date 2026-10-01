#!/usr/bin/env bash
# run_harness.sh — the single CI-able command for TEST-01 (D-06/D-07).
#
# Starts the pinned external openbu-mock + the clean-room :3000 sidecar,
# drives tools/plugin_runner --action none against them, asserts the D-08
# ordered JSONL chain (assert_chain.py), tears everything down, and exits
# with the ASSERTION's code. The runner's own exit code is informational
# only (`--action none` exits 0 even on flow failure — Pitfall 8).
#
# Exit: 0 = D-08 chain passed, 1 = assertion failed.
#
# Usage: tools/mock_harness/run_harness.sh [flags]
#   --abi MM.mm.pp            plugin ABI (default: README OQ3 resolved value)
#   --model MODEL             mock model (default: P1S)
#   --access-code CODE        pinned mock access code (default: 12345678)
#   --timeout SECONDS         --action none idle window (default: 6)
#   --connect-settle-ms MS    local_connect wait cap (default: 15000)
#   --log-out PATH            JSONL transcript (default: .cache/openbu-mock/run/harness.jsonl)
#   --ssdp {off,soft,hard}    ssdp_msg assert (default: derived from README)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

RUN=".cache/openbu-mock/run"
MOCK_BIN=".cache/openbu-mock/out/openbu-mock"
SIDECAR=".cache/mock_harness/build-responder/detect_responder"
HARNESS_DIR="tools/mock_harness"
README="$HARNESS_DIR/README.md"

die() { printf 'run_harness: %s\n' "$*" >&2; exit 1; }
log() { printf 'run_harness: %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
ABI="" MODEL="P1S" ACCESS_CODE="12345678" TIMEOUT_S="6" SETTLE_MS="15000"
LOG_OUT="$RUN/harness.jsonl" SSDP=""
while (( $# > 0 )); do
    case "$1" in
        --abi)              ABI="$2"; shift 2 ;;
        --model)            MODEL="$2"; shift 2 ;;
        --access-code)      ACCESS_CODE="$2"; shift 2 ;;
        --timeout)          TIMEOUT_S="$2"; shift 2 ;;
        --connect-settle-ms) SETTLE_MS="$2"; shift 2 ;;
        --log-out)          LOG_OUT="$2"; shift 2 ;;
        --ssdp)             SSDP="$2"; shift 2 ;;
        -h|--help)          sed -n '3,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *)                  die "unknown flag: $1 (see --help)" ;;
    esac
done

# Default --abi from the recorded OQ3 resolution (README).
if [[ -z "$ABI" ]]; then
    ABI="$(awk '/^OQ3 resolved: --abi /{print $4; exit}' "$README" 2>/dev/null || true)"
    [[ -n "$ABI" ]] || die "cannot derive default --abi from $README (expected an 'OQ3 resolved: --abi MM.mm.pp' line); pass --abi explicitly"
fi
# Default --ssdp from the recorded assert decision (README): hard only if
# README literally records 'assert decision: hard', else soft.
if [[ -z "$SSDP" ]]; then
    if grep -q 'assert decision: hard' "$README" 2>/dev/null; then
        SSDP="hard"
    else
        SSDP="soft"
    fi
fi
[[ "$SSDP" =~ ^(off|soft|hard)$ ]] || die "--ssdp must be off|soft|hard, got '$SSDP'"

# ---------------------------------------------------------------------------
# 1. Preflight (Pitfall 5): toolchain + pkg-config deps with actionable errors
# ---------------------------------------------------------------------------
missing=""
for c in cmake ninja g++ pkg-config python3 git; do
    command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
done
[[ -z "$missing" ]] || die "missing tools:$missing — one-time install (WSL, as root):
  apt-get update && apt-get install -y build-essential cmake ninja-build pkg-config libcurl4-openssl-dev libminizip-dev nlohmann-json3-dev"
pkg-config --exists openssl 2>/dev/null   || die "pkg-config: openssl not found — install libssl-dev"
pkg-config --exists libcurl 2>/dev/null   || die "pkg-config: libcurl not found — install libcurl4-openssl-dev"
pkg-config --exists minizip 2>/dev/null   || die "pkg-config: minizip not found — install libminizip-dev"

# ---------------------------------------------------------------------------
# 2. Ensure artifacts: pinned mock binary (D-04) + clean-room sidecar (D-01)
# ---------------------------------------------------------------------------
if [[ ! -x "$MOCK_BIN" ]]; then
    log "mock binary missing — running $HARNESS_DIR/fetch_mock.sh (needs Docker daemon for the build)"
    "$HARNESS_DIR/fetch_mock.sh"
fi
[[ -x "$MOCK_BIN" ]] || die "fetch_mock.sh did not produce $MOCK_BIN"
if [[ ! -x "$SIDECAR" ]]; then
    log "sidecar binary missing — running $HARNESS_DIR/build_responder.sh"
    "$HARNESS_DIR/build_responder.sh"
fi
[[ -x "$SIDECAR" ]] || die "build_responder.sh did not produce $SIDECAR"

# ---------------------------------------------------------------------------
# 3. Teardown trap: never leave listeners behind (EXIT/INT/TERM)
# ---------------------------------------------------------------------------
MOCK_PID="" RESP_PID=""
cleanup() {
    local rc=$?
    set +e
    [[ -n "$RESP_PID" ]] && kill "$RESP_PID" 2>/dev/null
    [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" 2>/dev/null
    sleep 1
    [[ -n "$RESP_PID" ]] && kill -9 "$RESP_PID" 2>/dev/null
    [[ -n "$MOCK_PID" ]] && kill -9 "$MOCK_PID" 2>/dev/null
    exit "$rc"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# 4. Start the mock (cwd = run dir so ca.pem lands in the gitignored run dir)
# ---------------------------------------------------------------------------
mkdir -p "$RUN"
: > "$RUN/mock.log"
( cd "$RUN" && exec "$ROOT/$MOCK_BIN" -model "$MODEL" -access-code "$ACCESS_CODE" -count 1 -debug > mock.log 2>&1 ) &
MOCK_PID=$!
ready=0
for _ in $(seq 1 30); do
    if grep -q 'MQTT: listening' "$RUN/mock.log" 2>/dev/null; then ready=1; break; fi
    if ! kill -0 "$MOCK_PID" 2>/dev/null; then break; fi
    sleep 1
done
[[ "$ready" = 1 ]] || { tail -20 "$RUN/mock.log" >&2 || true; die "mock did not become ready (see $RUN/mock.log above)"; }

# Parse the mock's stdout table (fixed-width columns) — NEVER hardcode
# serial/IP/code (Pitfall 7).
python3 - "$RUN/mock.log" "$RUN/identity.env" <<'PY'
import re, sys
lines = open(sys.argv[1], errors='replace').read().splitlines()
hdr = dashes = None
for i, l in enumerate(lines):
    s = l.strip()
    if hdr is None and s.startswith('IP') and 'Model' in l and 'Serial' in l and 'Code' in l:
        hdr = i
    elif hdr is not None and dashes is None and set(s) == {'-'}:
        dashes = i
        break
if hdr is None or dashes is None:
    sys.exit('identity table header not found in mock.log')
row = re.split(r'\s{2,}', lines[dashes + 1].strip())
if len(row) < 5:
    sys.exit('identity row malformed: %r' % lines[dashes + 1])
ip, model, serial, code, name = row[0], row[1], row[2], row[3], row[4]
with open(sys.argv[2], 'w') as f:
    f.write('IP=%s\nSERIAL=%s\nMODEL=%s\nNAME=%s\nCODE=%s\n' % (ip, serial, model, name, code))
PY
# shellcheck disable=SC1090
source "$RUN/identity.env"
log "identity: ip=$IP serial=$SERIAL name=$NAME model=$MODEL"

# ---------------------------------------------------------------------------
# 5. Trust anchors per the recorded OQ1 resolution: slicer_base64.cer AND
#    printer.cer = PEM copies of the mock's ca.pem (stock's LAN TLS verify
#    loads printer.cer from this folder — without it the client aborts
#    before ClientHello).
# ---------------------------------------------------------------------------
[[ -f "$RUN/ca.pem" ]] || die "$RUN/ca.pem not found — mock should generate it at startup"
cp "$RUN/ca.pem" "$RUN/slicer_base64.cer"
cp "$RUN/ca.pem" "$RUN/printer.cer"

# ---------------------------------------------------------------------------
# 6. Start the clean-room sidecar with identity.env values + OQ5 defaults
# ---------------------------------------------------------------------------
: > "$RUN/detect.log"
"$SIDECAR" --id "$SERIAL" --name "$NAME" --model C12 --version 01.09.01.00 \
    --bind-state free --connect lan > "$RUN/detect.log" 2>&1 &
RESP_PID=$!

# ---------------------------------------------------------------------------
# 7. Readiness: $IP:8883 (mock TLS) and :3000 (sidecar) must answer
# ---------------------------------------------------------------------------
up8883=0 up3000=0
for _ in $(seq 1 50); do
    if timeout 1 bash -c "</dev/tcp/$IP/8883" 2>/dev/null; then up8883=1; fi
    if timeout 1 bash -c '</dev/tcp/127.0.0.1/3000' 2>/dev/null; then up3000=1; fi
    if [[ "$up8883" = 1 && "$up3000" = 1 ]]; then break; fi
    sleep 0.2
done
if [[ "$up8883" != 1 || "$up3000" != 1 ]]; then
    tail -20 "$RUN/mock.log" >&2 || true
    tail -5 "$RUN/detect.log" >&2 || true
    die "readiness failed: mock:8883=$up8883 sidecar:3000=$up3000 (logs above)"
fi
log "ready: mock=$IP:8883 sidecar=:3000"

# ---------------------------------------------------------------------------
# 8. Drive the stock plugin; runner_rc= is EVIDENCE ONLY (Pitfall 8)
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$LOG_OUT")"
rm -f "$LOG_OUT" "$LOG_OUT.out" "$LOG_OUT.err"
runner_rc=0
tools/plugin_runner.sh --abi "$ABI" --action none --timeout "$TIMEOUT_S" \
    --dev-id "$SERIAL" --dev-ip "$IP" --access-code "$ACCESS_CODE" \
    --cert-file "$RUN/slicer_base64.cer" \
    --connect-settle-ms "$SETTLE_MS" --log-out "$LOG_OUT" \
    > "$LOG_OUT.out" 2> "$LOG_OUT.err" || runner_rc=$?
echo "runner_rc=$runner_rc (informational only — the verdict comes from assert_chain.py)"

# ---------------------------------------------------------------------------
# 9-10. Verdict: D-08 chain assertion; exit with ITS code after teardown
# ---------------------------------------------------------------------------
verdict_rc=0
python3 "$HARNESS_DIR/assert_chain.py" --log "$LOG_OUT" --ssdp "$SSDP" || verdict_rc=$?
log "log: $LOG_OUT  mock: $RUN/mock.log  identity: $RUN/identity.env"
exit "$verdict_rc"
