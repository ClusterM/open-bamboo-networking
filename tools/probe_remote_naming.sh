#!/usr/bin/env bash
# Probe stock (or open) libbambu_networking.so remote STOR naming for
# start_send_gcode_to_sdcard vs start_local_print.
#
# Documented: NETWORK_PLUGIN.md §6.14.3
# Driver:     tools/plugin_runner.sh (tools/plugin_runner/README.md)
#
# Prefer send_gcode_to_sdcard while the printer is busy printing — it
# only FTPS-uploads and does not start a job. local_print publishes
# project_file (will fail if the bed is occupied).
#
# Requires a LAN printer in Developer Mode. Credentials via env:
#   OBN_DEV_ID, OBN_DEV_IP, OBN_ACCESS_CODE
# Optional:
#   OBN_ABI=02.06.01          stock plugin version (default)
#   OBN_PLUGIN_PATH=…         use open build instead of stock cache
#   OBN_ACTION=send_gcode_to_sdcard | local_print
#
# After each upload the script FTPS-lists the printer root and greps for
# the expected basename. Uses verify_job-sized payloads only.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${ROOT}/tools/plugin_runner.sh"

DEV_ID="${OBN_DEV_ID:-}"
DEV_IP="${OBN_DEV_IP:-}"
ACCESS="${OBN_ACCESS_CODE:-}"
ABI="${OBN_ABI:-02.06.01}"
ACTION="${OBN_ACTION:-send_gcode_to_sdcard}"

if [[ -z "$DEV_ID" || -z "$DEV_IP" || -z "$ACCESS" ]]; then
    echo "Set OBN_DEV_ID, OBN_DEV_IP, OBN_ACCESS_CODE" >&2
    exit 64
fi

WORKDIR=$(mktemp -d /tmp/obn-naming-probe-XXXXXX)
PAYLOAD="${WORKDIR}/payload.bin"
echo -n 'X' > "$PAYLOAD"
G3MF="${WORKDIR}/job.gcode.3mf"
cp "$PAYLOAD" "$G3MF"

run_case() {
    local label="$1"
    local params_json="$2"
    local log="${WORKDIR}/runner-${label}.jsonl"
    echo "=== ${label} (abi=${ABI} action=${ACTION}) ==="
    : > "$log"
    if ! "$RUNNER" --abi "$ABI" \
        ${OBN_PLUGIN_PATH:+--plugin-path "$OBN_PLUGIN_PATH"} \
        --data-dir "${OBN_DATA_DIR:-$HOME/.config/BambuStudio}" \
        --cert-file "${OBN_CERT_FILE:-$HOME/Important/Projects/C/BambuStudio/resources/cert/slicer_base64.cer}" \
        --params-json "$params_json" \
        --action "$ACTION" \
        --gcode-3mf "$G3MF" \
        --dev-id "$DEV_ID" \
        --dev-ip "$DEV_IP" \
        --access-code "$ACCESS" \
        --connect-settle-ms 15000 \
        --timeout 120 \
        --fast-exit \
        --log-out "$log" \
        2>"${WORKDIR}/stderr-${label}.txt"; then
        echo "  runner exit non-zero (see ${WORKDIR}/stderr-${label}.txt)" >&2
    fi
    local finished
    finished=$(python3 - <<PY
import json
for line in open("$log"):
    try: j=json.loads(line)
    except: continue
    if j.get("_kind")=="finished":
        print(j.get("code"), (j.get("msg") or "")[:120])
PY
)
    echo "  finished: ${finished:-<no finished event>}"
}

list_remote() {
    local pattern="$1"
    echo "  LIST (curl ftps, pattern=${pattern}):"
    curl -k --ftp-ssl --user "bblp:${ACCESS}" "ftps://${DEV_IP}/" --list-only 2>/dev/null \
        | grep -F "$pattern" || echo "    (no match)"
}

# --- send_gcode_to_sdcard cases ---
CASE_DIR="${WORKDIR}/cases"
mkdir -p "$CASE_DIR"

cat > "${CASE_DIR}/verify_job.json" <<EOF
{"filename":"${PAYLOAD}","project_name":"verify_job","connection_type":"lan","use_ssl_for_ftp":true}
EOF

cat > "${CASE_DIR}/bare_name.json" <<EOF
{"filename":"${PAYLOAD}","project_name":"obn_probe_bare","task_name":"fallback_task","connection_type":"lan","use_ssl_for_ftp":true}
EOF

cat > "${CASE_DIR}/full_name.json" <<EOF
{"filename":"${PAYLOAD}","project_name":"obn_probe_bare.gcode.3mf","connection_type":"lan","use_ssl_for_ftp":true}
EOF

cat > "${CASE_DIR}/empty_project.json" <<EOF
{"filename":"${PAYLOAD}","project_name":"","task_name":"obn_task_only","connection_type":"lan","use_ssl_for_ftp":true}
EOF

cat > "${CASE_DIR}/print_bare.json" <<EOF
{"filename":"${G3MF}","project_name":"obn_print_bare","task_name":"obn_print_bare","connection_type":"lan","use_ssl_for_ftp":true,"plate_index":1}
EOF

echo "Workdir: $WORKDIR"
echo "Printer: $DEV_ID @ $DEV_IP"
echo

if [[ "$ACTION" == "send_gcode_to_sdcard" ]]; then
    run_case verify_job "${CASE_DIR}/verify_job.json"
    list_remote verify_job
    run_case bare_name "${CASE_DIR}/bare_name.json"
    list_remote obn_probe_bare
    run_case full_name "${CASE_DIR}/full_name.json"
    list_remote obn_probe_bare.gcode.3mf
    run_case empty_project "${CASE_DIR}/empty_project.json"
    list_remote obn_task_only
elif [[ "$ACTION" == "local_print" ]]; then
    run_case print_bare "${CASE_DIR}/print_bare.json"
    list_remote obn_print_bare
else
    echo "OBN_ACTION must be send_gcode_to_sdcard or local_print" >&2
    exit 64
fi

echo
echo "Logs in $WORKDIR (set OBN_KEEP=1 to preserve; default rm on exit)"
if [[ "${OBN_KEEP:-0}" != "1" ]]; then
    rm -rf "$WORKDIR"
fi
