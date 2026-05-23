#!/usr/bin/env bash
# Attach Frida TUTKSSL logger to a running Bambu Studio process.
# Send to Printer (ft_*) uses libbambu_networking.so — see tools/frida_ft_attach.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JS="${SCRIPT_DIR}/tutk_ssl_log.js"
FRIDA="${FRIDA:-$HOME/.local/bin/frida}"

if [[ ! -f "$JS" ]]; then
  echo "missing $JS" >&2
  exit 1
fi

if [[ ! -x "$FRIDA" ]] && ! command -v frida >/dev/null; then
  echo "frida not found. Install: pip3 install --user --break-system-packages frida-tools" >&2
  exit 1
fi
FRIDA="$(command -v frida || echo "$FRIDA")"

# yama ptrace_scope=1 blocks attach to non-child processes (Frida shows
# "process not found"). Needs 0 for attach-to-running-Studio workflow.
PTRACE_SCOPE="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 1)"
if [[ "$PTRACE_SCOPE" != "0" ]]; then
  echo "kernel.yama.ptrace_scope=$PTRACE_SCOPE (attach blocked)." >&2
  echo "Run once (needs sudo, until reboot):" >&2
  echo "  sudo sysctl kernel.yama.ptrace_scope=0" >&2
  echo "Or spawn Studio via Frida instead (see tools/tutk_ssl_log.js header)." >&2
  exit 1
fi

: > /tmp/tutk_ssl.log

# Real binary is AppImage mount: .../bin/bambu-studio (not the AppImage stub).
PID=""
if command -v pgrep >/dev/null; then
  PID="$(pgrep -nx bambu-studio 2>/dev/null || true)"
fi
if [[ -z "$PID" ]]; then
  for name in bambu-studio BambuStudio; do
    PID="$(pidof "$name" 2>/dev/null | awk '{print $NF}')" && break
  done
fi

if [[ -z "$PID" ]] || [[ ! -d "/proc/$PID" ]]; then
  echo "Bambu Studio is not running (expected process name: bambu-studio)." >&2
  echo "Start Studio first, then re-run this script." >&2
  exit 1
fi

EXE="$(readlink -f "/proc/$PID/exe" 2>/dev/null || true)"
echo "Attaching to pid $PID ${EXE:+($EXE)}"
echo "Log: /tmp/tutk_ssl.log"
echo "Open Device -> Files (External / Internal) to trigger :6000 traffic."
echo "Press Ctrl+C to detach."
exec "$FRIDA" -p "$PID" -l "$JS"
