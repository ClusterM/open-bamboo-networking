#!/usr/bin/env bash
# Attach Frida logger for libbambu_networking.so (Send to Printer / ft_*).
#
# Before capture, install the stock plugin:
#   cp ~/.config/BambuStudio/plugins/backup/libbambu_networking.so \
#      ~/.config/BambuStudio/plugins/libbambu_networking.so
# Restart Bambu Studio, then run this script and repeat Send to Printer.
#
# Wire capture (default ON): SSL_write/SSL_read plaintext when found; ABI JSON always -> ft_wire.log
# Stock plugin: static stripped OpenSSL — syscall read/write is TLS ciphertext (off by default).
#
#   ./tools/frida_ft_attach.sh              # ABI + wire (JSON in log via ABI hooks)
#   ./tools/frida_ft_attach.sh --safe       # ABI only (if Studio crashes)
#   FRIDA_FT_SYSCALL=1 ./tools/frida_ft_attach.sh   # also log syscalls (encrypted TLS)
#   ./tools/frida_ft_attach.sh --spawn      # spawn Studio (needs ptrace for attach)
#
# Logs:
#   /tmp/ft_upload_stock.log  — ABI (tee)
#   /tmp/ft_wire.log          — decrypted wire payloads (Frida File API)
#
# Device -> Files uses libBambuSource.so — see tools/frida_tutk_attach.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JS="${SCRIPT_DIR}/frida_ft_upload.js"
FRIDA="${FRIDA:-$HOME/.local/bin/frida}"
LOG="/tmp/ft_upload_stock.log"
WIRE_LOG="/tmp/ft_wire.log"
KEYLOG="${SSLKEYLOGFILE:-/tmp/ft_ssl_keys.log}"
SPAWN=0
SPAWN_BIN=""
FRIDA_FT_WIRE="${FRIDA_FT_WIRE:-1}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--wire|--safe] [--spawn [path/to/bambu-studio]]

Attach Frida to Bambu Studio and log ft_* ABI + :6000 plaintext (Frida wire hooks).

Log files:
  ABI:  /tmp/ft_upload_stock.log
  Wire: /tmp/ft_wire.log

Options:
  --wire     Enable SSL_write/read hooks (default)
  --safe     ABI hooks only (FRIDA_FT_WIRE=0)
  --spawn    Start Studio under Frida (optional binary path)

Env:
  FRIDA_FT_WIRE=0|1     wire hooks (default 1)
  FRIDA_FT_SYSCALL=0|1  log read/write syscalls (default 0; stock = TLS bytes)
  FRIDA_FT_TLS_RAW=0|1  dump TLS ciphertext when SYSCALL=1 (default 0)
  FRIDA_FT_PORT=6000    filter peer port
  FRIDA_FT_SSL_WRITE_OFF=0x...  hook static SSL_write (after RE backtrace in wire log)
  SSLKEYLOGFILE=...     Wireshark decryption if Studio started with it

Notes:
  - Restore stock libbambu_networking.so before sniffing (see script header).
  - Attach mode needs: sudo sysctl kernel.yama.ptrace_scope=0
  - If Studio still crashes, retry with --safe and use SSLKEYLOGFILE + tcpdump.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --spawn)
      SPAWN=1
      shift
      if [[ $# -gt 0 && "$1" != --* ]]; then
        SPAWN_BIN="$1"
        shift
      fi
      ;;
    --wire)
      FRIDA_FT_WIRE=1
      shift
      ;;
    --safe)
      FRIDA_FT_WIRE=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "$JS" ]]; then
  echo "missing $JS" >&2
  exit 1
fi

if [[ ! -x "$FRIDA" ]] && ! command -v frida >/dev/null; then
  echo "frida not found. Install: pip3 install --user --break-system-packages frida-tools" >&2
  exit 1
fi
FRIDA="$(command -v frida || echo "$FRIDA")"

: > "$LOG"
if [[ "$FRIDA_FT_WIRE" == "1" ]]; then
  : > "$WIRE_LOG"
fi

find_studio_bin() {
  local candidate=""
  if command -v pgrep >/dev/null; then
    local pid=""
    pid="$(pgrep -nx bambu-studio 2>/dev/null || true)"
    if [[ -n "$pid" && -d "/proc/$pid" ]]; then
      candidate="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
      if [[ -n "$candidate" && -x "$candidate" ]]; then
        echo "$candidate"
        return 0
      fi
    fi
  fi
  for guess in \
    "$HOME/.local/bin/Bambu_Studio_ubuntu-24.04_V02.07.00.55.AppImage" \
    "$HOME/.local/bin/BambuStudio" \
    "/usr/bin/bambu-studio"; do
    if [[ -x "$guess" ]]; then
      echo "$guess"
      return 0
    fi
  done
  return 1
}

run_frida() {
  export FRIDA_FT_WIRE
  export FRIDA_FT_PORT="${FRIDA_FT_PORT:-6000}"
  exec env FRIDA_FT_WIRE="$FRIDA_FT_WIRE" FRIDA_FT_PORT="${FRIDA_FT_PORT:-6000}" \
    "$FRIDA" "$@" \
    -e "globalThis.FRIDA_FT_WIRE='${FRIDA_FT_WIRE}'; globalThis.FRIDA_FT_PORT='${FRIDA_FT_PORT:-6000}';" \
    -l "$JS" 2>&1 | tee -a "$LOG"
}

if [[ "$SPAWN" -eq 1 ]]; then
  if [[ -z "$SPAWN_BIN" ]]; then
    SPAWN_BIN="$(find_studio_bin || true)"
  fi
  if [[ -z "$SPAWN_BIN" || ! -x "$SPAWN_BIN" ]]; then
    echo "Pass studio binary: $0 --spawn /path/to/Bambu_Studio.AppImage" >&2
    exit 1
  fi
  echo "Spawning: $SPAWN_BIN"
  echo "ABI log:  $LOG"
  if [[ "$FRIDA_FT_WIRE" == "1" ]]; then
    echo "Wire log: $WIRE_LOG (FRIDA_FT_WIRE=1 port=${FRIDA_FT_PORT:-6000})"
  else
    echo "Wire:     disabled (--safe)"
  fi
  echo "After Studio opens: Send to Printer -> Cache -> Send"
  echo "WARNING: --spawn often crashes AppImage (SIGSEGV in loader). Prefer:" >&2
  echo "  ./tools/run_studio_wire.sh && ./tools/frida_ft_attach.sh" >&2
  run_frida -f "$SPAWN_BIN"
fi

PTRACE_SCOPE="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 1)"
if [[ "$PTRACE_SCOPE" != "0" ]]; then
  echo "kernel.yama.ptrace_scope=$PTRACE_SCOPE (attach blocked)." >&2
  echo "Run once (needs sudo, until reboot):" >&2
  echo "  sudo sysctl kernel.yama.ptrace_scope=0" >&2
  echo "Or use spawn mode:" >&2
  echo "  $0 --spawn /path/to/Bambu_Studio.AppImage" >&2
  exit 1
fi

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
  echo "Start Studio with stock libbambu_networking.so, then re-run this script." >&2
  echo "Or: $0 --spawn" >&2
  exit 1
fi

EXE="$(readlink -f "/proc/$PID/exe" 2>/dev/null || true)"
echo "Attaching to pid $PID ${EXE:+($EXE)}"
echo "ABI log:  $LOG"
if [[ "$FRIDA_FT_WIRE" == "1" ]]; then
  echo "Wire log: $WIRE_LOG (FRIDA_FT_WIRE=1 port=${FRIDA_FT_PORT:-6000})"
else
  echo "Wire:     disabled (--safe)"
fi
echo "Use Send to Printer (Cache / External), not Device -> Files."
echo "Press Ctrl+C to detach."
run_frida -p "$PID"
