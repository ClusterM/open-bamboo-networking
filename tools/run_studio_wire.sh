#!/usr/bin/env bash
# Start Bambu Studio for :6000 wire capture with OUR libbambu_networking.so
# (dynamic OpenSSL → Frida SSL_write hooks work; stock static OpenSSL does not).
#
# Do NOT use frida --spawn for keylog — it crashes AppImage loaders.
# SSLKEYLOGFILE only helps our plugin (links libssl.so); stock ignores it.
#
# Usage:
#   ./tools/run_studio_wire.sh              # start Studio
#   ./tools/run_studio_wire.sh --keylog     # also set SSLKEYLOGFILE (our .so only)
# Then in another terminal:
#   ./tools/frida_ft_attach.sh
# Send to Printer → Cache → Send
set -euo pipefail

KEYLOG=0
STUDIO=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keylog) KEYLOG=1; shift ;;
    -h|--help)
      echo "Usage: $(basename "$0") [--keylog] [path/to/Bambu_Studio.AppImage]"
      exit 0
      ;;
    *)
      STUDIO="$1"
      shift
      ;;
  esac
done

if [[ -z "$STUDIO" ]]; then
  for guess in \
    "$HOME/.local/bin/Bambu_Studio_ubuntu-24.04_V02.07.00.55.AppImage" \
    "$HOME/.local/bin/BambuStudio"; do
    if [[ -x "$guess" ]]; then
      STUDIO="$guess"
      break
    fi
  done
fi

if [[ -z "$STUDIO" || ! -x "$STUDIO" ]]; then
  echo "Pass AppImage path: $0 /path/to/Bambu_Studio.AppImage" >&2
  exit 1
fi

PLUGIN="$HOME/.config/BambuStudio/plugins/libbambu_networking.so"
if [[ ! -f "$PLUGIN" ]]; then
  echo "missing $PLUGIN — build and install open-bambu-networking first" >&2
  exit 1
fi

export FRIDA_FT_WIRE=1
export FRIDA_FT_SYSCALL=0

if [[ "$KEYLOG" -eq 1 ]]; then
  export SSLKEYLOGFILE="${SSLKEYLOGFILE:-/tmp/ft_ssl_keys.log}"
  : > "$SSLKEYLOGFILE"
  echo "SSLKEYLOGFILE=$SSLKEYLOGFILE (works with our .so only, not stock)"
fi

echo "Starting: $STUDIO"
echo "Plugin:   $PLUGIN"
echo "Next:     ./tools/frida_ft_attach.sh   (attach, not --spawn)"
exec "$STUDIO"
