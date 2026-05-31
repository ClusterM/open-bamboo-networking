#!/bin/sh
# Assemble CI matrix artifacts into per-OS distribution archives.
# Called from the GitHub Actions 'package' job after download-artifact
# pulls all build artifacts into artifacts/.
#
# Input:  artifacts/obn-linux-v02.05.03.xx-x64/  (etc.)
# Output: dist-out/obn-linux-x64.tar.gz
#         dist-out/obn-linux-aarch64.tar.gz
#         dist-out/obn-windows-x64.zip
#         dist-out/obn-macos.tar.gz
set -eu

ARTIFACTS="${1:-artifacts}"
OUTDIR="${2:-dist-out}"
COMMIT="${GITHUB_SHA:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
DATE="$(date -u '+%Y-%m-%d %H:%M UTC')"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$OUTDIR"

# ── Helper: generate README.txt from template ───────────────────────────

generate_readme() {
    local platform="$1" install_script="$2" install_instructions="$3" dest="$4"
    sed \
        -e "s|@PLATFORM@|${platform}|g" \
        -e "s|@COMMIT@|${COMMIT}|g" \
        -e "s|@DATE@|${DATE}|g" \
        -e "s|@INSTALL_SCRIPT@|${install_script}|g" \
        -e "s|@INSTALL_INSTRUCTIONS@|${install_instructions}|g" \
        "$REPO_ROOT/packaging/readme.txt.in" > "$dest"
}

# ── Helper: collect ABI dirs for a platform ──────────────────────────────

collect_abi_dirs() {
    local pattern="$1" dest_base="$2"
    for art_dir in "$ARTIFACTS"/${pattern}; do
        [ -d "$art_dir" ] || continue
        # Extract ABI version from directory name: obn-linux-v02.05.03.xx-x64 -> 02.05.03
        dir_name=$(basename "$art_dir")
        abi_ver=$(echo "$dir_name" | sed -E 's/.*v([0-9]+\.[0-9]+\.[0-9]+)\..*/\1/')
        if [ -z "$abi_ver" ]; then
            echo "Warning: cannot extract ABI from $dir_name, skipping" >&2
            continue
        fi
        local target="$dest_base/lib/v${abi_ver}"
        mkdir -p "$target"
        cp -r "$art_dir"/* "$target/"
        echo "  Collected v${abi_ver} -> $(basename "$dest_base")/lib/v${abi_ver}/"
    done
}

# ── Linux x64 ────────────────────────────────────────────────────────────

echo "Assembling obn-linux-x64..."
STAGE="$OUTDIR/obn-linux-x64"
rm -rf "$STAGE"
mkdir -p "$STAGE"
collect_abi_dirs "obn-linux-v*-x64" "$STAGE"
cp "$REPO_ROOT/packaging/install.sh" "$STAGE/"
cp "$REPO_ROOT/packaging/obn.conf.in" "$STAGE/"
chmod +x "$STAGE/install.sh"
generate_readme "Linux x64" "install.sh" \
    "Run:  chmod +x install.sh && ./install.sh" "$STAGE/README.txt"
(cd "$OUTDIR" && tar czf obn-linux-x64.tar.gz obn-linux-x64/)
echo "  -> obn-linux-x64.tar.gz"

# ── Linux aarch64 ────────────────────────────────────────────────────────

echo "Assembling obn-linux-aarch64..."
STAGE="$OUTDIR/obn-linux-aarch64"
rm -rf "$STAGE"
mkdir -p "$STAGE"
collect_abi_dirs "obn-linux-v*-aarch64" "$STAGE"
cp "$REPO_ROOT/packaging/install.sh" "$STAGE/"
cp "$REPO_ROOT/packaging/obn.conf.in" "$STAGE/"
chmod +x "$STAGE/install.sh"
generate_readme "Linux aarch64" "install.sh" \
    "Run:  chmod +x install.sh && ./install.sh" "$STAGE/README.txt"
(cd "$OUTDIR" && tar czf obn-linux-aarch64.tar.gz obn-linux-aarch64/)
echo "  -> obn-linux-aarch64.tar.gz"

# ── Windows x64 ──────────────────────────────────────────────────────────

echo "Assembling obn-windows-x64..."
STAGE="$OUTDIR/obn-windows-x64"
rm -rf "$STAGE"
mkdir -p "$STAGE"
collect_abi_dirs "obn-v*-windows-x64" "$STAGE"
cp "$REPO_ROOT/packaging/install.ps1" "$STAGE/"
cp "$REPO_ROOT/packaging/install.bat" "$STAGE/"
cp "$REPO_ROOT/packaging/obn.conf.in" "$STAGE/"
generate_readme "Windows x64" "install.bat" \
    "Double-click install.bat, or run in PowerShell:  .\\\\install.ps1" "$STAGE/README.txt"
(cd "$OUTDIR" && zip -qr obn-windows-x64.zip obn-windows-x64/)
echo "  -> obn-windows-x64.zip"

# ── macOS ────────────────────────────────────────────────────────────────

echo "Assembling obn-macos..."
STAGE="$OUTDIR/obn-macos"
rm -rf "$STAGE"
mkdir -p "$STAGE"
collect_abi_dirs "obn-macos-v*" "$STAGE"
cp "$REPO_ROOT/packaging/install.sh" "$STAGE/"
cp "$REPO_ROOT/packaging/install.command" "$STAGE/"
cp "$REPO_ROOT/packaging/obn.conf.in" "$STAGE/"
chmod +x "$STAGE/install.sh" "$STAGE/install.command"
generate_readme "macOS" "install.command" \
    "Double-click install.command in Finder, or run:  ./install.sh" "$STAGE/README.txt"
(cd "$OUTDIR" && tar czf obn-macos.tar.gz obn-macos/)
echo "  -> obn-macos.tar.gz"

# ── Done ─────────────────────────────────────────────────────────────────

echo ""
echo "Distribution archives in $OUTDIR/:"
ls -lh "$OUTDIR"/*.tar.gz "$OUTDIR"/*.zip 2>/dev/null || true
