#!/bin/sh
# Assemble CI matrix artifacts into per-OS distribution archives.
# Called from the GitHub Actions 'package' job after download-artifact
# pulls all build artifacts into artifacts/.
#
# Environment:
#   OBN_BUILD_TYPE  - "release" or "interim" (default: interim)
#   OBN_VERSION     - project version string (e.g. "v1.0rc1"), read from
#                     include/obn/version.hpp when not set explicitly
#
# Input:  artifacts/obn-linux-v02.05.03.xx-x64/  (etc.)
# Output: dist-out/obn-linux-x64.tar.gz
#         dist-out/obn-linux-aarch64.tar.gz
#         dist-out/obn-windows-x64.zip
#         dist-out/obn-macos-arm64.tar.gz
#         dist-out/obn-macos-x64.tar.gz
set -eu

ARTIFACTS="${1:-artifacts}"
OUTDIR="${2:-dist-out}"
COMMIT="${GITHUB_SHA:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
SHORT_COMMIT=$(printf '%.7s' "$COMMIT")
DATE="$(date -u '+%Y-%m-%d %H:%M UTC')"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

BUILD_TYPE="${OBN_BUILD_TYPE:-interim}"

# Extract project version from the header if not provided via env
if [ -z "${OBN_VERSION:-}" ]; then
    OBN_VERSION=$(sed -n 's/.*OBN_PROJECT_VERSION "\([^"]*\)".*/\1/p' \
        "$REPO_ROOT/include/obn/version.hpp")
fi

# Build the version label for templates
if [ "$BUILD_TYPE" = "release" ]; then
    VERSION_LABEL="$OBN_VERSION"
else
    VERSION_LABEL="interim build, commit ${SHORT_COMMIT}"
fi

mkdir -p "$OUTDIR"

# ── Helper: generate README.txt from template ───────────────────────────

generate_readme() {
    local platform="$1" install_script="$2" install_instructions="$3" dest="$4"
    sed \
        -e "s|@PLATFORM@|${platform}|g" \
        -e "s|@VERSION_LABEL@|${VERSION_LABEL}|g" \
        -e "s|@COMMIT@|${COMMIT}|g" \
        -e "s|@DATE@|${DATE}|g" \
        -e "s|@INSTALL_SCRIPT@|${install_script}|g" \
        -e "s|@INSTALL_INSTRUCTIONS@|${install_instructions}|g" \
        "$REPO_ROOT/packaging/readme.txt.in" > "$dest"
}

# ── Helper: write VERSION file into staging dir ──────────────────────────

write_version_file() {
    local dest="$1"
    if [ "$BUILD_TYPE" = "release" ]; then
        printf '%s\n' "$OBN_VERSION" > "$dest/VERSION"
    else
        printf 'interim %s\n' "$SHORT_COMMIT" > "$dest/VERSION"
    fi
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
chmod +x "$STAGE/install.sh"
write_version_file "$STAGE"
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
chmod +x "$STAGE/install.sh"
write_version_file "$STAGE"
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
write_version_file "$STAGE"
generate_readme "Windows x64" "install.bat" \
    "Double-click install.bat, or run in PowerShell:  .\\\\install.ps1" "$STAGE/README.txt"
(cd "$OUTDIR" && zip -qr obn-windows-x64.zip obn-windows-x64/)
echo "  -> obn-windows-x64.zip"

# ── macOS arm64 ───────────────────────────────────────────────────────────

echo "Assembling obn-macos-arm64..."
STAGE="$OUTDIR/obn-macos-arm64"
rm -rf "$STAGE"
mkdir -p "$STAGE"
collect_abi_dirs "obn-macos-arm64-v*" "$STAGE"
cp "$REPO_ROOT/packaging/install.sh" "$STAGE/"
cp "$REPO_ROOT/packaging/install.command" "$STAGE/"
chmod +x "$STAGE/install.sh" "$STAGE/install.command"
write_version_file "$STAGE"
generate_readme "macOS (Apple Silicon)" "install.command" \
    "Double-click install.command in Finder, or run:  ./install.sh" "$STAGE/README.txt"
(cd "$OUTDIR" && tar czf obn-macos-arm64.tar.gz obn-macos-arm64/)
echo "  -> obn-macos-arm64.tar.gz"

# ── macOS x64 (Intel) ────────────────────────────────────────────────────

if ls "$ARTIFACTS"/obn-macos-x64-v* 1>/dev/null 2>&1; then
    echo "Assembling obn-macos-x64..."
    STAGE="$OUTDIR/obn-macos-x64"
    rm -rf "$STAGE"
    mkdir -p "$STAGE"
    collect_abi_dirs "obn-macos-x64-v*" "$STAGE"
    cp "$REPO_ROOT/packaging/install.sh" "$STAGE/"
    cp "$REPO_ROOT/packaging/install.command" "$STAGE/"
    chmod +x "$STAGE/install.sh" "$STAGE/install.command"
    write_version_file "$STAGE"
    generate_readme "macOS (Intel)" "install.command" \
        "Double-click install.command in Finder, or run:  ./install.sh" "$STAGE/README.txt"
    (cd "$OUTDIR" && tar czf obn-macos-x64.tar.gz obn-macos-x64/)
    echo "  -> obn-macos-x64.tar.gz"
else
    echo "Skipping obn-macos-x64 (no Intel macOS CI artifacts)"
fi

# ── Done ─────────────────────────────────────────────────────────────────

echo ""
echo "Distribution archives in $OUTDIR/:"
ls -lh "$OUTDIR"/*.tar.gz "$OUTDIR"/*.zip 2>/dev/null || true
