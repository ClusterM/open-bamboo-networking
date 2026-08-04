#!/bin/sh
# Open Bamboo Networking — interactive installer for Linux and macOS.
# Ships inside the distribution archive next to lib/vXX.XX.XX/ directories.
# Detects the slicer, matches the ABI version, copies binaries, and patches
# the slicer conf.
set -eu

# ── Helpers ──────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BOLD='' RESET='' GREEN='' YELLOW='' RED=''
if [ -t 1 ]; then
    BOLD='\033[1m' RESET='\033[0m'
    GREEN='\033[32m' YELLOW='\033[33m' RED='\033[31m'
fi

info()  { printf "${GREEN}[info]${RESET}  %s\n" "$*"; }
warn()  { printf "${YELLOW}[warn]${RESET}  %s\n" "$*" >&2; }
die()   { printf "${RED}[error]${RESET} %s\n" "$*" >&2; exit 1; }

prompt_yn() {
    printf "%s [Y/n] " "$1"
    read -r ans
    case "$ans" in
        [Nn]*) return 1 ;;
        *)     return 0 ;;
    esac
}

# ── OS detection ─────────────────────────────────────────────────────────

OS="$(uname -s)"
case "$OS" in
    Linux)  ;;
    Darwin) ;;
    *)      die "Unsupported OS: $OS (this installer supports Linux and macOS)" ;;
esac

# ── Client selection ─────────────────────────────────────────────────────

printf "\n${BOLD}Open Bamboo Networking — Installer${RESET}\n"
if [ -f "$SCRIPT_DIR/VERSION" ]; then
    VERSION_CONTENT=$(cat "$SCRIPT_DIR/VERSION")
    printf "  Build: %s\n" "$VERSION_CONTENT"
fi
printf "\n"
printf "Select your slicer:\n"
printf "  ${BOLD}1${RESET}) Bambu Studio\n"
printf "  ${BOLD}2${RESET}) Orca Slicer\n"
printf "\nChoice [1]: "
read -r choice
case "$choice" in
    2)  CLIENT=orca_slicer;  CLIENT_LABEL="Orca Slicer" ;;
    *)  CLIENT=bambu_studio; CLIENT_LABEL="Bambu Studio" ;;
esac
echo ""

# ── Config directory detection ───────────────────────────────────────────

# Known config paths per client variant (Linux only; macOS uses ~/Library/...).
# Format: label|conf_name|version_key|dir_path
# The Flatpak app-id for BambuStudio/BambuStudioBeta is com.bambulab.*,
# for OrcaSlicer it is com.orcaslicer.OrcaSlicer.

build_candidates() {
    CANDIDATES=""
    N_CANDIDATES=0

    add_candidate() {
        local label="$1" conf_name="$2" version_key="$3" dir_path="$4"
        if [ -d "$dir_path" ]; then
            N_CANDIDATES=$((N_CANDIDATES + 1))
            CANDIDATES="${CANDIDATES}${N_CANDIDATES}|${label}|${conf_name}|${version_key}|${dir_path}
"
        fi
    }

    case "$CLIENT" in
        bambu_studio)
            case "$OS" in
                Linux)
                    add_candidate "Bambu Studio" \
                        "BambuStudio.conf" "version" \
                        "${HOME}/.config/BambuStudio"
                    add_candidate "Bambu Studio (Flatpak)" \
                        "BambuStudio.conf" "version" \
                        "${HOME}/.var/app/com.bambulab.BambuStudio/config/BambuStudio"
                    add_candidate "Bambu Studio Beta" \
                        "BambuStudio.conf" "version" \
                        "${HOME}/.config/BambuStudioBeta"
                    add_candidate "Bambu Studio Beta (Flatpak)" \
                        "BambuStudio.conf" "version" \
                        "${HOME}/.var/app/com.bambulab.BambuStudioBeta/config/BambuStudioBeta"
                    ;;
                Darwin)
                    add_candidate "Bambu Studio" \
                        "BambuStudio.conf" "version" \
                        "${HOME}/Library/Application Support/BambuStudio"
                    add_candidate "Bambu Studio Beta" \
                        "BambuStudio.conf" "version" \
                        "${HOME}/Library/Application Support/BambuStudioBeta"
                    ;;
            esac
            ;;
        orca_slicer)
            case "$OS" in
                Linux)
                    add_candidate "Orca Slicer" \
                        "OrcaSlicer.conf" "network_plugin_version" \
                        "${HOME}/.config/OrcaSlicer"
                    add_candidate "Orca Slicer (Flatpak)" \
                        "OrcaSlicer.conf" "network_plugin_version" \
                        "${HOME}/.var/app/com.orcaslicer.OrcaSlicer/config/OrcaSlicer"
                    ;;
                Darwin)
                    add_candidate "Orca Slicer" \
                        "OrcaSlicer.conf" "network_plugin_version" \
                        "${HOME}/Library/Application Support/OrcaSlicer"
                    ;;
            esac
            ;;
    esac
}

build_candidates

if [ "$N_CANDIDATES" -eq 0 ]; then
    die "$CLIENT_LABEL config directory not found.
  Launch $CLIENT_LABEL at least once to create its config, then re-run this installer."
fi

if [ "$N_CANDIDATES" -eq 1 ]; then
    # Single candidate — use it directly
    CHOSEN_LINE=$(printf '%s' "$CANDIDATES" | head -n1)
else
    # Multiple candidates — let the user pick
    printf "Multiple installations found:\n"
    printf '%s' "$CANDIDATES" | while IFS='|' read -r num label _ _ dir_path; do
        printf "  ${BOLD}%s${RESET}) %s (%s)\n" "$num" "$label" "$dir_path"
    done
    printf "\nChoice [1]: "
    read -r pick
    pick="${pick:-1}"
    CHOSEN_LINE=$(printf '%s' "$CANDIDATES" | sed -n "${pick}p")
    if [ -z "$CHOSEN_LINE" ]; then
        die "Invalid choice: $pick"
    fi
fi

# Parse the chosen candidate
CLIENT_LABEL=$(printf '%s' "$CHOSEN_LINE" | cut -d'|' -f2)
CONF_NAME=$(printf '%s' "$CHOSEN_LINE" | cut -d'|' -f3)
VERSION_KEY=$(printf '%s' "$CHOSEN_LINE" | cut -d'|' -f4)
PREFIX=$(printf '%s' "$CHOSEN_LINE" | cut -d'|' -f5)
echo ""

if [ -z "$PREFIX" ] || [ ! -d "$PREFIX" ]; then
    die "$CLIENT_LABEL config directory not found.
  Launch $CLIENT_LABEL at least once to create its config, then re-run this installer."
fi

# ── ABI version detection ────────────────────────────────────────────────

LIB_DIR="$SCRIPT_DIR/lib"
if [ ! -d "$LIB_DIR" ]; then
    die "lib/ directory not found next to this script"
fi

CONF_FILE="$PREFIX/$CONF_NAME"

if [ "$CLIENT" = "orca_slicer" ]; then
    # Orca Slicer: always use 02.03.00 ABI (the version Orca ships by default).
    # The installer patches OrcaSlicer.conf to match, so the user does not need
    # to pick a specific network_plugin_version in Preferences.
    ABI_PREFIX="02.03.00"
    DETECTED_SOURCE="fixed"
else
    # Bambu Studio: detect version from slicer conf.
    if [ ! -f "$CONF_FILE" ]; then
        die "$CONF_NAME not found at $CONF_FILE
  Launch $CLIENT_LABEL at least once to create its config, then re-run this installer."
    fi

    DETECTED_VER=$(sed -n \
        "s/^[[:space:]]*\"${VERSION_KEY}\"[[:space:]]*:[[:space:]]*\"\([0-9][0-9.]*\)\".*/\1/p" \
        "$CONF_FILE" | head -n1)

    if [ -n "$DETECTED_VER" ]; then
        DETECTED_SOURCE="$CLIENT_LABEL v$DETECTED_VER"
    fi

    if [ -z "$DETECTED_VER" ]; then
        die "Cannot determine ABI version: key \"$VERSION_KEY\" not found in $CONF_FILE."
    fi

    # Extract major.minor.patch (first 3 components)
    ABI_PREFIX=$(echo "$DETECTED_VER" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/')
fi

PLUGIN_VER="${ABI_PREFIX}.99"

# ── Match available ABI directory ────────────────────────────────────────

MATCHED_DIR="$LIB_DIR/v${ABI_PREFIX}"

if [ ! -d "$MATCHED_DIR" ]; then
    AVAILABLE=$(ls -d "$LIB_DIR"/v*/ 2>/dev/null | xargs -I{} basename {} | sed 's/^v//' | tr '\n' ' ')
    die "No compatible ABI version for $DETECTED_SOURCE (need ${ABI_PREFIX}).
  Available in this package: ${AVAILABLE:-none}
  You may need a newer distribution package from GitHub."
fi

MATCHED_VER=$(basename "$MATCHED_DIR" | sed 's/^v//')
PLUGIN_VER="${MATCHED_VER}.99"

# ── Confirmation ─────────────────────────────────────────────────────────

DEST_DIR="$PREFIX/plugins"

printf "${BOLD}Installation summary:${RESET}\n"
printf "  Slicer:       %s\n" "$CLIENT_LABEL"
printf "  Config dir:   %s\n" "$PREFIX"
printf "  ABI version:  %s (%s)\n" "$MATCHED_VER" "$DETECTED_SOURCE"
printf "  Install to:   %s\n" "$DEST_DIR"
echo ""
warn "Close $CLIENT_LABEL before proceeding. If it is running, it will overwrite the patched config on exit."
echo ""
prompt_yn "Proceed?" || { echo "Aborted."; exit 0; }
echo ""

# ── Install binaries ─────────────────────────────────────────────────────

mkdir -p "$DEST_DIR"

case "$OS" in
    Linux)
        PLUGIN_EXT=".so"
        BAMBUSOURCE_NAME="libBambuSource.so"
        LIVE555_NAME="liblive555.so"
        ;;
    Darwin)
        PLUGIN_EXT=".dylib"
        BAMBUSOURCE_NAME="libBambuSource.dylib"
        LIVE555_NAME="liblive555.dylib"
        ;;
esac

case "$CLIENT" in
    bambu_studio)
        PLUGIN_DEST_NAME="libbambu_networking${PLUGIN_EXT}"
        ;;
    orca_slicer)
        PLUGIN_DEST_NAME="libbambu_networking_${PLUGIN_VER}${PLUGIN_EXT}"
        ;;
esac

# Main plugin
SRC_PLUGIN=$(ls "$MATCHED_DIR"/libbambu_networking${PLUGIN_EXT} 2>/dev/null | head -1)
if [ -z "$SRC_PLUGIN" ]; then
    die "Plugin binary not found in $MATCHED_DIR"
fi
cp "$SRC_PLUGIN" "$DEST_DIR/$PLUGIN_DEST_NAME"
info "Installed $PLUGIN_DEST_NAME"

# BambuSource
if [ -f "$MATCHED_DIR/$BAMBUSOURCE_NAME" ]; then
    cp "$MATCHED_DIR/$BAMBUSOURCE_NAME" "$DEST_DIR/$BAMBUSOURCE_NAME"
    info "Installed $BAMBUSOURCE_NAME"
fi

# live555 stub — only install if no existing large file
if [ -f "$MATCHED_DIR/$LIVE555_NAME" ]; then
    INSTALL_LIVE555=true
    if [ -f "$DEST_DIR/$LIVE555_NAME" ]; then
        existing_size=$(wc -c < "$DEST_DIR/$LIVE555_NAME" | tr -d ' ')
        if [ "$existing_size" -gt 65536 ]; then
            INSTALL_LIVE555=false
            info "Keeping existing $LIVE555_NAME (${existing_size} bytes, looks like vendor build)"
        fi
    fi
    if [ "$INSTALL_LIVE555" = true ]; then
        cp "$MATCHED_DIR/$LIVE555_NAME" "$DEST_DIR/$LIVE555_NAME"
        info "Installed $LIVE555_NAME"
    fi
fi

# OTA manifest (Bambu Studio only)
if [ "$CLIENT" = "bambu_studio" ] && [ -f "$MATCHED_DIR/network_plugins.json" ]; then
    mkdir -p "$PREFIX/ota/plugins"
    cp "$MATCHED_DIR/network_plugins.json" "$PREFIX/ota/plugins/network_plugins.json"
    info "Installed ota/plugins/network_plugins.json"
fi

# ── Patch slicer conf ────────────────────────────────────────────────────

patch_conf() {
    if [ ! -f "$CONF_FILE" ]; then
        die "$CONF_NAME not found at $CONF_FILE
  Launch $CLIENT_LABEL at least once to create it, then re-run this installer."
    fi

    # Python is available on virtually all Linux/macOS systems and gives us
    # reliable JSON manipulation without depending on jq.
    if ! command -v python3 >/dev/null 2>&1; then
        warn "python3 not found — skipping conf patch. Set the keys manually."
        return
    fi

    python3 - "$CONF_FILE" "$CLIENT" "$PLUGIN_VER" "$OS" <<'PYEOF'
import json, sys, os, re, shutil

conf_path, client, plugin_ver, os_name = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

with open(conf_path, 'r') as f:
    raw = f.read()

# Strip trailing MD5 checksum line for comparison
raw_json = re.sub(r'[\r\n]+# MD5 checksum[^\r\n]*[\r\n]*$', '', raw)

try:
    conf = json.loads(raw_json)
except json.JSONDecodeError:
    print(f"  [warn] Cannot parse {conf_path} as JSON, skipping patch", file=sys.stderr)
    sys.exit(0)

if 'app' not in conf or not isinstance(conf['app'], dict):
    print(f"  [warn] No 'app' object in {conf_path}, skipping patch", file=sys.stderr)
    sys.exit(0)

changed = False

if client == 'bambu_studio':
    for key, val in [('installed_networking', '1'), ('update_network_plugin', 'false')]:
        if conf['app'].get(key) != val:
            conf['app'][key] = val
            changed = True
    if os_name == 'Darwin':
        if conf['app'].get('ignore_module_cert') != '1':
            conf['app']['ignore_module_cert'] = '1'
            changed = True
else:  # orca_slicer
    patches = [
        ('installed_networking', 'true'),
        ('network_plugin_version', plugin_ver),
        ('network_plugin_remind_later', 'true'),
    ]
    if os_name == 'Darwin':
        patches.append(('ignore_module_cert', '1'))
    for key, val in patches:
        if conf['app'].get(key) != val:
            conf['app'][key] = val
            changed = True
    # Strip plugin_ver from skipped versions
    skipped = conf['app'].get('network_plugin_skipped_versions', '')
    if skipped and plugin_ver in skipped:
        parts = [v for v in skipped.split(';') if v and v != plugin_ver]
        new_skipped = ';'.join(parts)
        if new_skipped != skipped:
            conf['app']['network_plugin_skipped_versions'] = new_skipped
            changed = True

if not changed:
    print("  [info] Slicer conf already patched, no changes needed")
    sys.exit(0)

# Backup original
shutil.copy2(conf_path, conf_path + '.obn-bak')

new_json = json.dumps(conf, indent=4, ensure_ascii=False)
with open(conf_path, 'w') as f:
    f.write(new_json)
    f.write('\n# MD5 checksum 00000000000000000000000000000000\n')

print(f"  [info] Patched {os.path.basename(conf_path)} (backup: {os.path.basename(conf_path)}.obn-bak)")
PYEOF
}

patch_conf

# ── Summary ──────────────────────────────────────────────────────────────

OBN_CONF="$PREFIX/obn.conf"

printf "\n${BOLD}${GREEN}Installation complete!${RESET}\n\n"
printf "  Plugin:     %s\n" "$DEST_DIR/$PLUGIN_DEST_NAME"
printf "  Config:     %s\n" "$OBN_CONF"
printf "  Slicer:     %s (%s)\n" "$CLIENT_LABEL" "$PREFIX"
echo ""
printf "Next steps:\n"
printf "  1. Launch %s — it should load the open-bamboo-networking plugin\n" "$CLIENT_LABEL"
printf "  2. Edit %s to customize plugin behavior (created on first launch)\n" "$OBN_CONF"
echo ""
printf "GitHub: ${BOLD}https://github.com/ClusterM/open-bamboo-networking${RESET}\n\n"
