#!/bin/sh
# Open Bambu Networking — interactive installer for Linux and macOS.
# Ships inside the distribution archive next to lib/vXX.XX.XX/ directories.
# Detects the slicer, matches the ABI version, copies binaries, patches
# the slicer conf, and drops a default obn.conf if absent.
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

printf "\n${BOLD}Open Bambu Networking — Installer${RESET}\n\n"
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

# resolve_dirs <conf_name> <version_key> <dir_suffix>
# Sets CONF_NAME, VERSION_KEY, and populates candidate arrays.
resolve_dirs() {
    CONF_NAME="$1"
    VERSION_KEY="$2"
    local suffix="$3"
    NATIVE_DIR="${HOME}/.config/${suffix}"
    FLATPAK_DIR="${HOME}/.var/app/com.bambulab.${suffix}/config/${suffix}"
    MAC_DIR="${HOME}/Library/Application Support/${suffix}"
}

# find_prefix: pick PREFIX from the candidate dirs for the current OS.
find_prefix() {
    PREFIX=""
    case "$OS" in
        Linux)
            if [ -d "$NATIVE_DIR" ]; then
                PREFIX="$NATIVE_DIR"
            elif [ -d "$FLATPAK_DIR" ]; then
                PREFIX="$FLATPAK_DIR"
                info "Detected Flatpak install"
            fi
            ;;
        Darwin)
            if [ -d "$MAC_DIR" ]; then
                PREFIX="$MAC_DIR"
            fi
            ;;
    esac
}

case "$CLIENT" in
    bambu_studio)
        # Check whether both stable and beta directories exist
        resolve_dirs "BambuStudio.conf" "version" "BambuStudio"
        STABLE_NATIVE="$NATIVE_DIR"; STABLE_FLATPAK="$FLATPAK_DIR"; STABLE_MAC="$MAC_DIR"
        resolve_dirs "BambuStudio.conf" "version" "BambuStudioBeta"
        BETA_NATIVE="$NATIVE_DIR"; BETA_FLATPAK="$FLATPAK_DIR"; BETA_MAC="$MAC_DIR"

        HAS_STABLE=false; HAS_BETA=false
        case "$OS" in
            Linux)
                { [ -d "$STABLE_NATIVE" ] || [ -d "$STABLE_FLATPAK" ]; } && HAS_STABLE=true
                { [ -d "$BETA_NATIVE" ]   || [ -d "$BETA_FLATPAK" ];   } && HAS_BETA=true
                ;;
            Darwin)
                [ -d "$STABLE_MAC" ] && HAS_STABLE=true
                [ -d "$BETA_MAC" ]   && HAS_BETA=true
                ;;
        esac

        if [ "$HAS_STABLE" = true ] && [ "$HAS_BETA" = true ]; then
            printf "Both Bambu Studio and Bambu Studio Beta configs found.\n"
            printf "  ${BOLD}1${RESET}) Bambu Studio (stable)\n"
            printf "  ${BOLD}2${RESET}) Bambu Studio Beta\n"
            printf "\nChoice [1]: "
            read -r edition
            case "$edition" in
                2)
                    CLIENT_LABEL="Bambu Studio Beta"
                    resolve_dirs "BambuStudio.conf" "version" "BambuStudioBeta"
                    ;;
                *)
                    resolve_dirs "BambuStudio.conf" "version" "BambuStudio"
                    ;;
            esac
        elif [ "$HAS_BETA" = true ]; then
            CLIENT_LABEL="Bambu Studio Beta"
            resolve_dirs "BambuStudio.conf" "version" "BambuStudioBeta"
        else
            resolve_dirs "BambuStudio.conf" "version" "BambuStudio"
        fi
        ;;
    orca_slicer)
        resolve_dirs "OrcaSlicer.conf" "network_plugin_version" "OrcaSlicer"
        ;;
esac

find_prefix

# If no existing directory found, default to the standard path
if [ -z "$PREFIX" ]; then
    case "$CLIENT" in
        bambu_studio)
            case "$OS" in
                Linux)  PREFIX="${HOME}/.config/BambuStudio" ;;
                Darwin) PREFIX="${HOME}/Library/Application Support/BambuStudio" ;;
            esac
            ;;
        orca_slicer)
            case "$OS" in
                Linux)  PREFIX="${HOME}/.config/OrcaSlicer" ;;
                Darwin) PREFIX="${HOME}/Library/Application Support/OrcaSlicer" ;;
            esac
            ;;
    esac
fi

if [ -z "$PREFIX" ]; then
    die "Could not determine config directory for $CLIENT_LABEL"
fi

# ── ABI version detection ────────────────────────────────────────────────

CONF_FILE="$PREFIX/$CONF_NAME"
DETECTED_VER=""
if [ -r "$CONF_FILE" ]; then
    DETECTED_VER=$(sed -n \
        "s/^[[:space:]]*\"${VERSION_KEY}\"[[:space:]]*:[[:space:]]*\"\([0-9][0-9.]*\)\".*/\1/p" \
        "$CONF_FILE" | head -n1)
fi

if [ -z "$DETECTED_VER" ] && [ "$CLIENT" = "orca_slicer" ]; then
    DETECTED_VER="02.03.00"
    warn "No $VERSION_KEY in $CONF_FILE — defaulting to $DETECTED_VER"
fi

if [ -z "$DETECTED_VER" ]; then
    die "Cannot determine ABI version from $CONF_FILE.
  Launch $CLIENT_LABEL at least once to create its config, then re-run this installer."
fi

# Extract major.minor.patch (first 3 components)
ABI_PREFIX=$(echo "$DETECTED_VER" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/')
PLUGIN_VER="${ABI_PREFIX}.99"

# ── Match available ABI directory ────────────────────────────────────────

LIB_DIR="$SCRIPT_DIR/lib"
if [ ! -d "$LIB_DIR" ]; then
    die "lib/ directory not found next to this script"
fi

# List available versions sorted, try exact match first
MATCHED_DIR=""
if [ -d "$LIB_DIR/v${ABI_PREFIX}" ]; then
    MATCHED_DIR="$LIB_DIR/v${ABI_PREFIX}"
fi

if [ -z "$MATCHED_DIR" ]; then
    # Fall back: pick the highest version <= detected
    for d in "$LIB_DIR"/v*/; do
        [ -d "$d" ] || continue
        v=$(basename "$d" | sed 's/^v//')
        if [ "$(printf '%s\n%s' "$v" "$ABI_PREFIX" | sort -V | tail -1)" = "$ABI_PREFIX" ]; then
            MATCHED_DIR="$d"
        fi
    done
fi

if [ -z "$MATCHED_DIR" ] || [ ! -d "$MATCHED_DIR" ]; then
    AVAILABLE=$(ls -d "$LIB_DIR"/v*/ 2>/dev/null | xargs -I{} basename {} | sed 's/^v//' | tr '\n' ' ')
    die "No compatible ABI version for $CLIENT_LABEL v${DETECTED_VER} (need ${ABI_PREFIX}).
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
printf "  ABI version:  %s (detected %s v%s)\n" "$MATCHED_VER" "$CLIENT_LABEL" "$DETECTED_VER"
printf "  Install to:   %s\n" "$DEST_DIR"
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

# ── Create default obn.conf if absent ────────────────────────────────────

OBN_CONF="$PREFIX/obn.conf"
if [ ! -f "$OBN_CONF" ]; then
    if [ -f "$SCRIPT_DIR/obn.conf.in" ]; then
        cp "$SCRIPT_DIR/obn.conf.in" "$OBN_CONF"
    else
        die "obn.conf.in not found next to install.sh"
    fi
    info "Created default obn.conf"
fi

# ── Summary ──────────────────────────────────────────────────────────────

printf "\n${BOLD}${GREEN}Installation complete!${RESET}\n\n"
printf "  Plugin:     %s\n" "$DEST_DIR/$PLUGIN_DEST_NAME"
printf "  Config:     %s\n" "$OBN_CONF"
printf "  Slicer:     %s (%s)\n" "$CLIENT_LABEL" "$PREFIX"
echo ""
printf "Next steps:\n"
printf "  1. Close %s if it is running\n" "$CLIENT_LABEL"
printf "  2. Launch %s — it should load the open-bambu-networking plugin\n" "$CLIENT_LABEL"
printf "  3. Edit %s to customize plugin behavior\n" "$OBN_CONF"
echo ""
printf "GitHub: ${BOLD}https://github.com/ClusterM/open-bambu-networking${RESET}\n\n"
