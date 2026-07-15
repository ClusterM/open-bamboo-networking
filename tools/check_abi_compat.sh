#!/bin/sh
# ABI-compatibility checker for open-bamboo-networking.
#
# Baselines live under tools/abi_snapshot/vMM.mm.pp/ (first three version
# components of a Studio git tag, e.g. v02.06.00.51 -> v02.06.00). That
# matches Studio's networking compatibility gate (first 8 chars of the
# version string, e.g. "02.06.00").
#
# The checker runs four read-only tests (plus optional nm on a built .so):
#
#   1. upstream vs snapshot: bambu_networking.hpp — struct / enum / typedefs.
#      Before compare, BAMBU_NETWORK_AGENT_VERSION's last dotted component is
#      replaced with "xx" on both sides so patch bumps do not false-fail.
#
#   2. upstream vs snapshot: NetworkAgent.hpp (func_* typedefs for dlsym).
#
#   3. upstream vs snapshot: sorted bambu_network_* symbols from
#      NetworkAgent.cpp dlsym calls.
#
#   4. Repo: tests/probe_plugin.cpp symbol list vs snapshot symbols.txt.
#
# We intentionally do NOT byte-compare include/obn/bambu_networking.hpp to
# the snapshot (variant A): the vendored header uses ABI_VERSION-gated
# fields and omits BAMBU_NETWORK_AGENT_VERSION; drift vs upstream is caught
# by (1) and by compiling the plugin with the right ABI_VERSION from CMake.
#
# Upstream headers are always downloaded from raw.githubusercontent.com (curl;
# needs network). With no --tag, the newest v* tag is taken from GitHub via
# git ls-remote.
#
# Usage:
#   tools/check_abi_compat.sh
#   tools/check_abi_compat.sh --tag=v02.06.00.51
#   tools/check_abi_compat.sh --so=build/libbambu_networking.so
#   tools/check_abi_compat.sh --abi=02.06.00 --so=build/libbambu_networking.so
#   tools/check_abi_compat.sh --refresh [--tag=...]
#
# --abi=MM.mm.pp performs a local-only verification against the snapshot for
# that exact ABI series: it never contacts upstream and never compares against
# other ABI versions. This is what CI build jobs use so a plugin built for one
# ABI is not checked against a different (e.g. newer) ABI's symbol list.

set -eu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SNAP_ROOT="$REPO/tools/abi_snapshot"
UPSTREAM_REPO="bambulab/BambuStudio"

MODE="compare"
TAG=""
SO_PATH=""
ABI=""

usage() {
    sed -n '3,42p' "$0" | sed 's/^# \{0,1\}//'
}

for arg in "$@"; do
    case "$arg" in
        --tag=*)       TAG="${arg#*=}" ;;
        --refresh)     MODE="refresh" ;;
        --so=*)        SO_PATH="${arg#*=}" ;;
        --abi=*)       ABI="${arg#*=}" ;;
        -h|--help)     usage; exit 0 ;;
        *) echo "check_abi_compat: unknown option: $arg" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -n "$ABI" ] && [ "$MODE" = "refresh" ]; then
    echo "check_abi_compat: --abi cannot be combined with --refresh (refresh needs upstream)" >&2
    exit 2
fi
if [ -n "$ABI" ] && [ -n "$TAG" ]; then
    echo "check_abi_compat: --abi cannot be combined with --tag" >&2
    exit 2
fi
if [ -n "$ABI" ] && [ -z "$SO_PATH" ]; then
    echo "check_abi_compat: --abi requires --so=<built plugin> (nothing else to verify locally)" >&2
    exit 2
fi

# Strip trailing "-<n>-g<hash>" from `git describe` style tags.
sanitize_tag_for_series() {
    printf '%s' "$1" | sed -E 's/-[0-9]+-g[0-9a-fA-F]+$//'
}

# v02.06.00.51 or 02.06.00.51 -> v02.06.00
abi_series_from_tag() {
    t=$(sanitize_tag_for_series "$1")
    case "$t" in
        v*) raw="${t#v}" ;;
        *)  raw="$t" ;;
    esac
    oldIFS=$IFS
    IFS=.
    # shellcheck disable=SC2086
    set -- $raw
    IFS=$oldIFS
    if [ "$#" -lt 3 ]; then
        echo "check_abi_compat: cannot derive snapshot series from tag '$1' (need MM.mm.pp[.rr])" >&2
        exit 1
    fi
    printf 'v%s.%s.%s\n' "$1" "$2" "$3"
}

# Copy bambu_networking.hpp and normalize BAMBU_NETWORK_AGENT_VERSION last
# component to xx (only on the #define line).
normalize_bambu_net_hpp() {
    in="$1"
    out="$2"
    perl -pe 'if(/^#define\s+BAMBU_NETWORK_AGENT_VERSION\s/) {
        s/"(\d+\.\d+\.\d+)\.\d+"/"$1.xx"/;
    }' "$in" > "$out"
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

resolve_tag() {
    if [ -n "$TAG" ]; then
        echo "$TAG"
        return
    fi
    git ls-remote --tags --refs "https://github.com/$UPSTREAM_REPO.git" 'refs/tags/v*' 2>/dev/null \
        | awk -F/ '{print $NF}' \
        | sort -V \
        | tail -n1
}

fetch_upstream_file() {
    path="$1"; dst="$2"
    url="https://raw.githubusercontent.com/$UPSTREAM_REPO/$TAG/$path"
    if ! curl -fsSL "$url" -o "$dst"; then
        echo "check_abi_compat: cannot fetch $url" >&2
        exit 1
    fi
}

# In --abi mode we only verify the built plugin (and repo self-consistency)
# against a specific local snapshot series. No upstream tag resolution, no
# network fetch, and no comparison against any other ABI version.
if [ -n "$ABI" ]; then
    SERIES="v$ABI"
    SNAP="$SNAP_ROOT/$SERIES"
    if [ ! -d "$SNAP" ]; then
        echo "check_abi_compat: no snapshot directory for series '$SERIES' (--abi=$ABI)" >&2
        echo "check_abi_compat: expected: $SNAP" >&2
        echo "check_abi_compat: existing series under $SNAP_ROOT/:" >&2
        ls -1 "$SNAP_ROOT" 2>/dev/null | sed 's/^/  /' >&2 || true
        exit 1
    fi
else
    [ -n "$TAG" ] || TAG=$(resolve_tag)
    if [ -z "$TAG" ]; then
        echo "check_abi_compat: could not resolve an upstream tag (git ls-remote failed?)" >&2
        exit 1
    fi
    upstream_base="github.com/$UPSTREAM_REPO@$TAG"

    SERIES=$(abi_series_from_tag "$TAG" || exit 1)
    SNAP="$SNAP_ROOT/$SERIES"
    if [ ! -d "$SNAP" ]; then
        echo "check_abi_compat: no snapshot directory for series '$SERIES' (tag=$TAG)" >&2
        echo "check_abi_compat: expected: $SNAP" >&2
        echo "check_abi_compat: existing series under $SNAP_ROOT/:" >&2
        ls -1 "$SNAP_ROOT" 2>/dev/null | sed 's/^/  /' >&2 || true
        echo "check_abi_compat: add tools/abi_snapshot/$SERIES/ or run --refresh --tag=..." >&2
        exit 1
    fi

    mkdir -p "$WORK/live"
    fetch_upstream_file src/slic3r/Utils/bambu_networking.hpp "$WORK/live/bambu_networking.hpp"
    fetch_upstream_file src/slic3r/Utils/NetworkAgent.hpp     "$WORK/live/NetworkAgent.hpp"
    fetch_upstream_file src/slic3r/Utils/NetworkAgent.cpp     "$WORK/live/NetworkAgent.cpp"

    grep -oE 'get_network_function\("bambu_network_[a-zA-Z_0-9]+"\)' "$WORK/live/NetworkAgent.cpp" \
        | sed -E 's/^get_network_function\("//; s/"\)$//' \
        | LC_ALL=C sort -u > "$WORK/live/symbols.txt"

    normalize_bambu_net_hpp "$WORK/live/bambu_networking.hpp" "$WORK/live/bambu_networking.norm.hpp"
fi

# --- refresh mode -----------------------------------------------------------

if [ "$MODE" = "refresh" ]; then
    mkdir -p "$SNAP"
    cp "$WORK/live/bambu_networking.norm.hpp" "$SNAP/bambu_networking.hpp"
    cp "$WORK/live/NetworkAgent.hpp"         "$SNAP/NetworkAgent.hpp"
    LC_ALL=C sort -u "$WORK/live/symbols.txt" > "$SNAP/symbols.txt"
    printf '%s\n' "$TAG" > "$SNAP/SOURCE_TAG"
    cat <<EOF
check_abi_compat: refreshed $SNAP/ from $upstream_base

Next steps:
    1. Port any struct/callback changes into include/obn/bambu_networking.hpp
       (ABI_VERSION gates + drop BAMBU_NETWORK_AGENT_VERSION as needed).
    2. Update tests/probe_plugin.cpp if the symbol list changed.
    3. Re-run ./configure and make test to confirm everything still builds.
    4. Commit the snapshot + code changes together.
EOF
    exit 0
fi

# --- comparisons ------------------------------------------------------------

FAIL=0

if [ -n "$ABI" ]; then
    echo "Local ABI verification (no upstream comparison)"
else
    echo "Comparing against $upstream_base"
fi
echo "Snapshot series: $SERIES  (tag: $(cat "$SNAP/SOURCE_TAG" 2>/dev/null || echo '<no SOURCE_TAG>'))"
echo

report_diff() {
    label="$1"; expected="$2"; actual="$3"; hint="$4"
    if cmp -s "$expected" "$actual"; then
        printf '  [PASS] %s\n' "$label"
        return 0
    fi
    printf '  [FAIL] %s\n' "$label"
    printf '         %s\n' "$hint"
    echo   '         --- diff ---'
    diff -u "$expected" "$actual" | sed 's/^/         /'
    echo   '         ------------'
    FAIL=1
    return 1
}

report_missing() {
    label="$1"; expected="$2"; actual="$3"; hint="$4"; mode="${5:-exact}"
    sorted_expected="$WORK/$(basename "$expected").sorted"
    sorted_actual="$WORK/$(basename "$actual").sorted"
    LC_ALL=C sort -u "$expected" > "$sorted_expected"
    LC_ALL=C sort -u "$actual" > "$sorted_actual"
    missing=$(comm -23 "$sorted_expected" "$sorted_actual" || true)
    extra=$(comm -13 "$sorted_expected" "$sorted_actual" || true)
    if [ -z "$missing" ] && [ -z "$extra" ]; then
        printf '  [PASS] %s\n' "$label"
        return 0
    fi
    if [ "$mode" = 'superset' ] && [ -z "$missing" ]; then
        printf '  [PASS] %s (with %d unreferenced extras)\n' \
            "$label" "$(echo "$extra" | grep -c .)"
        printf  '         note: these symbols are exported but Studio does not resolve them at %s:\n' "${TAG:-$SERIES}"
        printf  '           %s\n' $extra
        return 0
    fi
    printf '  [FAIL] %s\n' "$label"
    printf '         %s\n' "$hint"
    if [ -n "$missing" ]; then
        echo   '         missing (in snapshot, not in actual):'
        printf  '           %s\n' $missing
    fi
    if [ -n "$extra" ] && [ "$mode" != 'superset' ]; then
        echo   '         extra (in actual, not in snapshot):'
        printf  '           %s\n' $extra
    fi
    FAIL=1
    return 1
}

if [ -z "$ABI" ]; then
    normalize_bambu_net_hpp "$SNAP/bambu_networking.hpp" "$WORK/snap_bambu.norm.hpp"

    echo 'Upstream vs snapshot:'
    report_diff 'bambu_networking.hpp (agent version ignored)' \
        "$WORK/snap_bambu.norm.hpp" "$WORK/live/bambu_networking.norm.hpp" \
        "Upstream changed structs/enums/callback typedefs. Port to include/obn/bambu_networking.hpp, then tools/check_abi_compat.sh --refresh --tag=$TAG"
    report_diff 'NetworkAgent.hpp (func_* typedef source)' \
        "$SNAP/NetworkAgent.hpp" "$WORK/live/NetworkAgent.hpp" \
        "Upstream changed a func_* typedef signature or added a new one. Re-check plugin implementations, then tools/check_abi_compat.sh --refresh --tag=$TAG"
    report_missing 'bambu_network_* symbol list (NetworkAgent.cpp dlsym calls)' \
        "$SNAP/symbols.txt" "$WORK/live/symbols.txt" \
        "Upstream added / removed ABI slots. Implement missing ones in src/abi_*.cpp, add them to tests/probe_plugin.cpp, then --refresh."

    echo
fi

# Repo self-consistency (probe_plugin.cpp vs snapshot symbol list) is a
# source-side check tied to the newest ABI and owned by the nightly abi-compat
# workflow. In --abi mode we skip it: tests/probe_plugin.cpp legitimately lists
# symbols from newer ABIs that an older-ABI snapshot does not contain.
if [ -z "$ABI" ]; then
    echo 'Repo self-consistency:'

    awk '
        /kBambuNetworkSymbols\[\]/      { inside = 1; next }
        inside && /\};/                 { inside = 0; next }
        inside                          {
            while (match($0, /"bambu_network_[a-zA-Z0-9_]+"/)) {
                print substr($0, RSTART + 1, RLENGTH - 2)
                $0 = substr($0, RSTART + RLENGTH)
            }
        }
    ' "$REPO/tests/probe_plugin.cpp" | LC_ALL=C sort -u > "$WORK/probe_symbols.txt"

    report_missing 'tests/probe_plugin.cpp symbol list' \
        "$SNAP/symbols.txt" "$WORK/probe_symbols.txt" \
        "The kBambuNetworkSymbols[] array in tests/probe_plugin.cpp is out of sync with the snapshot."
fi

if [ -n "$SO_PATH" ]; then
    echo
    echo 'Built plugin:'
    if [ ! -f "$SO_PATH" ]; then
        printf '  [FAIL] %s does not exist; build the plugin first.\n' "$SO_PATH"
        FAIL=1
    else
        UNAME_S=$(uname -s 2>/dev/null || printf '%s' '')
        if [ "$UNAME_S" = Darwin ]; then
            # Mach-O: no ELF dynamic symtab; -gU lists globals defined in the image.
            nm -gU "$SO_PATH" 2>/dev/null \
                | awk '{print $NF}' \
                | sed 's/^_//' \
                | grep -E '^bambu_network_' \
                | LC_ALL=C sort -u > "$WORK/so_symbols.txt"
        else
            nm -D --defined-only "$SO_PATH" 2>/dev/null \
                | awk '$2=="T" || $2=="W" {print $3}' \
                | grep -E '^bambu_network_' \
                | LC_ALL=C sort -u > "$WORK/so_symbols.txt"
        fi
        report_missing "$(basename "$SO_PATH") exports every snapshot symbol" \
            "$SNAP/symbols.txt" "$WORK/so_symbols.txt" \
            "Some bambu_network_* symbols declared in the snapshot are NOT exported by the built .so. Studio would crash when dlsym returns NULL." \
            'superset'
    fi
fi

echo
if [ "$FAIL" -eq 0 ]; then
    echo 'ABI OK.'
    exit 0
fi

if [ -n "$ABI" ]; then
    cat <<EOF
ABI verification failed for series $SERIES.

The plugin built for ABI $ABI does not export every symbol listed in
$SNAP/symbols.txt. Implement the missing bambu_network_* slots in src/abi_*.cpp
for this ABI version.
EOF
    exit 1
fi

cat <<EOF
ABI drift detected.

To review and accept upstream changes (after porting them into the plugin):
    tools/check_abi_compat.sh --refresh --tag=$TAG

To pin CI to a fixed upstream tag instead of latest:
    Pass --tag=... in .github/workflows/build.yml abi-compat job.
EOF
exit 1
