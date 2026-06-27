#!/bin/bash
set -e
cd "$(dirname "$0")"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "error: this tool only runs on Linux" >&2
    exit 1
fi

# Install build and runtime dependencies.
if command -v apt-get >/dev/null 2>&1; then
    if [[ $EUID -eq 0 ]]; then
        apt-get install -y \
            build-essential cmake ninja-build xxd curl unzip \
            libssl-dev libcurl4-openssl-dev zlib1g-dev
    else
        sudo apt-get install -y \
            build-essential cmake ninja-build xxd curl unzip \
            libssl-dev libcurl4-openssl-dev zlib1g-dev
    fi
else
    echo "warning: apt-get not found — ensure these are installed:" >&2
    echo "  build-essential cmake ninja-build xxd curl unzip" >&2
    echo "  libssl-dev libcurl4-openssl-dev zlib1g-dev" >&2
fi

make -j"$(nproc)"

echo ""
./bambu_extract_d --out slicer_key.pem "$@"
