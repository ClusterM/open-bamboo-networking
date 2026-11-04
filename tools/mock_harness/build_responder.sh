#!/usr/bin/env bash
# Build the clean-room :3000 detect sidecar (plan 04-02) into the gitignored
# .cache/mock_harness/build-responder/ tree. Run from anywhere; works inside
# WSL (D-07 venue). Idempotent: re-running reconfigures and rebuilds.
set -euo pipefail

cd "$(dirname "$0")/../.."   # repo root (bambu_network_oss)
BUILD_DIR=".cache/mock_harness/build-responder"

GEN_ARGS=()
if command -v ninja >/dev/null 2>&1; then
    GEN_ARGS=(-G Ninja)
fi

cmake -S tools/mock_harness -B "$BUILD_DIR" "${GEN_ARGS[@]}" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build "$BUILD_DIR"
test -x "$BUILD_DIR/detect_responder"
echo "[build_responder] built $BUILD_DIR/detect_responder"
