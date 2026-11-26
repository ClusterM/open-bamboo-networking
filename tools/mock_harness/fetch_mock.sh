#!/usr/bin/env bash
# fetch_mock.sh — fetch + build the openbu-mock external binary.
#
# Facts-only / external-binary-only: openbu-mock has NO LICENSE, so this script
# only clones into the gitignored .cache/openbu-mock/ and builds a binary there.
# Nothing from the clone is ever `git add`ed (this script never calls git add).
#
# BUILD_PATH: docker-golang
set -euo pipefail

MOCK_REPO="https://github.com/cygnusx-1-org/openbu-mock"
MOCK_PIN="e3db0ce7341f467e656cc860f1a0625c548a8f56"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBN_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MOCK_DIR="${OBN_ROOT}/.cache/openbu-mock"
SRC_DIR="${MOCK_DIR}/src"
OUT_DIR="${MOCK_DIR}/out"
BIN="${OUT_DIR}/openbu-mock"
STAMP="${OUT_DIR}/.built-from"

mkdir -p "${OUT_DIR}"

# --- clone / checkout (shallow fetch of the pinned SHA; master drift is never
# auto-bumped — if HEAD != MOCK_PIN below, we hard-fail instead of re-pinning).
if [ -d "${SRC_DIR}/.git" ] && [ "$(git -C "${SRC_DIR}" rev-parse HEAD 2>/dev/null || true)" = "${MOCK_PIN}" ]; then
  echo "[fetch_mock] clone already at pin ${MOCK_PIN}, skipping fetch"
else
  echo "[fetch_mock] fetching ${MOCK_PIN} from ${MOCK_REPO}"
  rm -rf "${SRC_DIR}"
  mkdir -p "${SRC_DIR}"
  git -C "${SRC_DIR}" init -q
  git -C "${SRC_DIR}" remote add origin "${MOCK_REPO}"
  git -C "${SRC_DIR}" fetch --depth 1 origin "${MOCK_PIN}"
  git -C "${SRC_DIR}" checkout -q --detach "${MOCK_PIN}"
fi

HEAD_SHA="$(git -C "${SRC_DIR}" rev-parse HEAD)"
if [ "${HEAD_SHA}" != "${MOCK_PIN}" ]; then
  echo "[fetch_mock] FATAL: checked-out SHA ${HEAD_SHA} != MOCK_PIN ${MOCK_PIN}" >&2
  echo "[fetch_mock] upstream master drifted — record the drift, NEVER auto-bump the pin" >&2
  exit 1
fi

# --- build (idempotent: only when the binary is missing or the checkout changed)
if [ -x "${BIN}" ] && [ -f "${STAMP}" ] && [ "$(cat "${STAMP}")" = "${HEAD_SHA}" ]; then
  echo "[fetch_mock] binary already built from ${HEAD_SHA}, skipping build"
  exit 0
fi

# --- resolve a working docker client (Docker required for the build)
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "[fetch_mock] FATAL: no working docker daemon (docker not found or not running)" >&2
  echo "[fetch_mock] start Docker Desktop / dockerd, then re-run" >&2
  exit 1
fi

echo "[fetch_mock] building linux-amd64 with golang:1.22 via docker (CGO_ENABLED=0, upstream build.sh flags)"
docker run --rm \
  -v "${SRC_DIR}:/src" \
  -v "${OUT_DIR}:/out" \
  -w /src \
  -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 \
  golang:1.22 \
  go build -buildvcs=false -trimpath -ldflags="-s -w" -o /out/openbu-mock .

# chmod may be denied (drvfs mount / container-root ownership) — assert, don't die
chmod +x "${BIN}" 2>/dev/null || true
if [ ! -x "${BIN}" ]; then
  echo "[fetch_mock] FATAL: ${BIN} not executable after build" >&2
  exit 1
fi
printf '%s\n' "${HEAD_SHA}" > "${STAMP}"
echo "[fetch_mock] built ${BIN}"
