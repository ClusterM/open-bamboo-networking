#!/usr/bin/env bash
# fetch_mock.sh — fetch + build the openbu-mock external binary (D-04).
#
# Facts-only / external-binary-only: openbu-mock has NO LICENSE, so this script
# only clones into the gitignored .cache/openbu-mock/ and builds a binary there.
# Nothing from the clone is ever `git add`ed (this script never calls git add).
#
# Run evidence (identity.env, mock.log, tls_dump.txt, spike-order*.jsonl, probe
# transcripts) lands in .cache/openbu-mock/run/ — recorded in README.md under
# "Environment & spikes" and "Gap analysis".
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
  echo "[fetch_mock] upstream master drifted — record the drift, NEVER auto-bump the pin (D-04)" >&2
  exit 1
fi

# --- build (idempotent: only when the binary is missing or the checkout changed)
if [ -x "${BIN}" ] && [ -f "${STAMP}" ] && [ "$(cat "${STAMP}")" = "${HEAD_SHA}" ]; then
  echo "[fetch_mock] binary already built from ${HEAD_SHA}, skipping build"
  exit 0
fi

# --- resolve a working docker client (D-04: Docker preferred)
# This host: WSL distro has no native `docker`, Docker Desktop WSL integration
# is off for Ubuntu -> fall back to `docker.exe` (interop) with Windows paths.
DOCKER_CMD=""
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  DOCKER_CMD="docker"
elif command -v docker.exe >/dev/null 2>&1 && docker.exe info >/dev/null 2>&1; then
  DOCKER_CMD="docker.exe"
else
  echo "[fetch_mock] FATAL: no working docker (docker/docker.exe both unavailable)" >&2
  echo "[fetch_mock] start Docker Desktop, or fall back to the local-Go path (D-04)" >&2
  exit 1
fi

# The Windows daemon cannot mount WSL drvfs paths like /mnt/d/... — translate
# /mnt/<drive>/... to <Drive>:/... when talking to docker.exe.
win_mount() {
  local p="$1"
  if [ "${DOCKER_CMD}" = "docker.exe" ] && [[ "$p" =~ ^/mnt/([a-zA-Z])/(.*)$ ]]; then
    printf '%s:/%s' "$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:lower:]' '[:upper:]')" "${BASH_REMATCH[2]}"
  else
    printf '%s' "$p"
  fi
}

echo "[fetch_mock] building linux-amd64 with golang:1.22 via ${DOCKER_CMD} (CGO_ENABLED=0, upstream build.sh flags)"
"${DOCKER_CMD}" run --rm \
  -v "$(win_mount "${SRC_DIR}"):/src" \
  -v "$(win_mount "${OUT_DIR}"):/out" \
  -w /src \
  -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 \
  golang:1.22 \
  go build -trimpath -ldflags="-s -w" -o /out/openbu-mock .

# chmod may be denied (drvfs mount / container-root ownership) — assert, don't die
chmod +x "${BIN}" 2>/dev/null || true
if [ ! -x "${BIN}" ]; then
  echo "[fetch_mock] FATAL: ${BIN} not executable after build" >&2
  exit 1
fi
printf '%s\n' "${HEAD_SHA}" > "${STAMP}"
echo "[fetch_mock] built ${BIN}"
