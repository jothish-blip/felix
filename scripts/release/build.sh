#!/usr/bin/env bash
set -euo pipefail

# Felix Multi-Platform Release Build Script
VERSION="${1:-1.0.0}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "dev")"
BUILD_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.GitCommit=${COMMIT} -X main.BuildTime=${BUILD_TIME} -X main.Release=Production"

echo "==========================================================="
echo " Building Felix Cross-Platform Release v${VERSION} (${COMMIT})"
echo "==========================================================="

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

TARGETS=(
  "windows/amd64/felix_windows_amd64.exe/felix.exe"
  "linux/amd64/felix_linux_amd64/felix"
  "linux/arm64/felix_linux_arm64/felix"
  "darwin/amd64/felix_darwin_amd64/felix"
  "darwin/arm64/felix_darwin_arm64/felix"
)

for target in "${TARGETS[@]}"; do
  IFS="/" read -r GOOS GOARCH OUTPUT_NAME BIN_NAME <<< "${target}"
  echo "[*] Compiling ${GOOS}/${GOARCH} -> ${OUTPUT_NAME}..."
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" go build -trimpath -ldflags "${LDFLAGS}" -o "${DIST_DIR}/${OUTPUT_NAME}" ./cmd/felix
  
  # Archive packaging
  STAGE_DIR="${DIST_DIR}/stage_${GOOS}_${GOARCH}"
  mkdir -p "${STAGE_DIR}"
  cp "${DIST_DIR}/${OUTPUT_NAME}" "${STAGE_DIR}/${BIN_NAME}"
  for doc in README.md USAGE.md SECURITY.md; do
    if [ -f "${REPO_ROOT}/${doc}" ]; then cp "${REPO_ROOT}/${doc}" "${STAGE_DIR}/"; fi
  done

  if [ "${GOOS}" = "windows" ]; then
    zip -q -j "${DIST_DIR}/felix_${VERSION}_windows_${GOARCH}.zip" "${STAGE_DIR}"/*
  else
    tar -czf "${DIST_DIR}/felix_${VERSION}_${GOOS}_${GOARCH}.tar.gz" -C "${STAGE_DIR}" .
  fi
  rm -rf "${STAGE_DIR}"
done

echo "[*] Generating update.json release metadata..."
get_hash() {
  local f="${DIST_DIR}/$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  else
    shasum -a 256 "$f" | awk '{print $1}'
  fi
}

WIN_HASH="$(get_hash "felix_${VERSION}_windows_amd64.zip")"
LIN_AMD_HASH="$(get_hash "felix_${VERSION}_linux_amd64.tar.gz")"
LIN_ARM_HASH="$(get_hash "felix_${VERSION}_linux_arm64.tar.gz")"
MAC_AMD_HASH="$(get_hash "felix_${VERSION}_darwin_amd64.tar.gz")"
MAC_ARM_HASH="$(get_hash "felix_${VERSION}_darwin_arm64.tar.gz")"

cat <<EOF > "${DIST_DIR}/update.json"
{
  "product": "felix",
  "channel": "stable",
  "version": "${VERSION}",
  "release": "https://github.com/jothish-blip/felix/releases/tag/v${VERSION}",
  "assets": {
    "windows-amd64": {
      "archive": "felix_${VERSION}_windows_amd64.zip",
      "sha256": "${WIN_HASH}",
      "signed": false
    },
    "linux-amd64": {
      "archive": "felix_${VERSION}_linux_amd64.tar.gz",
      "sha256": "${LIN_AMD_HASH}"
    },
    "linux-arm64": {
      "archive": "felix_${VERSION}_linux_arm64.tar.gz",
      "sha256": "${LIN_ARM_HASH}"
    },
    "darwin-amd64": {
      "archive": "felix_${VERSION}_darwin_amd64.tar.gz",
      "sha256": "${MAC_AMD_HASH}",
      "signed": false,
      "notarized": false
    },
    "darwin-arm64": {
      "archive": "felix_${VERSION}_darwin_arm64.tar.gz",
      "sha256": "${MAC_ARM_HASH}",
      "signed": false,
      "notarized": false
    }
  }
}
EOF
echo "[✓] update.json generated."

echo "[*] Computing SHA256 checksums..."
cd "${DIST_DIR}"
sha256sum * 2>/dev/null | grep -v "SHA256SUMS" > SHA256SUMS || shasum -a 256 * | grep -v "SHA256SUMS" > SHA256SUMS
echo "[✓] Release build complete."
