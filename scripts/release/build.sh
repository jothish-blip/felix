#!/usr/bin/env bash
set -euo pipefail

# Felix Multi-Platform Release Build Script
VERSION="${1:-2.0.0}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "==========================================================="
echo " Building Felix Release v${VERSION} via Packaging Pipeline"
echo "==========================================================="

cd "${REPO_ROOT}"
go run ./scripts/packaging "${VERSION}"
