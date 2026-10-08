#!/usr/bin/env bash
# Felix CLI POSIX Uninstallation Script
# Usage: ./scripts/uninstall.sh

set -euo pipefail

echo "==========================================================="
echo " FELIX :: CLI Uninstallation (POSIX)"
echo "==========================================================="

INSTALL_DIR="${HOME}/.felix/bin"
TARGET_BIN="${INSTALL_DIR}/felix"

if [ -f "${TARGET_BIN}" ]; then
    rm -f "${TARGET_BIN}"
    echo "[+] Removed binary: ${TARGET_BIN}"
else
    echo "[i] Binary not found at ${TARGET_BIN}"
fi

# Clean bin directory if empty
if [ -d "${INSTALL_DIR}" ] && [ -z "$(ls -A "${INSTALL_DIR}")" ]; then
    rmdir "${INSTALL_DIR}"
fi

echo ""
echo "[✓] Felix uninstalled successfully."
echo "[i] Note: User config directory (~/.felix) was preserved."
