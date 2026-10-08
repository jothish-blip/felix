#!/usr/bin/env bash
# Felix CLI POSIX Installation Script
# Usage: ./scripts/install.sh

set -euo pipefail

echo "==========================================================="
echo " FELIX :: CLI Installation (POSIX)"
echo "==========================================================="

INSTALL_DIR="${HOME}/.felix/bin"
mkdir -p "${INSTALL_DIR}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_BIN="${REPO_ROOT}/bin/felix"

if [ ! -f "${SOURCE_BIN}" ]; then
    echo "[*] Building felix binary from source..."
    (cd "${REPO_ROOT}" && go build -o bin/felix ./cmd/felix)
fi

if [ ! -f "${SOURCE_BIN}" ]; then
    echo "[-] Could not locate or build bin/felix" >&2
    exit 2
fi

cp -f "${SOURCE_BIN}" "${INSTALL_DIR}/felix"
chmod 755 "${INSTALL_DIR}/felix"

echo "[+] Installed felix binary to: ${INSTALL_DIR}/felix"

# PATH guidance
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    SHELL_PROFILE=""
    if [ -f "${HOME}/.zshrc" ]; then
        SHELL_PROFILE="${HOME}/.zshrc"
    elif [ -f "${HOME}/.bashrc" ]; then
        SHELL_PROFILE="${HOME}/.bashrc"
    elif [ -f "${HOME}/.profile" ]; then
        SHELL_PROFILE="${HOME}/.profile"
    fi

    if [ -n "${SHELL_PROFILE}" ]; then
        if ! grep -q "${INSTALL_DIR}" "${SHELL_PROFILE}"; then
            echo "export PATH=\"${INSTALL_DIR}:\$PATH\"" >> "${SHELL_PROFILE}"
            echo "[+] Added ${INSTALL_DIR} to ${SHELL_PROFILE}"
        fi
    else
        echo "[i] Ensure ${INSTALL_DIR} is added to your PATH."
    fi
fi

"${INSTALL_DIR}/felix" version
echo ""
echo "[✓] Felix installed successfully. Run 'felix --help' to get started."
