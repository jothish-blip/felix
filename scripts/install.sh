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

TMP_BIN="${INSTALL_DIR}/felix.tmp.$$"
cp -f "${SOURCE_BIN}" "${TMP_BIN}"
chmod 755 "${TMP_BIN}"

if [ ! -s "${TMP_BIN}" ]; then
    echo "[-] Verification failed: staged binary is empty!" >&2
    rm -f "${TMP_BIN}"
    exit 2
fi

mv -f "${TMP_BIN}" "${INSTALL_DIR}/felix"
echo "[+] Atomically installed felix binary to: ${INSTALL_DIR}/felix"

# Self-verify execution
if ! "${INSTALL_DIR}/felix" version >/dev/null 2>&1; then
    echo "[-] Verification failed: installed binary cannot execute!" >&2
    exit 2
fi

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
