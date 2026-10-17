#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${1:-python}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANIFEST_PATH="${SCRIPT_DIR}/release_firmwares.txt"
DIST_PATH="${REPO_ROOT}/dist"
WORK_PATH="${REPO_ROOT}/build/pyinstaller"

cd "${REPO_ROOT}"

mapfile -t FIRMWARE_NAMES < <(
    sed -e 's/\r$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "${MANIFEST_PATH}" \
        | grep -v -E '^(#|$)'
)

if [[ "${#FIRMWARE_NAMES[@]}" -eq 0 ]]; then
    echo "Error: The release firmware manifest is empty: ${MANIFEST_PATH}" >&2
    exit 1
fi

UNIQUE_COUNT="$(printf '%s\n' "${FIRMWARE_NAMES[@]}" | sort -u | wc -l | tr -d ' ')"
if [[ "${UNIQUE_COUNT}" -ne "${#FIRMWARE_NAMES[@]}" ]]; then
    echo "Error: The release firmware manifest contains duplicate names." >&2
    exit 1
fi

DATA_ARGS=()
for name in "${FIRMWARE_NAMES[@]}"; do
    source_path="${REPO_ROOT}/firmwares/${name}"
    if [[ ! -f "${source_path}" ]]; then
        echo "Error: Release firmware does not exist: ${source_path}" >&2
        exit 1
    fi
    DATA_ARGS+=("--add-data=${source_path}:firmwares")
done

"${PYTHON_BIN}" -m PyInstaller \
    --noconfirm \
    --clean \
    --onefile \
    --console \
    --name BekenEmulator-linux-x64 \
    --paths "${REPO_ROOT}" \
    --distpath "${DIST_PATH}" \
    --workpath "${WORK_PATH}" \
    --specpath "${WORK_PATH}" \
    --collect-all unicorn \
    --hidden-import Crypto.Cipher.AES \
    "${DATA_ARGS[@]}" \
    tools/sim_ui.py

BIN_PATH="${DIST_PATH}/BekenEmulator-linux-x64"
if [[ ! -f "${BIN_PATH}" ]]; then
    echo "Error: PyInstaller reported success but did not create ${BIN_PATH}" >&2
    exit 1
fi

chmod +x "${BIN_PATH}"
echo "Built ${BIN_PATH}"
