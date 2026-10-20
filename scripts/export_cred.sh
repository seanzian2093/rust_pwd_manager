#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 NEW_EXPORT_JSON_PATH" >&2
    echo "Exports plaintext credentials; choose a protected destination." >&2
    exit 2
fi

PWD_MANAGER_BIN="${PWD_MANAGER_BIN:-./target/debug/pwd_manager}"
MASTER_PASSPHRASE_FILE="${MASTER_PASSPHRASE_FILE:-./data/input/master_passphrase.txt}"
VAULT_FILE="${VAULT_FILE:-./data/output/vault.redb}"
KEY_FILE="${KEY_FILE:-./data/input/key.txt}"
EXPORT_FILE="$1"

if [ ! -x "$PWD_MANAGER_BIN" ]; then
    echo "Build the CLI first or set PWD_MANAGER_BIN to its executable path." >&2
    exit 1
fi
if [ ! -f "$MASTER_PASSPHRASE_FILE" ]; then
    echo "Set MASTER_PASSPHRASE_FILE to an owner-only passphrase file." >&2
    exit 1
fi
if [ -e "$EXPORT_FILE" ]; then
    echo "Refusing to export over existing file: $EXPORT_FILE" >&2
    exit 1
fi

"$PWD_MANAGER_BIN" export \
    --input "$VAULT_FILE" \
    --output "$EXPORT_FILE" \
    --master-passphrase-file "$MASTER_PASSPHRASE_FILE" \
    --key-file "$KEY_FILE"

echo "Export contains plaintext secrets. Keep it protected or securely remove it when no longer needed." >&2
