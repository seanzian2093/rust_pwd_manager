#!/bin/sh

_sourced=0
if [ -n "${ZSH_EVAL_CONTEXT-}" ]; then
    case "$ZSH_EVAL_CONTEXT" in
        *:file) _sourced=1 ;;
    esac
elif [ -n "${BASH_VERSION-}" ]; then
    if [ "${BASH_SOURCE[0]}" != "$0" ]; then
        _sourced=1
    fi
elif [ "${0##*/}" != "demo_find_options.sh" ]; then
    _sourced=1
fi

if [ "$_sourced" -eq 1 ]; then
    echo "Run this script as ./scripts/demo_find_options.sh; do not source it." >&2
    return 0 2>/dev/null || exit 0
fi
unset _sourced

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
    echo "Usage: $0 ACCOUNT [redacted|reveal|copy-password|copy-answer|copy-sub-password [INDEX]]" >&2
    exit 2
fi

ACCOUNT="$1"
MODE="${2:-redacted}"
INDEX="${3:-1}"
PWD_MANAGER_BIN="${PWD_MANAGER_BIN:-./target/debug/pwd_manager}"
MASTER_PASSPHRASE_FILE="${MASTER_PASSPHRASE_FILE:-./data/input/master_passphrase.txt}"
VAULT_FILE="${VAULT_FILE:-./data/output/vault.redb}"
KEY_FILE="${KEY_FILE:-./data/input/key.txt}"

if [ ! -x "$PWD_MANAGER_BIN" ]; then
    echo "Build the CLI first or set PWD_MANAGER_BIN to its executable path." >&2
    exit 1
fi
if [ ! -f "$MASTER_PASSPHRASE_FILE" ]; then
    echo "Set MASTER_PASSPHRASE_FILE to an owner-only passphrase file." >&2
    exit 1
fi

run_find() {
    "$PWD_MANAGER_BIN" find "$ACCOUNT" "$@" \
        --master-passphrase-file "$MASTER_PASSPHRASE_FILE" \
        --key-file "$KEY_FILE" \
        --input "$VAULT_FILE"
}

case "$MODE" in
    redacted)
        run_find
        ;;
    reveal)
        echo "Warning: --reveal prints secret values to stdout." >&2
        run_find --reveal
        ;;
    copy-password)
        run_find --copy-password
        ;;
    copy-answer)
        run_find --copy-answer "$INDEX"
        ;;
    copy-sub-password)
        run_find --copy-sub-password "$INDEX"
        ;;
    *)
        echo "Unknown find mode: $MODE" >&2
        echo "Choose redacted, reveal, copy-password, copy-answer, or copy-sub-password." >&2
        exit 2
        ;;
esac
