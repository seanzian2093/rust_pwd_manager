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
elif [ "${0##*/}" != "demo_vault_maintenance.sh" ]; then
    _sourced=1
fi

if [ "$_sourced" -eq 1 ]; then
    echo "Run this script as ./scripts/demo_vault_maintenance.sh; do not source it." >&2
    return 0 2>/dev/null || exit 0
fi
unset _sourced

set -eu

if [ "$#" -gt 2 ]; then
    echo "Usage: $0 [BACKUP_PATH [RESTORED_VAULT_PATH]]" >&2
    exit 2
fi

PWD_MANAGER_BIN="${PWD_MANAGER_BIN:-./target/debug/pwd_manager}"
VAULT_FILE="${VAULT_FILE:-./data/output/vault.redb}"
DEMO_SUFFIX=$(date '+%Y%m%d-%H%M%S')
BACKUP_FILE="${1:-./backups/vault-demo-$DEMO_SUFFIX.redb}"
RESTORED_VAULT="${2:-./data/output/vault-restored-demo-$DEMO_SUFFIX.redb}"

if [ ! -x "$PWD_MANAGER_BIN" ]; then
    echo "Build the CLI first or set PWD_MANAGER_BIN to its executable path." >&2
    exit 1
fi
if [ ! -f "$VAULT_FILE" ]; then
    echo "Vault file not found: $VAULT_FILE" >&2
    exit 1
fi
if [ "$BACKUP_FILE" = "$RESTORED_VAULT" ]; then
    echo "Backup and restored vault paths must be different." >&2
    exit 2
fi
if [ -e "$BACKUP_FILE" ]; then
    echo "Refusing to overwrite existing backup: $BACKUP_FILE" >&2
    exit 1
fi
if [ -e "$RESTORED_VAULT" ]; then
    echo "Refusing to overwrite existing restored vault: $RESTORED_VAULT" >&2
    exit 1
fi

echo "Ensure no other process is accessing $VAULT_FILE before continuing." >&2
echo "Creating backup: $BACKUP_FILE"
"$PWD_MANAGER_BIN" backup --input "$VAULT_FILE" --output "$BACKUP_FILE"

echo "Restoring backup to a separate vault: $RESTORED_VAULT"
"$PWD_MANAGER_BIN" restore --input "$BACKUP_FILE" --output "$RESTORED_VAULT"

echo "Compacting the original vault: $VAULT_FILE"
"$PWD_MANAGER_BIN" maintenance compact --input "$VAULT_FILE"

echo "Demo complete. Backup and restored vault were left at their paths above."
