#cargo build
app_name="${1:-outlook}"
MASTER_PASSPHRASE_FILE="${MASTER_PASSPHRASE_FILE:-./data/input/master_passphrase.txt}"
if [ ! -f "$MASTER_PASSPHRASE_FILE" ]; then
    echo "Set MASTER_PASSPHRASE_FILE to an owner-only passphrase file." >&2
    exit 1
fi

target/debug/pwd_manager find "$app_name" -j --reveal \
    --master-passphrase-file "$MASTER_PASSPHRASE_FILE" \
    --key-file ./data/input/key.txt \
    --input ./data/output/vault.redb
