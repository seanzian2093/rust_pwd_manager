# Secrets are staged in owner-only files so they never appear in argv or shell history.
MASTER_PASSPHRASE_FILE="${MASTER_PASSPHRASE_FILE:-./data/input/master_passphrase.txt}"
if [ ! -f "$MASTER_PASSPHRASE_FILE" ]; then
    echo "Set MASTER_PASSPHRASE_FILE to an owner-only passphrase file." >&2
    exit 1
fi

SECRETS=$(mktemp -d)
trap 'rm -rf "$SECRETS"' EXIT

(umask 077
 printf 'supersecret123' > "$SECRETS/pw"
 printf "Father's middle name?=Muller\nSecond pet?=T-Rex\n" > "$SECRETS/sec"
 printf 'api=ap2-SECRET\ndb=db2-SECRET\n' > "$SECRETS/sub")

target/debug/pwd_manager add outlook -u bob \
    --password-file "$SECRETS/pw" \
    --sec-file "$SECRETS/sec" \
    --sub-file "$SECRETS/sub" \
    --master-passphrase-file "$MASTER_PASSPHRASE_FILE" \
    --key-file ./data/input/key.txt \
    --output ./data/output/vault.redb
