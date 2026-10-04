cargo build

OUTPUT_FILE="${1:-./data/output/credentials.json}"

# Secrets are staged in owner-only files so they never appear in argv or shell history.
SECRETS=$(mktemp -d)
trap 'rm -rf "$SECRETS"' EXIT

(umask 077
 printf 'secret123' > "$SECRETS/pw"
 printf "Mother's maiden?=Smith\nFirst pet?=Rex\n" > "$SECRETS/sec"
 printf 'api=ap1-SECRET\ndb=db-SECRET\n' > "$SECRETS/sub")

target/debug/pwd_manager add Github -u alice \
    --password-file "$SECRETS/pw" \
    --sec-file "$SECRETS/sec" \
    --sub-file "$SECRETS/sub" \
    --key-file ./data/input/key.txt \
    --output "$OUTPUT_FILE"
