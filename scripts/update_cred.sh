# Secrets are staged in owner-only files so they never appear in argv or shell history.
SECRETS=$(mktemp -d)
trap 'rm -rf "$SECRETS"' EXIT

(umask 077
 printf 'supersecret456' > "$SECRETS/pw"
 printf "Father's middle name?=Muller2\nSecond pet?=T-Rex2\n" > "$SECRETS/sec"
 printf 'api=ap3-SECRET\ndb=db3-SECRET\n' > "$SECRETS/sub")

target/debug/pwd_manager update outlook -u bob2 \
    --password-file "$SECRETS/pw" \
    --sec-file "$SECRETS/sec" \
    --sub-file "$SECRETS/sub" \
    --key-file ./data/input/key.txt \
    --input ./data/output/credentials.json
