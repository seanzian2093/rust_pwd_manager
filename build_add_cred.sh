cargo build
target/debug/pwd_manager add Github -u alice --password secret123 \
    --sec "Mother's maiden?=Smith" \
    --sec "First pet?=Rex" \
    --sub "api=ap1-SECRET" \
    --sub "db=db-SECRET" \
    --key-file ~/.pwd_manager/key.txt \
    --nonce-file ~/.pwd_manager/nonce.txt \
    --output ~/.pwd_manager/credentials.json
