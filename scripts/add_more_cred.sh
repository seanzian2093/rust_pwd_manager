target/debug/pwd_manager add outlook -u bob --password supersecret123 \
    --sec "Father's middle name?=Muller" \
    --sec "Second pet?=T-Rex" \
    --sub "api=ap2-SECRET" \
    --sub "db=db2-SECRET" \
    --key-file ~/.pwd_manager/key.txt \
    --nonce-file ~/.pwd_manager/nonce.txt \
    --output ~/.pwd_manager/credentials.json
