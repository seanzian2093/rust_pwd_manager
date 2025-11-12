target/debug/pwd_manager update outlook -u bob2 --password supersecret456 \
    --sec "Father's middle name?=Muller2" \
    --sec "Second pet?=T-Rex2" \
    --sub "api=ap3-SECRET" \
    --sub "db=db3-SECRET" \
    --key-file ~/.pwd_manager/key.txt \
    --nonce-file ~/.pwd_manager/nonce.txt \
    --input ~/.pwd_manager/credentials.json
