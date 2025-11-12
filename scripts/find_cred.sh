#cargo build
target/debug/pwd_manager find outlook -j \
    --key-file ~/.pwd_manager/key.txt \
    --nonce-file ~/.pwd_manager/nonce.txt \
    --input ~/.pwd_manager/credentials.json
