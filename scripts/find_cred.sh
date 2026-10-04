#cargo build
app_name="${1:-outlook}"
target/debug/pwd_manager find "$app_name" -j \
    --key-file ./data/input/key.txt \
    --input ./data/output/credentials.json
