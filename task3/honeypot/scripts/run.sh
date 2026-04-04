#!/bin/bash
# Build and run the SSH honeypot in Docker

echo "[*] Building honeypot container..."
docker build -t ssh-honeypot .

echo "[*] Starting honeypot on port 22..."
echo "[*] Logs will be stored in ./logs/honeypot.json"

mkdir -p logs

docker run -it --rm \
    --name ssh-honeypot \
    -p 22:22 \
    -v "$(pwd)/logs:/var/log/honeypot" \
    --read-only \
    --tmpfs /tmp:size=10M \
    --tmpfs /etc/honeypot:size=1M \
    --memory=128m \
    --cpus=0.5 \
    --cap-drop=ALL \
    ssh-honeypot