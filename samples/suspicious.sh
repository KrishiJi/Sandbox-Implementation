#!/bin/bash
# Test Malware Script - benign but suspicious

# Simulate suspicious behavior
echo "[*] Creating hidden file..."
touch ~/.secret_config

echo "[*] Reading system passwd file..."
cat /etc/passwd > /tmp/passwd_copy.txt

echo "[*] Trying outbound connection (simulated)..."
curl http://example.com --output /dev/null

echo "[*] Sleeping for 5 seconds..."
sleep 5

echo "[+] Finished test script."

