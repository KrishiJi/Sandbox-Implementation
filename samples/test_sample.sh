#!/bin/bash
# Benign test sample mimicking malicious behavior
echo "[*] Hello, I am pretending to be malware."
touch /tmp/fakefile
cat /etc/passwd > /tmp/fake_copy

