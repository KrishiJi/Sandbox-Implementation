#!/bin/bash
# Run a file inside sandbox
echo "[+] Launching sandboxed execution..."
firejail --net=none --private --quiet "$1"

