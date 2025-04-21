# Linux Malware Sandbox (PBL Project)

A simple, extensible Linux-based sandbox for analyzing suspicious binaries and scripts. It isolates execution using Firejail, performs static and dynamic analysis, and generates behavior reports.

## Features
- Static analysis (hashes, strings, ELF headers)
- Dynamic system call tracing via strace
- Firejail sandboxing (no internet, private FS)
- HTML report generation

## Usage
```bash
python3 analysis/analyze_file.py

