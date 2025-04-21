# 🛡️ Malware Analysis Automation Framework

## Overview

This project is a rule-based and behavior-based malware analysis framework designed to automate the process of identifying potentially malicious files. It performs both static and dynamic analysis on executable samples and generates detailed HTML reports. The system is suitable for research, educational use, and as a foundation for extending more advanced malware analysis solutions.

---

## 🔍 Features

- **Static Analysis**
  - File type identification
  - String extraction
  - ELF header parsing (for ELF binaries)
  - Detection of suspicious keywords and functions

- **Dynamic Analysis**
  - Sandboxed execution using Firejail
  - File system activity monitoring using inotifywait
  - System call tracing via `strace`
  - Network traffic capture with `tcpdump`
  - Open file and socket inspection using `lsof`

- **Security Scoring**
  - Risk score based on rule-based indicators
  - Categorized threat level: Low, Medium, or High

- **HTML Report Generation**
  - Clean and structured format using Jinja2 templates
  - Embedded system behavior logs and findings
  - Downloadable PCAP and log references

---

## 📁 Directory Structure

- `samples/`: Input folder for malware or suspicious files to analyze
- `logs/`: Stores system and network logs generated during analysis
- `reports/`: Contains HTML reports summarizing the analysis results
- `utils/`: Helper functions used across the project (e.g., hashing)
- `templates/`: Jinja2 template used for generating the HTML report

---

## ⚙️ Requirements

- Python 3.x
- Linux system with root privileges (for tools like tcpdump)
- Tools used:
  - `firejail`, `strace`, `inotifywait`, `tcpdump`, `lsof`, `readelf`, `strings`, `file`
  - Python modules: `jinja2`

---

## ✅ How It Works

1. The user provides an input file (or a default one is selected).
2. The system computes hashes and runs static analysis.
3. If executable, dynamic analysis is launched in a sandbox.
4. Logs are collected and parsed for suspicious behavior.
5. A comprehensive HTML report is generated with findings and risk classification.

---

## 🔐 Safety Disclaimer

Always use isolated environments or virtual machines when testing suspicious files. This framework assumes a controlled sandboxed setup and **must not be run on a production machine**.

---

## 📄 License

This project is licensed under the MIT License.


