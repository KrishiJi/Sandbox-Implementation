#!/usr/bin/env python3
import sys
import subprocess
import os
import hashlib
import datetime
from pathlib import Path
import stat
import threading


# Add the parent directory (project root) to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from utils.helpers import hash_file, save_file, read_top_lines
from jinja2 import Environment, FileSystemLoader


LOG_DIR = Path("logs")
REPORT_DIR = Path("reports")
SAMPLES_DIR = Path("samples")
LOG_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

def get_file_info(file_path):
    try:
        st = os.stat(file_path)
        return {
            "size": st.st_size,
            "permissions": stat.filemode(st.st_mode),
            "last_modified": st.st_mtime,
        }
    except Exception as e:
        return {
            "size": "Unknown",
            "permissions": "Unknown",
            "last_modified": "Unknown"
        }

def compute_hashes(file_path):
    hashes = hash_file(file_path)
    with open(file_path, "rb") as f:
        data = f.read()
        hashes["md5"] = hashlib.md5(data).hexdigest()
        hashes["sha256"] = hashlib.sha256(data).hexdigest()
    return hashes

def run_static_analysis(file_path):
    result = {}
    result["file_cmd"] = subprocess.getoutput(f"file {file_path}")
    result["strings"] = subprocess.getoutput(f"strings {file_path} | head -n 20")
   # result["readelf"] = subprocess.getoutput(f"readelf -h {file_path}")
    file_type = result["file_cmd"].lower()
    if "elf" in file_type:
        result["readelf"] = subprocess.getoutput(f"readelf -h {file_path}")
    else:
        result["readelf"] = "Not an ELF file - skipping readelf."
    return result

def monitor_filesystem(path_to_watch, log_file_path, duration=15):
    def monitor():
        cmd = f"timeout {duration}s inotifywait -rq -e create,delete,modify {path_to_watch} >> {log_file_path}"
        subprocess.run(cmd, shell=True, timeout=duration)

    t = threading.Thread(target=monitor)
    t.start()
    return t

def monitor_network(log_file_path, duration=15):
    def monitor():
        cmd = f"sudo tcpdump -i any -w {log_file_path} -G {duration} -W 1"
        subprocess.run(cmd, shell=True)

    t = threading.Thread(target=monitor)
    t.start()
    return t

def run_dynamic_analysis(file_path, log_file):
    if not os.access(file_path, os.X_OK):
        print(f"[!] Skipping dynamic analysis: {file_path} is not executable.")
        return

    fs_log_file = log_file.with_name(f"fs_{log_file.name}")
    net_log_file = log_file.with_name(f"net_{log_file.stem}.pcap")

    fs_thread = monitor_filesystem("/tmp", fs_log_file)
    # Uncomment the following line if you want to enable network monitoring (requires removing --net=none)
    net_thread = monitor_network(net_log_file)

    try:
        # Monitor file system and network activity using strace
        with open(log_file, "w") as lf:
            lf.write("=== STRACE OUTPUT ===\n")
            subprocess.run(f"strace -f -o - {file_path}", shell=True, timeout=15, stdout=lf, stderr=subprocess.STDOUT)

            lf.write("\n=== LSOF OUTPUT (open files/network) ===\n")
            lsof_output = subprocess.getoutput(f"lsof -p $(pgrep -f {file_path.name} | head -n 1) 2>/dev/null")
            lf.write(lsof_output)

    except subprocess.TimeoutExpired:
        print("[!] Execution timed out (possible infinite loop or hang)")
    except Exception as e:
        print(f"[!] Error during dynamic analysis: {e}")

    fs_thread.join()
    net_thread.join()  # Uncomment if network monitoring is enabled

    return fs_log_file,net_log_file

    '''cmd = f"strace -f -o {log_file} {file_path}"
    try:
        subprocess.run(cmd, shell=True, timeout=15)
    except subprocess.TimeoutExpired:
        print("[!] Execution timed out (possible infinite loop or hang)")'''

def generate_report(file_path, hashes, static, log_file, report_path,file_info,fs_log_file,net_log_file):
    
    env = Environment(loader=FileSystemLoader(str(REPORT_DIR)))
    template = env.get_template("report_template_2.html")

    log_content = "No dynamic log available."
    if log_file.exists():
        log_content = read_top_lines(log_file, 40)

    fs_log_content = ""
    if fs_log_file.exists():
        with open(fs_log_file, "r") as fs_log:
            fs_lines = fs_log.readlines()[:30]
            fs_log_content = "<h2>File System Activity</h2><pre>" + "".join(fs_lines) + "</pre>"

    net_log_content = ""
    if net_log_file.exists():
        net_log_content = f"<h2>Network Traffic</h2><p>PCAP file captured: {net_log_file.name}</p>"



    # Render final report
    report_content = template.render(
        file_name=file_path.name,
         md5=hashes["md5"],
        sha256=hashes["sha256"],
        file_info=file_info,
        file_cmd=static["file_cmd"],
        strings=static["strings"],
        readelf=static["readelf"],
        syscall_log=log_content+fs_log_content+net_log_content,
        risk_score="6/10",
        risk_level="Medium"
    )

    with open(report_path, "w") as f:
        f.write(report_content)

    print(f"[+] HTML Report saved: {report_path}")

def main():
    default_sample = SAMPLES_DIR / "test_sample.sh"

    # Use the provided argument if available, else fallback to default
    if len(sys.argv) >= 2:
        sample = Path(sys.argv[1])
        if not sample.exists():
            print(f"[!] Provided sample file not found at: {sample}")
            return
    else:
        print("[*] No input file provided. Using default sample: test_sample.sh")
        sample = default_sample
        if not sample.exists():
            print("[!] Default sample file not found.")
            return

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = LOG_DIR / f"log_{timestamp}.txt"
    report_file = REPORT_DIR / f"report_{timestamp}.html"

    hashes = compute_hashes(sample)
    static_result = run_static_analysis(sample)
    fs_log_file,net_log_file=run_dynamic_analysis(sample, log_file)
    file_info = get_file_info(sample)
    generate_report(sample, hashes, static_result, log_file, report_file,file_info,fs_log_file,net_log_file)

if __name__ == "__main__":
    main()


