# utils/helpers.py

import hashlib

def hash_file(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()
        }

def save_file(path, content):
    with open(path, "w") as f:
        f.write(content)

def read_top_lines(file_path, lines=20):
    with open(file_path, "r") as f:
        return "".join(f.readlines()[:lines])

