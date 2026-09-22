import hashlib
import os

def compute_hash(file_path):
    if not os.path.exists(file_path):
        return None

    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)

    return sha256.hexdigest()

def verify_integrity(file_path, previous_hash):
    current_hash = compute_hash(file_path)

    if current_hash is None:
        return {"status": "missing", "match": False, "current_hash": None}

    match = current_hash == previous_hash
    return {
        "status": "ok" if match else "tampered",
        "match": match,
        "current_hash": current_hash
    }