import os
import json
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from modules.hasher import compute_hash
from modules.policy import evaluate_event, SENSITIVE_DIRS, SENSITIVE_FILES
from modules.logger import log_event

BACKEND_ROOT = os.path.dirname(os.path.dirname(__file__))
HASH_CACHE_FILE = os.path.join(BACKEND_ROOT, "logs", "hash_cache.json")
KNOWN_FILES_CACHE = os.path.join(BACKEND_ROOT, "logs", "known_sensitive_files.json")

SENSITIVE_DIR_NAMES = [os.path.basename(d) for d in SENSITIVE_DIRS]
RELEVANT_FOLDERS = SENSITIVE_DIR_NAMES + ["unauthorized_zone"]

COMMON_PROCESSES = ["notepad.exe", "explorer.exe", "WINWORD.EXE", "EXCEL.EXE",
                     "python.exe", "chrome.exe", "msedge.exe", "Code.exe"]

hash_cache = {}
known_sensitive_files = set()


def load_caches():
    global hash_cache, known_sensitive_files
    if os.path.exists(HASH_CACHE_FILE):
        with open(HASH_CACHE_FILE, "r") as f:
            try:
                hash_cache = json.load(f)
            except json.JSONDecodeError:
                hash_cache = {}
    if os.path.exists(KNOWN_FILES_CACHE):
        with open(KNOWN_FILES_CACHE, "r") as f:
            try:
                known_sensitive_files = set(json.load(f))
            except json.JSONDecodeError:
                known_sensitive_files = set()


def save_hash_cache():
    with open(HASH_CACHE_FILE, "w") as f:
        json.dump(hash_cache, f, indent=2)


def save_known_files():
    with open(KNOWN_FILES_CACHE, "w") as f:
        json.dump(list(known_sensitive_files), f, indent=2)


def is_relevant(path):
    normalized = path.replace("/", "\\")
    filename = os.path.basename(path)
    if filename in SENSITIVE_FILES:
        return True
    return any(folder in normalized for folder in RELEVANT_FOLDERS)


def is_under_sensitive(path):
    normalized = os.path.normpath(path)
    filename = os.path.basename(path)
    if filename in SENSITIVE_FILES:
        return True
    return any(normalized.startswith(os.path.normpath(d)) for d in SENSITIVE_DIRS)


def find_sensitive_root(filename):
    if filename in SENSITIVE_FILES:
        return SENSITIVE_DIRS[0]
    for d in SENSITIVE_DIRS:
        if os.path.exists(os.path.join(d, filename)) or filename in known_sensitive_files:
            return d
    return SENSITIVE_DIRS[0]


def find_owning_process(file_path):
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] not in COMMON_PROCESSES:
                    continue
                for f in proc.open_files():
                    if f.path == file_path:
                        return proc.info['name']
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                continue
    except Exception:
        pass
    return os.environ.get("USERNAME", "unknown") + "-session"


class TransferHandler(FileSystemEventHandler):

    def on_created(self, event):
        if event.is_directory or not is_relevant(event.src_path):
            return

        filename = os.path.basename(event.src_path)

        if is_under_sensitive(event.src_path):
            known_sensitive_files.add(filename)
            save_known_files()
            file_hash = compute_hash(event.src_path)
            hash_cache[event.src_path] = file_hash
            save_hash_cache()
            log_event(
                event_type="create",
                source=event.src_path,
                process=find_owning_process(event.src_path),
                status="normal",
                details={"note": "new sensitive file created"}
            )
        elif filename in known_sensitive_files:
            sensitive_root = find_sensitive_root(filename)
            fake_source = os.path.join(sensitive_root, filename)
            result = evaluate_event(fake_source, event.src_path)
            log_event(
                event_type="move",
                source=fake_source,
                destination=event.src_path,
                process=find_owning_process(event.src_path),
                status="violation" if result["violation"] else "normal",
                details=result
            )

    def on_modified(self, event):
        if event.is_directory or not is_relevant(event.src_path):
            return
        old_hash = hash_cache.get(event.src_path)
        new_hash = compute_hash(event.src_path)
        hash_cache[event.src_path] = new_hash
        save_hash_cache()
        tampered = old_hash is not None and old_hash != new_hash
        log_event(
            event_type="modify",
            source=event.src_path,
            process=find_owning_process(event.src_path),
            status="tampered" if tampered else "normal",
            details={"old_hash": old_hash, "new_hash": new_hash}
        )

    def on_moved(self, event):
        if event.is_directory:
            return
        if not is_relevant(event.src_path) and not is_relevant(event.dest_path):
            return
        result = evaluate_event(event.src_path, event.dest_path)
        hash_cache[event.dest_path] = hash_cache.pop(event.src_path, compute_hash(event.dest_path))
        save_hash_cache()
        log_event(
            event_type="move",
            source=event.src_path,
            destination=event.dest_path,
            process=find_owning_process(event.dest_path),
            status="violation" if result["violation"] else "normal",
            details=result
        )

    def on_deleted(self, event):
        if event.is_directory or not is_relevant(event.src_path):
            return
        if not is_under_sensitive(event.src_path):
            return
        hash_cache.pop(event.src_path, None)
        save_hash_cache()
        log_event(
            event_type="delete",
            source=event.src_path,
            status="alert",
            details={"note": "sensitive file deleted"}
        )


def start_watcher():
    for d in SENSITIVE_DIRS:
        os.makedirs(d, exist_ok=True)
    load_caches()
    handler = TransferHandler()
    observer = Observer()
    observer.schedule(handler, BACKEND_ROOT, recursive=True)
    observer.start()
    return observer