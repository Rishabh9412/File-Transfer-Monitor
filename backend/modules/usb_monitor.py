import psutil
import time
import threading

from modules.logger import log_event

known_drives = set()

def get_removable_drives():
    drives = set()
    for partition in psutil.disk_partitions():
        if "removable" in partition.opts.lower():
            drives.add(partition.device)
    return drives

def check_drives():
    global known_drives
    current_drives = get_removable_drives()

    new_drives = current_drives - known_drives
    removed_drives = known_drives - current_drives

    for drive in new_drives:
        log_event(
            event_type="usb_connect",
            source=drive,
            status="alert",
            details={"note": "removable drive connected"}
        )

    for drive in removed_drives:
        log_event(
            event_type="usb_disconnect",
            source=drive,
            status="normal",
            details={"note": "removable drive disconnected"}
        )

    known_drives = current_drives

def start_usb_monitor(poll_interval=3):
    global known_drives
    known_drives = get_removable_drives()

    def loop():
        while True:
            check_drives()
            time.sleep(poll_interval)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return thread