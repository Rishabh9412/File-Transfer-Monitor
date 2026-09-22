import json
import os
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "activity_log.json")

os.makedirs(LOG_DIR, exist_ok=True)

def log_event(event_type, source, destination=None, user=None, process=None, status="normal", details=None):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "source": source,
        "destination": destination,
        "user": user or os.getlogin(),
        "process": process,
        "status": status,
        "details": details
    }

    events = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                events = json.load(f)
            except json.JSONDecodeError:
                events = []

    events.append(entry)

    with open(LOG_FILE, "w") as f:
        json.dump(events, f, indent=2)

    return entry