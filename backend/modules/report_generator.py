import json
import os
from datetime import datetime

from modules.alert_engine import get_alerts, get_alert_summary

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "activity_log.json")
REPORT_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "audit_report.json")

def load_events():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def generate_report():
    events = load_events()
    alerts = get_alerts()
    alert_summary = get_alert_summary()

    event_counts = {}
    for e in events:
        event_type = e.get("event_type", "unknown")
        event_counts[event_type] = event_counts.get(event_type, 0) + 1

    report = {
        "generated_at": datetime.now().isoformat(),
        "total_events": len(events),
        "event_counts": event_counts,
        "total_alerts": len(alerts),
        "alert_breakdown": alert_summary["by_type"],
        "recent_alerts": alerts[:10]
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    return report