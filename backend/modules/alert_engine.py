import json
import os

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "activity_log.json")

ALERT_STATUSES = {"violation", "tampered", "alert"}

def get_alerts():
    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r") as f:
        try:
            events = json.load(f)
        except json.JSONDecodeError:
            return []

    alerts = [e for e in events if e.get("status") in ALERT_STATUSES]
    alerts.sort(key=lambda e: e["timestamp"], reverse=True)
    return alerts

def get_alert_summary():
    alerts = get_alerts()
    summary = {"total_alerts": len(alerts), "by_type": {}}

    for alert in alerts:
        event_type = alert.get("event_type", "unknown")
        summary["by_type"][event_type] = summary["by_type"].get(event_type, 0) + 1

    return summary