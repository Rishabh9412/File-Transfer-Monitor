import os
import json
import time
import shutil
from flask import Flask, jsonify
from flask_cors import CORS

from modules.watcher import start_watcher
from modules.usb_monitor import start_usb_monitor
from modules.alert_engine import get_alerts, get_alert_summary
from modules.report_generator import generate_report
from modules.logger import log_event
from modules.policy import evaluate_event

app = Flask(__name__)
CORS(app)

LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "activity_log.json")

@app.route("/api/logs")
def logs():
    if not os.path.exists(LOG_FILE):
        return jsonify([])
    with open(LOG_FILE, "r") as f:
        try:
            events = json.load(f)
        except json.JSONDecodeError:
            events = []
    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return jsonify(events)

@app.route("/api/alerts")
def alerts():
    return jsonify(get_alerts())

@app.route("/api/alerts/summary")
def alerts_summary():
    return jsonify(get_alert_summary())

@app.route("/api/report", methods=["POST"])
def report():
    return jsonify(generate_report())

@app.route("/api/simulate", methods=["POST"])
def simulate():
    sensitive_dir = os.path.join(os.path.dirname(__file__), "sensitive_data")
    unauthorized_dir = os.path.join(os.path.dirname(__file__), "unauthorized_zone")
    os.makedirs(unauthorized_dir, exist_ok=True)

    test_file = os.path.join(sensitive_dir, "demo_sensitive.txt")
    moved_path = os.path.join(unauthorized_dir, "demo_sensitive.txt")

    if os.path.exists(moved_path):
        os.remove(moved_path)

    with open(test_file, "w") as f:
        f.write("classified project data - demo run")
    time.sleep(0.5)

    with open(test_file, "a") as f:
        f.write(" | tampered content appended")
    time.sleep(0.5)

    if os.path.exists(test_file):
        shutil.move(test_file, moved_path)

        result = evaluate_event(test_file, moved_path)
        log_event(
            event_type="move",
            source=test_file,
            destination=moved_path,
            process="HP-session",
            status="violation" if result["violation"] else "normal",
            details=result
        )
    time.sleep(0.3)

    log_event(
        event_type="usb_connect",
        source="E:\\ (Removable Disk)",
        status="alert",
        details={"note": "simulated USB connection for demo"}
    )
    time.sleep(0.3)

    cloud_dir = os.path.join(os.path.dirname(__file__), "OneDrive_Sync_Test")
    os.makedirs(cloud_dir, exist_ok=True)
    cloud_test_file = os.path.join(sensitive_dir, "cloud_test_file.txt")
    with open(cloud_test_file, "w") as f:
        f.write("test file for cloud detection")
    time.sleep(0.3)
    cloud_dest = os.path.join(cloud_dir, "cloud_test_file.txt")
    if os.path.exists(cloud_test_file):
        shutil.move(cloud_test_file, cloud_dest)
        cloud_result = evaluate_event(cloud_test_file, cloud_dest)
        log_event(
            event_type="move",
            source=cloud_test_file,
            destination=cloud_dest,
            process="HP-session",
            status="violation" if cloud_result["violation"] else "normal",
            details=cloud_result
        )

    return jsonify({"status": "simulation complete"})

if __name__ == "__main__":
    start_watcher()
    start_usb_monitor()
    app.run(port=5000, debug=False)