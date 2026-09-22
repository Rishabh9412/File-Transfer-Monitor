import os

BACKEND_ROOT = os.path.dirname(os.path.dirname(__file__))

SENSITIVE_DIRS = [
    os.path.join(BACKEND_ROOT, "sensitive_data"),
    os.path.join(BACKEND_ROOT, "confidential_docs"),
]

SENSITIVE_FILES = [
    "payroll.xlsx",
    "employee_records.csv",
]

ALLOWED_DESTINATIONS = [
    os.path.join(BACKEND_ROOT, "logs"),
]

CLOUD_SYNC_MARKERS = ["onedrive", "dropbox", "google drive", "googledrive", "icloud"]


def is_sensitive(file_path):
    normalized = os.path.normpath(file_path)
    filename = os.path.basename(file_path)

    if filename in SENSITIVE_FILES:
        return True

    for sensitive_dir in SENSITIVE_DIRS:
        if normalized.startswith(os.path.normpath(sensitive_dir)):
            return True

    return False


def is_cloud_or_network_destination(destination_path):
    if destination_path is None:
        return False
    lowered = destination_path.lower()
    if lowered.startswith("\\\\"):
        return True
    for marker in CLOUD_SYNC_MARKERS:
        if marker in lowered:
            return True
    return False


def is_authorized(destination_path):
    if destination_path is None:
        return True
    if is_cloud_or_network_destination(destination_path):
        return False

    normalized_dest = os.path.normpath(destination_path)
    for allowed in ALLOWED_DESTINATIONS:
        if normalized_dest.startswith(os.path.normpath(allowed)):
            return True

    return False


def evaluate_event(source_path, destination_path=None):
    if not is_sensitive(source_path):
        return {"sensitive": False, "authorized": True, "violation": False, "cloud_or_network_transfer": False}

    authorized = is_authorized(destination_path)
    cloud_or_network = is_cloud_or_network_destination(destination_path)

    return {
        "sensitive": True,
        "authorized": authorized,
        "violation": not authorized,
        "cloud_or_network_transfer": cloud_or_network
    }