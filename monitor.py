import time
import socket
import psutil
import wmi
import requests
from datetime import datetime, UTC
from getpass import getpass

# Firebase Config
API_KEY = "AIzaSyCIY6AiBsGrq7wM0BBYGW2lM_0FLWjnH0k"
PROJECT_ID = "cybermonitor-1ab3c"

print("=== CyberMonitor Agent ===")
USER_EMAIL = input("Email: ")
USER_PASSWORD = getpass("Password: ")

wmi_obj = wmi.WMI()
hostname = socket.gethostname()

def login():
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    r = requests.post(url, json={"email": USER_EMAIL, "password": USER_PASSWORD, "returnSecureToken": True})
    r.raise_for_status()
    return r.json()["idToken"], r.json()["localId"]

def log_event(token, uid, message, severity):
    """Sends a detailed log entry to Firestore."""
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/logs"
    payload = {"fields": {
        "message": {"stringValue": message},
        "timestamp": {"timestampValue": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")},
        "severity": {"stringValue": severity}
    }}
    requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})

def update_status(token, uid, online, usb_list):
    """Updates the heartbeat and current USB list."""
    # Update Heartbeat
    status_url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}"
    status_payload = {"fields": {
        "is_online": {"booleanValue": online},
        "machine": {"stringValue": hostname},
        "last_seen": {"stringValue": datetime.now(UTC).isoformat()}
    }}
    requests.patch(status_url, json=status_payload, headers={"Authorization": f"Bearer {token}"})

    # Update USB List
    usb_url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/status/usb_status"
    usb_payload = {"fields": {"usb_devices": {"arrayValue": {"values": [
        {"mapValue": {"fields": {
            "device_name": {"stringValue": d["name"]},
            "serial": {"stringValue": d["serial"]}
        }}} for d in usb_list
    ]}}}}
    requests.patch(usb_url, json=usb_payload, headers={"Authorization": f"Bearer {token}"})

def scan_usbs():
    """Scans for external storage using a more permissive PNP check."""
    devices = []
    try:
        for disk in wmi_obj.Win32_DiskDrive():
            # Check for USBSTOR (Storage) or USB (General) in the DeviceID
            pnp_id = disk.PNPDeviceID or ""
            if "USBSTOR" in pnp_id or "USB" in disk.InterfaceType or "USB" in disk.Caption:
                devices.append({
                    "name": disk.Caption or "Generic USB Drive",
                    "serial": (disk.SerialNumber or "SN-HIDDEN").strip(),
                    "id": pnp_id
                })
    except: pass
    return devices

try:
    token, uid = login()
    update_status(token, uid, True, [])
    print("Agent Active. Watching for Plug/Unplug events...")

    known_devices = {d['id']: d for d in scan_usbs()}

    while True:
        current_list = scan_usbs()
        current_ids = {d['id']: d for d in current_list}

        # Check for Plug-In
        for dev_id, dev_info in current_ids.items():
            if dev_id not in known_devices:
                ts = datetime.now().strftime("%H:%M:%S")
                msg = f"[{ts}] PLUG-IN: {dev_info['name']} (Serial: {dev_info['serial']})"
                log_event(token, uid, msg, "HIGH")
                print(f"[+] {msg}")

        # Check for Plug-Out
        for dev_id, dev_info in known_devices.items():
            if dev_id not in current_ids:
                ts = datetime.now().strftime("%H:%M:%S")
                msg = f"[{ts}] PLUG-OUT: {dev_info['name']} (ID: {dev_id.split('\\')[-1]})"
                log_event(token, uid, msg, "INFO")
                print(f"[-] {msg}")

        known_devices = current_ids
        update_status(token, uid, True, current_list)
        time.sleep(5) # Faster polling for instant detection

except Exception as e:
    print(f"Error: {e}")
finally:
    if 'token' in locals():
        update_status(token, uid, False, [])
