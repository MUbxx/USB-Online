import os
import sys
import time
import socket
import requests
from datetime import datetime, UTC
from getpass import getpass
from usbmonitor import USBMonitor
from usbmonitor.attributes import ID_MODEL, ID_SERIAL, ID_VENDOR

# --- CONFIGURATION ---
API_KEY = "AIzaSyCIY6AiBsGrq7wM0BBYGW2lM_0FLWjnH0k"
PROJECT_ID = "cybermonitor-1ab3c"

print("=== CyberMonitor Agent v4.0 (Event-Driven) ===")
USER_EMAIL = input("Email: ")
USER_PASSWORD = getpass("Password: ")

hostname = socket.gethostname()

def login():
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    r = requests.post(url, json={"email": USER_EMAIL, "password": USER_PASSWORD, "returnSecureToken": True})
    r.raise_for_status()
    return r.json()["idToken"], r.json()["localId"]

def update_cloud_state(token, uid, is_online):
    """Updates the heartbeat and online status."""
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}"
    payload = {"fields": {
        "is_online": {"booleanValue": is_online},
        "machine": {"stringValue": hostname},
        "last_seen": {"stringValue": datetime.now(UTC).isoformat()}
    }}
    requests.patch(url, json=payload, headers={"Authorization": f"Bearer {token}"})

def log_event(token, uid, message, severity):
    """Sends a security log to the cloud."""
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/logs"
    payload = {"fields": {
        "message": {"stringValue": message},
        "timestamp": {"timestampValue": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")},
        "severity": {"stringValue": severity}
    }}
    requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})

def sync_usb_list(token, uid, monitor):
    """Syncs the currently connected devices to the dashboard."""
    devices = monitor.get_available_devices()
    usb_values = []
    for dev_id, info in devices.items():
        usb_values.append({"mapValue": {"fields": {
            "device_name": {"stringValue": info.get(ID_MODEL, "Unknown")},
            "serial": {"stringValue": info.get(ID_SERIAL, "N/A")},
            "vendor": {"stringValue": info.get(ID_VENDOR, "Generic")}
        }}})
    
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/status/usb_status"
    requests.patch(url, json={"fields": {"usb_devices": {"arrayValue": {"values": usb_values}}}}, 
                   headers={"Authorization": f"Bearer {token}"})

# --- CALLBACKS (The 'Eric-Canas' Logic) ---
def on_connect(device_id, device_info):
    msg = f"CONNECTED: {device_info.get(ID_MODEL)} (SN: {device_info.get(ID_SERIAL)})"
    print(f"[+] {msg}")
    log_event(global_token, global_uid, msg, "HIGH")
    sync_usb_list(global_token, global_uid, monitor)

def on_disconnect(device_id, device_info):
    msg = f"REMOVED: {device_info.get(ID_MODEL)} (ID: {device_id.split('/')[-1]})"
    print(f"[-] {msg}")
    log_event(global_token, global_uid, msg, "INFO")
    sync_usb_list(global_token, global_uid, monitor)

try:
    global_token, global_uid = login()
    monitor = USBMonitor()
    
    # Start the background daemon
    monitor.start_monitoring(on_connect=on_connect, on_disconnect=on_disconnect)
    
    # Mark Online
    update_cloud_state(global_token, global_uid, True)
    sync_usb_list(global_token, global_uid, monitor)
    
    print("Security Daemon Active. Press Ctrl+C to stop.")
    
    while True:
        # Keep main thread alive and update heartbeat
        update_cloud_state(global_token, global_uid, True)
        time.sleep(30)

except KeyboardInterrupt:
    print("\nStopping Agent...")
finally:
    if 'global_token' in locals():
        update_cloud_state(global_token, global_uid, False)
        monitor.stop_monitoring()
