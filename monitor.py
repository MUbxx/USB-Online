import time
import socket
import psutil
import wmi
import requests
import ctypes
import os
import sys
from datetime import datetime, UTC
from getpass import getpass

# Firebase Configuration
API_KEY = "AIzaSyCIY6AiBsGrq7wM0BBYGW2lM_0FLWjnH0k"
PROJECT_ID = "cybermonitor-1ab3c"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Self-elevate to Admin if not already
if not is_admin():
    print("Elevating to Administrator for hardware access...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    os._exit(0)

print("=== CyberMonitor Agent v3.0 (EXE Ready) ===")
USER_EMAIL = input("Enter CyberMonitor Email: ")
USER_PASSWORD = getpass("Password: ")

wmi_obj = wmi.WMI()
hostname = socket.gethostname()

def login():
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    r = requests.post(url, json={"email": USER_EMAIL, "password": USER_PASSWORD, "returnSecureToken": True})
    r.raise_for_status()
    return r.json()["idToken"], r.json()["localId"]

def set_cloud_status(token, uid, online_bool):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}"
    payload = {"fields": {
        "is_online": {"booleanValue": online_bool},
        "machine": {"stringValue": hostname},
        "last_seen": {"stringValue": datetime.now(UTC).isoformat()}
    }}
    requests.patch(url, json=payload, headers={"Authorization": f"Bearer {token}"})

def scan_usbs():
    devices = []
    try:
        for disk in wmi_obj.Win32_DiskDrive():
            if "USBSTOR" in (disk.PNPDeviceID or ""):
                devices.append({
                    "name": disk.Caption or "External Drive",
                    "serial": (disk.SerialNumber or "UNKNOWN").strip(),
                    "id": disk.PNPDeviceID
                })
    except: pass
    return devices

try:
    token, uid = login()
    set_cloud_status(token, uid, True)
    print("Agent Online. Monitoring hardware...")

    known_ids = {d['id'] for d in scan_usbs()}

    while True:
        current_list = scan_usbs()
        current_ids = {d['id'] for d in current_list}

        # Check for NEW connections
        for dev in current_list:
            if dev['id'] not in known_ids:
                print(f"[+] PLUGGED: {dev['name']}")
                # Log to Firestore
                log_url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/logs"
                requests.post(log_url, json={"fields": {
                    "message": {"stringValue": f"CONNECTED: {dev['name']} (SN: {dev['serial']})"},
                    "timestamp": {"timestampValue": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")},
                    "severity": {"stringValue": "HIGH"}
                }}, headers={"Authorization": f"Bearer {token}"})

        # Check for REMOVALS
        for dev_id in known_ids:
            if dev_id not in current_ids:
                print(f"[-] REMOVED: {dev_id}")
                # Log removal
                log_url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/logs"
                requests.post(log_url, json={"fields": {
                    "message": {"stringValue": f"REMOVED DEVICE: {dev_id.split('\\')[-1]}"},
                    "timestamp": {"timestampValue": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")},
                    "severity": {"stringValue": "INFO"}
                }}, headers={"Authorization": f"Bearer {token}"})

        known_ids = current_ids
        
        # Update live list and heartbeat
        usb_payload = {"fields": {"usb_devices": {"arrayValue": {"values": [
            {"mapValue": {"fields": {"device_name": {"stringValue": d["name"]}, "serial": {"stringValue": d["serial"]}}}} for d in current_list
        ]}}}}
        requests.patch(f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/status/usb_status", 
                       json=usb_payload, headers={"Authorization": f"Bearer {token}"})
        
        set_cloud_status(token, uid, True)
        time.sleep(5)

except Exception as e:
    print(f"Error: {e}")
finally:
    if 'token' in locals():
        set_cloud_status(token, uid, False)
        print("Agent Offline.")
