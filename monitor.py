import time
import socket
import psutil
import wmi
import requests
from datetime import datetime
from getpass import getpass

API_KEY = "AIzaSyCIY6AiBsGrq7wM0BBYGW2lM_0FLWjnH0k"
PROJECT_ID = "cybermonitor-1ab3c"

print("=== CyberMonitor Agent ===")
USER_EMAIL = input("Enter your CyberMonitor email: ")
USER_PASSWORD = getpass("Password: ")

hostname = socket.gethostname()
wmi_obj = wmi.WMI()
known_serials = set()

def login_and_get_token():
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    payload = {"email": USER_EMAIL, "password": USER_PASSWORD, "returnSecureToken": True}
    r = requests.post(url, json=payload)
    r.raise_for_status()
    data = r.json()
    return data["idToken"], data["localId"]

def firestore_set(path, obj, token):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/{path}"
    headers = {"Authorization": f"Bearer {token}"}
    return requests.patch(url, json=obj, headers=headers)

def firestore_add(path, obj, token):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/{path}"
    headers = {"Authorization": f"Bearer {token}"}
    return requests.post(url, json=obj, headers=headers)

def get_external_usb_storage():
    devices = []
    try:
        # FILTER: Only get physical disks where the interface is USB
        for disk in wmi_obj.Win32_DiskDrive(InterfaceType="USB"):
            devices.append({
                "name": disk.Caption or "Unknown USB Drive",
                "serial": (disk.SerialNumber or "NOSERIAL").strip(),
                "vendor": disk.Manufacturer or "Generic",
                "model": disk.Model or "External Storage"
            })
    except Exception as e:
        print("Detection error:", e)
    return devices

print("Connecting to cloud...")
token, uid = login_and_get_token()
print("Connected successfully.")

while True:
    try:
        usb_list = get_external_usb_storage()
        current_serials = {d["serial"] for d in usb_list}

        new_devices = [d for d in usb_list if d["serial"] not in known_serials]
        removed_serials = known_serials - current_serials

        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # 1. HEARTBEAT
        status_doc = {"fields": {
            "machine": {"stringValue": hostname},
            "active_user": {"stringValue": psutil.users()[0].name if psutil.users() else "SYSTEM"},
            "last_seen": {"timestampValue": timestamp}
        }}
        firestore_set(f"users/{uid}", status_doc, token)

        # 2. USB STATUS (Flattened for the Dashboard)
        usb_values = []
        for dev in usb_list:
            usb_values.append({"mapValue": {"fields": {
                "vendor": {"stringValue": dev["vendor"]},
                "device_name": {"stringValue": dev["name"]},
                "serial": {"stringValue": dev["serial"]}
            }}})
        
        firestore_set(f"users/{uid}/status/usb_status", 
                      {"fields": {"usb_devices": {"arrayValue": {"values": usb_values}}}}, token)

        # 3. LOG NEW CONNECTIONS
        for dev in new_devices:
            log = {"fields": {
                "message": {"stringValue": f"FLASH DRIVE DETECTED: {dev['name']} ({dev['serial']})"},
                "timestamp": {"timestampValue": timestamp},
                "severity": {"stringValue": "HIGH"}
            }}
            firestore_add(f"users/{uid}/logs", log, token)
            print(f"[+] Plugged: {dev['name']}")

        # 4. LOG REMOVALS
        for s in removed_serials:
            log = {"fields": {
                "message": {"stringValue": f"FLASH DRIVE REMOVED: {s}"},
                "timestamp": {"timestampValue": timestamp},
                "severity": {"stringValue": "INFO"}
            }}
            firestore_add(f"users/{uid}/logs", log, token)
            print(f"[-] Unplugged: {s}")

        known_serials = current_serials
        print("Heartbeat OK - Monitoring External USBs...")

    except Exception as e:
        print("Loop error:", e)
        try: token, uid = login_and_get_token()
        except: pass

    time.sleep(10)
