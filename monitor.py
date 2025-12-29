import time
import socket
import psutil
import wmi
import requests
from datetime import datetime, UTC
from getpass import getpass

# Configuration
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
    return r.json()["idToken"], r.json()["localId"]

def firestore_call(method, path, obj, token):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/{path}"
    headers = {"Authorization": f"Bearer {token}"}
    if method == "PATCH":
        return requests.patch(url, json=obj, headers=headers)
    return requests.post(url, json=obj, headers=headers)

def get_external_usb_storage():
    devices = []
    try:
        for disk in wmi_obj.Win32_DiskDrive():
            # Targets physical external drives specifically
            if "USBSTOR" in (disk.PNPDeviceID or ""):
                devices.append({
                    "name": disk.Caption or "External Drive",
                    "serial": (disk.SerialNumber or "UNKNOWN").strip(),
                    "vendor": disk.Manufacturer or "Generic"
                })
    except Exception as e:
        print("Detection error:", e)
    return devices

print("Connecting to cloud...")
token, uid = login_and_get_token()
print("Connected successfully. Monitoring for External USBs...")

while True:
    try:
        usb_list = get_external_usb_storage()
        current_serials = {d["serial"] for d in usb_list}
        
        new_devices = [d for d in usb_list if d["serial"] not in known_serials]
        removed_serials = known_serials - current_serials
        
        # Proper UTC Timestamp for 2025 standards
        timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # 1. Heartbeat
        status_doc = {"fields": {
            "machine": {"stringValue": hostname},
            "active_user": {"stringValue": psutil.users()[0].name if psutil.users() else "SYSTEM"},
            "last_seen": {"stringValue": timestamp} # Sending as string for easier JS parsing
        }}
        firestore_call("PATCH", f"users/{uid}", status_doc, token)

        # 2. USB Status
        usb_values = [{"mapValue": {"fields": {
            "vendor": {"stringValue": d["vendor"]},
            "device_name": {"stringValue": d["name"]},
            "serial": {"stringValue": d["serial"]}
        }}} for d in usb_list]
        
        firestore_call("PATCH", f"users/{uid}/status/usb_status", 
                       {"fields": {"usb_devices": {"arrayValue": {"values": usb_values}}}}, token)

        # 3. Logs
        for dev in new_devices:
            log = {"fields": {
                "message": {"stringValue": f"CONNECTED: {dev['name']} ({dev['serial']})"},
                "timestamp": {"timestampValue": timestamp},
                "severity": {"stringValue": "HIGH"}
            }}
            firestore_call("POST", f"users/{uid}/logs", log, token)
            print(f"[+] Plugged: {dev['name']}")

        for s in removed_serials:
            log = {"fields": {
                "message": {"stringValue": f"REMOVED: {s}"},
                "timestamp": {"timestampValue": timestamp},
                "severity": {"stringValue": "INFO"}
            }}
            firestore_call("POST", f"users/{uid}/logs", log, token)
            print(f"[-] Unplugged: {s}")

        known_serials = current_serials
        print("Heartbeat OK")

    except Exception as e:
        print("Loop error:", e)
        try: token, uid = login_and_get_token()
        except: pass

    time.sleep(10)
