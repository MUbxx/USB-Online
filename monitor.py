import time
import socket
import psutil
import wmi
import requests
from datetime import datetime

# ---------------- FIREBASE CONFIG ----------------
API_KEY = "AIzaSyCIY6AiBsGrq7wM0BBYGW2lM_0FLWjnH0k"
PROJECT_ID = "cybermonitor-1ab3c"

# Secure user login
USER_EMAIL = input("Enter your CyberMonitor email: ")
USER_PASSWORD = input("Password: ")

wmi_obj = wmi.WMI()
hostname = socket.gethostname()
known_devices = set()

# ---------------- LOGIN ----------------
def login_and_get_token():
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    payload = {"email": USER_EMAIL,"password": USER_PASSWORD,"returnSecureToken": True}
    r = requests.post(url, json=payload)
    r.raise_for_status()
    data = r.json()
    return data["idToken"], data["localId"]

# ---------------- FIRESTORE WRAPPERS ----------------
def firestore_set(path, obj, token):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/{path}"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.patch(url, json=obj, headers=headers)
    return r.json()

def firestore_add(collection_path, obj, token):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/{collection_path}"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.post(url, json=obj, headers=headers)
    return r.json()

# ---------------- USB DETECTION ----------------
def get_usb_devices():
    devices = []
    try:
        for d in wmi_obj.Win32_DiskDrive():
            if "USB" in str(d.InterfaceType):
                serial = getattr(d, "SerialNumber", "UNKNOWN").strip()
                devices.append({
                    "device_name": d.Model,
                    "serial": serial if serial else "UNKNOWN",
                    "vendor": getattr(d, "Manufacturer", "Unknown"),
                    "class": "Mass Storage"
                })
    except: pass
    return devices

# ---------------- MAIN LOOP ----------------
print("Connecting to CyberMonitor Cloud...")
token, uid = login_and_get_token()
print(f"Agent Active. Monitoring host: {hostname}")

while True:
    try:
        usb_list = get_usb_devices()
        current_serials = {d["serial"] for d in usb_list}
        
        # Detect new insertions
        new_devices = current_serials - known_devices
        
        # 1. Update Core Status & Heartbeat
        timestamp_iso = datetime.utcnow().isoformat() + "Z"
        status_doc = {
            "fields": {
                "online": {"booleanValue": True},
                "machine": {"stringValue": hostname},
                "active_user": {"stringValue": psutil.users()[0].name if psutil.users() else "UNKNOWN"},
                "last_seen": {"timestampValue": timestamp_iso}
            }
        }
        firestore_set(f"users/{uid}", status_doc, token)

        # 2. Update USB Status List
        device_array = []
        for dev in usb_list:
            device_array.append({
                "mapValue": {
                    "fields": {
                        "device_name": {"stringValue": dev["device_name"]},
                        "serial": {"stringValue": dev["serial"]},
                        "vendor": {"stringValue": dev["vendor"]},
                        "class": {"stringValue": dev["class"]},
                        "blocked": {"booleanValue": False} # Logic for blocking goes here
                    }
                }
            })
        
        firestore_set(f"users/{uid}/status/usb_status", 
                     {"fields":{"usb_devices":{"arrayValue":{"values":device_array}}}}, token)

        # 3. Log and Trigger Alerts
        for dev in usb_list:
            if dev["serial"] in new_devices:
                log_entry = {
                    "fields": {
                        "message": {"stringValue": f"NEW DEVICE: {dev['device_name']} ({dev['serial']}) detected on {hostname}"},
                        "timestamp": {"timestampValue": timestamp_iso},
                        "severity": {"stringValue": "HIGH"},
                        "send_email": {"booleanValue": True} # Flag for Firebase Cloud Function
                    }
                }
                firestore_add(f"users/{uid}/logs", log_entry, token)
                print(f"!!! Alert: New Device {dev['serial']}")

        known_devices = current_serials
        print(f"Heartbeat sent [{datetime.now().strftime('%H:%M:%S')}]")

    except Exception as e:
        print("Network Error:", e)
        try: token, uid = login_and_get_token() # Re-auth on fail
        except: pass

    time.sleep(5)
