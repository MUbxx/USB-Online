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
whitelist = set()
blocked = set()

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
    r.raise_for_status()
    return r.json()

def firestore_add(collection_path, obj, token):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/{collection_path}"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.post(url, json=obj, headers=headers)
    r.raise_for_status()
    return r.json()

# ---------------- USB DETECTION ----------------
def get_usb_devices():
    devices = []
    for d in wmi_obj.Win32_DiskDrive():
        if "USB" in str(d.InterfaceType):
            serial = getattr(d, "SerialNumber", "UNKNOWN")
            devices.append({
                "device_name": d.Model,
                "serial": serial.strip() if serial else "UNKNOWN",
                "vendor": getattr(d, "Manufacturer", "Unknown"),
                "class": "Mass Storage"
            })
    return devices

# ---------------- LOAD WHITELIST & BLOCKED ----------------
def load_config(token, uid):
    global whitelist, blocked
    try:
        wl_resp = requests.get(f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/config/whitelist",
                               headers={"Authorization": f"Bearer {token}"}).json()
        whitelist = set([d["stringValue"] for d in wl_resp.get("fields", {}).get("devices", {}).get("arrayValue", {}).get("values", [])])
    except:
        whitelist = set()
    try:
        blk_resp = requests.get(f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/config/blocked",
                               headers={"Authorization": f"Bearer {token}"}).json()
        blocked = set([d["stringValue"] for d in blk_resp.get("fields", {}).get("devices", {}).get("arrayValue", {}).get("values", [])])
    except:
        blocked = set()

# ---------------- MAIN ----------------
print("Logging into Firebase…")
token, uid = login_and_get_token()
print(f"Logged in as UID: {uid}")

while True:
    try:
        load_config(token, uid)
        usb_list = get_usb_devices()
        current_serials = {d["serial"] for d in usb_list}
        new_devices = current_serials - known_devices
        known_devices.update(current_serials)

        # ---------------- STATUS ----------------
        status_doc = {
            "fields": {
                "online": {"booleanValue": True},
                "machine": {"stringValue": hostname},
                "active_user": {"stringValue": psutil.users()[0].name if psutil.users() else "UNKNOWN"},
                "last_seen": {"integerValue": int(time.time())}
            }
        }
        firestore_set(f"users/{uid}", status_doc, token)

        # ---------------- USB STATUS ----------------
        device_array = []
        for dev in usb_list:
            dev["whitelisted"] = dev["serial"] in whitelist
            dev["blocked"] = dev["serial"] in blocked
            device_array.append({
                "mapValue": {
                    "fields": {
                        "device_name": {"stringValue": dev["device_name"]},
                        "serial": {"stringValue": dev["serial"]},
                        "vendor": {"stringValue": dev["vendor"]},
                        "class": {"stringValue": dev["class"]},
                        "whitelisted": {"booleanValue": dev["whitelisted"]},
                        "blocked": {"booleanValue": dev["blocked"]}
                    }
                }
            })
        firestore_set(f"users/{uid}/status/usb_status", {"fields":{"usb_devices":{"arrayValue":{"values":device_array}}}}, token)

        # ---------------- NEW DEVICE LOGS ----------------
        for dev in usb_list:
            if dev["serial"] in new_devices:
                log = {
                    "fields": {
                        "device_serial": {"stringValue": dev["serial"]},
                        "device_name": {"stringValue": dev["device_name"]},
                        "machine": {"stringValue": hostname},
                        "action": {"stringValue": "CONNECTED"},
                        "rule": {"stringValue": "Detection Event"},
                        "class": {"stringValue": "Mass Storage"},
                        "timestamp": {"integerValue": int(time.time())},
                        "severity": {"stringValue": "MEDIUM"}
                    }
                }
                firestore_add(f"users/{uid}/logs", log, token)
                # Optionally: send email alert here using cloud function

        print(f"Heartbeat sent at {datetime.now()}")

    except Exception as e:
        print("Error:", e)

    time.sleep(7)
