import requests
import time
import socket
import psutil
import wmi
from datetime import datetime
from getpass import getpass

# ---------------- FIREBASE CONFIG ----------------
API_KEY = "AIzaSyCIY6AiBsGrq7wM0BBYGW2lM_0FLWjnH0k"
PROJECT_ID = "cybermonitor-1ab3c"
# ------------------------------------------------

print("==== CyberMonitor Agent ====")
USER_EMAIL = input("Enter your CyberMonitor email: ")
USER_PASSWORD = getpass("Password: ")

wmi_obj = wmi.WMI()
hostname = socket.gethostname()
known_devices = set()
whitelist = set()
blocked_devices = set()


# -------- FIREBASE AUTH ----------
def login_and_get_token():
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    payload = {"email": USER_EMAIL, "password": USER_PASSWORD, "returnSecureToken": True}
    r = requests.post(url, json=payload)
    r.raise_for_status()
    data = r.json()
    print("LOGIN RESP:", data)
    return data["idToken"], data["localId"]


# -------- FIRESTORE HELPERS ----------
def firestore_set(path, obj, token):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/{path}"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.patch(url, json=obj, headers=headers)
    print("SET RESP:", r.text)
    r.raise_for_status()


def firestore_add(collection_path, obj, token):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/{collection_path}"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.post(url, json=obj, headers=headers)
    print("ADD RESP:", r.text)
    r.raise_for_status()


def firestore_get(path, token):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/{path}"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        return r.json()
    return None


# -------- USB DETECTION ----------
def get_usb_devices():
    devices = []
    for d in wmi_obj.Win32_DiskDrive():
        if "USB" in str(d.InterfaceType):
            devices.append({
                "device_name": d.Model,
                "serial": getattr(d, "SerialNumber", "UNKNOWN")
            })
    return devices


# -------- WHITELIST / BLOCK ----------
def load_whitelist(token, uid):
    global whitelist
    doc = firestore_get(f"users/{uid}/config/whitelist", token)
    if doc and "fields" in doc and "devices" in doc["fields"]:
        whitelist = set(v["stringValue"] for v in doc["fields"]["devices"].get("arrayValue", {}).get("values", []))
    else:
        whitelist = set()


def load_blocked(token, uid):
    global blocked_devices
    doc = firestore_get(f"users/{uid}/config/blocked", token)
    if doc and "fields" in doc and "devices" in doc["fields"]:
        blocked_devices = set(v["stringValue"] for v in doc["fields"]["devices"].get("arrayValue", {}).get("values", []))
    else:
        blocked_devices = set()


def update_whitelist_doc(token, uid):
    obj = {
        "fields": {
            "devices": {
                "arrayValue": {"values": [{"stringValue": d} for d in whitelist]}
            }
        }
    }
    firestore_set(f"users/{uid}/config/whitelist", obj, token)


def update_blocked_doc(token, uid):
    obj = {
        "fields": {
            "devices": {
                "arrayValue": {"values": [{"stringValue": d} for d in blocked_devices]}
            }
        }
    }
    firestore_set(f"users/{uid}/config/blocked", obj, token)


# -------- AGENT LOOP ----------
print("Logging into Firebase…")
token, uid = login_and_get_token()
print("Logged in UID:", uid)

# Ensure whitelist & blocked exist
update_whitelist_doc(token, uid)
update_blocked_doc(token, uid)

print("Agent running. Press CTRL+C to stop.")

while True:
    try:
        usb_list = get_usb_devices()
        current_serials = {d["serial"] for d in usb_list}
        new_devices = current_serials - known_devices
        known_devices.update(current_serials)

        # ---------- STATUS ----------
        status_doc = {
            "fields": {
                "online": {"booleanValue": True},
                "machine": {"stringValue": hostname},
                "last_seen": {"integerValue": int(time.time())},
                "active_user": {"stringValue": psutil.users()[0].name if psutil.users() else "UNKNOWN"},
            }
        }
        firestore_set(f"users/{uid}", status_doc, token)

        # ---------- USB STATUS ----------
        device_array = []
        for dev in usb_list:
            is_whitelisted = dev["serial"] in whitelist
            is_blocked = dev["serial"] in blocked_devices

            device_array.append({
                "mapValue": {
                    "fields": {
                        "device_name": {"stringValue": dev["device_name"]},
                        "serial": {"stringValue": dev["serial"]},
                        "whitelisted": {"booleanValue": is_whitelisted},
                        "blocked": {"booleanValue": is_blocked}
                    }
                }
            })

        firestore_set(
            f"users/{uid}/status/usb_status",
            {"fields": {"usb_devices": {"arrayValue": {"values": device_array}}}},
            token
        )

        # ---------- NEW DEVICE LOGS ----------
        for dev in usb_list:
            if dev["serial"] in new_devices:
                action = "CONNECTED"
                rule = "Whitelisted" if dev["serial"] in whitelist else "Detection Event"
                severity = "LOW" if dev["serial"] in whitelist else "MEDIUM"
                if dev["serial"] in blocked_devices:
                    action = "BLOCKED"
                    severity = "HIGH"

                log = {
                    "fields": {
                        "device_serial": {"stringValue": dev["serial"]},
                        "device_name": {"stringValue": dev["device_name"]},
                        "machine": {"stringValue": hostname},
                        "action": {"stringValue": action},
                        "rule": {"stringValue": rule},
                        "class": {"stringValue": "Mass Storage"},
                        "timestamp": {"integerValue": int(time.time())},
                        "severity": {"stringValue": severity}
                    }
                }
                firestore_add(f"users/{uid}/logs", log, token)

        # ---------- CHECK BLOCK REQUESTS ----------
        load_blocked(token, uid)
        for dev_serial in blocked_devices:
            if dev_serial in known_devices:
                print(f"[ALERT] Device {dev_serial} is blocked!")

        # ---------- REFRESH WHITELIST ----------
        load_whitelist(token, uid)

        print("Heartbeat sent at", datetime.now())
        time.sleep(7)

    except KeyboardInterrupt:
        print("Agent stopped by user.")
        break
    except Exception as e:
        print("Error:", str(e))
        import traceback
        traceback.print_exc()
        time.sleep(5)
