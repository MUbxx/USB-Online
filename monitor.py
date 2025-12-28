import requests
import time
import socket
import psutil
import wmi
from datetime import datetime
from getpass import getpass

# ---------- FIREBASE CONFIG ----------
API_KEY = "AIzaSyCIY6AiBsGrq7wM0BBYGW2lM_0FLWjnH0k"
PROJECT_ID = "cybermonitor-1ab3c"
# -------------------------------------

print("==== CyberMonitor Agent ====")

USER_EMAIL = input("Enter your CyberMonitor email: ")
USER_PASSWORD = getpass("Password: ")

wmi_obj = wmi.WMI()
hostname = socket.gethostname()
known_devices = set()


# -------- Authenticate user & get ID token -------
def login_and_get_token():
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"

    payload = {
        "email": USER_EMAIL,
        "password": USER_PASSWORD,
        "returnSecureToken": True
    }

    r = requests.post(url, json=payload)
    print("LOGIN RESP:", r.text)
    r.raise_for_status()
    data = r.json()

    return data["idToken"], data["localId"]


# ----- Firestore request wrapper -----
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


# -------- USB detection ----------
def get_usb_devices():
    devices = []

    for d in wmi_obj.Win32_DiskDrive():
        if "USB" in str(d.InterfaceType):
            devices.append({
                "device_name": d.Model,
                "serial": getattr(d, "SerialNumber", "UNKNOWN"),
            })
    return devices


print("Logging into Firebase…")
token, uid = login_and_get_token()
print("Logged in as UID:", uid)

print("Agent running. Press CTRL+C to stop.")

while True:
    try:
        usb_list = get_usb_devices()

        current_serials = {d["serial"] for d in usb_list}
        new_devices = current_serials - known_devices
        known_devices.update(current_serials)

        # ---------- STATUS DOCUMENT ----------
        status_doc = {
            "fields": {
                "online": {"booleanValue": True},
                "machine": {"stringValue": hostname},
                "last_seen": {"integerValue": int(time.time())},
                "active_user": {
                    "stringValue": psutil.users()[0].name if psutil.users() else "UNKNOWN"
                },
            }
        }

        firestore_set(f"users/{uid}", status_doc, token)

        # ---------- CREATE WHITELIST DOC IF MISSING ----------
        whitelist_doc = {
            "fields": {
                "devices": {
                    "arrayValue": {
                        "values": []
                    }
                }
            }
        }

        firestore_set(f"users/{uid}/config/whitelist", whitelist_doc, token)

        # ---------- USB DEVICE LIST DOCUMENT ----------
        device_array = []
        for dev in usb_list:
            device_array.append({
                "mapValue": {
                    "fields": {
                        "device_name": {"stringValue": dev["device_name"]},
                        "serial": {"stringValue": dev["serial"]}
                    }
                }
            })

        firestore_set(
            f"users/{uid}/status/usb_status",
            {
                "fields": {
                    "usb_devices": {
                        "arrayValue": {"values": device_array}
                    }
                }
            },
            token
        )

        # ---------- LOG NEW DEVICES ----------
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

        print("Heartbeat sent at", datetime.now())

    except KeyboardInterrupt:
        print("Agent stopped by user.")
        break

    except Exception as e:
        print("Error:", str(e))
        import traceback
        traceback.print_exc()

    time.sleep(7)
