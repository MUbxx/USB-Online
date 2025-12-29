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

known_devices = set()

def login_and_get_token():
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    payload = {
        "email": USER_EMAIL,
        "password": USER_PASSWORD,
        "returnSecureToken": True
    }
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

def get_usb_devices():
    devices = []

    try:
        for dev in wmi_obj.Win32_PnPEntity():
            if not dev.PNPClass:
                continue

            if "USB" not in dev.PNPClass:
                continue

            serial = getattr(dev, "SerialNumber", None)
            if isinstance(serial, str):
                serial = serial.strip()
            else:
                serial = "UNKNOWN"

            devices.append({
                "device_name": dev.Name or "Unknown USB Device",
                "serial": serial,
                "vendor": dev.Manufacturer or "Unknown",
                "class": dev.PNPClass
            })

    except Exception as e:
        print("USB detection error:", e)

    return devices


print("Connecting to cloud...")
token, uid = login_and_get_token()
print("Connected successfully.")

while True:
    try:
        usb_list = get_usb_devices()
        current_serials = {d["serial"] for d in usb_list}

        new_devices = current_serials - known_devices
        removed_devices = known_devices - current_serials

        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # ---------- HEARTBEAT ----------
        status_doc = {
            "fields": {
                "machine": {"stringValue": hostname},
                "active_user": {
                    "stringValue": psutil.users()[0].name if psutil.users() else "UNKNOWN"
                },
                "last_seen": {"timestampValue": timestamp}
            }
        }

        firestore_set(f"users/{uid}", status_doc, token)

        # ---------- USB LIST ----------
        device_array = []
        for dev in usb_list:
            device_array.append({
                "mapValue": {
                    "fields": {
                        "device_name": {"stringValue": dev["device_name"]},
                        "serial": {"stringValue": dev["serial"]},
                        "vendor": {"stringValue": dev["vendor"]},
                        "class": {"stringValue": dev["class"]},
                    }
                }
            })

        firestore_set(
            f"users/{uid}/status/usb_status",
            {"fields": {"usb_devices": {"arrayValue": {"values": device_array}}}},
            token
        )

        # ---------- NEW DEVICES ----------
        for dev in usb_list:
            if dev["serial"] in new_devices:

                log_entry = {
                    "fields": {
                        "message": {
                            "stringValue": f"NEW USB DETECTED: {dev['device_name']} ({dev['serial']})"
                        },
                        "timestamp": {"timestampValue": timestamp},
                        "severity": {"stringValue": "HIGH"},
                        "send_email": {"booleanValue": True}
                    }
                }

                firestore_add(f"users/{uid}/logs", log_entry, token)
                print("[+] New USB attached:", dev["serial"])

        # ---------- REMOVED DEVICES ----------
        for serial in removed_devices:

            log_entry = {
                "fields": {
                    "message": {
                        "stringValue": f"USB REMOVED: {serial}"
                    },
                    "timestamp": {"timestampValue": timestamp},
                    "severity": {"stringValue": "INFO"},
                    "send_email": {"booleanValue": False}
                }
            }

            firestore_add(f"users/{uid}/logs", log_entry, token)
            print("[-] USB removed:", serial)

        known_devices = current_serials

        print("Heartbeat OK")

    except Exception as e:
        print("Error in monitoring loop:", e)
        try:
            token, uid = login_and_get_token()
        except:
            pass

    time.sleep(10)
