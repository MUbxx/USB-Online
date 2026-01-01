import socket
import time
import requests
from datetime import datetime, timezone
from getpass import getpass
from usbmonitor import USBMonitor
from usbmonitor.attributes import ID_MODEL, ID_SERIAL, ID_VENDOR

API_KEY = "YOUR_FIREBASE_WEB_API_KEY"
PROJECT_ID = "cybermonitor-1ab3c"

print("=== CyberMonitor Agent v5.0 ===")

EMAIL = input("Email: ")
PASSWORD = getpass("Password: ")
HOSTNAME = socket.gethostname()


def login():
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"

    r = requests.post(url, json={
        "email": EMAIL,
        "password": PASSWORD,
        "returnSecureToken": True
    })

    r.raise_for_status()

    j = r.json()
    return j["idToken"], j["localId"]


def update_user_state(token, uid, online=True):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}"

    payload = {
        "fields": {
            "email": {"stringValue": EMAIL},
            "machine": {"stringValue": HOSTNAME},
            "is_online": {"booleanValue": online},
            "last_seen": {"timestampValue": datetime.now(timezone.utc).isoformat()}
        }
    }

    requests.patch(url, json=payload, headers={"Authorization": f"Bearer {token}"})


def push_log(token, uid, message, severity="INFO"):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/logs"

    payload = {
        "fields": {
            "message": {"stringValue": message},
            "severity": {"stringValue": severity},
            "timestamp": {"timestampValue": datetime.now(timezone.utc).isoformat()}
        }
    }

    requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})


def sync_usb_devices(token, uid, monitor):
    devices = monitor.get_available_devices()

    usb_array = []

    for dev_id, info in devices.items():

        model = info.get(ID_MODEL, "Unknown")
        serial = info.get(ID_SERIAL, "N/A")
        vendor = info.get(ID_VENDOR, "Generic")

        token_id = f"{vendor}:{serial}"

        usb_array.append({
            "mapValue": {
                "fields": {
                    "device_name": {"stringValue": model},
                    "token": {"stringValue": token_id},
                    "pnp_id": {"stringValue": dev_id}
                }
            }
        })

    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/status/usb_status"

    payload = {
        "fields": {
            "usb_devices": {
                "arrayValue": {"values": usb_array}
            }
        }
    }

    requests.patch(url, json=payload, headers={"Authorization": f"Bearer {token}"})


def on_connect(dev_id, info):
    msg = f"CONNECTED: {info.get(ID_MODEL)}"
    print(msg)
    push_log(TOKEN, UID, msg, "HIGH")
    sync_usb_devices(TOKEN, UID, monitor)


def on_disconnect(dev_id, info):
    msg = f"REMOVED: {info.get(ID_MODEL)}"
    print(msg)
    push_log(TOKEN, UID, msg, "INFO")
    sync_usb_devices(TOKEN, UID, monitor)


TOKEN, UID = login()

monitor = USBMonitor()
monitor.start_monitoring(on_connect=on_connect, on_disconnect=on_disconnect)

update_user_state(TOKEN, UID, True)
sync_usb_devices(TOKEN, UID, monitor)

print("Agent running. Ctrl+C to stop.")

try:
    while True:
        update_user_state(TOKEN, UID, True)
        time.sleep(20)

except KeyboardInterrupt:
    print("Stopping...")

finally:
    update_user_state(TOKEN, UID, False)
    monitor.stop_monitoring()
