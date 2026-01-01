import time
import socket
import requests
import pythoncom
import wmi
from datetime import datetime, timezone
from getpass import getpass

API_KEY = "YOUR_FIREBASE_WEB_API_KEY"
PROJECT_ID = "cybermonitor-1ab3c"

print("=== CyberMonitor Agent v6.0 (Windows Stable) ===")

EMAIL = input("Email: ")
PASSWORD = getpass("Password: ")
HOSTNAME = socket.gethostname()


# ---------------- FIREBASE AUTH ----------------
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


# ---------------- USER ONLINE STATE ----------------
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


# ---------------- LOG EVENT ----------------
def push_log(token, uid, msg, severity="INFO"):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/logs"

    payload = {
        "fields": {
            "message": {"stringValue": msg},
            "severity": {"stringValue": severity},
            "timestamp": {"timestampValue": datetime.now(timezone.utc).isoformat()}
        }
    }

    requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})


# ---------------- USB ENUMERATION (ONLY EXTERNAL DEVICES) ----------------
def get_usb_devices():
    pythoncom.CoInitialize()
    c = wmi.WMI()

    devices = {}

    # -------- USB storage drives (Pendrive / HDD / SSD) --------
    for d in c.Win32_DiskDrive():
        if "USB" in str(d.InterfaceType):

            name = d.Caption or "USB Storage Device"
            pnp = d.PNPDeviceID or "N/A"
            token = pnp  # unique fingerprint

            devices[token] = {
                "device_name": name,
                "token": token,
                "pnp_id": pnp
            }

    # -------- Mobile phones (MTP / PTP) --------
    for d in c.Win32_PnPEntity():
        if d.PNPClass in ["WPD", "Portable Devices"]:
            if "USB" not in str(d.Name):
                continue

            name = d.Name or "USB Mobile Device"
            pnp = d.PNPDeviceID or "N/A"
            token = pnp

            devices[token] = {
                "device_name": name,
                "token": token,
                "pnp_id": pnp
            }

    return devices


# ---------------- SYNC LIST TO FIRESTORE ----------------
def sync_usb_list(token, uid, devices):
    arr = []

    for dev in devices.values():
        arr.append({
            "mapValue": {
                "fields": {
                    "device_name": {"stringValue": dev["device_name"]},
                    "token": {"stringValue": dev["token"]},
                    "pnp_id": {"stringValue": dev["pnp_id"]}
                }
            }
        })

    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/status/usb_status"

    payload = {
        "fields": {
            "usb_devices": {"arrayValue": {"values": arr}}
        }
    }

    requests.patch(url, json=payload, headers={"Authorization": f"Bearer {token}"})


# ---------------- MAIN LOOP ----------------
TOKEN, UID = login()
update_user_state(TOKEN, UID, True)

previous = {}

print("Monitoring ONLY external USB devices…")
print("Press Ctrl+C to stop")

try:
    while True:

        current = get_usb_devices()

        # detect newly connected
        for k in current:
            if k not in previous:
                msg = f"CONNECTED: {current[k]['device_name']}"
                print(msg)
                push_log(TOKEN, UID, msg, "HIGH")

        # detect removed
        for k in list(previous):
            if k not in current:
                msg = f"REMOVED: {previous[k]['device_name']}"
                print(msg)
                push_log(TOKEN, UID, msg, "INFO")

        sync_usb_list(TOKEN, UID, current)

        previous = current

        # heartbeat for online/offline status
        update_user_state(TOKEN, UID, True)

        time.sleep(3)

except KeyboardInterrupt:
    print("Exiting agent…")

finally:
    update_user_state(TOKEN, UID, False)
