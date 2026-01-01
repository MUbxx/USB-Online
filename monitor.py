import time
import socket
import requests
import pythoncom
import wmi
from datetime import datetime, timezone
from getpass import getpass

API_KEY = "AIzaSyCIY6AiBsGrq7wM0BBYGW2lM_0FLWjnH0k"
PROJECT_ID = "cybermonitor-1ab3c"

print("=== CyberMonitor Agent v6.5 (Windows Universal USB Detection) ===")

EMAIL = input("Email: ")
PASSWORD = getpass("Password: ")
HOSTNAME = socket.gethostname()


# ------------- LOGIN -----------------
def login():
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"

    r = requests.post(url, json={
        "email": EMAIL,
        "password": PASSWORD,
        "returnSecureToken": True
    })

    r.raise_for_status()
    j = r.json()

    print("[+] Login success")

    return j["idToken"], j["localId"]


# ------------- USER ONLINE HEARTBEAT -------------
def update_user_state(token, uid, online=True):
    try:
        url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}"

        payload = {
            "fields": {
                "email": {"stringValue": EMAIL},
                "machine": {"stringValue": HOSTNAME},
                "is_online": {"booleanValue": online},
                "last_seen": {"timestampValue": datetime.now(timezone.utc).isoformat()}
            }
        }

        r = requests.patch(url, json=payload, headers={"Authorization": f"Bearer {token}"})
        print("Heartbeat:", r.status_code)

    except Exception as e:
        print("Heartbeat error:", e)


# ------------- LOG PUSH -------------
def push_log(token, uid, msg, severity="INFO"):
    print("LOG:", msg)

    try:
        url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/logs"

        payload = {
            "fields": {
                "message": {"stringValue": msg},
                "severity": {"stringValue": severity},
                "timestamp": {"timestampValue": datetime.now(timezone.utc).isoformat()}
            }
        }

        requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})

    except Exception as e:
        print("Log error:", e)


# ------------- UNIVERSAL USB DETECTION -------------
def get_usb_devices():
    pythoncom.CoInitialize()
    c = wmi.WMI()

    devices = {}

    try:
        # ---------------- STORAGE DEVICES ----------------
        for d in c.Win32_DiskDrive():

            # BusType 7 = USB
            bus = getattr(d, "BusType", None)

            interface = str(getattr(d, "InterfaceType", ""))
            media = str(getattr(d, "MediaType", ""))

            if (
                "USB" in interface
                or "Removable" in media
                or bus == 7
            ):

                name = d.Caption or "USB Storage Device"
                pnp = d.PNPDeviceID or "N/A"
                token = pnp

                devices[token] = {
                    "device_name": name,
                    "token": token,
                    "pnp_id": pnp
                }

        # ---------------- MOBILE DEVICES ----------------
        for d in c.Win32_PnPEntity():

            name = str(getattr(d, "Name", ""))
            pclass = str(getattr(d, "PNPClass", ""))

            if any(x in name for x in ["MTP", "Phone", "Portable", "Android", "iPhone"]):
                pnp = d.PNPDeviceID or "N/A"
                token = pnp

                devices[token] = {
                    "device_name": name,
                    "token": token,
                    "pnp_id": pnp
                }

    except Exception as e:
        print("USB scan error:", e)

    print("Detected external devices:", len(devices))
    return devices


# ------------- SYNC -------------
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

    r = requests.patch(url, json=payload, headers={"Authorization": f"Bearer {token}"})
    print("USB sync:", r.status_code)


# ------------- MAIN LOOP -------------
TOKEN, UID = login()

update_user_state(TOKEN, UID, True)

previous = {}

print("\nMonitoring ONLY external devices (phones + pendrives)\n")


try:
    while True:

        current = get_usb_devices()

        # new device
        for k in current:
            if k not in previous:
                msg = f"CONNECTED: {current[k]['device_name']}"
                push_log(TOKEN, UID, msg, "HIGH")

        # removed
        for k in list(previous):
            if k not in current:
                msg = f"REMOVED: {previous[k]['device_name']}"
                push_log(TOKEN, UID, msg, "INFO")

        sync_usb_list(TOKEN, UID, current)

        previous = current

        update_user_state(TOKEN, UID, True)

        time.sleep(3)

except KeyboardInterrupt:
    print("Stopping agent...")

finally:
    update_user_state(TOKEN, UID, False)
