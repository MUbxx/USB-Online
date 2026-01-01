import requests
import time
import socket
import wmi
from datetime import datetime, timezone

# ------------ YOUR FIREBASE PROJECT ------------
PROJECT_ID = "cybermonitor-1ab3c"
UID = "MXXq4tHL35hzKi9PJytPCXWDSzn1"
API_KEY = "AIzaSyCIY6AiBsGrq7wM0BBYGW2lM_0FLWjnH0k"
# ------------------------------------------------

EMAIL = input("Email: ")
PASSWORD = input("Password: ")

HOSTNAME = socket.gethostname()
c = wmi.WMI()

def ist_now_iso():
    return datetime.now(timezone.utc).isoformat()

def login():
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    payload = {"email": EMAIL, "password": PASSWORD, "returnSecureToken": True}
    r = requests.post(url, json=payload)
    data = r.json()
    if "idToken" not in data:
        print("Login failed:", data)
        exit()
    print("[+] Login success")
    return data["idToken"], data["localId"]

TOKEN, LOCAL_UID = login()

def heartbeat(online=True):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{UID}?updateMask.fieldPaths=is_online&updateMask.fieldPaths=last_seen"
    payload = {
        "fields": {
            "is_online": {"booleanValue": online},
            "last_seen": {"timestampValue": ist_now_iso()},
            "email": {"stringValue": EMAIL},
            "machine": {"stringValue": HOSTNAME}
        }
    }
    r = requests.patch(url, json=payload, headers={"Authorization": f"Bearer {TOKEN}"})
    print("Heartbeat:", r.status_code)

def push_log(msg):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{UID}/logs"
    payload = {
        "fields": {
            "message": {"stringValue": msg},
            "timestamp": {"timestampValue": ist_now_iso()}
        }
    }
    requests.post(url, json=payload, headers={"Authorization": f"Bearer {TOKEN}"})

def list_external_usb():
    devices = []
    for usb in c.Win32_PnPEntity():
        if not usb.Name:
            continue
        name = usb.Name.lower()

        # skip internal controllers/hubs
        if "root hub" in name:
            continue
        if "host controller" in name:
            continue
        if "bluetooth" in name:
            continue
        if "keyboard" in name or "mouse" in name:
            continue

        # include true externals
        if "mass storage" in name or "usb device" in name or "portable" in name or "android" in name or "iphone" in name:
            devices.append(usb.Name)

    return list(set(devices))

def sync_usb(devices):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{UID}/status/usb_status"
    arr = []

    for d in devices:
        arr.append({
            "mapValue": {
                "fields": {
                    "device_name": {"stringValue": d},
                    "token": {"stringValue": HOSTNAME}
                }
            }
        })

    payload = {"fields": {"usb_devices": {"arrayValue": {"values": arr}}}}

    r = requests.patch(url, json=payload, headers={"Authorization": f"Bearer {TOKEN}"})
    print("USB sync:", r.status_code)

print("=== CyberMonitor Agent — FINAL ===")
print("Monitoring ONLY external devices…")
push_log("Agent started")
heartbeat(True)

old = []

try:
    while True:
        new = list_external_usb()

        if new != old:
            # connection/dismount logs
            for d in new:
                if d not in old:
                    push_log(f"CONNECTED: {d}")
            for d in old:
                if d not in new:
                    push_log(f"DISCONNECTED: {d}")

            sync_usb(new)
            old = new

        heartbeat(True)
        time.sleep(3)

except KeyboardInterrupt:
    print("Exiting…")
    heartbeat(False)
    push_log("Agent stopped")
