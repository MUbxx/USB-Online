import time
import socket
import psutil
import wmi
import requests
from datetime import datetime
from getpass import getpass
import subprocess

API_KEY = "AIzaSyCIY6AiBsGrq7wM0BBYGW2lM_0FLWjnH0k"
PROJECT_ID = "cybermonitor-1ab3c"

print("=== CyberMonitor Advanced Agent ===")
USER_EMAIL = input("Email: ")
USER_PASSWORD = getpass("Password: ")

wmi_obj = wmi.WMI()
hostname = socket.gethostname()

known_devices = set()
allowed_serials = set()
blocked_serials = set()

def block_usb_storage():
    try:
        subprocess.call(
            'reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR /v Start /t REG_DWORD /d 4 /f',
            shell=True
        )
        subprocess.call('sc stop USBSTOR', shell=True)
        print("[!] Mass-storage devices blocked")
    except Exception as e:
        print("BLOCK ERROR:", e)

def unblock_usb_storage():
    try:
        subprocess.call(
            'reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR /v Start /t REG_DWORD /d 3 /f',
            shell=True
        )
        subprocess.call('sc start USBSTOR', shell=True)
        print("[+] Mass-storage re-enabled")
    except Exception as e:
        print("UNBLOCK ERROR:", e)

def login_and_get_token():
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    payload = {"email": USER_EMAIL, "password": USER_PASSWORD, "returnSecureToken": True}
    r = requests.post(url, json=payload)
    r.raise_for_status()
    data = r.json()

    if not data.get("emailVerified", True):
        print("⚠ Please verify your email before using the agent")
    return data["idToken"], data["localId"]

def firestore_get(path, token):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/{path}"
    headers = {"Authorization": f"Bearer {token}"}
    return requests.get(url, headers=headers).json()

def firestore_set(path, obj, token):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/{path}"
    headers = {"Authorization": f"Bearer {token}"}
    return requests.patch(url, json=obj, headers=headers)

def firestore_add(collection_path, obj, token):
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/{collection_path}"
    headers = {"Authorization": f"Bearer {token}"}
    return requests.post(url, json=obj, headers=headers)

def sync_policy(token, uid):
    global allowed_serials, blocked_serials
    pol = firestore_get(f"users/{uid}/status/policy", token)

    try:
        allowed_serials = {v["stringValue"] for v in pol["fields"]["allowed"]["arrayValue"]["values"]}
        blocked_serials = {v["stringValue"] for v in pol["fields"]["blocked"]["arrayValue"]["values"]}
    except:
        allowed_serials = set()
        blocked_serials = set()

def get_usb_devices():
    devices = []
    for d in wmi_obj.Win32_DiskDrive():
        if "USB" in str(d.InterfaceType):
            raw_serial = getattr(d, "SerialNumber", None)
            serial = raw_serial.strip() if isinstance(raw_serial, str) else "UNKNOWN"
            devices.append({
                "device_name": d.Model,
                "serial": serial or "UNKNOWN",
                "vendor": getattr(d, "Manufacturer", "Unknown"),
                "class": "Mass Storage",
            })
    return devices

print("Connecting…")
token, uid = login_and_get_token()
sync_policy(token, uid)

while True:
    usb_list = get_usb_devices()
    current_serials = {d["serial"] for d in usb_list}

    new_devices = current_serials - known_devices
    removed_devices = known_devices - current_serials

    timestamp_iso = datetime.utcnow().isoformat() + "Z"

    # ---------- BLOCK POLICY ENFORCEMENT ----------
    for dev in usb_list:
        if dev["serial"] in blocked_serials:
            block_usb_storage()

            log_entry = {
                "fields": {
                    "message": {"stringValue": f"BLOCKED USB ATTEMPT: {dev['serial']}"},
                    "timestamp": {"timestampValue": timestamp_iso},
                    "severity": {"stringValue": "CRITICAL"},
                    "send_email": {"booleanValue": True},
                }
            }
            firestore_add(f"users/{uid}/logs", log_entry, token)

    # ---------- UNBLOCK IF ALLOWED ----------
    if any(s in allowed_serials for s in current_serials):
        unblock_usb_storage()

    # ---------- POLICY HEARTBEAT ----------
    status_doc = {
        "fields": {
            "online": {"booleanValue": True},
            "machine": {"stringValue": hostname},
            "active_user": {"stringValue": psutil.users()[0].name if psutil.users() else "UNKNOWN"},
            "last_seen": {"timestampValue": timestamp_iso},
        }
    }
    firestore_set(f"users/{uid}", status_doc, token)

    known_devices = current_serials
    time.sleep(10)
