import time
import socket
import psutil
import wmi
import requests
import ctypes
import os
from datetime import datetime, UTC
from getpass import getpass

# Firebase Config
API_KEY = "AIzaSyCIY6AiBsGrq7wM0BBYGW2lM_0FLWjnH0k"
PROJECT_ID = "cybermonitor-1ab3c"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("ERROR: YOU MUST RUN THIS AS ADMINISTRATOR TO DETECT USBs.")
    print("Right-click CMD/PowerShell and select 'Run as Administrator'.")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    input("Press Enter to exit...")
    os._exit(1)

print("=== CyberMonitor Agent ===")
USER_EMAIL = input("Email: ")
USER_PASSWORD = getpass("Password: ")

wmi_obj = wmi.WMI()
hostname = socket.gethostname()

def login():
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    r = requests.post(url, json={"email": USER_EMAIL, "password": USER_PASSWORD, "returnSecureToken": True})
    r.raise_for_status()
    return r.json()["idToken"], r.json()["localId"]

def update_cloud_status(token, uid, online_bool):
    """Updates the main user document with online status and machine name."""
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}?updateMask.fieldPaths=is_online&updateMask.fieldPaths=machine&updateMask.fieldPaths=last_seen"
    payload = {
        "fields": {
            "is_online": {"booleanValue": online_bool},
            "machine": {"stringValue": hostname},
            "last_seen": {"stringValue": datetime.now(UTC).isoformat()}
        }
    }
    requests.patch(url, json=payload, headers={"Authorization": f"Bearer {token}"})

def get_usb_storage():
    """Detects storage drives using the 'USBSTOR' hardware ID pattern."""
    devices = []
    try:
        for disk in wmi_obj.Win32_DiskDrive():
            # USBSTOR is the hardware pattern for almost all external storage on Windows
            if "USBSTOR" in (disk.PNPDeviceID or ""):
                devices.append({
                    "name": disk.Caption or "External Drive",
                    "serial": (disk.SerialNumber or "UNKNOWN").strip(),
                    "vendor": disk.Manufacturer or "Generic"
                })
    except Exception as e:
        print(f"Hardware Scan Error: {e}")
    return devices

try:
    token, uid = login()
    update_cloud_status(token, uid, True)
    print(f"Connected to {PROJECT_ID}. Monitoring...")

    while True:
        usb_list = get_usb_storage()
        
        # 1. Update USB status list
        usb_payload = {"fields": {"usb_devices": {"arrayValue": {"values": [
            {"mapValue": {"fields": {
                "device_name": {"stringValue": d["name"]},
                "vendor": {"stringValue": d["vendor"]},
                "serial": {"stringValue": d["serial"]}
            }}} for d in usb_list
        ]}}}}
        requests.patch(f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}/status/usb_status", 
                       json=usb_payload, headers={"Authorization": f"Bearer {token}"})
        
        # 2. Heartbeat (keeps 'Online' status fresh)
        update_cloud_status(token, uid, True)
        
        print(f"Heartbeat OK - {len(usb_list)} drives found.")
        time.sleep(10)

except Exception as e:
    print(f"Fatal Error: {e}")
finally:
    # This block triggers when the script stops or is closed
    if 'token' in locals() and 'uid' in locals():
        print("Sending Offline signal...")
        update_cloud_status(token, uid, False)
