import time
import subprocess
import re
import os
from datetime import datetime
import pytz
import smtplib
from email.message import EmailMessage

import firebase_admin
from firebase_admin import credentials, firestore

# ================= FIREBASE INIT =================
cred = credentials.Certificate("cybermonitor-1ab3c-firebase-adminsdk-fbsvc-e5d6987eba.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

# ================= TIMEZONE (LOCAL IST) =================
IST = pytz.timezone("Asia/Kolkata")

def now_ist():
    return datetime.now(IST).isoformat()

# ================= SMTP CONFIG =================
SMTP_EMAIL = "mubeenmass577@gmail.com"
SMTP_PASSWORD = os.getenv("USB_MONITOR_APP_PASSWORD")

if not SMTP_PASSWORD:
    print("[FATAL] SMTP password not found.")
    print("Set environment variable: USB_MONITOR_APP_PASSWORD")
    exit(1)

def send_email_alert(to_email, subject, message):
    try:
        msg = EmailMessage()
        msg["From"] = f"CyberMonitor <{SMTP_EMAIL}>"
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(message)

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)

        print("[EMAIL] Alert sent to", to_email)
    except Exception as e:
        print("[EMAIL ERROR]", e)

# ================= USER INPUT =================
email = input("Enter your email: ").strip()
machine = input("Enter machine name: ").strip()

UID = email.replace("@", "_").replace(".", "_")
print(f"[+] UID: {UID}")

user_ref = db.collection("users").document(UID)

user_ref.set({
    "email": email,
    "machine": machine,
    "is_online": True,
    "last_seen": now_ist()
}, merge=True)

# ================= TRUST CHECK =================
def is_device_trusted(user_ref, device_name):
    return user_ref.collection("trusted").document(device_name).get().exists

# ================= DEVICE NAME FALLBACK =================
VENDOR_MAP = {
    "VID_0781": "SanDisk USB Storage",
    "VID_0951": "Kingston USB Storage",
    "VID_22D9": "Realme Mobile Device",
    "VID_18D1": "Android Mobile Device",
    "VID_04E8": "Samsung Mobile Device",
}

INTERNAL_VIDS = {"VID_8087"}  # Intel Bluetooth

# ================= USB ENUMERATION =================
def get_usb_devices():
    result = subprocess.run(
        ["wmic", "path", "Win32_PnPEntity", "get", "DeviceID,Name"],
        capture_output=True,
        text=True
    )

    devices = {}

    for line in result.stdout.splitlines():
        if "USB\\VID_" not in line:
            continue

        parts = re.split(r"\s{2,}", line.strip(), maxsplit=1)
        if len(parts) != 2:
            continue

        device_id, name = parts
        device_id = device_id.strip()
        name = name.strip()

        # Remove composite interfaces
        base_id = re.sub(r"&MI_\\d+", "", device_id)

        # Ignore internal USB
        if any(v in base_id for v in INTERNAL_VIDS):
            continue

        # Clean name
        if not name or "unknown" in name.lower():
            vid_match = re.search(r"(VID_[0-9A-F]{4})", base_id)
            vid = vid_match.group(1) if vid_match else None
            name = VENDOR_MAP.get(vid, "Unknown USB Device")

        devices[base_id] = name

    return devices

# ================= BASELINE =================
print("[*] Creating USB baseline (no alerts on startup)...")
previous_devices = get_usb_devices()
print(f"[*] Baseline ready ({len(previous_devices)} devices ignored)\n")

print("[+] USB monitoring started...\n")

# ================= MAIN LOOP =================
try:
    while True:
        timestamp = now_ist()

        user_ref.update({
            "is_online": True,
            "last_seen": timestamp
        })

        current_devices = get_usb_devices()

        # USB CONNECTED
        for dev in current_devices:
            if dev not in previous_devices:
                device_name = current_devices[dev]
                print(f"[USB +] {device_name}")

                user_ref.collection("usb_status").add({
                    "name": device_name,
                    "risk": "MEDIUM",
                    "timestamp": timestamp
                })

                user_ref.collection("logs").add({
                    "event": "USB Connected",
                    "device": device_name,
                    "timestamp": timestamp
                })

                # Email only if NOT trusted
                if not is_device_trusted(user_ref, device_name):
                    send_email_alert(
                        email,
                        "🚨 CyberMonitor Alert: USB Device Connected",
                        f"""
Hello,

A USB device has been detected on your system.

Device Name : {device_name}
Machine     : {machine}
Time        : {timestamp}

If this device was not connected by you, please disconnect it immediately.

For more details and activity logs, log in to your CyberMonitor dashboard:
https://mubxx.github.io/USB-Online/login.html

Regards,
CyberMonitor Security System
"""
                    )
                else:
                    print(f"[INFO] {device_name} is trusted. Email skipped.")

        # USB REMOVED
        for dev in previous_devices:
            if dev not in current_devices:
                device_name = previous_devices[dev]
                print(f"[USB -] {device_name}")

                user_ref.collection("logs").add({
                    "event": "USB Removed",
                    "device": device_name,
                    "timestamp": timestamp
                })

        previous_devices = current_devices
        time.sleep(5)

except KeyboardInterrupt:
    user_ref.update({
        "is_online": False,
        "last_seen": now_ist()
    })
    print("\n[!] Monitoring stopped")
