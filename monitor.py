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

# ================= TIMEZONE (IST) =================
IST = pytz.timezone("Asia/Kolkata")
def now_ist():
    return datetime.now(IST).isoformat()

# ================= SMTP CONFIG =================
SMTP_EMAIL = "mubeenmass577@gmail.com"
SMTP_PASSWORD = os.getenv("USB_MONITOR_APP_PASSWORD")

if not SMTP_PASSWORD:
    print("[FATAL] Set USB_MONITOR_APP_PASSWORD")
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

        print("[EMAIL] Alert sent")
    except Exception as e:
        print("[EMAIL ERROR]", e)

# ================= USER INPUT =================
email = input("Enter your email: ").strip()
machine = input("Enter machine name: ").strip()
UID = email.replace("@", "_").replace(".", "_")

user_ref = db.collection("users").document(UID)

user_ref.set({
    "email": email,
    "machine": machine,
    "is_online": True,
    "last_seen": now_ist()
}, merge=True)

# ================= USB FILTER RULES =================
IGNORE_NAMES = [
    "USB Composite Device",
    "MIDI",
    "Interface",
    "ADB",
    "Generic",
]

INTERNAL_VIDS = {"VID_8087"}  # Intel Bluetooth

# ================= USB ENUMERATION (LOGICAL DEVICE ONLY) =================
def get_usb_devices():
    result = subprocess.run(
        ["wmic", "path", "Win32_PnPEntity", "get", "DeviceID,Name"],
        capture_output=True,
        text=True
    )

    logical_devices = {}

    for line in result.stdout.splitlines():
        if "USB\\VID_" not in line:
            continue

        parts = re.split(r"\s{2,}", line.strip(), maxsplit=1)
        if len(parts) != 2:
            continue

        device_id, name = parts
        name = name.strip()

        # Ignore noisy interface names
        if any(x.lower() in name.lower() for x in IGNORE_NAMES):
            continue

        vid_pid = re.search(r"(VID_[0-9A-F]{4}&PID_[0-9A-F]{4})", device_id)
        if not vid_pid:
            continue

        key = vid_pid.group(1)

        # Ignore internal USB
        if any(v in key for v in INTERNAL_VIDS):
            continue

        # Keep best readable name
        logical_devices[key] = name

    return logical_devices

# ================= BASELINE =================
print("[*] Creating baseline (existing devices ignored)...")
previous_devices = get_usb_devices()
print(f"[*] Baseline ready ({len(previous_devices)} devices)\n")

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

        # CONNECTED
        for dev in current_devices:
            if dev not in previous_devices:
                name = current_devices[dev]
                print(f"[USB +] {name}")

                user_ref.collection("usb_status").document(dev).set({
                    "name": name,
                    "risk": "MEDIUM",
                    "timestamp": timestamp
                })

                user_ref.collection("logs").add({
                    "event": "USB Connected",
                    "device": name,
                    "timestamp": timestamp
                })

                send_email_alert(
                    email,
                    "🚨 CyberMonitor Alert: USB Device Connected",
                    f"""
Hello,

A USB device has been connected.

Device  : {name}
Machine : {machine}
Time    : {timestamp}

View details:
https://mubxx.github.io/USB-Online/login.html
"""
                )

        # REMOVED
        for dev in previous_devices:
            if dev not in current_devices:
                name = previous_devices[dev]
                print(f"[USB -] {name}")

                user_ref.collection("usb_status").document(dev).delete()

                user_ref.collection("logs").add({
                    "event": "USB Removed",
                    "device": name,
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
