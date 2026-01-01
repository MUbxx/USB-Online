import time
import subprocess
import re
import os
from datetime import datetime, timezone
import smtplib
from email.message import EmailMessage

import firebase_admin
from firebase_admin import credentials, firestore

# ================= FIREBASE INIT =================
cred = credentials.Certificate("cybermonitor-1ab3c-firebase-adminsdk-fbsvc-e5d6987eba.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

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
    "last_seen": datetime.now(timezone.utc).isoformat()
}, merge=True)

# ================= USB DEVICE NAME FIX =================
VENDOR_MAP = {
    "VID_22D9": "Realme Mobile Device",
    "VID_18D1": "Android Mobile Device",
    "VID_04E8": "Samsung Mobile Device",
    "VID_0781": "SanDisk USB Storage",
    "VID_0951": "Kingston USB Storage",
}

INTERNAL_VIDS = {"VID_8087"}  # Intel Bluetooth (ignore)

def get_usb_devices():
    result = subprocess.run(
        ["wmic", "path", "Win32_PnPEntity", "get", "DeviceID"],
        capture_output=True,
        text=True
    )

    devices = {}

    for line in result.stdout.splitlines():
        line = line.strip()
        if "USB\\VID_" not in line:
            continue

        # Remove composite interface IDs
        base_id = re.sub(r"&MI_\\d+", "", line)

        # Ignore internal USB
        if any(v in base_id for v in INTERNAL_VIDS):
            continue

        vid_match = re.search(r"(VID_[0-9A-F]{4})", base_id)
        vid = vid_match.group(1) if vid_match else None

        device_name = VENDOR_MAP.get(vid, "Unknown USB Device")
        devices[base_id] = device_name

    return devices

# ================= BASELINE FIX =================
print("[*] Creating USB baseline (no alerts on startup)...")
previous_devices = get_usb_devices()
print(f"[*] Baseline ready ({len(previous_devices)} devices ignored)\n")

print("[+] USB monitoring started...\n")

# ================= MAIN LOOP =================
try:
    while True:
        now = datetime.now(timezone.utc).isoformat()

        user_ref.update({
            "is_online": True,
            "last_seen": now
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
                    "timestamp": now
                })

                user_ref.collection("logs").add({
                    "event": "USB Connected",
                    "device": device_name,
                    "timestamp": now
                })

                # -------- PROFESSIONAL EMAIL CONTENT --------
                send_email_alert(
                    email,
                    "🚨 CyberMonitor Alert: USB Device Connected",
                    f"""
Hello,

A USB device has been detected on your system.

Device Name : {device_name}
Machine     : {machine}
Time        : {now}

If this device was not connected by you, please disconnect it immediately.

For more details and activity logs, log in to your CyberMonitor dashboard:
https://mubxx.github.io/USB-Online/login.html

Regards,
CyberMonitor Security System
"""
                )

        # USB REMOVED
        for dev in previous_devices:
            if dev not in current_devices:
                device_name = previous_devices[dev]
                print(f"[USB -] {device_name}")

                user_ref.collection("logs").add({
                    "event": "USB Removed",
                    "device": device_name,
                    "timestamp": now
                })

        previous_devices = current_devices
        time.sleep(5)

except KeyboardInterrupt:
    user_ref.update({
        "is_online": False,
        "last_seen": datetime.now(timezone.utc).isoformat()
    })
    print("\n[!] Monitoring stopped")
