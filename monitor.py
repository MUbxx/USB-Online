import requests
import time
import json
import os
import socket
import psutil
import wmi

API_KEY="AIzaSyCIY6AiBsGrq7wM0BBYGW2lM_0FLWjnH0k"
PROJECT="cybermonitor-1ab3c"

w=wmi.WMI()
hostname=socket.gethostname()

CONFIG_FILE="agent_auth.json"


# ------------------------------------------
# Save + load local auth
# ------------------------------------------
def save_config(data):
    with open(CONFIG_FILE,"w") as f:
        json.dump(data,f)

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE) as f:
        return json.load(f)


# ------------------------------------------
# Firebase authentication
# ------------------------------------------
def login():
    email=input("Enter your CyberMonitor email: ")
    password=input("Password: ")

    url=f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    r=requests.post(url,json={
        "email":email,
        "password":password,
        "returnSecureToken":True
    })

    r.raise_for_status()
    data=r.json()
    save_config(data)

    return data["idToken"], data["localId"], data["refreshToken"]


def refresh(refresh_token):
    url=f"https://securetoken.googleapis.com/v1/token?key={API_KEY}"
    r=requests.post(url,data={
        "grant_type":"refresh_token",
        "refresh_token":refresh_token
    })

    r.raise_for_status()
    j=r.json()

    return j["id_token"], j["user_id"], refresh_token


# ------------------------------------------
# Firestore helpers
# ------------------------------------------
def firestore(path, method, obj, token):
    url=f"https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents/{path}"
    headers={"Authorization":f"Bearer {token}"}

    res=getattr(requests,method)(url,json=obj,headers=headers)

    return res.json()


def get_document(path, token):
    url=f"https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents/{path}"
    headers={"Authorization":f"Bearer {token}"}
    r=requests.get(url,headers=headers)
    return r.json()


# ------------------------------------------
# USB Enum
# ------------------------------------------
def get_usb():
    devs=[]
    for d in w.Win32_DiskDrive():
        if "USB" in str(d.InterfaceType):
            devs.append({
                "name":d.Model,
                "serial":getattr(d,"SerialNumber","UNKNOWN")
            })
    return devs


# ------------------------------------------
# Login or refresh token
# ------------------------------------------
cfg=load_config()
if cfg:
    token,uid,rt=refresh(cfg["refreshToken"])
else:
    token,uid,rt=login()

print("Logged in as UID:",uid)

known=set()

while True:
    try:
        # -------------------------------------------------------
        # Heartbeat
        # -------------------------------------------------------
        firestore(f"status/{uid}","patch",{
            "fields":{
                "online":{"booleanValue":True},
                "last_seen":{"integerValue":int(time.time())},
                "machine":{"stringValue":hostname},
                "active_user":{"stringValue": psutil.users()[0].name if psutil.users() else "UNKNOWN"}
            }
        },token)

        # -------------------------------------------------------
        # Fetch user doc (or auto-create)
        # -------------------------------------------------------
        user_doc=get_document(f"users/{uid}",token)

        if "fields" not in user_doc:
            # auto create default user doc
            print("User document missing — creating defaults")

            firestore(f"users/{uid}","patch",{
              "fields":{
                "whitelist":{"arrayValue":{}},
                "policies":{"mapValue":{
                   "fields":{
                     "blockUnknown":{"booleanValue":True},
                     "alertHID":{"booleanValue":True},
                     "readOnly":{"booleanValue":False}
                   }
                }}
              }
            },token)

            wl=[]
            blockUnknown=True
            alertHID=True

        else:
            # read safely
            fields=user_doc["fields"]

            wl=[]
            if "whitelist" in fields:
                wl=[v["stringValue"] for v in fields["whitelist"]["arrayValue"].get("values",[])]

            pol = fields.get("policies",{}).get("mapValue",{}).get("fields",{})

            blockUnknown = pol.get("blockUnknown",{"booleanValue":True})["booleanValue"]
            alertHID = pol.get("alertHID",{"booleanValue":True})["booleanValue"]

        # -------------------------------------------------------
        # USB Detection
        # -------------------------------------------------------
        usb=get_usb()

        current={d["serial"] for d in usb}
        new=current-known
        known=current

        for d in usb:
            serial=d["serial"]
            name=d["name"]

            if serial in wl:
                action="WHITELISTED"
            elif blockUnknown:
                action="BLOCKED"
            else:
                action="ALLOWED"

            log={
              "fields":{
                "uid":{"stringValue":uid},
                "device_serial":{"stringValue":serial},
                "device_name":{"stringValue":name},
                "machine":{"stringValue":hostname},
                "action":{"stringValue":action},
                "timestamp":{"integerValue":int(time.time())}
              }
            }

            firestore("logs","post",log,token)

        print("✓ Heartbeat + policy sync OK")

        time.sleep(7)

    except Exception as e:
        print("Error:",e)
        time.sleep(5)
