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

def save_config(data):
    with open(CONFIG_FILE,"w") as f:
        json.dump(data,f)

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE) as f:
        return json.load(f)

def login():
    email=input("Enter your CyberMonitor email: ")
    password=input("Password: ")

    url=f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    r=requests.post(url,json={
        "email":email,
        "password":password,
        "returnSecureToken":True
    }).json()

    save_config(r)
    return r["idToken"],r["localId"],r["refreshToken"]

def refresh(refresh_token):
    url=f"https://securetoken.googleapis.com/v1/token?key={API_KEY}"
    r=requests.post(url,data={
        "grant_type":"refresh_token",
        "refresh_token":refresh_token
    }).json()
    return r["id_token"],r["user_id"],refresh_token

def firestore(path,method,obj,token):
    url=f"https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents/{path}"
    headers={"Authorization":f"Bearer {token}"}
    getattr(requests,method)(url,json=obj,headers=headers)

def get_usb():
    devs=[]
    for d in w.Win32_DiskDrive():
        if "USB" in str(d.InterfaceType):
            devs.append({
                "name":d.Model,
                "serial":getattr(d,"SerialNumber","UNKNOWN")
            })
    return devs

cfg=load_config()
if cfg:
    token,uid,rt=refresh(cfg["refreshToken"])
else:
    token,uid,rt=login()

known=set()

while True:
    try:
        # heartbeat
        firestore(f"status/{uid}","patch",{
            "fields":{
                "online":{"booleanValue":True},
                "last_seen":{"integerValue":int(time.time())},
                "machine":{"stringValue":hostname}
            }
        },token)

        # get policies
        u=requests.get(
            f"https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents/users/{uid}",
            headers={"Authorization":f"Bearer {token}"}
        ).json()

        fields=u["fields"]
        wl=[v["stringValue"] for v in fields["whitelist"]["arrayValue"].get("values",[])]
        policies=fields["policies"]["mapValue"]["fields"]

        blockUnknown=policies["blockUnknown"]["booleanValue"]
        alertHID=policies["alertHID"]["booleanValue"]

        usb=get_usb()
        current={d["serial"] for d in usb}
        new=current-known
        known=current

        for d in usb:
            action="ALLOWED"

            if d["serial"] not in wl and blockUnknown:
                action="BLOCKED"

            log={
              "fields":{
                "uid":{"stringValue":uid},
                "device_serial":{"stringValue":d["serial"]},
                "device_name":{"stringValue":d["name"]},
                "action":{"stringValue":action},
                "timestamp":{"integerValue":int(time.time())}
              }
            }

            firestore("logs","post",log,token)

        print("Heartbeat sent")
        time.sleep(8)

    except Exception as e:
        print("Error:",e)
        time.sleep(5)
