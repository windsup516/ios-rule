import json
import requests

BASE = "https://202.189.9.12:2053/GgNjUAsZQKkV2W5S5b"
USERNAME = "admin"
PASSWORD = "2b08c456"
INBOUND_ID = 1
TARGET_USER = "18602496065"

s = requests.Session()
s.verify = False

login = s.post(
    BASE + "/login",
    data={"username": USERNAME, "password": PASSWORD},
    timeout=5,
)
print("login:", login.status_code, login.text[:200])

r = s.get(BASE + f"/panel/api/inbounds/get/{INBOUND_ID}", timeout=5)
print("get:", r.status_code, r.text[:200])

data = r.json()
obj = data["obj"]

settings = json.loads(obj["settings"])
accounts = settings.get("accounts", [])

found = False
for acc in accounts:
    if acc.get("user") == TARGET_USER:
        acc["pass"] = "EXPIRED_" + TARGET_USER
        found = True

if not found:
    print("target user not found")
    raise SystemExit(1)

obj["settings"] = json.dumps(settings, ensure_ascii=False)

u = s.post(
    BASE + f"/panel/api/inbounds/update/{INBOUND_ID}",
    json=obj,
    timeout=5,
)
print("update:", u.status_code, u.text[:500])