import base64
import os
import re
import sqlite3
import subprocess
from pathlib import Path

DB = "/opt/ios-rule/data/cardkey.db"
REMOTE_HOST = "202.189.9.12"
REMOTE_USER = "root"

PORT_START = 28889
PORT_END = 39999


def safe_name(username: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", username)


conn = sqlite3.connect(DB)
cur = conn.cursor()

cols = [r[1] for r in cur.execute("pragma table_info(users);").fetchall()]
if "socks_port" not in cols:
    cur.execute("alter table users add column socks_port INTEGER")
    conn.commit()

used_ports = {
    r[0]
    for r in cur.execute(
        "select socks_port from users where socks_port is not null"
    ).fetchall()
}

users_no_port = cur.execute(
    "select username from users where socks_port is null order by id asc"
).fetchall()

next_port = PORT_START
for (username,) in users_no_port:
    while next_port in used_ports:
        next_port += 1

    if next_port > PORT_END:
        raise RuntimeError("端口池已用完")

    cur.execute(
        "update users set socks_port=? where username=?",
        (next_port, username),
    )
    used_ports.add(next_port)
    next_port += 1

conn.commit()

active_users = cur.execute(
    """
    select username, ss_password, socks_port
    from users
    where status='active'
      and ss_password is not null
      and socks_port is not null
    order by id asc
    """
).fetchall()

conn.close()

tmp_dir = Path("/tmp/gost_user_services")
tmp_dir.mkdir(exist_ok=True)

active_service_names = []

# 停掉旧的总服务，避免占用 28889
subprocess.run(
    [
        "ssh",
        f"{REMOTE_USER}@{REMOTE_HOST}",
        "systemctl stop gost-socks 2>/dev/null || true; "
        "systemctl disable gost-socks 2>/dev/null || true",
    ],
    check=False,
)

for username, password, port in active_users:
    name = safe_name(username)
    service_name = f"gost-u-{name}.service"
    active_service_names.append(service_name)

    auth = base64.b64encode(f"{username}:{password}".encode()).decode()

    service = f"""[Unit]
Description=Gost SOCKS5 User {username}
After=network.target

[Service]
ExecStart=/usr/local/bin/gost3 -L "socks5://:{port}?auth={auth}"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""

    local_path = tmp_dir / service_name
    local_path.write_text(service, encoding="utf-8")

    subprocess.run(
        [
            "scp",
            str(local_path),
            f"{REMOTE_USER}@{REMOTE_HOST}:/etc/systemd/system/{service_name}",
        ],
        check=True,
    )

# 删除远端已经不 active 的用户服务
result = subprocess.run(
    [
        "ssh",
        f"{REMOTE_USER}@{REMOTE_HOST}",
        "ls /etc/systemd/system/gost-u-*.service 2>/dev/null || true",
    ],
    text=True,
    capture_output=True,
)

remote_service_names = []
for line in result.stdout.splitlines():
    base = os.path.basename(line.strip())
    if base:
        remote_service_names.append(base)

for service_name in remote_service_names:
    if service_name not in active_service_names:
        subprocess.run(
            [
                "ssh",
                f"{REMOTE_USER}@{REMOTE_HOST}",
                f"systemctl stop {service_name} 2>/dev/null || true; "
                f"systemctl disable {service_name} 2>/dev/null || true; "
                f"rm -f /etc/systemd/system/{service_name}",
            ],
            check=False,
        )

# 启动 active 用户服务
if active_service_names:
    services = " ".join(active_service_names)
    subprocess.run(
        [
            "ssh",
            f"{REMOTE_USER}@{REMOTE_HOST}",
            f"systemctl daemon-reload && "
            f"systemctl enable --now {services} && "
            f"systemctl restart {services}",
        ],
        check=True,
    )
else:
    subprocess.run(
        [
            "ssh",
            f"{REMOTE_USER}@{REMOTE_HOST}",
            "systemctl daemon-reload",
        ],
        check=True,
    )

print(f"synced {len(active_users)} active user(s) to gost3 per-user services")
for username, _, port in active_users:
    print(f"{username} -> {port}")