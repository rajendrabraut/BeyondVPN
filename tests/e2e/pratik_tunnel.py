"""Real WireGuard tunnel from this Windows PC to beyond-gateway running in a Pratik container.

Steps (see deploy/pratik/README.md):
  1. `python tests/e2e/pratik_tunnel.py control-plane`   -> starts the control plane on 127.0.0.1:8000,
     creates server `pratik-1`, prints the gateway key, keeps running.
  2. start the gateway container with that key (pratik run ...).
  3. `python tests/e2e/pratik_tunnel.py client`          -> registers a device, connects, writes a
     split-tunnel WireGuard config (only 10.8.0.1/32 is routed, so normal traffic is untouched).

The data dir and the WireGuard client config go to the folder named by BEYOND_PRATIK_DEMO_DIR
(default: %TEMP%/beyond-pratik-demo).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_e2e import ADMIN, ROOT, USER, wait_for  # noqa: E402

DEMO = Path(os.environ.get("BEYOND_PRATIK_DEMO_DIR", Path(os.environ.get("TEMP", "/tmp")) / "beyond-pratik-demo"))
BASE = "http://127.0.0.1:8000"
WG = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WireGuard" / "wg.exe"


def control_plane() -> int:
    DEMO.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "BEYOND_DATA_DIR": str(DEMO / "cp"), "BEYOND_ADMIN_EMAIL": ADMIN[0], "BEYOND_ADMIN_PASSWORD": ADMIN[1], "PYTHONPATH": str(ROOT / "control-plane")}
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "beyond_cp.main:create_app", "--factory", "--host", "127.0.0.1", "--port", "8000", "--log-level", "warning"], cwd=ROOT / "control-plane", env=env)
    try:
        wait_for(lambda: httpx.get(f"{BASE}/healthz").status_code == 200, what="control plane")
        c = httpx.Client(base_url=BASE, timeout=20)
        admin = {"Authorization": "Bearer " + c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]}).json()["access_token"]}
        r = c.post("/api/v1/admin/servers", headers=admin, json={"id": "pratik-1", "name": "Pratik local", "country": "IN", "city": "Pune", "hostname": "localhost"})
        if r.status_code == 201:
            (DEMO / "gateway.key").write_text(r.json()["gateway_key"])
        c.post("/api/v1/auth/register", json={"email": USER[0], "password": USER[1], "full_name": "Alice", "accept_logging_policy": True})
        print(f"READY control plane {BASE}; gateway key in {DEMO / 'gateway.key'}", flush=True)
        while proc.poll() is None:
            time.sleep(1)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        proc.terminate()


def client() -> int:
    c = httpx.Client(base_url=BASE, timeout=20)
    wait_for(lambda: c.get("/api/v1/servers", headers=_user(c)).json()[0]["status"] == "online", timeout=60, what="gateway online")
    h = _user(c)
    priv = subprocess.run([str(WG), "genkey"], capture_output=True, text=True, check=True).stdout.strip()
    pub = subprocess.run([str(WG), "pubkey"], input=priv, capture_output=True, text=True, check=True).stdout.strip()
    dev = c.post("/api/v1/devices", headers=h, json={"name": "pratik-demo", "platform": "windows", "public_key": pub, "posture": {"os": "windows"}}).json()["id"]
    cfg = c.post("/api/v1/sessions/connect", headers=h, json={"device_id": dev, "server_id": "pratik-1"}).json()
    conf = (
        f"[Interface]\nPrivateKey = {priv}\nAddress = {cfg['address']}\n\n"
        f"[Peer]\nPublicKey = {cfg['peer_public_key']}\nPresharedKey = {cfg['preshared_key']}\n"
        "AllowedIPs = 10.8.0.1/32\nEndpoint = 127.0.0.1:51820\nPersistentKeepalive = 5\n"
    )
    out = DEMO / "bvpnpratik.conf"
    out.write_text(conf)
    (DEMO / "session.json").write_text(json.dumps({"device": dev, "address": cfg["address"]}))
    print(f"client config written to {out} (tunnel IP {cfg['address']})")
    return 0


def activity() -> int:
    c = httpx.Client(base_url=BASE, timeout=20)
    print(json.dumps(c.get("/api/v1/me/activity", headers=_user(c)).json(), indent=1)[:1500])
    return 0


def _user(c: httpx.Client) -> dict:
    return {"Authorization": "Bearer " + c.post("/api/v1/auth/login", json={"email": USER[0], "password": USER[1]}).json()["access_token"]}


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    raise SystemExit({"control-plane": control_plane, "client": client, "activity": activity}.get(cmd, lambda: print(__doc__) or 2)())
