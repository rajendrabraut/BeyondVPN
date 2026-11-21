"""End-to-end test across languages: Python control plane <-> Rust gateway <-> Rust desktop agent.

What it proves (no root / real WireGuard needed; gateway & agent run in dry-run mode):
  1. Gateway authenticates to the control plane, heartbeats, and the server turns "online".
  2. Desktop agent logs in, registers its device key, and connects (gets a WireGuard config).
  3. Gateway peer sync receives that device's peer.
  4. A Python-issued EdDSA proxy token is accepted by the Rust proxy; a CONNECT tunnel works.
  5. Policy blocklist reaches the gateway; DNS sinkholes the blocked domain.
  6. Gateway uploads DNS + web activity logs; they appear for the user and admin.
  7. Audit chain verifies.

Usage:  python tests/e2e/run_e2e.py   (from repo root; needs `cargo build` done and control-plane venv)
"""
from __future__ import annotations

import base64
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
EXE = ".exe" if os.name == "nt" else ""
TARGET = ROOT / "core" / "target" / "debug"
GATEWAY = TARGET / f"beyond-gateway{EXE}"
AGENT = TARGET / f"beyond-agent{EXE}"
ADMIN = ("admin@beyondvpn.example.com", "AdminPassw0rd!")
USER = ("alice@beyondvpn.example.com", "AlicePassw0rd1")


def free_port(kind=socket.SOCK_STREAM) -> int:
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_for(fn, timeout=45.0, every=0.5, what="condition"):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            v = fn()
            if v:
                return v
        except Exception as e:  # noqa: BLE001
            last = e
        time.sleep(every)
    raise AssertionError(f"timed out waiting for {what} (last error: {last})")


def step(msg: str) -> None:
    print(f"[e2e] {msg}", flush=True)


def echo_server(port: int) -> None:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen()

    def handle(c):
        with c:
            data = c.recv(1024)
            c.sendall(data)

    def loop():
        while True:
            c, _ = srv.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def dns_query(name: str, port: int) -> bytes:
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(q, ("127.0.0.1", port))
    data, _ = s.recvfrom(512)
    return data


def main() -> int:
    for b in (GATEWAY, AGENT):
        if not b.exists():
            print(f"missing {b}; run `cargo build` in core/ first", file=sys.stderr)
            return 2
    tmp = Path(tempfile.mkdtemp(prefix="beyond-e2e-"))
    procs: list[subprocess.Popen] = []
    try:
        cp_port, proxy_port, dns_port, echo_port = free_port(), free_port(), free_port(socket.SOCK_DGRAM), free_port()
        base = f"http://127.0.0.1:{cp_port}"
        env = {**os.environ, "BEYOND_DATA_DIR": str(tmp / "cp"), "BEYOND_ADMIN_EMAIL": ADMIN[0], "BEYOND_ADMIN_PASSWORD": ADMIN[1], "PYTHONPATH": str(ROOT / "control-plane")}

        step("starting control plane")
        procs.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "beyond_cp.main:create_app", "--factory", "--port", str(cp_port), "--log-level", "warning"], cwd=ROOT / "control-plane", env=env))
        wait_for(lambda: httpx.get(f"{base}/healthz").status_code == 200, what="control plane")
        c = httpx.Client(base_url=base, timeout=20)

        admin = {"Authorization": "Bearer " + c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]}).json()["access_token"]}
        r = c.post("/api/v1/admin/servers", headers=admin, json={"id": "local-1", "name": "Local Test", "country": "IN", "city": "Pune", "hostname": "localhost", "proxy_port": proxy_port})
        assert r.status_code == 201, r.text
        gw_key = r.json()["gateway_key"]
        c.put("/api/v1/admin/policy", headers=admin, json={"blocked_domains": ["ads.blocked.example"], "logging_mode": "full"}).raise_for_status()

        step("starting Rust gateway (dry-run)")
        cfg = tmp / "gateway.toml"
        cfg.write_text(
            f'gateway_id = "local-1"\ncontrol_plane_url = "{base}"\ndry_run = true\nsync_interval_secs = 2\n'
            f'[dns]\nlisten = "127.0.0.1:{dns_port}"\nupstream = "udp://127.0.0.1:9"\n'
            f'[proxy]\nlisten = "127.0.0.1:{proxy_port}"\nallowed_ports = [{echo_port}, 443]\nallow_private_destinations = true\n'
        )
        procs.append(subprocess.Popen([str(GATEWAY), "run", "--config", str(cfg)], env={**os.environ, "BEYOND_GATEWAY_KEY": gw_key, "RUST_LOG": "warn"}))
        wait_for(lambda: c.get("/api/v1/admin/servers", headers=admin).json()[0]["status"] == "online", what="gateway heartbeat")
        step("gateway online")

        step("registering user + desktop agent login/connect")
        c.post("/api/v1/auth/register", json={"email": USER[0], "password": USER[1], "full_name": "Alice", "accept_logging_policy": True}).raise_for_status()
        aenv = {**os.environ, "BEYOND_AGENT_DIR": str(tmp / "agent"), "BEYOND_AGENT_DRY_RUN": "1", "BEYOND_PASSWORD": USER[1], "RUST_LOG": "warn"}
        run = lambda *a: subprocess.run([str(AGENT), *a], env=aenv, capture_output=True, text=True, timeout=60)  # noqa: E731
        out = run("login", "--api", base, "--email", USER[0])
        assert out.returncode == 0, out.stderr
        out = run("connect", "--server", "local-1")
        assert out.returncode == 0 and "Connected" in out.stdout, out.stderr + out.stdout
        conf = (tmp / "agent" / "beyond0.conf")
        if conf.exists():  # removed on Windows after import; present on unix dry-run
            assert "PrivateKey" in conf.read_text()
        st = run("status")
        assert "connected : true" in st.stdout, st.stdout
        user = {"Authorization": "Bearer " + c.post("/api/v1/auth/login", json={"email": USER[0], "password": USER[1]}).json()["access_token"]}
        devices = c.get("/api/v1/devices", headers=user).json()
        assert len(devices) == 1 and devices[0]["platform"] in {"windows", "linux", "macos"}
        step(f"agent connected; device {devices[0]['id'][:8]} registered")

        step("checking gateway received the peer")
        peers = c.get("/api/v1/gateway/peers", headers={"X-Gateway-Id": "local-1", "X-Gateway-Key": gw_key}).json()["peers"]
        assert [p["public_key"] for p in peers] == [devices[0]["public_key"]]

        step("browser-extension path: Python token -> Rust proxy")
        echo_server(echo_port)
        tok = c.post("/api/v1/proxy/token", headers=user, json={"server_id": "local-1"}).json()["token"]
        auth = base64.b64encode(f"beyond:{tok}".encode()).decode()

        def tunnel(auth_header: str | None) -> bytes:
            s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
            hdr = f"Proxy-Authorization: Basic {auth_header}\r\n" if auth_header else ""
            s.sendall(f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n{hdr}\r\n".encode())
            resp = s.recv(1024)
            if resp.startswith(b"HTTP/1.1 200"):
                s.sendall(b"ping-beyond")
                resp += s.recv(1024)
            s.close()
            return resp

        def tunnel_ok():
            r = tunnel(auth)
            return r.startswith(b"HTTP/1.1 200") and r.endswith(b"ping-beyond")

        # The gateway learns the signing key on its first sync; retry briefly.
        wait_for(tunnel_ok, timeout=20, what="authenticated proxy tunnel")
        assert tunnel(None).startswith(b"HTTP/1.1 407")
        step("proxy tunnel OK; unauthenticated request rejected (407)")

        step("DNS sinkhole from admin policy")
        resp = wait_for(lambda: (lambda d: d if d[3] & 0x0F == 0 and d[7] == 1 else None)(dns_query("ads.blocked.example", dns_port)), timeout=20, what="dns sinkhole")
        assert resp[-4:] == b"\x00\x00\x00\x00"

        step("waiting for activity logs to be uploaded (<=30s)")
        wait_for(lambda: any(w["host"] == "127.0.0.1" for w in c.get("/api/v1/me/activity", headers=user).json()["web"]), timeout=40, what="web activity log")
        wait_for(lambda: any(d["domain"] == "ads.blocked.example" and d["blocked"] for d in c.get("/api/v1/admin/logs/dns", headers=admin, params={"hours": 1}).json()), timeout=40, what="dns log")
        usage = c.get("/api/v1/me/usage", headers=user).json()
        assert usage["month_total_bytes"] > 0, usage
        step(f"logs present; metered {usage['month_total_bytes']} bytes")

        out = run("disconnect")
        assert out.returncode == 0, out.stderr
        wait_for(lambda: c.get("/api/v1/gateway/peers", headers={"X-Gateway-Id": "local-1", "X-Gateway-Key": gw_key}).json()["peers"] == [], what="peer removal")
        assert c.get("/api/v1/admin/audit/verify", headers=admin).json()["ok"] is True
        step("disconnect removed the peer; audit chain intact")
        print("\nE2E PASSED")
        return 0
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
