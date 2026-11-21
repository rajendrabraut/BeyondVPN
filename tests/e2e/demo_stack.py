"""Local demo stack for clicking through the desktop app / portal without real WireGuard.

Starts: control plane (uvicorn), Rust gateway (dry-run) and the desktop agent
daemon (`beyond-agent serve`, dry-run backend). Creates an admin, a demo user and
one "online" server. Prints the env vars the Electron app needs and keeps running
until Ctrl+C.

Usage (repo root, after `cargo build` in core/):
    python tests/e2e/demo_stack.py [--port 8000]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_e2e import ADMIN, AGENT, GATEWAY, ROOT, USER, free_port, wait_for  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--agent-port", type=int, default=47800)
    a = ap.parse_args()
    tmp = Path(tempfile.mkdtemp(prefix="beyond-demo-"))
    base = f"http://127.0.0.1:{a.port}"
    procs: list[subprocess.Popen] = []
    try:
        env = {**os.environ, "BEYOND_DATA_DIR": str(tmp / "cp"), "BEYOND_ADMIN_EMAIL": ADMIN[0], "BEYOND_ADMIN_PASSWORD": ADMIN[1], "PYTHONPATH": str(ROOT / "control-plane")}
        procs.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "beyond_cp.main:create_app", "--factory", "--port", str(a.port), "--log-level", "warning"], cwd=ROOT / "control-plane", env=env))
        wait_for(lambda: httpx.get(f"{base}/healthz").status_code == 200, what="control plane")
        c = httpx.Client(base_url=base, timeout=20)
        admin = {"Authorization": "Bearer " + c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]}).json()["access_token"]}
        gw_key = c.post("/api/v1/admin/servers", headers=admin, json={"id": "in-pune-1", "name": "Pune Demo", "country": "IN", "city": "Pune", "hostname": "localhost", "proxy_port": free_port()}).json()["gateway_key"]
        cfg = tmp / "gateway.toml"
        cfg.write_text(f'gateway_id = "in-pune-1"\ncontrol_plane_url = "{base}"\ndry_run = true\nsync_interval_secs = 3\n[dns]\nenabled = false\n[proxy]\nenabled = false\n')
        procs.append(subprocess.Popen([str(GATEWAY), "run", "--config", str(cfg)], env={**os.environ, "BEYOND_GATEWAY_KEY": gw_key, "RUST_LOG": "warn"}))
        wait_for(lambda: c.get("/api/v1/admin/servers", headers=admin).json()[0]["status"] == "online", what="gateway heartbeat")
        c.post("/api/v1/auth/register", json={"email": USER[0], "password": USER[1], "full_name": "Alice", "accept_logging_policy": True}).raise_for_status()
        agent_dir = tmp / "agent"
        aenv = {**os.environ, "BEYOND_AGENT_DIR": str(agent_dir), "BEYOND_AGENT_DRY_RUN": "1", "RUST_LOG": "warn"}
        procs.append(subprocess.Popen([str(AGENT), "serve", "--port", str(a.agent_port)], env=aenv))
        wait_for(lambda: (agent_dir / "agent.token").exists(), what="agent token")
        print(f"READY control-plane={base} user={USER[0]}", flush=True)
        print(f"BEYOND_AGENT_DIR={agent_dir}", flush=True)
        while all(p.poll() is None for p in procs):
            time.sleep(1)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
