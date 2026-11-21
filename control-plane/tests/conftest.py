from __future__ import annotations

import base64
import os
import secrets

import pytest
from fastapi.testclient import TestClient

from beyond_cp import config, security
from beyond_cp.wgkeys import generate_keypair

ADMIN_EMAIL = "admin@beyondvpn.example.com"
ADMIN_PW = "AdminPassw0rd!"
USER_PW = "UserPassw0rd1"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("BEYOND_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("BEYOND_ADMIN_EMAIL", ADMIN_EMAIL)
    monkeypatch.setenv("BEYOND_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("BEYOND_AUTH_RATE_PER_MINUTE", "1000")
    for k in ("BEYOND_DATABASE_URL", "BEYOND_SIGNING_KEY", "BEYOND_DATA_KEY"):
        monkeypatch.delenv(k, raising=False)
    config.reset_settings()
    security.reset_keys()
    security.limiter.reset()
    from beyond_cp.main import create_app

    yield create_app()
    config.reset_settings()
    security.reset_keys()


@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c


def login(client, email, pw, totp=None) -> dict:
    r = client.post("/api/v1/auth/login", json={"email": email, "password": pw, "totp_code": totp})
    assert r.status_code == 200, r.text
    return r.json()


def bearer(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


@pytest.fixture()
def admin_h(client):
    return bearer(login(client, ADMIN_EMAIL, ADMIN_PW))


def make_user(client, email=None, pw=USER_PW) -> tuple[str, dict]:
    email = email or f"u{secrets.token_hex(4)}@beyondvpn.example.com"
    r = client.post("/api/v1/auth/register", json={"email": email, "password": pw, "full_name": "Test User", "accept_logging_policy": True})
    assert r.status_code == 201, r.text
    return email, bearer(login(client, email, pw))


@pytest.fixture()
def user(client):
    return make_user(client)


def make_server(client, admin_h, sid="in-mum-1", online=True) -> str:
    r = client.post(
        "/api/v1/admin/servers",
        headers=admin_h,
        json={"id": sid, "name": f"Server {sid}", "country": "IN", "city": "Mumbai", "hostname": f"{sid}.vpn.beyondvpn.example.com", "features": ["p2p"]},
    )
    assert r.status_code == 201, r.text
    key = r.json()["gateway_key"]
    if online:
        heartbeat(client, sid, key)
    return key


def gw_h(sid: str, key: str) -> dict:
    return {"X-Gateway-Id": sid, "X-Gateway-Key": key}


def heartbeat(client, sid, key, public_key=None):
    pk = public_key or generate_keypair()[1]
    r = client.post("/api/v1/gateway/heartbeat", headers=gw_h(sid, key), json={"public_key": pk, "listen_port": 51820, "active_peers": 0, "load": 0.1, "version": "test"})
    assert r.status_code == 200, r.text


def register_device(client, h, platform="windows", posture=None) -> tuple[str, str]:
    _, pub = generate_keypair()
    r = client.post("/api/v1/devices", headers=h, json={"name": "laptop", "platform": platform, "public_key": pub, "posture": posture or {"os": platform}})
    assert r.status_code == 200, r.text
    return r.json()["id"], pub


def ed25519_pub(client):
    raw = base64.b64decode(client.get("/api/v1/keys/signing").json()["public_key"])
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    return Ed25519PublicKey.from_public_bytes(raw)


os.environ.setdefault("PYTHONHASHSEED", "0")
