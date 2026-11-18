import base64
import json

import pyotp

from .conftest import ADMIN_EMAIL, USER_PW, bearer, login, make_user


def test_health_and_security_headers(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["ok"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "max-age" in r.headers["strict-transport-security"]


def test_register_validation(client):
    weak = client.post("/api/v1/auth/register", json={"email": "a@beyondvpn.example.com", "password": "short", "accept_logging_policy": True})
    assert weak.status_code == 422
    nodigit = client.post("/api/v1/auth/register", json={"email": "a@beyondvpn.example.com", "password": "onlyletters!!", "accept_logging_policy": True})
    assert nodigit.status_code == 422
    noconsent = client.post("/api/v1/auth/register", json={"email": "a@beyondvpn.example.com", "password": USER_PW})
    assert noconsent.status_code == 422
    ok = client.post("/api/v1/auth/register", json={"email": "A@BeyondVPN.example.com", "password": USER_PW, "accept_logging_policy": True})
    assert ok.status_code == 201 and ok.json()["email"] == "a@beyondvpn.example.com"
    assert "password_hash" not in ok.json()
    dup = client.post("/api/v1/auth/register", json={"email": "a@beyondvpn.example.com", "password": USER_PW, "accept_logging_policy": True})
    assert dup.status_code == 409


def test_login_failures_are_generic_and_lock_out(client):
    email, _ = make_user(client)
    unknown = client.post("/api/v1/auth/login", json={"email": "nobody@beyondvpn.example.com", "password": "x"})
    wrong = client.post("/api/v1/auth/login", json={"email": email, "password": "wrongPassw0rd"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()
    for _ in range(4):
        client.post("/api/v1/auth/login", json={"email": email, "password": "wrongPassw0rd"})
    locked = client.post("/api/v1/auth/login", json={"email": email, "password": USER_PW})
    assert locked.status_code == 423


def test_me_requires_valid_token(client, user):
    _, h = user
    assert client.get("/api/v1/me", headers=h).status_code == 200
    assert client.get("/api/v1/me").status_code == 401
    assert client.get("/api/v1/me", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_alg_none_and_tampered_tokens_rejected(client, user):
    _, h = user
    tok = h["Authorization"][7:]
    head, payload, sig = tok.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    claims["role"] = "admin"
    evil = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {head}.{evil}.{sig}"}).status_code == 401
    none_head = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {none_head}.{payload}."}).status_code == 401


def test_refresh_rotation_and_reuse_detection(client):
    email, _ = make_user(client)
    t1 = login(client, email, USER_PW)
    r = client.post("/api/v1/auth/refresh", json={"refresh_token": t1["refresh_token"]})
    assert r.status_code == 200
    t2 = r.json()
    assert t2["refresh_token"] != t1["refresh_token"]
    # Replaying the old token revokes the whole family, including t2.
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": t1["refresh_token"]}).status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": t2["refresh_token"]}).status_code == 401


def test_logout_revokes_refresh(client):
    email, _ = make_user(client)
    t = login(client, email, USER_PW)
    assert client.post("/api/v1/auth/logout", json={"refresh_token": t["refresh_token"]}).status_code == 200
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]}).status_code == 401


def test_mfa_flow(client):
    email, h = make_user(client)
    setup = client.post("/api/v1/auth/mfa/setup", headers=h).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/")
    assert client.post("/api/v1/auth/mfa/enable", headers=h, json={"code": "000000"}).status_code == 400
    code = pyotp.TOTP(setup["secret"]).now()
    assert client.post("/api/v1/auth/mfa/enable", headers=h, json={"code": code}).status_code == 200
    r = client.post("/api/v1/auth/login", json={"email": email, "password": USER_PW})
    assert r.status_code == 401 and r.json()["detail"] == "mfa_required"
    bad = client.post("/api/v1/auth/login", json={"email": email, "password": USER_PW, "totp_code": "123456"})
    assert bad.status_code == 401
    good = login(client, email, USER_PW, pyotp.TOTP(setup["secret"]).now())
    me = client.get("/api/v1/me", headers=bearer(good)).json()
    assert me["mfa_enabled"] is True


def test_registration_can_be_disabled(client, monkeypatch):
    from beyond_cp.config import get_settings

    monkeypatch.setattr(get_settings(), "allow_registration", False)
    r = client.post("/api/v1/auth/register", json={"email": "x@beyondvpn.example.com", "password": USER_PW, "accept_logging_policy": True})
    assert r.status_code == 403


def test_auth_rate_limit(client, monkeypatch):
    from beyond_cp.config import get_settings

    monkeypatch.setattr(get_settings(), "auth_rate_per_minute", 3)
    codes = [client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": "nope"}).status_code for _ in range(5)]
    assert 429 in codes
