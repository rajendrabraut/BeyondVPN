"""OIDC single sign-on against an in-process fake identity provider."""
from __future__ import annotations

import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from beyond_cp import config, security
from beyond_cp.routers import sso

from .conftest import ADMIN_EMAIL, ADMIN_PW, USER_PW, bearer, login, make_user

ISSUER = "https://idp.example.com"
CLIENT_ID = "beyond-test"
RETURN = "http://localhost:5173/"


class FakeIdP:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.claims: dict = {}
        self.codes: dict[str, str] = {}  # code -> nonce
        self.token_requests: list[dict] = []

    def jwks(self) -> dict:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk |= {"kid": "k1", "use": "sig", "alg": "RS256"}
        return {"keys": [jwk]}

    def id_token(self, nonce: str) -> str:
        now = int(time.time())
        base = {"iss": ISSUER, "aud": CLIENT_ID, "iat": now, "exp": now + 300, "nonce": nonce, "sub": "idp-user-1", "email": "carol@corp.example", "email_verified": True, "name": "Carol"}
        return jwt.encode(base | self.claims, self.key, algorithm="RS256", headers={"kid": "k1"})

    def handler(self, req: httpx.Request) -> httpx.Response:
        if req.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize", "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/jwks"})
        if req.url.path == "/jwks":
            return httpx.Response(200, json=self.jwks())
        if req.url.path == "/token":
            form = parse_qs(req.content.decode())
            self.token_requests.append(form)
            nonce = self.codes.get(form["code"][0])
            if nonce is None:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": self.id_token(nonce), "access_token": "x", "token_type": "Bearer"})
        return httpx.Response(404)


def make_app(tmp_path, monkeypatch, **provider):
    monkeypatch.setenv("BEYOND_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("BEYOND_ADMIN_EMAIL", ADMIN_EMAIL)
    monkeypatch.setenv("BEYOND_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("BEYOND_AUTH_RATE_PER_MINUTE", "1000")
    monkeypatch.setenv("BEYOND_OIDC_PROVIDERS", json.dumps([{"id": "corp", "name": "Corp SSO", "issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "s3cret"} | provider]))
    for k in ("BEYOND_DATABASE_URL", "BEYOND_SIGNING_KEY", "BEYOND_DATA_KEY"):
        monkeypatch.delenv(k, raising=False)
    config.reset_settings()
    security.reset_keys()
    security.limiter.reset()
    from beyond_cp.main import create_app

    return create_app()


@pytest.fixture()
def idp():
    fake = FakeIdP()
    sso.set_http_client(httpx.Client(transport=httpx.MockTransport(fake.handler)))
    yield fake
    sso.set_http_client(None)
    config.reset_settings()
    security.reset_keys()


@pytest.fixture()
def sso_client(tmp_path, monkeypatch, idp):
    with TestClient(make_app(tmp_path, monkeypatch, allowed_domains=["corp.example"])) as c:
        yield c


def run_flow(c: TestClient, idp: FakeIdP, return_to: str = RETURN) -> str:
    r = c.get("/api/v1/auth/sso/corp/start", params={"return_to": return_to}, follow_redirects=False)
    assert r.status_code == 302, r.text
    q = parse_qs(urlsplit(r.headers["location"]).query)
    assert q["code_challenge_method"] == ["S256"] and q["client_id"] == [CLIENT_ID]
    idp.codes["authcode-1"] = q["nonce"][0]
    r = c.get("/api/v1/auth/sso/corp/callback", params={"state": q["state"][0], "code": "authcode-1"}, follow_redirects=False)
    assert r.status_code == 302
    return r.headers["location"]


def fragment(loc: str) -> dict:
    return {k: v[0] for k, v in parse_qs(urlsplit(loc).fragment).items()}


def test_providers_listed_without_secrets(sso_client):
    r = sso_client.get("/api/v1/auth/sso/providers")
    assert r.json() == [{"id": "corp", "name": "Corp SSO"}]


def test_full_flow_creates_user_and_requires_consent(sso_client, idp):
    loc = run_flow(sso_client, idp)
    assert loc.startswith(RETURN + "#")
    code = fragment(loc)["sso_code"]
    # PKCE verifier and client auth were sent to the IdP.
    assert "code_verifier" in idp.token_requests[0]
    r = sso_client.post("/api/v1/auth/sso/exchange", json={"code": code})
    assert r.status_code == 428 and r.json()["detail"] == "logging_consent_required"
    r = sso_client.post("/api/v1/auth/sso/exchange", json={"code": code, "accept_logging_policy": True})
    assert r.status_code == 200, r.text
    me = sso_client.get("/api/v1/me", headers=bearer(r.json())).json()
    assert me["email"] == "carol@corp.example"
    # One-time code cannot be replayed.
    assert sso_client.post("/api/v1/auth/sso/exchange", json={"code": code, "accept_logging_policy": True}).status_code == 401
    # SSO-only accounts cannot log in with a password.
    r = sso_client.post("/api/v1/auth/login", json={"email": "carol@corp.example", "password": "!sso-only"})
    assert r.status_code == 401


def test_second_login_reuses_identity(sso_client, idp):
    for _ in range(2):
        code = fragment(run_flow(sso_client, idp))["sso_code"]
        assert sso_client.post("/api/v1/auth/sso/exchange", json={"code": code, "accept_logging_policy": True}).status_code == 200
    admin = bearer(login(sso_client, ADMIN_EMAIL, ADMIN_PW))
    users = sso_client.get("/api/v1/admin/users", headers=admin).json()
    assert sum(1 for u in users if u["email"] == "carol@corp.example") == 1


def test_state_is_single_use(sso_client, idp):
    r = sso_client.get("/api/v1/auth/sso/corp/start", params={"return_to": RETURN}, follow_redirects=False)
    q = parse_qs(urlsplit(r.headers["location"]).query)
    idp.codes["c"] = q["nonce"][0]
    assert sso_client.get("/api/v1/auth/sso/corp/callback", params={"state": q["state"][0], "code": "c"}, follow_redirects=False).status_code == 302
    assert sso_client.get("/api/v1/auth/sso/corp/callback", params={"state": q["state"][0], "code": "c"}, follow_redirects=False).status_code == 400


def test_open_redirect_rejected(sso_client):
    r = sso_client.get("/api/v1/auth/sso/corp/start", params={"return_to": "https://evil.example/"}, follow_redirects=False)
    assert r.status_code == 400
    r = sso_client.get("/api/v1/auth/sso/corp/start", params={"return_to": "beyondvpn://sso"}, follow_redirects=False)
    assert r.status_code == 302


def test_app_redirect_gets_code_in_query(sso_client, idp):
    loc = run_flow(sso_client, idp, return_to="beyondvpn://sso?n=abc123")
    assert loc.startswith("beyondvpn://sso?n=abc123&sso_code=") and "#" not in loc
    code = parse_qs(urlsplit(loc).query)["sso_code"][0]
    assert sso_client.post("/api/v1/auth/sso/exchange", json={"code": code, "accept_logging_policy": True}).status_code == 200


def test_domain_not_allowed(sso_client, idp):
    idp.claims = {"email": "mallory@other.example"}
    err = fragment(run_flow(sso_client, idp))
    assert "sso_code" not in err and "not allowed" in err["sso_error"]


def test_nonce_mismatch_rejected(sso_client, idp):
    idp.claims = {"nonce": "attacker"}
    assert "nonce" in fragment(run_flow(sso_client, idp))["sso_error"]


def test_wrong_audience_rejected(sso_client, idp):
    idp.claims = {"aud": "someone-else"}
    assert "invalid ID token" in fragment(run_flow(sso_client, idp))["sso_error"]


def test_unverified_email_rejected(sso_client, idp):
    idp.claims = {"email_verified": False}
    assert "unverified" in fragment(run_flow(sso_client, idp))["sso_error"]


def test_existing_account_linked_only_for_authoritative_domain(sso_client, idp):
    make_user(sso_client, "carol@corp.example", USER_PW)
    code = fragment(run_flow(sso_client, idp))["sso_code"]  # allowed_domains=[corp.example] => link
    assert sso_client.post("/api/v1/auth/sso/exchange", json={"code": code}).status_code == 200


def test_existing_account_not_linked_by_untrusted_idp(tmp_path, monkeypatch, idp):
    with TestClient(make_app(tmp_path, monkeypatch)) as c:  # no allowed_domains
        make_user(c, "carol@corp.example", USER_PW)
        assert "already exists" in fragment(run_flow(c, idp))["sso_error"]


def test_unknown_provider_404(sso_client):
    assert sso_client.get("/api/v1/auth/sso/nope/start", follow_redirects=False).status_code == 404
