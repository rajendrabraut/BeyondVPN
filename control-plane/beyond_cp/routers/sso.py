"""Single sign-on with OpenID Connect (Azure AD / Entra ID, Google Workspace, Okta, Keycloak, ...).

Flow (authorization code + PKCE, confidential client):
  1. Client opens  GET /api/v1/auth/sso/{provider}/start?return_to=<app url>
  2. We redirect to the IdP with state, nonce and an S256 code challenge.
  3. IdP redirects to  GET /api/v1/auth/sso/{provider}/callback?code&state
  4. We exchange the code, verify the ID token (signature via JWKS, iss, aud, exp, nonce),
     find or create the user, and redirect to  <return_to>#sso_code=<one-time code>.
     The code lives in the URL fragment so it never reaches a server log.
  5. Client calls  POST /api/v1/auth/sso/exchange {code}  and gets normal access/refresh tokens.

SAML-only IdPs can be bridged through an OIDC broker (e.g. Keycloak) until native SAML lands.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from datetime import timedelta
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..deps import client_ip
from ..models import SsoLogin, User, UserIdentity, utcnow
from ..schemas import TokenOut
from ..security import limiter, sha256_hex
from .auth import _issue

router = APIRouter(prefix="/api/v1/auth/sso", tags=["sso"])

STATE_TTL = timedelta(minutes=10)
CODE_TTL = timedelta(minutes=2)
SSO_PASSWORD_HASH = "!sso-only"  # never a valid argon2 hash => password login always fails
ID_TOKEN_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"]

_http: httpx.Client | None = None
_cache: dict[str, tuple[float, dict]] = {}


def set_http_client(client: httpx.Client | None) -> None:
    """Tests inject an httpx client with a MockTransport (fake IdP)."""
    global _http
    _http = client
    _cache.clear()


def _client() -> httpx.Client:
    global _http
    if _http is None:
        _http = httpx.Client(timeout=10, follow_redirects=False)
    return _http


def _get_json(url: str, ttl: float = 3600) -> dict:
    hit = _cache.get(url)
    if hit and hit[0] > time.time():
        return hit[1]
    r = _client().get(url)
    r.raise_for_status()
    data = r.json()
    _cache[url] = (time.time() + ttl, data)
    return data


def _provider(pid: str) -> dict:
    for p in get_settings().oidc_providers:
        if p["id"] == pid:
            return p
    raise HTTPException(404, "unknown SSO provider")


def _discovery(p: dict) -> dict:
    d = _get_json(f"{p['issuer']}/.well-known/openid-configuration")
    if d.get("issuer", "").rstrip("/") != p["issuer"]:
        raise HTTPException(502, "IdP discovery issuer mismatch")
    return d


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _callback_url(pid: str) -> str:
    return f"{get_settings().public_url.rstrip('/')}/api/v1/auth/sso/{pid}/callback"


def _origin(url: str) -> str:
    u = urlsplit(url)
    return f"{u.scheme}://{u.netloc}".lower()


def _allowed_return(url: str) -> bool:
    s = get_settings()
    if any(url == r or url.startswith(r.rstrip("/") + "/") or url.startswith(r + "?") for r in s.sso_app_redirects):
        return True
    u = urlsplit(url)
    if u.scheme not in {"http", "https"} or not u.netloc or "#" in url:
        return False
    return _origin(url) in {_origin(o) for o in [*s.cors_origins, s.public_url]}


def _rate(request: Request, bucket: str) -> None:
    if not limiter.allow(f"sso-{bucket}:{client_ip(request)}", get_settings().auth_rate_per_minute):
        raise HTTPException(429, "too many requests, slow down")


def _fail(return_to: str, msg: str) -> RedirectResponse:
    return RedirectResponse(f"{return_to}#{urlencode({'sso_error': msg})}", status_code=302)


@router.get("/providers")
def providers():
    return [{"id": p["id"], "name": p["name"]} for p in get_settings().oidc_providers]


@router.get("/{pid}/start")
def start(pid: str, request: Request, return_to: str | None = None, db: Session = Depends(get_db)):
    _rate(request, "start")
    p = _provider(pid)
    rt = return_to or get_settings().public_url.rstrip("/") + "/"
    if len(rt) > 512 or not _allowed_return(rt):
        raise HTTPException(400, "return_to not allowed")
    d = _discovery(p)
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    db.add(SsoLogin(state=state, provider=pid, nonce=nonce, code_verifier=verifier, return_to=rt))
    db.commit()
    q = {
        "response_type": "code",
        "client_id": p["client_id"],
        "redirect_uri": _callback_url(pid),
        "scope": p["scopes"],
        "state": state,
        "nonce": nonce,
        "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()),
        "code_challenge_method": "S256",
    }
    return RedirectResponse(f"{d['authorization_endpoint']}?{urlencode(q)}", status_code=302)


def _verify_id_token(p: dict, d: dict, id_token: str, nonce: str) -> dict:
    try:
        kid = jwt.get_unverified_header(id_token).get("kid")
        jwks = jwt.PyJWKSet.from_dict(_get_json(d["jwks_uri"], ttl=600))
        keys = [k for k in jwks.keys if kid is None or k.key_id == kid]
        if not keys:  # key rotation: refetch once
            _cache.pop(d["jwks_uri"], None)
            jwks = jwt.PyJWKSet.from_dict(_get_json(d["jwks_uri"], ttl=600))
            keys = [k for k in jwks.keys if kid is None or k.key_id == kid]
        if not keys:
            raise HTTPException(401, "ID token signed with unknown key")
        claims = jwt.decode(
            id_token,
            keys[0].key,
            algorithms=ID_TOKEN_ALGS,
            audience=p["client_id"],
            issuer=d["issuer"],
            leeway=60,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as e:
        raise HTTPException(401, f"invalid ID token: {e}") from None
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise HTTPException(401, "ID token nonce mismatch")
    return claims


def _resolve_user(db: Session, p: dict, claims: dict, ip: str) -> User:
    sub = str(claims["sub"])
    email = str(claims.get("email") or claims.get("preferred_username") or "").lower()
    if claims.get("email_verified") is False:
        raise HTTPException(403, "IdP reports the email as unverified")
    domain = email.rsplit("@", 1)[-1] if "@" in email else ""
    if p["allowed_domains"] and domain not in p["allowed_domains"]:
        raise HTTPException(403, "your organisation is not allowed to use this sign-in")
    ident = db.execute(select(UserIdentity).where(UserIdentity.provider == p["id"], UserIdentity.subject == sub)).scalar_one_or_none()
    if ident is not None:
        user = db.get(User, ident.user_id)
        ident.last_login_at = utcnow()
    else:
        if "@" not in email:
            raise HTTPException(403, "IdP did not return an email address")
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is not None:
            # Only auto-link an existing account when this IdP is authoritative for the domain;
            # otherwise any IdP that lets users pick an email could take over accounts.
            if not p["allowed_domains"]:
                raise HTTPException(409, "an account with this email already exists; sign in with your password")
        else:
            if not p["auto_create"]:
                raise HTTPException(403, "no account for this identity; ask an administrator")
            user = User(email=email, password_hash=SSO_PASSWORD_HASH, full_name=str(claims.get("name") or "")[:120], role=p["default_role"])
            db.add(user)
            db.flush()
            audit.record(db, user.id, "user.register_sso", email, ip, {"provider": p["id"]})
        db.add(UserIdentity(user_id=user.id, provider=p["id"], subject=sub, email=email, last_login_at=utcnow()))
    if user is None or not user.is_active:
        raise HTTPException(403, "account disabled")
    return user


@router.get("/{pid}/callback")
def callback(pid: str, request: Request, state: str = "", code: str = "", error: str = "", db: Session = Depends(get_db)):
    _rate(request, "callback")
    p = _provider(pid)
    row = db.get(SsoLogin, state) if state else None
    if row is None or row.provider != pid or row.completed_at is not None or utcnow() - row.created_at > STATE_TTL:
        raise HTTPException(400, "SSO session expired or invalid; start again")
    row.completed_at = utcnow()  # state is single-use, even on failure
    db.commit()
    if error or not code:
        return _fail(row.return_to, error or "missing code")
    d = _discovery(p)
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": _callback_url(pid), "code_verifier": row.code_verifier}
    auth = None
    if p["token_auth"] == "client_secret_post":
        form |= {"client_id": p["client_id"], "client_secret": p["client_secret"]}
    else:
        auth = (p["client_id"], p["client_secret"])
    try:
        r = _client().post(d["token_endpoint"], data=form, auth=auth, headers={"Accept": "application/json"})
        r.raise_for_status()
        id_token = r.json()["id_token"]
    except (httpx.HTTPError, KeyError, ValueError):
        return _fail(row.return_to, "token exchange with identity provider failed")
    ip = client_ip(request)
    try:
        claims = _verify_id_token(p, d, id_token, row.nonce)
        user = _resolve_user(db, p, claims, ip)
    except HTTPException as e:
        db.rollback()
        audit.record(db, "anonymous", "auth.sso_failed", pid, ip, {"reason": str(e.detail)})
        return _fail(row.return_to, str(e.detail))
    one_time = secrets.token_urlsafe(32)
    row.user_id = user.id
    row.code_hash = sha256_hex(one_time)
    db.commit()
    return RedirectResponse(f"{row.return_to}#{urlencode({'sso_code': one_time})}", status_code=302)


class SsoExchangeIn(BaseModel):
    code: str = Field(min_length=10, max_length=128)
    accept_logging_policy: bool = False


@router.post("/exchange", response_model=TokenOut)
def exchange(body: SsoExchangeIn, request: Request, db: Session = Depends(get_db)):
    _rate(request, "exchange")
    row = db.execute(select(SsoLogin).where(SsoLogin.code_hash == sha256_hex(body.code))).scalar_one_or_none()
    if row is None or row.consumed or row.completed_at is None or utcnow() - row.completed_at > CODE_TTL:
        raise HTTPException(401, "invalid or expired SSO code")
    user = db.get(User, row.user_id) if row.user_id else None
    if user is None or not user.is_active:
        raise HTTPException(401, "account disabled")
    if get_settings().require_logging_consent and user.logging_consent_at is None:
        if not body.accept_logging_policy:
            # Code stays valid (until CODE_TTL) so the client can ask the user and retry.
            raise HTTPException(428, "logging_consent_required")
        user.logging_consent_at = utcnow()
    row.consumed = True
    user.last_login_at = utcnow()
    user.failed_logins = 0
    db.commit()
    audit.record(db, user.id, "auth.login_sso", user.email, client_ip(request), {"provider": row.provider})
    return _issue(db, user)
