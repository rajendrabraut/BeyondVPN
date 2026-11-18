from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..deps import client_ip, current_user
from ..models import RefreshToken, User, new_id, utcnow
from ..schemas import LoginIn, MfaCodeIn, RefreshIn, RegisterIn, TokenOut, UserOut
from ..security import (
    PASSWORD_RULE,
    burn_password_check,
    decrypt,
    encrypt,
    hash_password,
    issue_token,
    limiter,
    new_opaque_token,
    new_totp_secret,
    password_ok,
    sha256_hex,
    totp_uri,
    verify_password,
    verify_totp,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _rate_limit(request: Request, bucket: str) -> None:
    ip = client_ip(request)
    if not limiter.allow(f"{bucket}:{ip}", get_settings().auth_rate_per_minute):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many requests, slow down")


def _issue(db: Session, user: User, family: str | None = None) -> TokenOut:
    s = get_settings()
    access, _ = issue_token(user.id, "access", s.access_ttl, email=user.email, role=user.role)
    raw = new_opaque_token()
    db.add(RefreshToken(user_id=user.id, family=family or new_id(), token_hash=sha256_hex(raw), expires_at=utcnow() + timedelta(seconds=s.refresh_ttl)))
    db.commit()
    return TokenOut(access_token=access, refresh_token=raw, expires_in=s.access_ttl)


@router.post("/register", response_model=UserOut, status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    s = get_settings()
    _rate_limit(request, "register")
    if not s.allow_registration:
        raise HTTPException(403, "self-registration disabled; ask an administrator")
    if not password_ok(body.password):
        raise HTTPException(422, f"password must be {PASSWORD_RULE}")
    if s.require_logging_consent and not body.accept_logging_policy:
        raise HTTPException(422, "you must accept the activity logging policy")
    email = body.email.lower()
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        # Same status as success-path validation errors would leak existence; use 409 but generic text.
        raise HTTPException(409, "unable to register with this email")
    user = User(email=email, password_hash=hash_password(body.password), full_name=body.full_name.strip(), logging_consent_at=utcnow() if body.accept_logging_policy else None)
    db.add(user)
    db.commit()
    audit.record(db, user.id, "user.register", user.email, client_ip(request))
    return user


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    s = get_settings()
    _rate_limit(request, "login")
    ip = client_ip(request)
    user = db.execute(select(User).where(User.email == body.email.lower())).scalar_one_or_none()
    if user is None:
        burn_password_check(body.password)
        raise HTTPException(401, "invalid credentials")
    if user.locked_until and user.locked_until > utcnow():
        audit.record(db, user.id, "auth.login_locked", user.email, ip)
        raise HTTPException(423, "account temporarily locked after repeated failures")
    if not verify_password(user.password_hash, body.password):
        user.failed_logins += 1
        if user.failed_logins >= s.max_failed_logins:
            user.locked_until = utcnow() + timedelta(seconds=s.lockout_seconds)
            user.failed_logins = 0
        db.commit()
        audit.record(db, user.id, "auth.login_failed", user.email, ip)
        raise HTTPException(401, "invalid credentials")
    if not user.is_active:
        raise HTTPException(403, "account disabled")
    if user.mfa_enabled:
        if not body.totp_code:
            raise HTTPException(401, "mfa_required")
        if not verify_totp(decrypt(user.mfa_secret_enc or ""), body.totp_code):
            user.failed_logins += 1
            db.commit()
            audit.record(db, user.id, "auth.mfa_failed", user.email, ip)
            raise HTTPException(401, "invalid credentials")
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    db.commit()
    audit.record(db, user.id, "auth.login", user.email, ip)
    return _issue(db, user)


@router.post("/refresh", response_model=TokenOut)
def refresh(body: RefreshIn, request: Request, db: Session = Depends(get_db)):
    _rate_limit(request, "refresh")
    rt = db.execute(select(RefreshToken).where(RefreshToken.token_hash == sha256_hex(body.refresh_token))).scalar_one_or_none()
    if rt is None or rt.revoked or rt.expires_at < utcnow():
        raise HTTPException(401, "invalid refresh token")
    if rt.used:
        # Reuse of a rotated token => likely theft. Kill the whole family.
        db.execute(update(RefreshToken).where(RefreshToken.family == rt.family).values(revoked=True))
        db.commit()
        audit.record(db, rt.user_id, "auth.refresh_reuse_detected", rt.family, client_ip(request))
        raise HTTPException(401, "invalid refresh token")
    user = db.get(User, rt.user_id)
    if user is None or not user.is_active:
        raise HTTPException(401, "account disabled")
    rt.used = True
    db.commit()
    return _issue(db, user, family=rt.family)


@router.post("/logout")
def logout(body: RefreshIn, db: Session = Depends(get_db)):
    rt = db.execute(select(RefreshToken).where(RefreshToken.token_hash == sha256_hex(body.refresh_token))).scalar_one_or_none()
    if rt is not None:
        db.execute(update(RefreshToken).where(RefreshToken.family == rt.family).values(revoked=True))
        db.commit()
        audit.record(db, rt.user_id, "auth.logout")
    return {"ok": True}


@router.post("/mfa/setup")
def mfa_setup(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.mfa_enabled:
        raise HTTPException(409, "MFA already enabled")
    secret = new_totp_secret()
    user.mfa_secret_enc = encrypt(secret)
    db.commit()
    return {"secret": secret, "otpauth_uri": totp_uri(secret, user.email)}


@router.post("/mfa/enable")
def mfa_enable(body: MfaCodeIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not user.mfa_secret_enc or not verify_totp(decrypt(user.mfa_secret_enc), body.code):
        raise HTTPException(400, "invalid code")
    user.mfa_enabled = True
    db.commit()
    audit.record(db, user.id, "auth.mfa_enabled", user.email, client_ip(request))
    return {"ok": True}


@router.post("/mfa/disable")
def mfa_disable(body: MfaCodeIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not user.mfa_enabled or not verify_totp(decrypt(user.mfa_secret_enc or ""), body.code):
        raise HTTPException(400, "invalid code")
    user.mfa_enabled = False
    user.mfa_secret_enc = None
    db.commit()
    audit.record(db, user.id, "auth.mfa_disabled", user.email, client_ip(request))
    return {"ok": True}
