from __future__ import annotations

import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import Server, User
from .security import decode_token, secure_compare, sha256_hex


def client_ip(request: Request) -> str:
    if get_settings().trust_proxy_headers:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


def current_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = decode_token(authorization[7:], "access")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    user = db.get(User, claims["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "account disabled")
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    return user


def require_auditor(user: User = Depends(current_user)) -> User:
    """Admins and read-only auditors may read logs."""
    if user.role not in {"admin", "auditor"}:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "auditor role required")
    return user


def gateway(
    x_gateway_id: str | None = Header(default=None),
    x_gateway_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Server:
    if not x_gateway_id or not x_gateway_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "gateway credentials required")
    srv = db.get(Server, x_gateway_id)
    if srv is None or not secure_compare(srv.gateway_key_hash, sha256_hex(x_gateway_key)):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid gateway credentials")
    return srv
