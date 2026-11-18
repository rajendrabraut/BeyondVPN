"""Beyond VPN control plane (FastAPI)."""
from __future__ import annotations

import logging
import threading
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import delete, select

from . import __version__, audit
from .config import get_settings
from .db import Base, engine, init_engine, session
from .models import DnsLog, ProxyLog, RefreshToken, User, utcnow
from .routers import admin, auth, gateway, me, vpn
from .security import hash_password, keys, password_ok

log = logging.getLogger("beyond_cp")
MAX_BODY = 16 * 1024 * 1024


def purge_expired(retention_days: int) -> dict[str, int]:
    """Delete activity logs past retention and expired refresh tokens."""
    cutoff = utcnow() - timedelta(days=retention_days)
    with session() as db:
        n_dns = db.execute(delete(DnsLog).where(DnsLog.ts < cutoff)).rowcount
        n_web = db.execute(delete(ProxyLog).where(ProxyLog.ts < cutoff)).rowcount
        n_rt = db.execute(delete(RefreshToken).where(RefreshToken.expires_at < utcnow())).rowcount
        db.commit()
        if n_dns or n_web:
            audit.record(db, "system", "retention.purge", "", "", {"dns": n_dns, "web": n_web, "days": retention_days})
    return {"dns": n_dns, "web": n_web, "refresh_tokens": n_rt}


def bootstrap_admin() -> None:
    s = get_settings()
    if not s.admin_email or not s.admin_password:
        return
    with session() as db:
        if db.execute(select(User).where(User.email == s.admin_email.lower())).scalar_one_or_none():
            return
        if not password_ok(s.admin_password):
            log.error("BEYOND_ADMIN_PASSWORD too weak; admin not created")
            return
        db.add(User(email=s.admin_email.lower(), password_hash=hash_password(s.admin_password), role="admin", full_name="Administrator", logging_consent_at=utcnow()))
        db.commit()
        audit.record(db, "system", "admin.bootstrap", s.admin_email.lower())
        log.warning("bootstrap admin %s created; rotate the password and unset BEYOND_ADMIN_PASSWORD", s.admin_email)


def _retention_loop(stop: threading.Event) -> None:
    while not stop.wait(6 * 3600):
        try:
            purge_expired(get_settings().log_retention_days)
        except Exception:  # pragma: no cover
            log.exception("retention purge failed")


def create_app() -> FastAPI:
    s = get_settings()
    init_engine(s.database_url)
    Base.metadata.create_all(engine())
    keys()  # create signing/data keys eagerly
    bootstrap_admin()
    stop = threading.Event()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        purge_expired(s.log_retention_days)
        t = threading.Thread(target=_retention_loop, args=(stop,), daemon=True)
        t.start()
        yield
        stop.set()

    app = FastAPI(title="Beyond VPN Control Plane", version=__version__, lifespan=lifespan, docs_url="/docs", redoc_url=None)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=s.cors_origins,
        allow_credentials=False,  # bearer tokens, no cookies => no CSRF surface
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.middleware("http")
    async def hardening(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > MAX_BODY:
            return JSONResponse({"detail": "request too large"}, status_code=413)
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        resp.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'" if not request.url.path.startswith("/docs") else "frame-ancestors 'none'")
        return resp

    @app.get("/healthz", tags=["ops"])
    def healthz():
        return {"ok": True, "version": __version__}

    @app.get("/api/v1/keys/signing", tags=["ops"])
    def signing_key():
        return {"alg": "EdDSA", "public_key": keys().public_b64}

    for r in (auth.router, vpn.router, me.router, gateway.router, admin.router):
        app.include_router(r)
    return app
