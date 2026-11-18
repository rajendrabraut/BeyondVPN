"""Self-service endpoints: profile, usage, own activity (transparency), GDPR export/erase."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import client_ip, current_user
from ..models import Device, DnsLog, ProxyLog, UsageDaily, User, VpnSession, utcnow
from ..schemas import UserOut
from ..security import verify_password
from .vpn import month_usage

router = APIRouter(prefix="/api/v1/me", tags=["me"])


@router.get("", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@router.post("/consent")
def consent(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    user.logging_consent_at = utcnow()
    db.commit()
    audit.record(db, user.id, "user.logging_consent", user.email, client_ip(request))
    return {"ok": True}


@router.get("/usage")
def usage(days: int = Query(30, ge=1, le=366), user: User = Depends(current_user), db: Session = Depends(get_db)):
    since = (utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = db.execute(select(UsageDaily).where(UsageDaily.user_id == user.id, UsageDaily.day >= since).order_by(UsageDaily.day)).scalars().all()
    return {
        "days": [{"day": r.day, "rx_bytes": r.rx_bytes, "tx_bytes": r.tx_bytes} for r in rows],
        "month_total_bytes": month_usage(db, user.id),
        "data_cap_bytes": user.data_cap_bytes,
    }


@router.get("/sessions")
def sessions(limit: int = Query(50, ge=1, le=500), user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.execute(select(VpnSession).where(VpnSession.user_id == user.id).order_by(VpnSession.started_at.desc()).limit(limit)).scalars().all()
    return [
        {"id": s.id, "server_id": s.server_id, "kind": s.kind, "started_at": s.started_at, "ended_at": s.ended_at, "rx_bytes": s.rx_bytes, "tx_bytes": s.tx_bytes, "device_id": s.device_id}
        for s in rows
    ]


@router.get("/activity")
def activity(limit: int = Query(200, ge=1, le=2000), user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Users can always see exactly what was logged about them."""
    dns = db.execute(select(DnsLog).where(DnsLog.user_id == user.id).order_by(DnsLog.ts.desc()).limit(limit)).scalars().all()
    web = db.execute(select(ProxyLog).where(ProxyLog.user_id == user.id).order_by(ProxyLog.ts.desc()).limit(limit)).scalars().all()
    return {
        "dns": [{"ts": d.ts, "domain": d.domain, "qtype": d.qtype, "blocked": d.blocked, "server_id": d.server_id} for d in dns],
        "web": [{"ts": p.ts, "host": p.host, "port": p.port, "bytes_up": p.bytes_up, "bytes_down": p.bytes_down, "blocked": p.blocked, "server_id": p.server_id} for p in web],
    }


class EraseIn(BaseModel):
    password: str


@router.post("/erase")
def erase(body: EraseIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Right to erasure (GDPR art. 17 / DPDP Act s.12). Audit trail keeps only the pseudonymous id."""
    if not verify_password(user.password_hash, body.password):
        raise HTTPException(403, "password required to delete the account")
    uid = user.id
    for model in (DnsLog, ProxyLog):
        db.execute(delete(model).where(model.user_id == uid))
    db.execute(delete(UsageDaily).where(UsageDaily.user_id == uid))
    db.execute(delete(VpnSession).where(VpnSession.user_id == uid))
    db.execute(delete(Device).where(Device.user_id == uid))
    db.delete(user)
    db.commit()
    audit.record(db, uid, "user.erase", "", client_ip(request))
    return {"ok": True}
