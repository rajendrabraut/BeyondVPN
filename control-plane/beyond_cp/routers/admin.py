"""Administration & reporting (Forti EMS-style console backend)."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from .. import audit, policy
from ..db import get_db
from ..deps import client_ip, require_admin, require_auditor
from ..models import AuditEvent, Device, DnsLog, Peer, ProxyLog, RefreshToken, Server, UsageDaily, User, VpnSession, utcnow
from ..schemas import PolicyPatch, ServerCreate, ServerPatch, UserOut, UserPatch
from ..security import new_opaque_token, sha256_hex
from .vpn import server_out, server_status

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


def _since(hours: int) -> datetime:
    return utcnow() - timedelta(hours=hours)


# ------------------------------------------------------------------ users
@router.get("/users", response_model=list[UserOut])
def users(q: str | None = None, _: User = Depends(require_auditor), db: Session = Depends(get_db)):
    stmt = select(User).order_by(User.created_at)
    if q:
        stmt = stmt.where(User.email.contains(q.lower()))
    return db.execute(stmt.limit(1000)).scalars().all()


@router.patch("/users/{user_id}", response_model=UserOut)
def patch_user(user_id: str, body: UserPatch, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "user not found")
    if u.id == admin.id and (body.is_active is False or (body.role and body.role != "admin")):
        raise HTTPException(400, "you cannot disable or demote yourself")
    changes = body.model_dump(exclude_none=True, exclude={"clear_data_cap"})
    for k, v in changes.items():
        setattr(u, k, v)
    if body.clear_data_cap:
        u.data_cap_bytes = None
        changes["data_cap_bytes"] = None
    if body.is_active is False:
        # Immediate cut-off: revoke refresh tokens, deactivate peers, close sessions.
        db.execute(update(RefreshToken).where(RefreshToken.user_id == u.id).values(revoked=True))
        dev_ids = select(Device.id).where(Device.user_id == u.id)
        db.execute(update(Peer).where(Peer.device_id.in_(dev_ids)).values(active=False))
        db.execute(update(VpnSession).where(VpnSession.user_id == u.id, VpnSession.ended_at.is_(None)).values(ended_at=utcnow()))
    db.commit()
    audit.record(db, admin.id, "admin.user_update", u.id, client_ip(request), changes)
    return u


@router.get("/users/{user_id}/devices")
def user_devices(user_id: str, _: User = Depends(require_auditor), db: Session = Depends(get_db)):
    rows = db.execute(select(Device).where(Device.user_id == user_id)).scalars().all()
    return [{"id": d.id, "name": d.name, "platform": d.platform, "posture": d.posture, "revoked": d.revoked, "last_seen_at": d.last_seen_at} for d in rows]


# ------------------------------------------------------------------ servers
@router.get("/servers")
def servers(_: User = Depends(require_auditor), db: Session = Depends(get_db)):
    out = []
    for s in db.execute(select(Server)).scalars():
        d = server_out(s).model_dump()
        d.update(enabled=s.enabled, active_peers=s.active_peers, version=s.version, last_heartbeat_at=s.last_heartbeat_at, tunnel_cidr=s.tunnel_cidr, public_key=s.public_key)
        out.append(d)
    return out


@router.post("/servers", status_code=201)
def create_server(body: ServerCreate, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.get(Server, body.id):
        raise HTTPException(409, "server id exists")
    key = new_opaque_token()
    s = Server(**body.model_dump(), gateway_key_hash=sha256_hex(key))
    db.add(s)
    db.commit()
    audit.record(db, admin.id, "admin.server_create", s.id, client_ip(request), {"hostname": s.hostname})
    # The gateway key is shown exactly once.
    return {"id": s.id, "gateway_key": key, "status": server_status(s)}


@router.post("/servers/{server_id}/rotate-key")
def rotate_key(server_id: str, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(404, "server not found")
    key = new_opaque_token()
    s.gateway_key_hash = sha256_hex(key)
    db.commit()
    audit.record(db, admin.id, "admin.server_rotate_key", s.id, client_ip(request))
    return {"id": s.id, "gateway_key": key}


@router.patch("/servers/{server_id}")
def patch_server(server_id: str, body: ServerPatch, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(404, "server not found")
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(s, k, v)
    db.commit()
    audit.record(db, admin.id, "admin.server_update", s.id, client_ip(request), changes)
    return server_out(s)


# ------------------------------------------------------------------ policy
@router.get("/policy")
def get_policy(_: User = Depends(require_auditor), db: Session = Depends(get_db)):
    return policy.get_all(db)


@router.put("/policy")
def put_policy(body: PolicyPatch, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    changes = body.model_dump(exclude_none=True)
    result = policy.set_many(db, changes)
    audit.record(db, admin.id, "admin.policy_update", "", client_ip(request), {k: (v if k != "blocked_domains" else f"{len(v)} domains") for k, v in changes.items()})
    return result


# ------------------------------------------------------------------ sessions & logs
@router.get("/sessions")
def sessions(active: bool = False, limit: int = Query(200, le=2000), _: User = Depends(require_auditor), db: Session = Depends(get_db)):
    stmt = select(VpnSession, User.email).join(User, User.id == VpnSession.user_id).order_by(VpnSession.started_at.desc()).limit(limit)
    if active:
        stmt = stmt.where(VpnSession.ended_at.is_(None))
    return [
        {"id": s.id, "email": e, "user_id": s.user_id, "server_id": s.server_id, "kind": s.kind, "device_id": s.device_id, "client_ip": s.client_ip, "started_at": s.started_at, "ended_at": s.ended_at, "rx_bytes": s.rx_bytes, "tx_bytes": s.tx_bytes}
        for s, e in db.execute(stmt).all()
    ]


def _dns_query(user_id: str | None, domain: str | None, blocked: bool | None, hours: int):
    stmt = select(DnsLog, User.email).outerjoin(User, User.id == DnsLog.user_id).where(DnsLog.ts >= _since(hours)).order_by(DnsLog.ts.desc())
    if user_id:
        stmt = stmt.where(DnsLog.user_id == user_id)
    if domain:
        stmt = stmt.where(DnsLog.domain.contains(domain.lower()))
    if blocked is not None:
        stmt = stmt.where(DnsLog.blocked.is_(blocked))
    return stmt


def _proxy_query(user_id: str | None, host: str | None, hours: int):
    stmt = select(ProxyLog, User.email).outerjoin(User, User.id == ProxyLog.user_id).where(ProxyLog.ts >= _since(hours)).order_by(ProxyLog.ts.desc())
    if user_id:
        stmt = stmt.where(ProxyLog.user_id == user_id)
    if host:
        stmt = stmt.where(ProxyLog.host.contains(host.lower()))
    return stmt


def _dns_row(d: DnsLog, email: str | None) -> dict:
    return {"ts": d.ts, "email": email, "user_id": d.user_id, "device_id": d.device_id, "server_id": d.server_id, "client_ip": d.client_ip, "domain": d.domain, "qtype": d.qtype, "blocked": d.blocked}


def _proxy_row(p: ProxyLog, email: str | None) -> dict:
    return {"ts": p.ts, "email": email, "user_id": p.user_id, "device_id": p.device_id, "server_id": p.server_id, "host": p.host, "port": p.port, "bytes_up": p.bytes_up, "bytes_down": p.bytes_down, "duration_ms": p.duration_ms, "blocked": p.blocked}


@router.get("/logs/dns")
def dns_logs(
    request: Request,
    user_id: str | None = None,
    domain: str | None = None,
    blocked: bool | None = None,
    hours: int = Query(24, ge=1, le=24 * 366),
    limit: int = Query(500, ge=1, le=5000),
    viewer: User = Depends(require_auditor),
    db: Session = Depends(get_db),
):
    # Reading someone's browsing history is itself an audited action.
    audit.record(db, viewer.id, "admin.view_dns_logs", user_id or "*", client_ip(request), {"domain": domain, "hours": hours})
    return [_dns_row(d, e) for d, e in db.execute(_dns_query(user_id, domain, blocked, hours).limit(limit)).all()]


@router.get("/logs/web")
def web_logs(
    request: Request,
    user_id: str | None = None,
    host: str | None = None,
    hours: int = Query(24, ge=1, le=24 * 366),
    limit: int = Query(500, ge=1, le=5000),
    viewer: User = Depends(require_auditor),
    db: Session = Depends(get_db),
):
    audit.record(db, viewer.id, "admin.view_web_logs", user_id or "*", client_ip(request), {"host": host, "hours": hours})
    return [_proxy_row(p, e) for p, e in db.execute(_proxy_query(user_id, host, hours).limit(limit)).all()]


def _csv_cell(v) -> str:
    s = "" if v is None else str(v)
    # CSV/formula injection guard for spreadsheet consumers.
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@router.get("/logs/export.csv")
def export_csv(
    request: Request,
    kind: str = Query("dns", pattern="^(dns|web)$"),
    user_id: str | None = None,
    hours: int = Query(24, ge=1, le=24 * 366),
    viewer: User = Depends(require_auditor),
    db: Session = Depends(get_db),
):
    audit.record(db, viewer.id, "admin.export_logs", user_id or "*", client_ip(request), {"kind": kind, "hours": hours})
    if kind == "dns":
        rows = [_dns_row(d, e) for d, e in db.execute(_dns_query(user_id, None, None, hours).limit(200000)).all()]
    else:
        rows = [_proxy_row(p, e) for p, e in db.execute(_proxy_query(user_id, None, hours).limit(200000)).all()]
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow({k: _csv_cell(v) for k, v in r.items()})
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="beyond-{kind}-logs.csv"'})


# ------------------------------------------------------------------ reports
@router.get("/reports/summary")
def summary(_: User = Depends(require_auditor), db: Session = Depends(get_db)):
    today = utcnow().strftime("%Y-%m-%d")
    month = utcnow().strftime("%Y-%m")
    return {
        "users": db.execute(select(func.count()).select_from(User)).scalar_one(),
        "active_users": db.execute(select(func.count()).select_from(User).where(User.is_active.is_(True))).scalar_one(),
        "devices": db.execute(select(func.count()).select_from(Device).where(Device.revoked.is_(False))).scalar_one(),
        "active_sessions": db.execute(select(func.count()).select_from(VpnSession).where(VpnSession.ended_at.is_(None))).scalar_one(),
        "servers_online": sum(1 for s in db.execute(select(Server)).scalars() if server_status(s) == "online"),
        "bytes_today": int(db.execute(select(func.coalesce(func.sum(UsageDaily.rx_bytes + UsageDaily.tx_bytes), 0)).where(UsageDaily.day == today)).scalar_one()),
        "bytes_month": int(db.execute(select(func.coalesce(func.sum(UsageDaily.rx_bytes + UsageDaily.tx_bytes), 0)).where(UsageDaily.day.like(f"{month}-%"))).scalar_one()),
        "blocked_today": db.execute(select(func.count()).select_from(DnsLog).where(DnsLog.blocked.is_(True), DnsLog.ts >= _since(24))).scalar_one(),
    }


@router.get("/reports/top-domains")
def top_domains(hours: int = Query(24 * 7, ge=1, le=24 * 366), limit: int = Query(25, le=500), _: User = Depends(require_auditor), db: Session = Depends(get_db)):
    rows = db.execute(
        select(DnsLog.domain, func.count().label("n"), func.count(func.distinct(DnsLog.user_id)).label("users"))
        .where(DnsLog.ts >= _since(hours))
        .group_by(DnsLog.domain)
        .order_by(func.count().desc())
        .limit(limit)
    ).all()
    return [{"domain": d, "queries": n, "users": u} for d, n, u in rows]


@router.get("/reports/usage")
def usage_report(days: int = Query(30, ge=1, le=366), _: User = Depends(require_auditor), db: Session = Depends(get_db)):
    since = (utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = db.execute(
        select(User.email, func.sum(UsageDaily.rx_bytes), func.sum(UsageDaily.tx_bytes))
        .join(User, User.id == UsageDaily.user_id)
        .where(UsageDaily.day >= since)
        .group_by(User.email)
        .order_by(func.sum(UsageDaily.rx_bytes + UsageDaily.tx_bytes).desc())
    ).all()
    return [{"email": e, "rx_bytes": int(rx or 0), "tx_bytes": int(tx or 0)} for e, rx, tx in rows]


# ------------------------------------------------------------------ audit
@router.get("/audit")
def audit_log(limit: int = Query(200, le=5000), action: str | None = None, _: User = Depends(require_auditor), db: Session = Depends(get_db)):
    stmt = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    return [{"id": a.id, "ts": a.ts, "actor": a.actor, "action": a.action, "target": a.target, "ip": a.ip, "detail": a.detail, "hash": a.hash} for a in db.execute(stmt).scalars()]


@router.get("/audit/verify")
def audit_verify(_: User = Depends(require_auditor), db: Session = Depends(get_db)):
    ok, bad = audit.verify_chain(db)
    return {"ok": ok, "first_bad_id": bad}
