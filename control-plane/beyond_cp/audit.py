"""Tamper-evident audit log: each event stores sha256(prev_hash || canonical_event)."""
from __future__ import annotations

import hashlib
import json
import threading

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditEvent, utcnow

GENESIS = "0" * 64
_lock = threading.Lock()


def _digest(prev: str, ts: str, actor: str, action: str, target: str, ip: str, detail: dict) -> str:
    body = json.dumps({"ts": ts, "actor": actor, "action": action, "target": target, "ip": ip, "detail": detail}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + body).encode()).hexdigest()


def record(db: Session, actor: str, action: str, target: str = "", ip: str = "", detail: dict | None = None, commit: bool = True) -> AuditEvent:
    detail = detail or {}
    with _lock:
        last = db.execute(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)).scalar_one_or_none()
        prev = last.hash if last else GENESIS
        ts = utcnow().replace(microsecond=0)
        h = _digest(prev, ts.isoformat(), actor, action, target, ip, detail)
        ev = AuditEvent(ts=ts, actor=actor, action=action, target=target, ip=ip, detail=detail, prev_hash=prev, hash=h)
        db.add(ev)
        if commit:
            db.commit()
        else:
            db.flush()
    return ev


def verify_chain(db: Session) -> tuple[bool, int | None]:
    """Returns (ok, first_bad_event_id)."""
    prev = GENESIS
    for ev in db.execute(select(AuditEvent).order_by(AuditEvent.id)).scalars():
        expected = _digest(prev, ev.ts.replace(microsecond=0).isoformat(), ev.actor, ev.action, ev.target, ev.ip, ev.detail or {})
        if ev.prev_hash != prev or ev.hash != expected:
            return False, ev.id
        prev = ev.hash
    return True, None
