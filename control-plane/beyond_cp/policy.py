"""Organisation-wide policy stored in the `settings` table."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from .models import Setting

DEFAULTS: dict[str, Any] = {
    # off | metadata | full  — what gateways may record about browsing.
    "logging_mode": "full",
    # NetShield-style org blocklist (domains, suffix-matched by gateways).
    "blocked_domains": [],
    "kill_switch_required": False,
    "split_tunnel_allowed": True,
    # Forti-style posture gate: reject devices reporting firewall disabled.
    "require_device_posture": False,
    "allowed_platforms": ["windows", "macos", "linux", "android", "ios", "browser", "other"],
    "max_devices_per_user": 10,
}


def get(db: Session, key: str) -> Any:
    row = db.get(Setting, key)
    return row.value if row is not None else DEFAULTS[key]


def get_all(db: Session) -> dict[str, Any]:
    return {k: get(db, k) for k in DEFAULTS}


def set_many(db: Session, values: dict[str, Any]) -> dict[str, Any]:
    for k, v in values.items():
        if k not in DEFAULTS:
            raise KeyError(k)
        row = db.get(Setting, k)
        if row is None:
            db.add(Setting(key=k, value=v))
        else:
            row.value = v
    db.commit()
    return get_all(db)
