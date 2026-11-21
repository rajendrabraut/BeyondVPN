"""Endpoints called by gateway nodes (authenticated with per-gateway secret)."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import policy
from ..db import get_db
from ..deps import gateway
from ..models import Device, DnsLog, HopLink, Peer, ProxyLog, Server, UsageDaily, User, VpnSession, utcnow
from ..schemas import DnsLogBatch, Heartbeat, ProxyLogBatch, UsageReport
from ..security import decrypt, keys
from .vpn import month_usage

router = APIRouter(prefix="/api/v1/gateway", tags=["gateway"])


def _ts(epoch: int) -> datetime:
    now = utcnow()
    try:
        t = datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        return now
    # Never trust gateway clocks far into the future.
    return min(t, now)


def _add_usage(db: Session, user_id: str, rx: int, tx: int) -> None:
    day = utcnow().strftime("%Y-%m-%d")
    row = db.get(UsageDaily, (user_id, day))
    if row is None:
        db.add(UsageDaily(user_id=user_id, day=day, rx_bytes=rx, tx_bytes=tx))
        db.flush()
    else:
        row.rx_bytes += rx
        row.tx_bytes += tx


@router.get("/peers")
def peers(srv: Server = Depends(gateway), db: Session = Depends(get_db)):
    rows = db.execute(
        select(Peer, Device, User)
        .join(Device, Device.id == Peer.device_id)
        .join(User, User.id == Device.user_id)
        .where(Peer.server_id == srv.id, Peer.active.is_(True), Device.revoked.is_(False), User.is_active.is_(True))
    ).all()
    out = []
    over_cap: set[str] = set()
    for peer, dev, user in rows:
        if user.data_cap_bytes is not None and month_usage(db, user.id) >= user.data_cap_bytes:
            over_cap.add(user.id)
            continue
        out.append(
            {"public_key": dev.public_key, "preshared_key": decrypt(peer.preshared_key_enc), "tunnel_ip": peer.tunnel_ip, "user_id": user.id, "device_id": dev.id, "exit_server_id": peer.exit_server_id}
        )
    revoked = set(db.execute(select(User.id).where(User.is_active.is_(False))).scalars()) | over_cap
    pol = policy.get_all(db)

    # Multi-hop, this gateway as ENTRY: uplinks to exits that active peers use.
    wanted_exits = {p["exit_server_id"] for p in out if p["exit_server_id"]}
    hops = []
    for link, exit_ in db.execute(select(HopLink, Server).join(Server, Server.id == HopLink.exit_server_id).where(HopLink.entry_server_id == srv.id)).all():
        if link.exit_server_id in wanted_exits and exit_.public_key and exit_.enabled:
            hops.append(
                {"exit_server_id": exit_.id, "slot": link.slot, "endpoint": f"{exit_.hostname}:{exit_.wg_port}", "public_key": exit_.public_key, "preshared_key": decrypt(link.preshared_key_enc), "address": link.tunnel_ip}
            )
    routable = {h["exit_server_id"] for h in hops}
    for p in out:  # never route a peer into an uplink that is not configured
        if p["exit_server_id"] not in routable:
            p["exit_server_id"] = None
    # Multi-hop, this gateway as EXIT: entry gateways appear as ordinary peers on wg0.
    hop_peers = []
    for link, entry in db.execute(select(HopLink, Server).join(Server, Server.id == HopLink.entry_server_id).where(HopLink.exit_server_id == srv.id)).all():
        if entry.hop_public_key and entry.enabled:
            hop_peers.append({"public_key": entry.hop_public_key, "preshared_key": decrypt(link.preshared_key_enc), "tunnel_ip": link.tunnel_ip, "user_id": "", "device_id": f"hop:{entry.id}"})
    return {
        "hops": hops,
        "hop_peers": hop_peers,
        "peers": out,
        "signing_public_key": keys().public_b64,
        "blocked_domains": pol["blocked_domains"],
        "logging_mode": pol["logging_mode"],
        "revoked_subjects": sorted(revoked),
    }


@router.post("/heartbeat")
def heartbeat(body: Heartbeat, srv: Server = Depends(gateway), db: Session = Depends(get_db)):
    srv.public_key = body.public_key
    srv.wg_port = body.listen_port or srv.wg_port
    srv.active_peers = body.active_peers
    srv.load = body.load
    srv.version = body.version
    srv.hop_public_key = body.hop_public_key
    srv.stealth_port = body.stealth_port
    srv.last_heartbeat_at = utcnow()
    db.commit()
    return {"ok": True}


@router.post("/usage")
def usage(body: UsageReport, srv: Server = Depends(gateway), db: Session = Depends(get_db)):
    accepted = 0
    for s in body.samples:
        row = db.execute(
            select(Peer, Device).join(Device, Device.id == Peer.device_id).where(Device.public_key == s.public_key, Peer.server_id == srv.id)
        ).first()
        if row is None:
            continue
        peer, dev = row
        # Gateway rx = bytes the user uploaded; gateway tx = bytes the user downloaded.
        user_rx, user_tx = s.tx_bytes, s.rx_bytes
        _add_usage(db, dev.user_id, user_rx, user_tx)
        if s.last_handshake:
            peer.last_handshake = _ts(s.last_handshake)
        sess = db.execute(
            select(VpnSession)
            .where(VpnSession.device_id == dev.id, VpnSession.server_id == srv.id, VpnSession.kind == "wireguard")
            .order_by(VpnSession.started_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if sess is not None:
            sess.rx_bytes += user_rx
            sess.tx_bytes += user_tx
        accepted += 1
    db.commit()
    return {"accepted": accepted}


@router.post("/dns-logs")
def dns_logs(body: DnsLogBatch, srv: Server = Depends(gateway), db: Session = Depends(get_db)):
    if policy.get(db, "logging_mode") != "full":
        return {"accepted": 0}
    # Attribute by tunnel IP on *this* server; never trust a gateway-supplied user id blindly.
    by_ip = {
        p.tunnel_ip: (d.user_id, d.id)
        for p, d in db.execute(select(Peer, Device).join(Device, Device.id == Peer.device_id).where(Peer.server_id == srv.id)).all()
    }
    n = 0
    for e in body.entries:
        user_id, device_id = by_ip.get(e.client_ip, (None, None))
        db.add(
            DnsLog(ts=_ts(e.ts), user_id=user_id, device_id=device_id, server_id=srv.id, client_ip=e.client_ip, domain=e.domain.lower()[:253], qtype=e.qtype[:8], blocked=e.blocked)
        )
        n += 1
    db.commit()
    return {"accepted": n}


@router.post("/proxy-logs")
def proxy_logs(body: ProxyLogBatch, srv: Server = Depends(gateway), db: Session = Depends(get_db)):
    mode = policy.get(db, "logging_mode")
    known = set(db.execute(select(User.id).where(User.id.in_({e.user_id for e in body.entries}))).scalars())
    n = 0
    for e in body.entries:
        if e.user_id not in known:
            continue
        _add_usage(db, e.user_id, e.bytes_down, e.bytes_up)
        if mode == "off":
            continue
        db.add(
            ProxyLog(
                ts=_ts(e.ts),
                user_id=e.user_id,
                device_id=e.device_id,
                server_id=srv.id,
                host="-" if mode == "metadata" else e.host.lower()[:253],
                port=e.port,
                bytes_up=e.bytes_up,
                bytes_down=e.bytes_down,
                duration_ms=e.duration_ms,
                blocked=e.blocked,
            )
        )
        n += 1
    db.commit()
    return {"accepted": n}
