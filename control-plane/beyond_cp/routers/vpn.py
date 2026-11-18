"""User-facing VPN endpoints: devices, servers, WireGuard sessions, browser proxy tokens."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from .. import audit, ipam, policy
from ..config import get_settings
from ..db import get_db
from ..deps import client_ip, current_user
from ..models import Device, Peer, Server, UsageDaily, User, VpnSession, utcnow
from ..schemas import ConnectIn, ConnectOut, DeviceIn, DeviceOut, ProxyTokenIn, ProxyTokenOut, ServerOut
from ..security import decrypt, encrypt, issue_token
from ..wgkeys import generate_psk

router = APIRouter(prefix="/api/v1", tags=["vpn"])

HEARTBEAT_STALE = timedelta(minutes=2)


def server_status(s: Server) -> str:
    if not s.enabled:
        return "maintenance"
    if s.public_key is None or s.last_heartbeat_at is None or utcnow() - s.last_heartbeat_at > HEARTBEAT_STALE:
        return "offline"
    return "online"


def server_out(s: Server) -> ServerOut:
    return ServerOut(
        id=s.id,
        name=s.name,
        country=s.country,
        city=s.city,
        hostname=s.hostname,
        endpoint=f"{s.hostname}:{s.wg_port}",
        proxy_port=s.proxy_port,
        load=round(s.load, 3),
        features=s.features or [],
        tier=s.tier,
        status=server_status(s),
    )


def month_usage(db: Session, user_id: str) -> int:
    prefix = utcnow().strftime("%Y-%m")
    total = db.execute(
        select(func.coalesce(func.sum(UsageDaily.rx_bytes + UsageDaily.tx_bytes), 0)).where(UsageDaily.user_id == user_id, UsageDaily.day.like(f"{prefix}-%"))
    ).scalar_one()
    return int(total)


# ------------------------------------------------------------------ devices
@router.get("/devices", response_model=list[DeviceOut])
def list_devices(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return db.execute(select(Device).where(Device.user_id == user.id).order_by(Device.created_at)).scalars().all()


@router.post("/devices", response_model=DeviceOut)
def register_device(body: DeviceIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    pol = policy.get_all(db)
    if body.platform not in pol["allowed_platforms"]:
        raise HTTPException(403, f"platform {body.platform} not allowed by policy")
    existing = db.execute(select(Device).where(Device.public_key == body.public_key)).scalar_one_or_none()
    if existing is not None:
        if existing.user_id != user.id:
            raise HTTPException(409, "public key already registered")
        if existing.revoked:
            raise HTTPException(403, "device revoked; generate a new key")
        existing.name, existing.platform, existing.posture = body.name, body.platform, body.posture
        existing.last_seen_at = utcnow()
        db.commit()
        return existing
    count = db.execute(select(func.count()).select_from(Device).where(Device.user_id == user.id, Device.revoked.is_(False))).scalar_one()
    if count >= pol["max_devices_per_user"]:
        raise HTTPException(403, "device limit reached; remove a device first")
    dev = Device(user_id=user.id, name=body.name, platform=body.platform, public_key=body.public_key, posture=body.posture, last_seen_at=utcnow())
    db.add(dev)
    db.commit()
    audit.record(db, user.id, "device.register", dev.id, client_ip(request), {"platform": dev.platform, "name": dev.name})
    return dev


@router.delete("/devices/{device_id}")
def revoke_device(device_id: str, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    dev = db.get(Device, device_id)
    if dev is None or dev.user_id != user.id:
        raise HTTPException(404, "device not found")
    dev.revoked = True
    db.execute(update(Peer).where(Peer.device_id == dev.id).values(active=False))
    db.execute(update(VpnSession).where(VpnSession.device_id == dev.id, VpnSession.ended_at.is_(None)).values(ended_at=utcnow()))
    db.commit()
    audit.record(db, user.id, "device.revoke", dev.id, client_ip(request))
    return {"ok": True}


# ------------------------------------------------------------------ servers
@router.get("/servers", response_model=list[ServerOut])
def list_servers(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.execute(select(Server).order_by(Server.country, Server.name)).scalars().all()
    return [server_out(s) for s in rows]


# ------------------------------------------------------------------ sessions
def _check_access(db: Session, user: User, dev: Device | None) -> dict:
    pol = policy.get_all(db)
    if dev is not None and pol["require_device_posture"]:
        posture = dev.posture or {}
        if not posture.get("os") or posture.get("firewall_enabled") is False or posture.get("rooted") is True:
            raise HTTPException(403, "device does not meet security posture requirements")
    if user.data_cap_bytes is not None and month_usage(db, user.id) >= user.data_cap_bytes:
        raise HTTPException(403, "monthly data cap reached")
    return pol


@router.post("/sessions/connect", response_model=ConnectOut)
def connect(body: ConnectIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    dev = db.get(Device, body.device_id)
    if dev is None or dev.user_id != user.id:
        raise HTTPException(404, "device not found")
    if dev.revoked:
        raise HTTPException(403, "device revoked")
    srv = db.get(Server, body.server_id)
    if srv is None:
        raise HTTPException(404, "server not found")
    if server_status(srv) != "online":
        raise HTTPException(503, "server not available")
    pol = _check_access(db, user, dev)

    peer = db.execute(select(Peer).where(Peer.device_id == dev.id, Peer.server_id == srv.id)).scalar_one_or_none()
    if peer is None:
        try:
            ip = ipam.allocate(db, srv)
        except ipam.PoolExhausted:
            raise HTTPException(503, "server full, pick another location")
        peer = Peer(device_id=dev.id, server_id=srv.id, tunnel_ip=ip, preshared_key_enc=encrypt(generate_psk()))
        db.add(peer)
    peer.active = True
    # One active WireGuard session per device.
    db.execute(
        update(VpnSession).where(VpnSession.device_id == dev.id, VpnSession.kind == "wireguard", VpnSession.ended_at.is_(None)).values(ended_at=utcnow())
    )
    db.execute(update(Peer).where(Peer.device_id == dev.id, Peer.server_id != srv.id).values(active=False))
    sess = VpnSession(user_id=user.id, device_id=dev.id, server_id=srv.id, kind="wireguard", client_ip=client_ip(request))
    db.add(sess)
    dev.last_seen_at = utcnow()
    db.commit()
    audit.record(db, user.id, "vpn.connect", srv.id, client_ip(request), {"device": dev.id, "tunnel_ip": peer.tunnel_ip})
    return ConnectOut(
        session_id=sess.id,
        address=f"{peer.tunnel_ip}/32",
        dns=[ipam.gateway_ip(srv)],
        mtu=1420,
        peer_public_key=srv.public_key or "",
        preshared_key=decrypt(peer.preshared_key_enc),
        endpoint=f"{srv.hostname}:{srv.wg_port}",
        allowed_ips=["0.0.0.0/0", "::/0"],
        persistent_keepalive=25,
        policy={"kill_switch_required": pol["kill_switch_required"], "split_tunnel_allowed": pol["split_tunnel_allowed"]},
    )


@router.post("/sessions/{session_id}/disconnect")
def disconnect(session_id: str, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    sess = db.get(VpnSession, session_id)
    if sess is None or sess.user_id != user.id:
        raise HTTPException(404, "session not found")
    if sess.ended_at is None:
        sess.ended_at = utcnow()
        if sess.device_id:
            db.execute(update(Peer).where(Peer.device_id == sess.device_id, Peer.server_id == sess.server_id).values(active=False))
        db.commit()
        audit.record(db, user.id, "vpn.disconnect", sess.server_id, client_ip(request), {"session": sess.id})
    return {"ok": True}


# ------------------------------------------------------------------ browser extension
@router.post("/proxy/token", response_model=ProxyTokenOut)
def proxy_token(body: ProxyTokenIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    srv = db.get(Server, body.server_id)
    if srv is None:
        raise HTTPException(404, "server not found")
    if server_status(srv) != "online":
        raise HTTPException(503, "server not available")
    dev = None
    if body.device_id:
        dev = db.get(Device, body.device_id)
        if dev is None or dev.user_id != user.id or dev.revoked:
            raise HTTPException(404, "device not found")
    pol = policy.get_all(db)
    if "browser" not in pol["allowed_platforms"]:
        raise HTTPException(403, "browser extension not allowed by policy")
    _check_access(db, user, dev)
    s = get_settings()
    # Re-use the open proxy session for this user/server instead of creating one per token refresh.
    sess = db.execute(
        select(VpnSession).where(VpnSession.user_id == user.id, VpnSession.server_id == srv.id, VpnSession.kind == "proxy", VpnSession.ended_at.is_(None))
    ).scalar_one_or_none()
    if sess is None:
        sess = VpnSession(user_id=user.id, device_id=dev.id if dev else None, server_id=srv.id, kind="proxy", client_ip=client_ip(request))
        db.add(sess)
        db.commit()
        audit.record(db, user.id, "proxy.connect", srv.id, client_ip(request))
    token, exp = issue_token(user.id, "proxy", s.proxy_ttl, aud=srv.id, sid=dev.id if dev else sess.id)
    return ProxyTokenOut(token=token, host=srv.hostname, port=srv.proxy_port, expires_at=exp, session_id=sess.id)


@router.post("/proxy/disconnect")
def proxy_disconnect(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    db.execute(update(VpnSession).where(VpnSession.user_id == user.id, VpnSession.kind == "proxy", VpnSession.ended_at.is_(None)).values(ended_at=utcnow()))
    db.commit()
    audit.record(db, user.id, "proxy.disconnect", "", client_ip(request))
    return {"ok": True}
