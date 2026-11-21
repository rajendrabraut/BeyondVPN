"""Relational model. Works on SQLite (dev/single node) and PostgreSQL (prod)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_id() -> str:
    return uuid.uuid4().hex


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str] = mapped_column(String(120), default="")
    role: Mapped[str] = mapped_column(String(16), default="user")  # user | admin | auditor
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    logging_consent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    data_cap_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    platform: Mapped[str] = mapped_column(String(16))  # windows|macos|linux|android|ios|browser|other
    public_key: Mapped[str] = mapped_column(String(64), unique=True)
    posture: Mapped[dict] = mapped_column(JSON, default=dict)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Server(Base):
    __tablename__ = "servers"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    country: Mapped[str] = mapped_column(String(2))
    city: Mapped[str] = mapped_column(String(80), default="")
    hostname: Mapped[str] = mapped_column(String(253))
    wg_port: Mapped[int] = mapped_column(Integer, default=51820)
    proxy_port: Mapped[int] = mapped_column(Integer, default=8443)
    tunnel_cidr: Mapped[str] = mapped_column(String(18), default="10.8.0.0/22")
    public_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    gateway_key_hash: Mapped[str] = mapped_column(String(128))
    features: Mapped[list] = mapped_column(JSON, default=list)  # p2p, streaming, secure-core, tor
    tier: Mapped[str] = mapped_column(String(16), default="free")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    load: Mapped[float] = mapped_column(default=0.0)
    active_peers: Mapped[int] = mapped_column(Integer, default=0)
    version: Mapped[str] = mapped_column(String(32), default="")
    stealth_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    hop_public_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Peer(Base):
    """A device's WireGuard identity on one gateway (stable tunnel IP)."""

    __tablename__ = "peers"
    __table_args__ = (
        UniqueConstraint("device_id", "server_id"),
        UniqueConstraint("server_id", "tunnel_ip"),
    )
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"), index=True)
    tunnel_ip: Mapped[str] = mapped_column(String(15))
    preshared_key_enc: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    last_handshake: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # Multi-hop: route this peer's traffic out through another gateway.
    exit_server_id: Mapped[str | None] = mapped_column(ForeignKey("servers.id", ondelete="SET NULL"), nullable=True)


class HopLink(Base):
    """Entry gateway -> exit gateway WireGuard uplink. The entry is a peer on the exit's wg0."""

    __tablename__ = "hop_links"
    __table_args__ = (UniqueConstraint("entry_server_id", "slot"), UniqueConstraint("exit_server_id", "tunnel_ip"))
    entry_server_id: Mapped[str] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True)
    exit_server_id: Mapped[str] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True)
    # Small per-entry number: interface bhop<slot>, routing table 51000+slot on the entry gateway.
    slot: Mapped[int] = mapped_column(Integer)
    tunnel_ip: Mapped[str] = mapped_column(String(15))
    preshared_key_enc: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class VpnSession(Base):
    __tablename__ = "vpn_sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(12), default="wireguard")  # wireguard | proxy
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    tx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class UsageDaily(Base):
    __tablename__ = "usage_daily"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    day: Mapped[str] = mapped_column(String(10), primary_key=True)  # YYYY-MM-DD (UTC)
    rx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    tx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)


class DnsLog(Base):
    __tablename__ = "dns_logs"
    __table_args__ = (Index("ix_dns_user_ts", "user_id", "ts"), Index("ix_dns_domain", "domain"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    server_id: Mapped[str] = mapped_column(String(40))
    client_ip: Mapped[str] = mapped_column(String(45))
    domain: Mapped[str] = mapped_column(String(253))
    qtype: Mapped[str] = mapped_column(String(8))
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)


class ProxyLog(Base):
    __tablename__ = "proxy_logs"
    __table_args__ = (Index("ix_proxy_user_ts", "user_id", "ts"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    server_id: Mapped[str] = mapped_column(String(40))
    host: Mapped[str] = mapped_column(String(253))
    port: Mapped[int] = mapped_column(Integer)
    bytes_up: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_down: Mapped[int] = mapped_column(BigInteger, default=0)
    duration_ms: Mapped[int] = mapped_column(BigInteger, default=0)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditEvent(Base):
    """Append-only, hash-chained audit trail (tamper evident)."""

    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(128), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    family: Mapped[str] = mapped_column(String(32), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class UserIdentity(Base):
    """Link between a local user and an external SSO identity (OIDC issuer + subject)."""

    __tablename__ = "user_identities"
    __table_args__ = (UniqueConstraint("provider", "subject"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(40))
    subject: Mapped[str] = mapped_column(String(255))
    email: Mapped[str] = mapped_column(String(254), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class SsoLogin(Base):
    """One SSO attempt: state/nonce/PKCE while at the IdP, then a one-time login code."""

    __tablename__ = "sso_logins"
    state: Mapped[str] = mapped_column(String(64), primary_key=True)
    provider: Mapped[str] = mapped_column(String(40))
    nonce: Mapped[str] = mapped_column(String(64))
    code_verifier: Mapped[str] = mapped_column(String(128))
    return_to: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    code_hash: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)


class Setting(Base):
    """Global policy key/value store (logging mode, blocklists, ...)."""

    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict | list | str | int | bool | None] = mapped_column(JSON)
