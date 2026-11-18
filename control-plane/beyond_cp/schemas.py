from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

WG_KEY = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")
HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)*[a-zA-Z0-9-]{1,63}$")
DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z0-9-]{2,63}$")

Platform = Literal["windows", "macos", "linux", "android", "ios", "browser", "other"]


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=256)
    full_name: str = Field(default="", max_length=120)
    accept_logging_policy: bool = False


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=256)
    totp_code: str | None = Field(default=None, max_length=10)


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshIn(BaseModel):
    refresh_token: str = Field(max_length=200)


class MfaCodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    mfa_enabled: bool
    data_cap_bytes: int | None
    created_at: datetime
    last_login_at: datetime | None
    logging_consent_at: datetime | None


class DeviceIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    platform: Platform
    public_key: str
    posture: dict[str, Any] = Field(default_factory=dict)

    @field_validator("public_key")
    @classmethod
    def _key(cls, v: str) -> str:
        if not WG_KEY.match(v):
            raise ValueError("not a WireGuard public key")
        return v

    @field_validator("posture")
    @classmethod
    def _posture(cls, v: dict) -> dict:
        if len(str(v)) > 2000:
            raise ValueError("posture too large")
        return v


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    platform: str
    public_key: str
    posture: dict
    revoked: bool
    created_at: datetime
    last_seen_at: datetime | None


class ServerOut(BaseModel):
    id: str
    name: str
    country: str
    city: str
    hostname: str
    endpoint: str
    proxy_port: int
    load: float
    features: list[str]
    tier: str
    status: str


class ServerCreate(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9-]{2,40}$")
    name: str = Field(min_length=1, max_length=80)
    country: str = Field(pattern=r"^[A-Z]{2}$")
    city: str = Field(default="", max_length=80)
    hostname: str
    wg_port: int = Field(default=51820, ge=1, le=65535)
    proxy_port: int = Field(default=8443, ge=1, le=65535)
    tunnel_cidr: str = Field(default="10.8.0.0/22")
    features: list[str] = Field(default_factory=list)
    tier: Literal["free", "plus", "enterprise"] = "free"

    @field_validator("hostname")
    @classmethod
    def _host(cls, v: str) -> str:
        if not HOSTNAME.match(v):
            raise ValueError("invalid hostname")
        return v.lower()

    @field_validator("tunnel_cidr")
    @classmethod
    def _cidr(cls, v: str) -> str:
        import ipaddress

        net = ipaddress.ip_network(v, strict=True)
        if net.version != 4 or not net.is_private or net.prefixlen > 29:
            raise ValueError("tunnel_cidr must be a private IPv4 network /29 or larger")
        return str(net)


class ServerPatch(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    features: list[str] | None = None
    tier: Literal["free", "plus", "enterprise"] | None = None


class ConnectIn(BaseModel):
    device_id: str = Field(max_length=32)
    server_id: str = Field(max_length=40)


class ConnectOut(BaseModel):
    session_id: str
    address: str
    dns: list[str]
    mtu: int
    peer_public_key: str
    preshared_key: str
    endpoint: str
    allowed_ips: list[str]
    persistent_keepalive: int
    policy: dict[str, Any]


class ProxyTokenIn(BaseModel):
    server_id: str = Field(max_length=40)
    device_id: str | None = Field(default=None, max_length=32)


class ProxyTokenOut(BaseModel):
    token: str
    host: str
    port: int
    scheme: str = "https"
    expires_at: int
    session_id: str


# ---- gateway telemetry (mirror of core/crates/beyond-common/src/telemetry.rs)
class Heartbeat(BaseModel):
    public_key: str
    listen_port: int
    active_peers: int = Field(ge=0)
    load: float = Field(ge=0, le=1)
    version: str = Field(max_length=32)

    @field_validator("public_key")
    @classmethod
    def _key(cls, v: str) -> str:
        if not WG_KEY.match(v):
            raise ValueError("not a WireGuard public key")
        return v


class UsageSample(BaseModel):
    public_key: str
    rx_bytes: int = Field(ge=0)
    tx_bytes: int = Field(ge=0)
    last_handshake: int = 0
    endpoint: str | None = None


class UsageReport(BaseModel):
    samples: list[UsageSample] = Field(max_length=10000)


class DnsLogEntry(BaseModel):
    client_ip: str = Field(max_length=45)
    user_id: str | None = None
    device_id: str | None = None
    domain: str = Field(max_length=253)
    qtype: str = Field(max_length=8)
    blocked: bool
    ts: int


class DnsLogBatch(BaseModel):
    entries: list[DnsLogEntry] = Field(max_length=50000)


class ProxyLogEntry(BaseModel):
    user_id: str
    device_id: str | None = None
    host: str = Field(max_length=253)
    port: int
    bytes_up: int = Field(ge=0)
    bytes_down: int = Field(ge=0)
    ts: int
    duration_ms: int = Field(ge=0)
    blocked: bool


class ProxyLogBatch(BaseModel):
    entries: list[ProxyLogEntry] = Field(max_length=50000)


class UserPatch(BaseModel):
    is_active: bool | None = None
    role: Literal["user", "admin", "auditor"] | None = None
    data_cap_bytes: int | None = Field(default=None, ge=0)
    clear_data_cap: bool = False


class PolicyPatch(BaseModel):
    logging_mode: Literal["off", "metadata", "full"] | None = None
    blocked_domains: list[str] | None = Field(default=None, max_length=100000)
    kill_switch_required: bool | None = None
    split_tunnel_allowed: bool | None = None
    require_device_posture: bool | None = None
    allowed_platforms: list[Platform] | None = None
    max_devices_per_user: int | None = Field(default=None, ge=1, le=1000)

    @field_validator("blocked_domains")
    @classmethod
    def _domains(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        out = []
        for d in v:
            d = d.strip().lower().rstrip(".")
            if not DOMAIN.match(d):
                raise ValueError(f"invalid domain: {d}")
            out.append(d)
        return sorted(set(out))
