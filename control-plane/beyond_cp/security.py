"""Cryptographic helpers: password hashing, EdDSA tokens, field encryption, rate limiting."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .config import get_settings

_ph = PasswordHasher()  # argon2id, library defaults (64 MiB, t=3)
ISSUER = "beyond-vpn"
API_AUDIENCE = "beyond-api"


# ---------------------------------------------------------------- passwords
PASSWORD_RULE = "at least 10 characters including a letter and a digit"


def password_ok(pw: str) -> bool:
    return len(pw) >= 10 and re.search(r"[A-Za-z]", pw) is not None and re.search(r"\d", pw) is not None


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw_hash: str, pw: str) -> bool:
    try:
        return _ph.verify(pw_hash, pw)
    except (VerificationError, InvalidHashError):
        return False


# Constant-time dummy check to keep login timing uniform for unknown users.
_DUMMY_HASH = _ph.hash("dummy-password-0")


def burn_password_check(pw: str) -> None:
    verify_password(_DUMMY_HASH, pw)


# ---------------------------------------------------------------- key material
class Keys:
    def __init__(self, data_dir: Path):
        self.signing = self._load_signing(data_dir)
        self.fernet = Fernet(self._load_data_key(data_dir))
        raw_pub = self.signing.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_b64 = base64.b64encode(raw_pub).decode()

    @staticmethod
    def _write_secret(path: Path, data: bytes) -> None:
        path.write_bytes(data)
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover - windows
            pass

    def _load_signing(self, d: Path) -> Ed25519PrivateKey:
        env = os.getenv("BEYOND_SIGNING_KEY")
        if env:
            return Ed25519PrivateKey.from_private_bytes(base64.b64decode(env))
        p = d / "signing.key"
        if p.exists():
            return Ed25519PrivateKey.from_private_bytes(base64.b64decode(p.read_text().strip()))
        k = Ed25519PrivateKey.generate()
        raw = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        self._write_secret(p, base64.b64encode(raw))
        return k

    def _load_data_key(self, d: Path) -> bytes:
        env = os.getenv("BEYOND_DATA_KEY")
        if env:
            return env.encode()
        p = d / "data.key"
        if p.exists():
            return p.read_bytes().strip()
        k = Fernet.generate_key()
        self._write_secret(p, k)
        return k


_keys: Keys | None = None
_keys_lock = threading.Lock()


def keys() -> Keys:
    global _keys
    with _keys_lock:
        if _keys is None:
            _keys = Keys(get_settings().data_dir)
        return _keys


def reset_keys() -> None:
    global _keys
    _keys = None


def encrypt(s: str) -> str:
    return keys().fernet.encrypt(s.encode()).decode()


def decrypt(s: str) -> str:
    try:
        return keys().fernet.decrypt(s.encode()).decode()
    except InvalidToken as e:  # pragma: no cover - key rotation mistakes
        raise ValueError("cannot decrypt field: wrong BEYOND_DATA_KEY?") from e


# ---------------------------------------------------------------- tokens
def issue_token(sub: str, typ: str, ttl: int, aud: str = API_AUDIENCE, **extra) -> tuple[str, int]:
    now = int(time.time())
    exp = now + ttl
    payload = {"iss": ISSUER, "sub": sub, "typ": typ, "aud": aud, "iat": now, "nbf": now - 5, "exp": exp, "jti": secrets.token_hex(8)}
    payload.update({k: v for k, v in extra.items() if v is not None})
    return jwt.encode(payload, keys().signing, algorithm="EdDSA"), exp


def decode_token(token: str, typ: str, aud: str = API_AUDIENCE) -> dict:
    claims = jwt.decode(
        token,
        keys().signing.public_key(),
        algorithms=["EdDSA"],  # never accept "none"/HS*
        audience=aud,
        issuer=ISSUER,
        leeway=30,
        options={"require": ["exp", "sub", "typ"]},
    )
    if claims.get("typ") != typ:
        raise jwt.InvalidTokenError("wrong token type")
    return claims


def new_opaque_token() -> str:
    return secrets.token_urlsafe(48)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def secure_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------- MFA
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="Beyond VPN")


def verify_totp(secret: str, code: str | None) -> bool:
    if not code or not code.isdigit():
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


# ---------------------------------------------------------------- rate limiting
class RateLimiter:
    """In-process sliding-window limiter. Replace with Redis for multi-replica deployments."""

    def __init__(self) -> None:
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()
