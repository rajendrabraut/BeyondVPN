"""Runtime configuration (12-factor: everything from environment variables)."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    v = os.getenv(name)
    return default if not v else int(v)


def _oidc_providers() -> list[dict]:
    raw = os.getenv("BEYOND_OIDC_PROVIDERS", "")
    path = os.getenv("BEYOND_OIDC_PROVIDERS_FILE")
    if path:
        raw = Path(path).read_text(encoding="utf-8")
    if not raw.strip():
        return []
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("BEYOND_OIDC_PROVIDERS must be a JSON list")
    out = []
    for p in data:
        missing = [k for k in ("id", "issuer", "client_id") if not p.get(k)]
        if missing:
            raise ValueError(f"OIDC provider missing {missing}")
        if not str(p["issuer"]).startswith("https://") and not p.get("allow_insecure_issuer"):
            raise ValueError(f"OIDC issuer for {p['id']} must be https://")
        out.append(
            {
                "id": str(p["id"]),
                "name": str(p.get("name") or p["id"]),
                "issuer": str(p["issuer"]).rstrip("/"),
                "client_id": str(p["client_id"]),
                "client_secret": str(p.get("client_secret") or os.getenv(f"BEYOND_OIDC_SECRET_{str(p['id']).upper().replace('-', '_')}", "")),
                "scopes": str(p.get("scopes") or "openid email profile"),
                "allowed_domains": [d.lower() for d in p.get("allowed_domains", [])],
                "auto_create": bool(p.get("auto_create", True)),
                "default_role": p.get("default_role", "user") if p.get("default_role", "user") in {"user", "auditor"} else "user",
                "token_auth": p.get("token_auth", "client_secret_basic"),
            }
        )
    return out


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("BEYOND_DATA_DIR", "./data")))
    database_url: str = field(default_factory=lambda: os.getenv("BEYOND_DATABASE_URL", ""))
    public_url: str = field(default_factory=lambda: os.getenv("BEYOND_PUBLIC_URL", "http://127.0.0.1:8000"))
    cors_origins: list[str] = field(
        default_factory=lambda: [o.strip() for o in os.getenv("BEYOND_CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()]
    )
    access_ttl: int = field(default_factory=lambda: _int("BEYOND_ACCESS_TTL", 900))
    refresh_ttl: int = field(default_factory=lambda: _int("BEYOND_REFRESH_TTL", 7 * 86400))
    proxy_ttl: int = field(default_factory=lambda: _int("BEYOND_PROXY_TTL", 1800))
    log_retention_days: int = field(default_factory=lambda: _int("BEYOND_LOG_RETENTION_DAYS", 30))
    allow_registration: bool = field(default_factory=lambda: _bool("BEYOND_ALLOW_REGISTRATION", True))
    require_logging_consent: bool = field(default_factory=lambda: _bool("BEYOND_REQUIRE_LOGGING_CONSENT", True))
    max_failed_logins: int = field(default_factory=lambda: _int("BEYOND_MAX_FAILED_LOGINS", 5))
    lockout_seconds: int = field(default_factory=lambda: _int("BEYOND_LOCKOUT_SECONDS", 900))
    auth_rate_per_minute: int = field(default_factory=lambda: _int("BEYOND_AUTH_RATE_PER_MINUTE", 30))
    admin_email: str | None = field(default_factory=lambda: os.getenv("BEYOND_ADMIN_EMAIL"))
    admin_password: str | None = field(default_factory=lambda: os.getenv("BEYOND_ADMIN_PASSWORD"))
    trust_proxy_headers: bool = field(default_factory=lambda: _bool("BEYOND_TRUST_PROXY_HEADERS", False))
    # Shared rate limits across control-plane replicas, e.g. redis://redis:6379/0 (unset = in-process).
    redis_url: str = field(default_factory=lambda: os.getenv("BEYOND_REDIS_URL", ""))
    # SSO (OpenID Connect). JSON list of providers, inline or in a file; see docs/SSO.md.
    oidc_providers: list[dict] = field(default_factory=lambda: _oidc_providers())
    # Extra redirect targets allowed after SSO besides CORS origins / public URL
    # (e.g. "beyondvpn://sso" for the desktop and mobile apps).
    sso_app_redirects: list[str] = field(
        default_factory=lambda: [o.strip() for o in os.getenv("BEYOND_SSO_APP_REDIRECTS", "beyondvpn://sso").split(",") if o.strip()]
    )

    def __post_init__(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if not self.database_url:
            self.database_url = f"sqlite:///{(self.data_dir / 'beyond.db').as_posix()}"


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings(s: Settings | None = None) -> None:
    """Used by tests to inject configuration."""
    global _settings
    _settings = s
