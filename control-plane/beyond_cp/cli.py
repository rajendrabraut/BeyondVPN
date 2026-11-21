"""Operator CLI.

    python -m beyond_cp.cli create-admin --email admin@example.com
    python -m beyond_cp.cli create-server --id in-mum-1 --name "Mumbai 1" --country IN --hostname mum1.vpn.example.com
    python -m beyond_cp.cli purge-logs
    python -m beyond_cp.cli verify-audit
    python -m beyond_cp.cli migrate
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import select

from . import audit
from .config import get_settings
from .db import init_engine, migrate, session
from .models import Server, User, utcnow
from .schemas import ServerCreate
from .security import PASSWORD_RULE, hash_password, new_opaque_token, password_ok, sha256_hex


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="beyond-cp")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("create-admin")
    a.add_argument("--email", required=True)
    s = sub.add_parser("create-server")
    s.add_argument("--id", required=True)
    s.add_argument("--name", required=True)
    s.add_argument("--country", required=True)
    s.add_argument("--city", default="")
    s.add_argument("--hostname", required=True)
    s.add_argument("--wg-port", type=int, default=51820)
    s.add_argument("--proxy-port", type=int, default=8443)
    s.add_argument("--tunnel-cidr", default="10.8.0.0/22")
    s.add_argument("--features", default="")
    sub.add_parser("purge-logs")
    sub.add_parser("verify-audit")
    sub.add_parser("migrate", help="apply database migrations (also done at server start)")
    args = p.parse_args(argv)

    url = get_settings().database_url
    init_engine(url)
    result = migrate(url)
    if args.cmd == "migrate":
        print(f"schema {result}")
        return 0

    if args.cmd == "create-admin":
        pw = os.getenv("BEYOND_ADMIN_PASSWORD") or getpass.getpass("Admin password: ")
        if not password_ok(pw):
            print(f"password must be {PASSWORD_RULE}", file=sys.stderr)
            return 2
        with session() as db:
            u = db.execute(select(User).where(User.email == args.email.lower())).scalar_one_or_none()
            if u:
                u.role, u.password_hash = "admin", hash_password(pw)
            else:
                db.add(User(email=args.email.lower(), password_hash=hash_password(pw), role="admin", logging_consent_at=utcnow()))
            db.commit()
            audit.record(db, "cli", "admin.create", args.email.lower())
        print(f"admin {args.email} ready")
    elif args.cmd == "create-server":
        body = ServerCreate(
            id=args.id,
            name=args.name,
            country=args.country.upper(),
            city=args.city,
            hostname=args.hostname,
            wg_port=args.wg_port,
            proxy_port=args.proxy_port,
            tunnel_cidr=args.tunnel_cidr,
            features=[f for f in args.features.split(",") if f],
        )
        key = new_opaque_token()
        with session() as db:
            if db.get(Server, body.id):
                print("server exists", file=sys.stderr)
                return 1
            db.add(Server(**body.model_dump(), gateway_key_hash=sha256_hex(key)))
            db.commit()
            audit.record(db, "cli", "admin.server_create", body.id)
        print(f"server {body.id} created")
        print(f"BEYOND_GATEWAY_KEY={key}")
        print("Store this key in the gateway's environment; it is not shown again.")
    elif args.cmd == "purge-logs":
        from .main import purge_expired

        print(purge_expired(get_settings().log_retention_days))
    elif args.cmd == "verify-audit":
        with session() as db:
            ok, bad = audit.verify_chain(db)
        print("audit chain OK" if ok else f"audit chain BROKEN at event {bad}")
        return 0 if ok else 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
