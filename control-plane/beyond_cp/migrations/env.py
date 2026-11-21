"""Alembic environment. The connection URL comes from the caller (beyond_cp.db.migrate) or
BEYOND_DATABASE_URL; nothing is read from alembic.ini, so no credentials live in files."""
from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine

from beyond_cp import models  # noqa: F401  (registers all tables on Base.metadata)
from beyond_cp.config import get_settings
from beyond_cp.db import Base

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    return config.attributes.get("url") or get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True, render_as_batch=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is None:
        engine = create_engine(_url())
        with engine.connect() as conn:
            _run(conn)
        engine.dispose()
    else:
        _run(connection)


def _run(conn) -> None:
    # render_as_batch: SQLite needs table rebuilds for ALTER; PostgreSQL ignores it.
    context.configure(connection=conn, target_metadata=target_metadata, render_as_batch=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
