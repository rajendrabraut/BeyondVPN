from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def init_engine(url: str) -> Engine:
    global _engine, _SessionLocal
    kwargs: dict = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    _engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(_engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _):  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def alembic_config(url: str):
    """Alembic config pointing at the migrations shipped inside the package."""
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", "beyond_cp:migrations")
    cfg.attributes["url"] = url
    return cfg


def migrate(url: str) -> str:
    """Bring the schema to the latest revision. Returns the action taken.

    Databases created before migrations existed (pre-0.0.0.1 `create_all`, same schema as the
    first revision) are stamped instead of re-created, so no data is touched.
    """
    from alembic import command
    from sqlalchemy import inspect

    cfg = alembic_config(url)
    tables = set(inspect(engine()).get_table_names())
    if tables and "alembic_version" not in tables:
        command.stamp(cfg, "0001_initial")
        command.upgrade(cfg, "head")
        return "stamped legacy schema, upgraded"
    command.upgrade(cfg, "head")
    return "upgraded"


def engine() -> Engine:
    assert _engine is not None, "init_engine() not called"
    return _engine


def session() -> Session:
    assert _SessionLocal is not None, "init_engine() not called"
    return _SessionLocal()


def get_db() -> Iterator[Session]:
    db = session()
    try:
        yield db
    finally:
        db.close()
