"""Schema is created and evolved only through Alembic migrations."""
from __future__ import annotations

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from beyond_cp import db, models  # noqa: F401
from beyond_cp.db import Base


def _url(tmp_path, name="m.db"):
    return f"sqlite:///{(tmp_path / name).as_posix()}"


def test_migrations_match_models(tmp_path):
    url = _url(tmp_path)
    db.init_engine(url)
    assert db.migrate(url) == "upgraded"
    eng = create_engine(url)
    with eng.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)
    assert diff == [], f"models and migrations disagree: {diff}"
    with eng.connect() as conn:
        assert conn.execute(text("select version_num from alembic_version")).scalar() == "0001_initial"


def test_migrate_is_idempotent(tmp_path):
    url = _url(tmp_path)
    db.init_engine(url)
    db.migrate(url)
    assert db.migrate(url) == "upgraded"


def test_pre_migration_database_is_stamped_not_recreated(tmp_path):
    url = _url(tmp_path)
    db.init_engine(url)
    Base.metadata.create_all(db.engine())  # how databases were created before 0.0.0.1
    with db.engine().begin() as conn:
        conn.execute(text("insert into settings (key, value) values ('marker', '\"kept\"')"))
    assert db.migrate(url) == "stamped legacy schema, upgraded"
    with db.engine().connect() as conn:
        assert conn.execute(text("select value from settings where key='marker'")).scalar() == '"kept"'
        assert conn.execute(text("select version_num from alembic_version")).scalar() == "0001_initial"


def test_initial_revision_is_forward_only(tmp_path):
    url = _url(tmp_path)
    db.init_engine(url)
    db.migrate(url)
    with pytest.raises(RuntimeError, match="cannot be downgraded"):
        command.downgrade(db.alembic_config(url), "base")
    assert "users" in inspect(create_engine(url)).get_table_names()
