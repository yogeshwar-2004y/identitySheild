"""Database access.

The API connects as `is_app`, a role that is neither owner nor superuser, so the
row-level-security policies installed by migration 0002 apply to every query.
`tenant_session()` sets `app.tenant_id` with SET LOCAL for the transaction:
a query that forgets a tenant filter still cannot see another tenant's rows.
"""
from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

_engine: Engine | None = None
_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine, _factory
    if _engine is None:
        _engine = create_engine(get_settings().database_url, pool_pre_ping=True, pool_size=10, max_overflow=20)
        _factory = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def reset_engine(url: str | None = None) -> None:
    """Used by tests to point the app at the test database."""
    global _engine, _factory
    if _engine is not None:
        _engine.dispose()
    _engine = create_engine(url or get_settings().database_url, pool_pre_ping=True)
    _factory = sessionmaker(bind=_engine, expire_on_commit=False)


def _factory_() -> sessionmaker[Session]:
    get_engine()
    assert _factory is not None
    return _factory


def bind_tenant(db: Session, tenant_id: uuid.UUID | str) -> None:
    # set_config(..., true) == SET LOCAL: scoped to the current transaction only.
    db.execute(text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": str(tenant_id)})


@contextmanager
def tenant_session(tenant_id: uuid.UUID | str) -> Iterator[Session]:
    """Transaction bound to one tenant. Commits on success, rolls back on error."""
    db = _factory_()()
    try:
        db.begin()
        bind_tenant(db, tenant_id)
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def platform_session() -> Iterator[Session]:
    """Transaction with no tenant bound: only the `tenants` table is visible."""
    db = _factory_()()
    try:
        db.begin()
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
