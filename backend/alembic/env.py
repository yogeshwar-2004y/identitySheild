"""Migrations run as the table owner (MIGRATION_DATABASE_URL), never as the runtime role."""
from __future__ import annotations

import os

from alembic import context
from sqlalchemy import create_engine, pool

from app.models import Base

target_metadata = Base.metadata


def _url() -> str:
    url = context.get_x_argument(as_dictionary=True).get("url") or os.environ.get("MIGRATION_DATABASE_URL")
    if not url:
        raise RuntimeError("MIGRATION_DATABASE_URL is not set")
    return url


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
