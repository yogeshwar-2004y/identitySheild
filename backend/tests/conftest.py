"""Test harness.

Runs inside the API container against the dedicated `identityshield_test` database
(migrated from scratch on every run, accessed as the RLS-bound `is_app` role) and
Redis DB 15. Keycloak is replaced by tests.fakes.FakeIdP.
"""
from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from typing import Any

# Point the app at test resources BEFORE any app module reads settings.
os.environ["DATABASE_URL"] = os.environ["TEST_DATABASE_URL"]
os.environ["REDIS_URL"] = os.environ["TEST_REDIS_URL"]
os.environ["MIGRATION_DATABASE_URL"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
os.environ["LAB_MODE"] = "true"
os.environ["COOKIE_SECURE"] = "true"
os.environ["RATE_LIMIT_AUTH_PER_MINUTE"] = "100000"
os.environ["RATE_LIMIT_API_PER_MINUTE"] = "100000"

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.core.keycloak import override_idp  # noqa: E402
from app.core.redis import get_redis  # noqa: E402
from app.core.security import encrypt_str  # noqa: E402
from app.db.session import platform_session, reset_engine, tenant_session  # noqa: E402
from app.models import Tenant, User  # noqa: E402
from app.tenancy.service import seed_tenant_defaults  # noqa: E402
from tests.fakes import FakeIdP  # noqa: E402

ROLE_NAMES = ["admin", "analyst", "hr", "user", "eng-developer", "eng-prod-access", "finance-viewer",
              "finance-approver", "sales-crm"]


@pytest.fixture(scope="session", autouse=True)
def _database() -> Iterator[None]:
    owner = create_engine(os.environ["TEST_MIGRATION_DATABASE_URL"], isolation_level="AUTOCOMMIT")
    with owner.connect() as c:
        c.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
        c.execute(text("GRANT USAGE ON SCHEMA public TO is_app"))
    owner.dispose()
    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")
    reset_engine(os.environ["TEST_DATABASE_URL"])
    get_redis().flushdb()
    yield


@pytest.fixture()
def owner_engine() -> Iterator[Any]:
    """Superuser/owner connection: bypasses RLS. Used only to simulate tampering."""
    eng = create_engine(os.environ["TEST_MIGRATION_DATABASE_URL"])
    yield eng
    eng.dispose()


class TenantEnv:
    def __init__(self, tenant_id: uuid.UUID, realm: str, idp: FakeIdP) -> None:
        self.id = tenant_id
        self.realm = realm
        self.idp = idp

    def add_user(self, username: str, roles: list[str], *, department: str = "Engineering", state: str = "ACTIVE",
                 password: str = "pw") -> User:
        kc_id = self.idp.add_user(username, password, roles)
        with tenant_session(self.id) as db:
            from sqlalchemy import select

            from app.models import Role, UserRole

            u = User(tenant_id=self.id, username=username, email=f"{username}@{self.realm}.test", full_name=username.title(),
                     department=department, state=state, kc_user_id=kc_id)
            db.add(u)
            db.flush()
            for r in db.execute(select(Role).where(Role.name.in_(roles))).scalars():
                db.add(UserRole(tenant_id=self.id, user_id=u.id, role_id=r.id, granted_by="seed"))
            db.flush()
            db.expunge(u)
            return u


def make_tenant(realm: str | None = None) -> TenantEnv:
    realm = realm or f"t{uuid.uuid4().hex[:10]}"
    idp = FakeIdP(realm)
    override_idp(realm, idp)
    with platform_session() as db:
        t = Tenant(name=realm.title(), realm=realm, status="ACTIVE", settings={},
                   client_secret_enc=encrypt_str("secret"), hr_webhook_secret_enc=encrypt_str("hr-secret"))
        db.add(t)
        db.flush()
        tid = t.id
    with tenant_session(tid) as db:
        seed_tenant_defaults(db, tid, ROLE_NAMES)
    return TenantEnv(tid, realm, idp)


@pytest.fixture()
def tenant() -> TenantEnv:
    return make_tenant()


@pytest.fixture()
def client() -> Iterator[TestClient]:
    from app.main import app

    # https base URL so the Secure (__Host-) cookies round-trip like in a browser.
    with TestClient(app, base_url="https://testserver") as c:
        yield c


LAB = {"X-Lab-Key": ""}


def lab_headers(ip: str = "203.0.113.10", ua: str = "pytest-browser") -> dict[str, str]:
    return {"X-Lab-Key": get_settings().lab_api_key, "X-Lab-Client-IP": ip, "User-Agent": ua}


def login(client: TestClient, t: TenantEnv, username: str, ip: str = "203.0.113.10", ua: str = "pytest-browser",
          password: str = "pw") -> dict[str, Any]:
    r = client.post("/lab/login", json={"tenant": t.realm, "username": username, "password": password},
                    headers=lab_headers(ip, ua))
    assert r.status_code == 200, r.text
    return dict(r.json())


def auth(token: str, ip: str = "203.0.113.10", ua: str = "pytest-browser") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", **lab_headers(ip, ua)}
