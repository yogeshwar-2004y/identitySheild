"""Cross-tenant isolation: API-level and database-level (row-level security)."""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.db.session import platform_session, tenant_session
from app.models import Alert, AuditLog, Session as SessionRow, User
from tests.conftest import TenantEnv, auth, login, make_tenant


def _attack_setup(client: TestClient) -> tuple[TenantEnv, TenantEnv, dict, dict]:
    a, b = make_tenant(), make_tenant()
    a.add_user("victim", ["user"])
    a.add_user("aadmin", ["admin", "user"])
    b.add_user("badmin", ["admin", "user"])
    va = login(client, a, "victim")
    # a real alert in tenant A
    client.get("/auth/me", headers=auth(va["access_token"], "198.51.100.1", "evil"))
    return a, b, va, login(client, b, "badmin")


def test_admin_of_tenant_b_cannot_touch_tenant_a(client: TestClient) -> None:
    a, b, va, bs = _attack_setup(client)
    hb = auth(bs["access_token"])
    with tenant_session(a.id) as db:
        a_user = db.execute(select(User).where(User.username == "victim")).scalar_one()
        a_alert = db.execute(select(Alert)).scalars().first()
    assert a_alert is not None
    assert client.get(f"/users/{a_user.id}", headers=hb).status_code == 404
    assert client.get(f"/users/{a_user.id}/timeline", headers=hb).status_code == 404
    assert client.get(f"/alerts/{a_alert.id}", headers=hb).status_code == 404
    assert client.patch(f"/alerts/{a_alert.id}", headers=hb, json={"status": "RESOLVED"}).status_code == 404
    assert client.delete(f"/sessions/{va['session_id']}", headers=hb).status_code == 404
    assert client.post("/lifecycle/leaver", headers=hb, json={"user_id": str(a_user.id)}).status_code == 404
    assert client.get(f"/users/{a_user.id}/sessions", headers=hb).json() == []
    names = {u["username"] for u in client.get("/users", headers=hb).json()}
    assert names == {"badmin"}
    assert all(x["id"] != str(a_alert.id) for x in client.get("/alerts", headers=hb).json())
    assert client.get("/audit/verify", headers=hb).json()["valid"] is True


def test_token_tenant_claim_cannot_be_swapped(client: TestClient) -> None:
    import jwt

    from app.core.config import get_settings

    a, b, _, bs = _attack_setup(client)
    claims = jwt.decode(bs["access_token"], options={"verify_signature": False})
    claims["tenant_id"] = str(a.id)  # re-signing requires the server secret; an attacker does not have it
    forged = jwt.encode(claims, "x" * 40, algorithm="HS256")
    assert client.get("/users", headers=auth(forged)).status_code == 401
    # Defense in depth: even a validly signed token whose tenant does not own its session is refused.
    claims_ok = jwt.encode(claims, get_settings().jwt_secret, algorithm="HS256")
    r = client.get("/users", headers=auth(claims_ok))
    assert r.status_code == 401 and r.json()["detail"]["code"] == "session_mismatch"


def test_rls_blocks_queries_without_tenant_filter(client: TestClient) -> None:
    a, b, _, _ = _attack_setup(client)
    # A query with NO tenant filter, run in tenant B's transaction, only ever sees tenant B rows.
    with tenant_session(b.id) as db:
        tenants_seen = {r[0] for r in db.execute(text("SELECT DISTINCT tenant_id FROM users")).all()}
        assert tenants_seen == {b.id}
        assert all(s.tenant_id == b.id for s in db.execute(select(SessionRow)).scalars())
    # No tenant bound at all -> zero rows (fail closed).
    with platform_session() as db:
        assert db.execute(text("SELECT count(*) FROM users")).scalar_one() == 0
    # Writing a row for another tenant is rejected by the WITH CHECK clause.
    with pytest.raises(DBAPIError):
        with tenant_session(b.id) as db:
            db.add(User(tenant_id=a.id, username="planted", email=f"p{uuid.uuid4().hex}@x", state="ACTIVE"))
            db.flush()


def test_runtime_role_cannot_rewrite_audit_history(client: TestClient) -> None:
    a, _, _, _ = _attack_setup(client)
    with pytest.raises(DBAPIError):
        with tenant_session(a.id) as db:
            db.execute(text("UPDATE audit_log SET actor = 'nobody'"))
    with pytest.raises(DBAPIError):
        with tenant_session(a.id) as db:
            db.execute(text("DELETE FROM audit_log"))
    with tenant_session(a.id) as db:
        assert db.execute(select(AuditLog)).first() is not None
