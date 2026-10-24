"""Tamper-evident audit log."""
from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import text

from app.audit.service import verify_chain, write_audit
from app.db.session import tenant_session
from tests.conftest import TenantEnv, auth, login


def test_chain_verifies_and_detects_tampering(client: TestClient, tenant: TenantEnv, owner_engine) -> None:  # type: ignore[no-untyped-def]
    with tenant_session(tenant.id) as db:
        ids = [write_audit(db, tenant.id, actor="t", action=f"test.{i}", detail={"i": i}).id for i in range(5)]
    with tenant_session(tenant.id) as db:
        ok = verify_chain(db, tenant.id)
    assert ok["valid"] and ok["checked"] >= 5
    # An attacker with direct DB access edits one historical row.
    with owner_engine.begin() as c:
        c.execute(text("UPDATE audit_log SET detail = '{\"i\": 999}'::jsonb WHERE id = :id"), {"id": ids[2]})
    tenant.add_user("aud", ["analyst", "user"])
    s = login(client, tenant, "aud")
    r = client.get("/audit/verify", headers=auth(s["access_token"]))
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is False and body["broken_at_id"] == ids[2]


def test_deleting_a_row_breaks_the_chain(tenant: TenantEnv, owner_engine) -> None:  # type: ignore[no-untyped-def]
    with tenant_session(tenant.id) as db:
        ids = [write_audit(db, tenant.id, actor="t", action="x").id for _ in range(3)]
    with owner_engine.begin() as c:
        c.execute(text("DELETE FROM audit_log WHERE id = :id"), {"id": ids[1]})
    with tenant_session(tenant.id) as db:
        res = verify_chain(db, tenant.id)
    assert res["valid"] is False and res["broken_at_id"] == ids[2] and res["reason"] == "prev_hash mismatch"


def test_audit_requires_privileged_role(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("plain", ["user"])
    s = login(client, tenant, "plain")
    assert client.get("/audit", headers=auth(s["access_token"])).status_code == 403
