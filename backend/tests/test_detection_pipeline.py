"""Event ingestion -> detection -> scoring -> response, end to end through the database."""
from __future__ import annotations

import json
import time
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import get_settings
from app.core.security import hmac_sha256_hex
from app.db.session import tenant_session
from app.detection.engine import run_periodic
from app.events.poller import poll_tenant
from app.models import Alert, DetectionRule, Event, ResponsePlaybook, Tenant, User
from tests.conftest import TenantEnv, auth, lab_headers, login


def _alerts(t: TenantEnv, rule: str) -> list[Alert]:
    with tenant_session(t.id) as db:
        return list(db.execute(select(Alert).where(Alert.rule_key == rule)).scalars())


def test_signed_keycloak_ingest_normalizes_and_dedupes(client: TestClient, tenant: TenantEnv) -> None:
    u = tenant.add_user("ola", ["user"])
    kc_id = u.kc_user_id
    batch = {"realm": tenant.realm, "events": [
        {"id": "kc-1", "time": int(time.time() * 1000), "type": "LOGIN", "userId": kc_id, "ipAddress": "203.0.113.5",
         "details": {"username": "ola"}},
        {"id": "kc-2", "time": int(time.time() * 1000), "type": "LOGIN_ERROR", "userId": kc_id,
         "ipAddress": "203.0.113.5", "error": "invalid_user_credentials", "details": {"username": "ola"}},
    ]}
    raw = json.dumps(batch).encode()
    sig = "sha256=" + hmac_sha256_hex(get_settings().ingest_hmac_secret, raw)
    assert client.post("/ingest/keycloak", content=raw, headers={"X-IS-Signature": "sha256=bad"}).status_code == 401
    r = client.post("/ingest/keycloak", content=raw, headers={"X-IS-Signature": sig, "Content-Type": "application/json"})
    assert r.json() == {"stored": 2, "skipped": 0}
    r = client.post("/ingest/keycloak", content=raw, headers={"X-IS-Signature": sig, "Content-Type": "application/json"})
    assert r.json()["stored"] == 0  # replay / overlap is idempotent
    with tenant_session(tenant.id) as db:
        evs = list(db.execute(select(Event).where(Event.source == "keycloak", Event.user_id == u.id)).scalars())
        assert {e.type for e in evs} == {"LOGIN", "LOGIN_ERROR"}
        assert evs[0].geo and evs[0].geo["country"] == "IN"
        user = db.get(User, u.id)
        assert user and user.last_login_at is not None


def test_simulated_attacks_fire_detections(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("pat", ["user"])
    # brute force + credential stuffing through Keycloak (fake) -> poller -> D07 / D08
    for i in range(6):
        client.post("/lab/login", json={"tenant": tenant.realm, "username": "pat", "password": f"bad{i}"},
                    headers=lab_headers("100.69.0.9"))
    for name in ["a1", "a2", "a3", "a4", "a5", "a6"]:
        client.post("/lab/login", json={"tenant": tenant.realm, "username": name, "password": "x"},
                    headers=lab_headers("100.65.0.7"))
    assert _alerts(tenant, "D07") and _alerts(tenant, "D08")
    # impossible travel -> D01
    login(client, tenant, "pat", ip="203.0.113.10")
    login(client, tenant, "pat", ip="198.51.100.20")
    poll_tenant(tenant.id)
    assert _alerts(tenant, "D01")


def test_out_of_band_admin_grant_is_privilege_escalation_and_reverted(client: TestClient, tenant: TenantEnv) -> None:
    u = tenant.add_user("quin", ["user"])
    kc_user = tenant.idp.users[u.kc_user_id]  # type: ignore[index]
    kc_user.roles.add("admin")
    tenant.idp.admin_event_log.append({
        "id": str(uuid.uuid4()), "time": int(time.time() * 1000), "operationType": "CREATE",
        "resourceType": "REALM_ROLE_MAPPING", "resourcePath": f"users/{u.kc_user_id}/role-mappings/realm",
        "representation": json.dumps([{"name": "admin"}]), "authDetails": {"userId": "someone-else"},
    })
    poll_tenant(tenant.id)
    a = _alerts(tenant, "D06")
    assert a and a[0].severity == "critical"
    assert "admin" not in kc_user.roles  # revert_role response


def test_dry_run_playbook_only_records(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("rae", ["user"])
    with tenant_session(tenant.id) as db:
        pb = db.execute(select(ResponsePlaybook).where(ResponsePlaybook.rule_key == "D02")).scalar_one()
        pb.mode = "DRY_RUN"
    s = login(client, tenant, "rae", ua="A")
    client.get("/auth/me", headers=auth(s["access_token"], "198.51.100.3", "B"))
    a = _alerts(tenant, "D02")[0]
    assert all(r["status"] == "dry_run" for r in a.response["results"])
    assert client.get("/auth/me", headers=auth(s["access_token"])).status_code == 200  # nothing was revoked


def test_disabled_rule_does_not_fire(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("sid", ["user"])
    with tenant_session(tenant.id) as db:
        db.execute(select(DetectionRule).where(DetectionRule.rule_key == "D02")).scalar_one().enabled = False
    s = login(client, tenant, "sid", ua="A")
    assert client.get("/auth/me", headers=auth(s["access_token"], "198.51.100.3", "B")).status_code == 200
    assert _alerts(tenant, "D02") == []


def test_periodic_rules(tenant: TenantEnv) -> None:
    from datetime import timedelta

    from app.core.security import utcnow
    from app.models import LifecycleEvent

    u = tenant.add_user("tom", ["user"])
    with tenant_session(tenant.id) as db:
        user = db.get(User, u.id)
        assert user
        user.created_at = utcnow() - timedelta(days=100)
        db.add(LifecycleEvent(tenant_id=tenant.id, user_id=u.id, kind="LEAVER", status="FAILED", requested_by="hr",
                              created_at=utcnow() - timedelta(hours=3), steps={}))
    with tenant_session(tenant.id) as db:
        t = db.get(Tenant, tenant.id)
        assert t
        keys = {a.rule_key for a in run_periodic(db, t)}
    assert {"D05", "D12"} <= keys
    with tenant_session(tenant.id) as db:
        t = db.get(Tenant, tenant.id)
        assert t and run_periodic(db, t) == []  # de-duplicated


def test_alert_triage_and_overview(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("ana", ["analyst", "user"], department="Security")
    tenant.add_user("vic", ["user"])
    s = login(client, tenant, "vic", ua="A")
    client.get("/auth/me", headers=auth(s["access_token"], "198.51.100.3", "B"))
    h = auth(login(client, tenant, "ana")["access_token"])
    alerts = client.get("/alerts?status=OPEN", headers=h).json()
    assert alerts
    aid = alerts[0]["id"]
    detail = client.get(f"/alerts/{aid}", headers=h).json()
    assert detail["evidence"] and detail["response"]["results"]
    assert client.patch(f"/alerts/{aid}", headers=h, json={"status": "RESOLVED", "notes": "confirmed"}).json()["status"] == "RESOLVED"
    ov = client.get("/overview", headers=h).json()
    assert ov["kpis"]["active_users"] >= 2 and "alerts_daily" in ov
    rules = client.get("/rules", headers=h).json()
    assert len(rules) == 12
    pbs = client.get("/playbooks", headers=h).json()
    assert len(pbs["playbooks"]) == 12 and "revoke_session" in pbs["available_actions"]
