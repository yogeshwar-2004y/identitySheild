"""Identity lifecycle: Joiner / Mover / Leaver, approvals, idempotency, retry, HR webhook."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.redis import get_redis
from app.core.security import utcnow
from app.db.session import tenant_session
from app.lifecycle.service import due_scheduled_leavers, execute_leaver
from app.models import Alert, ApiKey, AuditLog, LifecycleEvent, Session as SessionRow, User
from tests.conftest import TenantEnv, auth, lab_headers, login


def _admin(client: TestClient, t: TenantEnv) -> str:
    t.add_user("root", ["admin", "user"], department="IT")
    return str(login(client, t, "root")["access_token"])


def test_joiner_provisions_with_template_and_activates_on_first_login(client: TestClient, tenant: TenantEnv) -> None:
    at = _admin(client, tenant)
    r = client.post("/lifecycle/joiner", headers=auth(at), json={
        "full_name": "Asha Kumar", "email": "asha@corp.example", "department": "Engineering", "lab_demo_password": False})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "COMPLETED" and body["user"]["state"] == "PENDING"
    kc = next(u for u in tenant.idp.users.values() if u.username == "asha")
    assert kc.roles == {"user", "eng-developer"}
    assert set(kc.required_actions) == {"VERIFY_EMAIL", "UPDATE_PASSWORD", "CONFIGURE_TOTP"}
    assert ("send_actions_email", kc.id) in tenant.idp.calls
    # duplicate is rejected; same idempotency key returns the same request
    assert client.post("/lifecycle/joiner", headers=auth(at), json={
        "full_name": "Asha Kumar", "email": "asha@corp.example", "department": "Engineering"}).status_code == 409
    # first login completes onboarding
    kc.password, kc.required_actions = "pw", []
    s = login(client, tenant, "asha")
    assert s["user"]["state"] == "ACTIVE"
    with tenant_session(tenant.id) as db:
        actions = [a.action for a in db.execute(select(AuditLog)).scalars()]
    assert "lifecycle.joiner.completed" in actions and "user.activated" in actions


def test_joiner_validation(client: TestClient, tenant: TenantEnv) -> None:
    at = _admin(client, tenant)
    r = client.post("/lifecycle/joiner", headers=auth(at), json={"full_name": "<script>", "email": "nope", "department": "x"})
    assert r.status_code == 422


def test_mover_access_diff_reissues_session(client: TestClient, tenant: TenantEnv) -> None:
    at = _admin(client, tenant)
    u = tenant.add_user("bea", ["user", "eng-developer"], department="Engineering")
    s = login(client, tenant, "bea")
    r = client.post("/lifecycle/mover", headers=auth(at), json={"user_id": str(u.id), "new_department": "Finance"})
    assert r.status_code == 201 and r.json()["status"] == "COMPLETED"
    assert r.json()["access_diff"]["added"] == ["finance-viewer"] and r.json()["access_diff"]["removed"] == ["eng-developer"]
    # old token carries stale claims -> refused, refresh issues a NEW session id
    r = client.get("/auth/me", headers=auth(s["access_token"]))
    assert r.status_code == 401 and r.json()["detail"]["code"] == "claims_changed"
    r = client.post("/auth/refresh", json={"refresh_token": s["refresh_token"]}, headers=lab_headers())
    assert r.status_code == 200 and r.json()["session_id"] != s["session_id"]
    assert client.get("/auth/me", headers=auth(r.json()["access_token"])).status_code == 200


def test_mover_sensitive_role_needs_approval_with_separation_of_duties(client: TestClient, tenant: TenantEnv) -> None:
    at = _admin(client, tenant)
    tenant.add_user("hr1", ["hr", "user"], department="HR")
    hr_at = login(client, tenant, "hr1")["access_token"]
    u = tenant.add_user("cy", ["user", "eng-developer"])
    r = client.post("/lifecycle/mover", headers=auth(hr_at), json={"user_id": str(u.id), "add_roles": ["eng-prod-access"]})
    lc = r.json()
    assert lc["status"] == "PENDING_APPROVAL" and lc["access_diff"]["sensitive"] == ["eng-prod-access"]
    assert "eng-prod-access" not in next(x for x in tenant.idp.users.values() if x.username == "cy").roles
    # HR cannot approve (RBAC); requester cannot approve own request (SoD)
    assert client.post(f"/lifecycle/{lc['id']}/approve", headers=auth(hr_at), json={"approve": True}).status_code == 403
    r = client.post(f"/lifecycle/{lc['id']}/approve", headers=auth(at), json={"approve": True, "reason": "ok"})
    assert r.status_code == 200 and r.json()["status"] == "COMPLETED"
    assert "eng-prod-access" in next(x for x in tenant.idp.users.values() if x.username == "cy").roles
    with tenant_session(tenant.id) as db:  # approved grant must not look like privilege escalation
        assert not list(db.execute(select(Alert).where(Alert.rule_key == "D06")).scalars())


def test_leaver_leaves_zero_sessions_and_cannot_authenticate(client: TestClient, tenant: TenantEnv) -> None:
    at = _admin(client, tenant)
    u = tenant.add_user("dee", ["user", "finance-viewer"], department="Finance")
    s1, s2 = login(client, tenant, "dee"), login(client, tenant, "dee")
    with tenant_session(tenant.id) as db:
        db.add(ApiKey(tenant_id=tenant.id, user_id=u.id, name="ci", prefix="isk_x", key_hash=uuid.uuid4().hex * 2))
    r = client.post("/lifecycle/leaver", headers=auth(at), json={"user_id": str(u.id), "reason": "resigned"})
    body = r.json()
    assert body["status"] == "COMPLETED", body
    assert all(body["steps"]["verify"]["checks"].values())
    for s in (s1, s2):
        assert client.get("/auth/me", headers=auth(s["access_token"])).status_code == 401
        assert client.post("/auth/refresh", json={"refresh_token": s["refresh_token"]}, headers=lab_headers()).status_code == 401
    r = client.post("/lab/login", json={"tenant": tenant.realm, "username": "dee", "password": "pw"}, headers=lab_headers())
    assert r.status_code == 401
    with tenant_session(tenant.id) as db:
        user = db.get(User, u.id)
        assert user and user.state == "DEPROVISIONED"
        live = db.execute(select(SessionRow).where(SessionRow.user_id == u.id, SessionRow.revoked_at.is_(None))).all()
        assert live == []
        assert db.execute(select(ApiKey).where(ApiKey.user_id == u.id, ApiKey.revoked_at.is_(None))).all() == []
        # the failed login attempt after deprovisioning is a ghost-account alert (critical)
        ghost = list(db.execute(select(Alert).where(Alert.rule_key == "D04")).scalars())
        assert ghost and ghost[0].severity == "critical"
    # idempotent: a second leaver returns the same completed request
    r2 = client.post("/lifecycle/leaver", headers=auth(at), json={"user_id": str(u.id)})
    assert r2.json()["id"] == body["id"]


def test_leaver_failure_mid_workflow_then_retry_resumes(client: TestClient, tenant: TenantEnv) -> None:
    at = _admin(client, tenant)
    u = tenant.add_user("eve", ["user", "sales-crm"], department="Sales")
    login(client, tenant, "eve")
    tenant.idp.fail_next["remove_realm_roles"] = 1  # Keycloak outage during step 4
    r = client.post("/lifecycle/leaver", headers=auth(at), json={"user_id": str(u.id)})
    body = r.json()
    assert body["status"] == "FAILED" and "remove_roles" in body["error"]
    done = set(body["steps"])
    assert {"disable_account", "revoke_sessions", "revoke_tokens"} <= done and "remove_roles" not in done
    # partially deprovisioned is still safe: disabled + no sessions
    assert not next(x for x in tenant.idp.users.values() if x.username == "eve").enabled
    r = client.post(f"/lifecycle/{body['id']}/retry", headers=auth(at))
    assert r.json()["status"] == "COMPLETED"
    with tenant_session(tenant.id) as db:
        lc = db.get(LifecycleEvent, uuid.UUID(body["id"]))
        assert lc and lc.attempts == 2
        # steps done before the failure were not repeated
        assert lc.steps["disable_account"]["at"] == body["steps"]["disable_account"]["at"]


def test_scheduled_leaver_runs_when_due(client: TestClient, tenant: TenantEnv) -> None:
    at = _admin(client, tenant)
    u = tenant.add_user("fin", ["user"])
    when = (utcnow() + timedelta(hours=2)).isoformat()
    r = client.post("/lifecycle/leaver", headers=auth(at), json={"user_id": str(u.id), "effective_at": when})
    lc_id = uuid.UUID(r.json()["id"])
    assert r.json()["status"] == "SCHEDULED"
    assert execute_leaver(tenant.id, lc_id, actor="scheduler") == "SCHEDULED"
    with tenant_session(tenant.id) as db:
        db.get(LifecycleEvent, lc_id).effective_at = utcnow() - timedelta(minutes=1)  # type: ignore[union-attr]
    with tenant_session(tenant.id) as db:
        assert lc_id in due_scheduled_leavers(db)
    assert execute_leaver(tenant.id, lc_id, actor="scheduler") == "COMPLETED"


def test_cannot_deprovision_self(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("solo", ["admin", "user"])
    s = login(client, tenant, "solo")
    me = client.get("/auth/me", headers=auth(s["access_token"])).json()
    assert client.post("/lifecycle/leaver", headers=auth(s["access_token"]), json={"user_id": me["id"]}).status_code == 400


def _signed(secret: str, body: dict) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(body).encode()
    ts = str(int(time.time()))
    sig = "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + raw, hashlib.sha256).hexdigest()
    return raw, {"X-HR-Timestamp": ts, "X-HR-Signature": sig, "Content-Type": "application/json"}


def test_hr_webhook_hmac_and_replay(client: TestClient, tenant: TenantEnv) -> None:
    body = {"event": "hire", "idempotency_key": f"hire-{uuid.uuid4()}",
            "employee": {"email": "new.hire@corp.example", "full_name": "New Hire", "department": "Sales"}}
    raw, h = _signed("hr-secret", body)
    r = client.post("/lifecycle/webhook/hr", content=raw, headers={**h, "X-Tenant": tenant.realm})
    assert r.status_code == 202 and r.json()["status"] == "COMPLETED"
    assert client.post("/lifecycle/webhook/hr", content=raw, headers={**h, "X-Tenant": tenant.realm}).status_code == 409
    raw2, h2 = _signed("wrong-secret", body)
    assert client.post("/lifecycle/webhook/hr", content=raw2, headers={**h2, "X-Tenant": tenant.realm}).status_code == 401
    old = {**h, "X-HR-Timestamp": str(int(time.time()) - 3600)}
    assert client.post("/lifecycle/webhook/hr", content=raw, headers={**old, "X-Tenant": tenant.realm}).status_code == 401
    term = {"event": "terminate", "idempotency_key": f"term-{uuid.uuid4()}",
            "employee": {"email": "new.hire@corp.example", "full_name": "New Hire", "department": "Sales"}}
    raw3, h3 = _signed("hr-secret", term)
    r = client.post("/lifecycle/webhook/hr", content=raw3, headers={**h3, "X-Tenant": tenant.realm})
    assert r.status_code == 202 and r.json()["status"] == "COMPLETED"
    assert get_redis().exists(f"hr:nonce:{h['X-HR-Signature']}")


def test_hr_webhook_rejects_malformed_body(client: TestClient, tenant: TenantEnv) -> None:
    raw, h = _signed("hr-secret", {"event": "hire", "employee": {"email": "nope"}, "idempotency_key": "k" * 10})
    assert client.post("/lifecycle/webhook/hr", content=raw, headers={**h, "X-Tenant": tenant.realm}).status_code == 422
