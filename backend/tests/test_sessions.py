"""Session management and safe logout (evaluation criteria: session management, safe logout)."""
from __future__ import annotations

import time
import uuid
from datetime import timedelta

import jwt
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.redis import get_redis
from app.core.security import utcnow
from app.db.session import tenant_session
from app.models import Alert, Session as SessionRow
from tests.conftest import TenantEnv, auth, lab_headers, login


def _alerts(t: TenantEnv, rule: str) -> list[Alert]:
    with tenant_session(t.id) as db:
        return list(db.execute(select(Alert).where(Alert.rule_key == rule)).scalars())


def test_oidc_code_flow_sets_hardened_cookies(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("alice", ["admin", "user"])
    r = client.get(f"/auth/login?tenant={tenant.realm}", follow_redirects=False)
    assert r.status_code == 302 and r.headers["cache-control"] == "no-store"
    state = r.headers["location"].split("state=")[1]
    assert tenant.idp.last_auth["code_challenge"]  # PKCE S256 challenge was sent
    kc_id = next(u.id for u in tenant.idp.users.values() if u.username == "alice")
    tenant.idp.codes["code-1"] = kc_id
    r = client.get(f"/auth/callback?code=code-1&state={state}", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].endswith("/auth/complete")
    cookies = r.headers.get_list("set-cookie")
    rt = next(c for c in cookies if c.startswith("__Host-is_rt="))
    for attr in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
        assert attr.lower() in rt.lower()
    assert "Domain" not in rt  # __Host- prefix forbids Domain
    # state is single use
    r2 = client.get(f"/auth/callback?code=code-1&state={state}", follow_redirects=False)
    assert "invalid_state" in r2.headers["location"]
    # refresh needs the CSRF double-submit header
    assert client.post("/auth/refresh").status_code == 403
    csrf = client.cookies.get("__Host-is_csrf")
    r = client.post("/auth/refresh", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200 and r.json()["user"]["roles"] == ["admin", "user"]
    assert r.headers["cache-control"] == "no-store"


def test_logout_invalidates_access_refresh_and_idp_session(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("bob", ["user"])
    s = login(client, tenant, "bob")
    at, rt = s["access_token"], s["refresh_token"]
    assert client.get("/auth/me", headers=auth(at)).status_code == 200
    r = client.post("/auth/logout", headers=auth(at))
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    assert "cookies" in r.headers["clear-site-data"]
    # 1. replayed access token -> 401 (Redis revocation list, checked on every request)
    r = client.get("/auth/me", headers=auth(at))
    assert r.status_code == 401 and r.json()["detail"]["code"] == "token_revoked"
    # 2. refresh token -> 401
    r = client.post("/auth/refresh", json={"refresh_token": rt}, headers=lab_headers())
    assert r.status_code == 401
    # 3. Keycloak SSO session ended
    assert any(c[0] == "end_session" for c in tenant.idp.calls)
    assert tenant.idp.sessions == {}
    # 4. back-button: authenticated responses are never cacheable
    with tenant_session(tenant.id) as db:
        assert db.get(SessionRow, uuid.UUID(s["session_id"])).revoke_reason == "logout"  # type: ignore[union-attr]


def test_logout_all_revokes_every_session(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("carol", ["user"])
    a, b = login(client, tenant, "carol"), login(client, tenant, "carol")
    r = client.post("/auth/logout-all", headers=auth(a["access_token"]))
    assert r.json()["sessions_revoked"] == 2
    assert client.get("/auth/me", headers=auth(b["access_token"])).status_code == 401
    assert any(c[0] == "logout_user" for c in tenant.idp.calls)


def test_refresh_rotation_and_reuse_detection(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("dan", ["user"])
    s = login(client, tenant, "dan")
    rt1 = s["refresh_token"]
    r = client.post("/auth/refresh", json={"refresh_token": rt1}, headers=lab_headers())
    assert r.status_code == 200
    rt2, at2 = r.json()["refresh_token"], r.json()["access_token"]
    assert rt2 != rt1
    # replaying the rotated token kills the whole family
    r = client.post("/auth/refresh", json={"refresh_token": rt1}, headers=lab_headers())
    assert r.status_code == 401 and r.json()["detail"]["code"] == "refresh_reuse"
    assert client.post("/auth/refresh", json={"refresh_token": rt2}, headers=lab_headers()).status_code == 401
    assert client.get("/auth/me", headers=auth(at2)).status_code == 401
    alerts = _alerts(tenant, "D03")
    assert alerts and alerts[0].risk >= 70


def test_idle_timeout(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("erin", ["user"])
    s = login(client, tenant, "erin")
    get_redis().set(f"sess:last:{s['session_id']}", str(int(time.time()) - 16 * 60))
    r = client.get("/auth/me", headers=auth(s["access_token"]))
    assert r.status_code == 401 and r.json()["detail"]["code"] == "idle_timeout"
    with tenant_session(tenant.id) as db:
        assert db.get(SessionRow, uuid.UUID(s["session_id"])).revoke_reason == "idle_timeout"  # type: ignore[union-attr]


def test_absolute_timeout(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("fay", ["user"])
    s = login(client, tenant, "fay")
    with tenant_session(tenant.id) as db:
        db.get(SessionRow, uuid.UUID(s["session_id"])).expires_at = utcnow() - timedelta(seconds=1)  # type: ignore[union-attr]
    r = client.post("/auth/refresh", json={"refresh_token": s["refresh_token"]}, headers=lab_headers())
    assert r.status_code == 401 and r.json()["detail"]["code"] == "absolute_timeout"


def test_access_token_never_outlives_session(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("gil", ["user"])
    s = login(client, tenant, "gil")
    exp = jwt.decode(s["access_token"], options={"verify_signature": False})["exp"]
    assert exp - time.time() <= 300 + 2


def test_concurrent_session_cap_evicts_oldest(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("hal", ["user"])
    sessions = [login(client, tenant, "hal") for _ in range(4)]  # cap = 3
    assert client.get("/auth/me", headers=auth(sessions[0]["access_token"])).status_code == 401
    assert client.get("/auth/me", headers=auth(sessions[3]["access_token"])).status_code == 200
    with tenant_session(tenant.id) as db:
        assert db.get(SessionRow, uuid.UUID(sessions[0]["session_id"])).revoke_reason == "concurrent_session_cap"  # type: ignore[union-attr]


def test_stolen_token_replay_from_new_network_is_detected_and_revoked(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("ivy", ["user"])
    s = login(client, tenant, "ivy", ip="203.0.113.10", ua="Chrome")
    assert client.get("/auth/me", headers=auth(s["access_token"], "203.0.113.10", "Chrome")).status_code == 200
    r = client.get("/auth/me", headers=auth(s["access_token"], "198.51.100.66", "python-requests"))
    assert r.status_code == 401
    a = _alerts(tenant, "D02")[0]
    assert a.risk >= 70 and any(x["action"] == "revoke_session" and x["status"] == "done" for x in a.response["results"])
    assert client.get("/auth/me", headers=auth(s["access_token"], "203.0.113.10", "Chrome")).status_code == 401


def test_kill_session_and_cannot_kill_other_users(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("jo", ["user"])
    tenant.add_user("kim", ["user"])
    a1, a2 = login(client, tenant, "jo"), login(client, tenant, "jo")
    k = login(client, tenant, "kim")
    listing = client.get("/sessions", headers=auth(a1["access_token"])).json()
    assert {x["id"] for x in listing} == {a1["session_id"], a2["session_id"]}
    assert client.delete(f"/sessions/{k['session_id']}", headers=auth(a1["access_token"])).status_code == 404
    assert client.delete(f"/sessions/{a2['session_id']}", headers=auth(a1["access_token"])).status_code == 200
    assert client.get("/auth/me", headers=auth(a2["access_token"])).status_code == 401


def test_backchannel_logout_from_keycloak(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("lee", ["user"])
    s = login(client, tenant, "lee")
    with tenant_session(tenant.id) as db:
        kc_sid = db.get(SessionRow, uuid.UUID(s["session_id"])).kc_session_id  # type: ignore[union-attr]
    r = client.post("/auth/backchannel-logout", data={"logout_token": tenant.idp.logout_token(str(kc_sid))})
    assert r.status_code == 200
    assert client.get("/auth/me", headers=auth(s["access_token"])).status_code == 401
    bad = client.post("/auth/backchannel-logout", data={"logout_token": "not-a-jwt"})
    assert bad.status_code == 400


def test_idp_session_killed_elsewhere_ends_app_session_on_refresh(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("max", ["user"])
    s = login(client, tenant, "max")
    tenant.idp.sessions.clear()  # admin killed the SSO session in Keycloak
    r = client.post("/auth/refresh", json={"refresh_token": s["refresh_token"]}, headers=lab_headers())
    assert r.status_code == 401 and r.json()["detail"]["code"] == "idp_session_ended"


def test_security_headers_and_tampered_token(client: TestClient, tenant: TenantEnv) -> None:
    r = client.get("/health/live")
    for h in ("x-frame-options", "x-content-type-options", "content-security-policy", "strict-transport-security"):
        assert h in r.headers
    tenant.add_user("ned", ["user"])
    s = login(client, tenant, "ned")
    parts = s["access_token"].split(".")
    forged = jwt.encode({**jwt.decode(s["access_token"], options={"verify_signature": False}), "roles": ["admin"]},
                        "attacker-key-attacker-key-attacker-key", algorithm="HS256")
    assert client.get("/auth/me", headers=auth(forged)).status_code == 401
    assert client.get("/auth/me", headers=auth(parts[0] + "." + parts[1] + ".x")).status_code == 401
    assert client.get("/auth/me").status_code == 401


def test_force_mfa_step_up_is_scoped_to_the_risky_session(client: TestClient, tenant: TenantEnv) -> None:
    from app.db.session import tenant_session as ts
    from app.models import Alert as A, Tenant as T
    from app.response.engine import execute_actions

    tenant.add_user("oli", ["user"])
    safe, risky = login(client, tenant, "oli"), login(client, tenant, "oli")
    with ts(tenant.id) as db:
        t = db.get(T, tenant.id)
        u = db.get(SessionRow, uuid.UUID(risky["session_id"]))
        assert t and u
        a = A(tenant_id=tenant.id, rule_key="D01", title="x", severity="high", user_id=u.user_id, session_id=u.id)
        db.add(a)
        db.flush()
        execute_actions(db, t, a, ["force_mfa"], "ACTIVE")
    r = client.post("/auth/refresh", json={"refresh_token": risky["refresh_token"]}, headers=lab_headers())
    assert r.status_code == 401 and r.json()["detail"]["code"] == "step_up_required"
    assert client.post("/auth/refresh", json={"refresh_token": safe["refresh_token"]}, headers=lab_headers()).status_code == 200
    kc = next(x for x in tenant.idp.users.values() if x.username == "oli")
    assert "CONFIGURE_TOTP" in kc.required_actions
