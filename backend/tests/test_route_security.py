"""Every endpoint is authenticated unless explicitly public; RBAC is enforced."""
from __future__ import annotations

import re

from fastapi.testclient import TestClient

from app.main import PUBLIC_PATHS, app
from tests.conftest import TenantEnv, auth, login


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "00000000-0000-0000-0000-000000000000", path)


def test_every_non_public_route_rejects_anonymous_requests(client: TestClient) -> None:
    checked = 0
    paths = app.openapi()["paths"]
    for path, ops in paths.items():
        if path in PUBLIC_PATHS or path.startswith("/lab/scenarios") or path.startswith("/health"):
            continue
        for method in ops:
            r = client.request(method.upper(), _concrete(path), json={})
            assert r.status_code == 401, f"{method} {path} returned {r.status_code}"
            checked += 1
    assert checked > 30


def test_rbac_matrix(client: TestClient, tenant: TenantEnv) -> None:
    tenant.add_user("u1", ["user"])
    tenant.add_user("h1", ["hr", "user"], department="HR")
    tenant.add_user("an1", ["analyst", "user"], department="Security")
    u = auth(login(client, tenant, "u1")["access_token"])
    h = auth(login(client, tenant, "h1")["access_token"])
    an = auth(login(client, tenant, "an1")["access_token"])
    assert client.get("/alerts", headers=u).status_code == 403
    assert client.get("/alerts", headers=h).status_code == 403
    assert client.get("/alerts", headers=an).status_code == 200
    assert client.get("/hunts", headers=an).status_code == 200
    assert client.post("/lifecycle/joiner", headers=an, json={"full_name": "X Y", "email": "x@y.example", "department": "Sales"}).status_code == 403
    assert client.get("/lifecycle/requests", headers=h).status_code == 200
    rid = client.get("/rules", headers=an).json()[0]["id"]
    assert client.put(f"/rules/{rid}", headers=an, json={"enabled": False}).status_code == 403
    assert client.put("/tenants/me/settings", headers=an, json={}).status_code == 403
    assert client.get("/sessions", headers=u).status_code == 200
    assert client.get("/sessions/all", headers=u).status_code == 403


def test_lab_endpoints_need_lab_key(client: TestClient, tenant: TenantEnv) -> None:
    assert client.post("/lab/login", json={"tenant": tenant.realm, "username": "x"}).status_code == 401
    assert client.post("/lab/login", json={"tenant": tenant.realm, "username": "x"},
                       headers={"X-Lab-Key": "wrong"}).status_code == 401
