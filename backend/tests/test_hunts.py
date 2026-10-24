"""Every prebuilt hunt returns the expected identities against the real seed data set."""
from __future__ import annotations

import random

import pytest
from fastapi.testclient import TestClient

from app import seed
from app.db.session import tenant_session
from app.models import Tenant
from tests.conftest import TenantEnv, auth, login, make_tenant

EXPECTED = {
    "multi_country_logins": {"grace"},
    "dormant_then_active": {"erin"},
    "sessions_beyond_absolute": {"ivan"},
    "many_role_grants": {"mallory"},
    "deprovisioned_activity": {"dave"},
    "failing_ips_many_users": {"100.66.0.44"},
    "off_hours_logins": {"heidi"},
    "token_abuse": {"judy"},
    "sensitive_roles_without_approval": {"mallory"},
    "never_logged_in": {"frank"},
}


@pytest.fixture(scope="module")
def seeded() -> TenantEnv:
    t = make_tenant()
    from app.core.security import utcnow

    now = utcnow()
    with tenant_session(t.id) as db:
        tenant = db.get(Tenant, t.id)
        assert tenant is not None
        users = {}
        for spec in seed.ACME_USERS:
            from datetime import timedelta

            created = now - timedelta(days=50 if spec["profile"] == "never" else 120)
            u = seed.ensure_user(db, tenant, spec, created)
            u._seed_profile = spec["profile"]  # type: ignore[attr-defined]
            users[spec["u"]] = u
        db.flush()
        seed._departed(db, tenant, users["dave"], now)
        seed._stale_session(db, tenant, users["ivan"], now)
        seed._api_keys(db, tenant, users)
        seed.history(db, tenant, users, random.Random(42))
    return t


def test_all_prebuilt_hunts_find_planted_identities(client: TestClient, seeded: TenantEnv) -> None:
    seeded.add_user("hunter", ["analyst", "user"], department="Security")
    h = auth(login(client, seeded, "hunter")["access_token"])
    hunts = client.get("/hunts", headers=h).json()["hunts"]
    assert len(hunts) >= 8
    by_builtin = {x["query"]["name"]: x for x in hunts if x["query"]["kind"] == "builtin"}
    assert set(EXPECTED) <= set(by_builtin)
    for name, expected in EXPECTED.items():
        r = client.post(f"/hunts/{by_builtin[name]['id']}/run", headers=h, json={"params": {}})
        assert r.status_code == 200, r.text
        found = {row.get("username") or row.get("ip") for row in r.json()["results"]}
        assert found == expected, f"{name}: {found} != {expected}"
        run_id = r.json()["run"]["id"]
    v = client.patch(f"/hunts/runs/{run_id}", headers=h, json={"verdict": "CONFIRMED", "notes": "ok"})
    assert v.json()["verdict"] == "CONFIRMED"


def test_custom_filter_hunt_and_adhoc_search(client: TestClient, seeded: TenantEnv) -> None:
    seeded.add_user("hunter2", ["analyst", "user"], department="Security")
    h = auth(login(client, seeded, "hunter2")["access_token"])
    r = client.post("/hunts", headers=h, json={
        "name": "Failures by IP", "hypothesis": "Spraying sources",
        "query": {"kind": "filter", "filters": {"types": ["LOGIN_ERROR"], "since_hours": 24}, "group_by": "ip", "min_count": 5}})
    assert r.status_code == 201
    run = client.post(f"/hunts/{r.json()['id']}/run", headers=h, json={"params": {}}).json()
    assert "100.66.0.44" in {x["key"] for x in run["results"]}
    bad = client.post("/hunts", headers=h, json={"name": "x" * 5, "hypothesis": "sql please",
                                                 "query": {"kind": "sql", "sql": "select 1"}})
    assert bad.status_code == 422
    s = client.post("/hunt/search", headers=h, json={"types": ["LOGIN"], "country": "SG", "since_hours": 48})
    assert {x["username"] for x in s.json()["results"]} == {"grace"}
    g = client.post("/hunt/search", headers=h, json={"group_by": "country", "since_hours": 24 * 90})
    assert "IN" in {x["key"] for x in g.json()["results"]}
    users = client.get("/users", headers=h).json()
    grace = next(u for u in users if u["username"] == "grace")
    tl = client.get(f"/users/{grace['id']}/timeline", headers=h).json()
    assert "event" in {i["category"] for i in tl["items"]}
