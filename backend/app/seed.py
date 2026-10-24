"""Demo data: tenants, users, roles, 30 days of history, and planted findings.

Idempotent: safe to run repeatedly (existing users/events are kept).
Every prebuilt hunt has a known expected answer in this data set
(see tests/test_hunts.py and docs/report/README):

  multi_country_logins            -> grace
  dormant_then_active             -> erin
  sessions_beyond_absolute        -> ivan
  many_role_grants                -> mallory
  deprovisioned_activity          -> dave
  failing_ips_many_users          -> 100.66.0.44
  off_hours_logins                -> heidi
  token_abuse                     -> judy
  sensitive_roles_without_approval-> mallory (eng-prod-access)
  never_logged_in                 -> frank
"""
from __future__ import annotations

import logging
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from app.audit.service import write_audit
from app.core.config import get_settings
from app.core.security import sha256_hex, ua_hash, utcnow
from app.core.tenancy import idp_for
from app.db.session import tenant_session
from app.events.service import record_event
from app.lifecycle.service import template_roles
from app.models import ApiKey, Event, LifecycleEvent, Role, Session as SessionRow, Tenant, User, UserRole
from app.tenancy.service import provision_tenant

log = logging.getLogger("seed")
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"

# username, full name, department, extra roles, state, profile
ACME_USERS: list[dict[str, Any]] = [
    {"u": "alice", "n": "Alice Admin", "d": "IT", "extra": [], "profile": "office"},
    {"u": "sam", "n": "Sam Analyst", "d": "Security", "extra": [], "profile": "office"},
    {"u": "hana", "n": "Hana Resources", "d": "HR", "extra": [], "profile": "office"},
    {"u": "bob", "n": "Bob Builder", "d": "Engineering", "extra": [], "profile": "office"},
    {"u": "carol", "n": "Carol Chen", "d": "Finance", "extra": [], "profile": "office"},
    {"u": "dave", "n": "Dave Departed", "d": "Sales", "extra": [], "profile": "departed"},
    {"u": "erin", "n": "Erin Dormant", "d": "Finance", "extra": [], "profile": "dormant"},
    {"u": "frank", "n": "Frank Forgotten", "d": "Sales", "extra": [], "profile": "never"},
    {"u": "mallory", "n": "Mallory Many", "d": "Engineering",
     "extra": ["eng-prod-access", "finance-viewer", "sales-crm"], "profile": "office"},
    {"u": "grace", "n": "Grace Global", "d": "Sales", "extra": [], "profile": "traveller"},
    {"u": "heidi", "n": "Heidi Night", "d": "Engineering", "extra": [], "profile": "night"},
    {"u": "ivan", "n": "Ivan Stale", "d": "Engineering", "extra": [], "profile": "office"},
    {"u": "judy", "n": "Judy Replay", "d": "Finance", "extra": [], "profile": "office"},
]
GLOBEX_USERS: list[dict[str, Any]] = [
    {"u": "gina", "n": "Gina Globex", "d": "IT", "extra": [], "profile": "office"},
    {"u": "gus", "n": "Gus Globex", "d": "Engineering", "extra": [], "profile": "office"},
]
OFFICE_IPS = ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.20"]


def _email(username: str, realm: str) -> str:
    return f"{username}@{realm}.example"


def ensure_user(db: Any, tenant: Tenant, spec: dict[str, Any], created_at: datetime) -> User:
    s = get_settings()
    email = _email(spec["u"], tenant.realm)
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    idp = idp_for(tenant)
    if user is None:
        user = User(tenant_id=tenant.id, username=spec["u"], email=email, full_name=spec["n"], department=spec["d"],
                    state="ACTIVE", created_at=created_at, activated_at=created_at)
        db.add(user)
        db.flush()
    if not user.kc_user_id:
        first, _, last = spec["n"].partition(" ")
        user.kc_user_id = idp.create_user(username=spec["u"], email=email, first_name=first, last_name=last,
                                          required_actions=[], password=s.demo_password)
    roles = {r.name: r for r in db.execute(select(Role).where(Role.tenant_id == tenant.id)).scalars()}
    wanted = sorted(set(template_roles(db, tenant.id, spec["d"])) | set(spec["extra"]))
    if spec["profile"] != "departed":
        idp.add_realm_roles(user.kc_user_id, wanted)
        for name in wanted:
            if db.get(UserRole, {"user_id": user.id, "role_id": roles[name].id}) is None:
                # mallory's extras simulate manual grants made outside the workflow
                granted_by = "manual:legacy-admin" if name in spec["extra"] else "seed"
                db.add(UserRole(tenant_id=tenant.id, user_id=user.id, role_id=roles[name].id, granted_by=granted_by,
                                granted_at=created_at))
    db.flush()
    return user


def _login_event(db: Any, tenant: Tenant, user: User, ts: datetime, ip: str, ua: str = CHROME,
                 outcome: str = "SUCCESS", type_: str = "LOGIN", **details: Any) -> None:
    record_event(db, tenant, type=type_, user_id=user.id, username=user.username, ip=ip, ua_hash=ua_hash(ua),
                 outcome=outcome, source="seed", source_id=f"seed:{user.username}:{type_}:{ts.isoformat()}:{ip}",
                 ts=ts, details=details, detect=False)


def history(db: Any, tenant: Tenant, users: dict[str, User], rng: random.Random) -> None:
    now = utcnow()
    if db.execute(select(Event.id).where(Event.source == "seed").limit(1)).scalar_one_or_none():
        log.info("history already seeded for %s", tenant.realm)
        return
    for name, user in users.items():
        profile = user._seed_profile  # type: ignore[attr-defined]
        if profile in ("never",):
            continue
        if profile == "dormant":
            for days in (75, 70, 66, 62):
                _login_event(db, tenant, user, (now - timedelta(days=days)).replace(hour=9),
                             rng.choice(OFFICE_IPS))
            _login_event(db, tenant, user, (now - timedelta(days=2)).replace(hour=10, minute=12), "203.0.113.30")
            user.last_login_at = (now - timedelta(days=2)).replace(hour=10, minute=12)
            continue
        if profile == "departed":
            for d in range(30, 8, -1):
                if d % 7 in (5, 6):
                    continue
                _login_event(db, tenant, user, (now - timedelta(days=d)).replace(hour=rng.randint(6, 13),
                                                                                  minute=rng.randint(0, 59)),
                             rng.choice(OFFICE_IPS))
            continue
        for d in range(30, 0, -1):
            day = now - timedelta(days=d)
            if day.weekday() >= 5:
                continue
            hour = 2 if profile == "night" else rng.randint(6, 13)
            ts = day.replace(hour=hour, minute=rng.randint(0, 59), second=0, microsecond=0)
            ip = rng.choice(OFFICE_IPS)
            _login_event(db, tenant, user, ts, ip, rng.choice([CHROME, MAC]))
            _login_event(db, tenant, user, ts + timedelta(hours=rng.randint(4, 8)), ip, type_="LOGOUT")
            user.last_login_at = ts
            if rng.random() < 0.12:
                _login_event(db, tenant, user, ts - timedelta(minutes=2), ip, outcome="FAILURE", type_="LOGIN_ERROR",
                             error="invalid_user_credentials")
    # grace: three countries in the last 24h (multi-country hunt)
    g = users.get("grace")
    if g is not None:
        # pick three daytime (06-23 UTC) slots in the last 24h so the off-hours hunt stays clean
        slots = [now - timedelta(hours=h) for h in range(2, 24) if 6 <= (now - timedelta(hours=h)).hour <= 23]
        for ts, ip in zip((slots[-1], slots[len(slots) // 2], slots[0]), ("203.0.113.40", "100.66.0.10",
                                                                           "100.64.0.15")):
            _login_event(db, tenant, g, ts, ip)
    # dave: activity after deprovisioning (ghost)
    dv = users.get("dave")
    if dv is not None and dv.deprovisioned_at:
        _login_event(db, tenant, dv, dv.deprovisioned_at + timedelta(days=2), "100.67.0.20", outcome="FAILURE",
                     type_="LOGIN_ERROR", error="user_disabled")
    # judy: token replay / reuse traces
    j = users.get("judy")
    if j is not None:
        _login_event(db, tenant, j, now - timedelta(days=1, hours=2), "198.51.100.77", outcome="FAILURE",
                     type_="TOKEN_REJECTED", reason="revoked")
        _login_event(db, tenant, j, now - timedelta(days=1, hours=2, minutes=-1), "198.51.100.77", outcome="FAILURE",
                     type_="REFRESH_TOKEN_REUSE", family_id=str(uuid.uuid4()))
    # spraying IP across 6 accounts in the last 24h
    for i, name in enumerate(["alice", "bob", "carol", "hana", "sam", "nobody"]):
        u = users.get(name)
        ts = now - timedelta(hours=5, minutes=i)
        record_event(db, tenant, type="LOGIN_ERROR", user_id=u.id if u else None, username=name, ip="100.66.0.44",
                     ua_hash=ua_hash("curl/8.4"), outcome="FAILURE", source="seed",
                     source_id=f"seed:spray:{name}:{ts.isoformat()}",
                     ts=ts, details={"error": "invalid_user_credentials" if u else "user_not_found"}, detect=False)


def seed_tenant(name: str, realm: str, specs: list[dict[str, Any]], *, rich: bool) -> None:
    tenant = provision_tenant(name, realm)
    rng = random.Random(42)
    now = utcnow()
    with tenant_session(tenant.id) as db:
        tenant = db.get(Tenant, tenant.id)
        assert tenant is not None
        users: dict[str, User] = {}
        for spec in specs:
            created = now - timedelta(days=50 if spec["profile"] == "never" else 120)
            user = ensure_user(db, tenant, spec, created)
            user._seed_profile = spec["profile"]  # type: ignore[attr-defined]
            users[spec["u"]] = user
            if not db.execute(select(LifecycleEvent.id).where(LifecycleEvent.user_id == user.id,
                                                              LifecycleEvent.kind == "JOINER")).first():
                db.add(LifecycleEvent(tenant_id=tenant.id, user_id=user.id, kind="JOINER", status="COMPLETED",
                                      requested_by="seed", payload={"department": spec["d"], "seeded": True},
                                      steps={"create_account": {"at": created.isoformat()}},
                                      access_diff={"added": template_roles(db, tenant.id, spec["d"]), "removed": []},
                                      created_at=created, completed_at=created))
        db.flush()
        if rich:
            _departed(db, tenant, users.get("dave"), now)
            _stale_session(db, tenant, users.get("ivan"), now)
            _api_keys(db, tenant, users)
        history(db, tenant, users, rng)
        write_audit(db, tenant.id, actor="seed", action="seed.completed", target=f"realm:{realm}",
                    detail={"users": sorted(users)})
    log.info("seeded tenant %s (%s) with %d users", name, realm, len(specs))


def _departed(db: Any, tenant: Tenant, dave: User | None, now: datetime) -> None:
    if dave is None or dave.state == "DEPROVISIONED":
        return
    trigger = now - timedelta(days=8, hours=5)
    disabled = trigger + timedelta(hours=3)  # slower than the 60 min SLA -> D12
    if dave.kc_user_id:
        idp_for(tenant).set_enabled(dave.kc_user_id, False)
    for ur in db.execute(select(UserRole).where(UserRole.user_id == dave.id)).scalars():
        db.delete(ur)
    dave.state, dave.deprovisioned_at = "DEPROVISIONED", disabled
    steps = {k: {"at": disabled.isoformat()} for k in ("disable_account", "revoke_sessions", "revoke_tokens",
                                                        "remove_roles", "revoke_api_keys", "mark_deprovisioned")}
    steps["verify"] = {"at": disabled.isoformat(), "checks": {"seeded": True}}
    db.add(LifecycleEvent(tenant_id=tenant.id, user_id=dave.id, kind="LEAVER", status="COMPLETED",
                          requested_by="hr-webhook", payload={"reason": "Resigned"}, steps=steps,
                          access_diff={"added": [], "removed": ["user", "sales-crm"]}, created_at=trigger,
                          completed_at=disabled))


def _stale_session(db: Any, tenant: Tenant, ivan: User | None, now: datetime) -> None:
    if ivan is None or db.execute(select(SessionRow.id).where(SessionRow.user_id == ivan.id,
                                                             SessionRow.source == "legacy")).first():
        return
    created = now - timedelta(hours=20)
    db.add(SessionRow(tenant_id=tenant.id, user_id=ivan.id, ip="203.0.113.12", geo={"country": "IN"}, asn="AS64500",
                      ua_hash=ua_hash(CHROME), user_agent=CHROME, source="legacy", created_at=created,
                      last_seen_at=created, expires_at=now + timedelta(days=7)))


def _api_keys(db: Any, tenant: Tenant, users: dict[str, User]) -> None:
    for name in ("bob", "dave"):
        u = users.get(name)
        if u is None or db.execute(select(ApiKey.id).where(ApiKey.user_id == u.id)).first():
            continue
        raw = f"isk_{tenant.realm}_seed{name}{uuid.uuid4().hex}"
        db.add(ApiKey(tenant_id=tenant.id, user_id=u.id, name=f"{name}-ci-token", prefix=raw[:12],
                      key_hash=sha256_hex(raw), revoked_at=u.deprovisioned_at if name == "dave" else None))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    seed_tenant("Acme Corp", "acme", ACME_USERS, rich=True)
    seed_tenant("Globex Inc", "globex", GLOBEX_USERS, rich=False)
    from app.detection.engine import run_periodic

    for realm in ("acme", "globex"):
        from app.db.session import platform_session

        with platform_session() as pdb:
            tid = pdb.execute(select(Tenant.id).where(Tenant.realm == realm)).scalar_one()
        with tenant_session(tid) as db:
            t = db.get(Tenant, tid)
            assert t is not None
            alerts = run_periodic(db, t)
            log.info("%s: periodic detections raised %d alerts", realm, len(alerts))
    s = get_settings()
    print("\nSeed complete.")
    print(f"  Dashboard: {s.public_url}   tenant: acme")
    print("  Users (password = DEMO_PASSWORD in .env): alice (admin), sam (analyst), hana (hr), bob (user)")
    print("  Second tenant for isolation tests: globex (gina = admin)")


if __name__ == "__main__":
    main()
