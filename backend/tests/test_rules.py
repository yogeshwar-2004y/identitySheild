"""Every detection rule has a positive and a negative test on synthetic event sequences."""
from __future__ import annotations

import uuid
from datetime import timedelta

from app.detection.base import GrantView, LeaverView, UserView
from app.detection.rules import RULE_CLASSES
from app.detection.rules.auth import BruteForce, CredentialStuffing, ImpossibleTravel, MfaFatigue, OffHoursAccess
from app.detection.rules.identity import DelayedDeprovisioning, GhostAccount, OrphanedAccount, PrivilegeEscalation
from app.detection.rules.session import MassAccess, RefreshTokenReuse, SessionHijack
from tests.fakes import T0, MemoryContext, ev

U = uuid.uuid4()
S = uuid.uuid4()
IN = {"country": "IN", "city": "Coimbatore", "lat": 11.0168, "lon": 76.9558}
US = {"country": "US", "city": "New York", "lat": 40.7128, "lon": -74.006}
IN2 = {"country": "IN", "city": "Bengaluru", "lat": 12.9716, "lon": 77.5946}


def test_registry_has_all_twelve_rules() -> None:
    assert sorted(RULE_CLASSES) == [f"D{i:02d}" for i in range(1, 13)]
    for cls in RULE_CLASSES.values():
        assert cls.attack_technique and cls.severity in ("low", "medium", "high", "critical") and 0 < cls.weight <= 100


# D01 ---------------------------------------------------------------------------------
def test_d01_impossible_travel_fires() -> None:
    a = ev("LOGIN", 0, user_id=U, geo=IN, ip="203.0.113.1")
    b = ev("LOGIN", 30, user_id=U, geo=US, ip="198.51.100.1")
    f = ImpossibleTravel().evaluate(b, MemoryContext([a, b]))
    assert len(f) == 1 and f[0].evidence["implied_speed_kmh"] > 900


def test_d01_plausible_travel_does_not_fire() -> None:
    a = ev("LOGIN", 0, user_id=U, geo=IN)
    b = ev("LOGIN", 60 * 20, user_id=U, geo=US)  # 20 hours later: ~650 km/h
    assert ImpossibleTravel().evaluate(b, MemoryContext([a, b])) == []
    c = ev("LOGIN", 10, user_id=U, geo=IN2)  # nearby city, short distance
    assert ImpossibleTravel().evaluate(c, MemoryContext([a, c])) == []


# D02 ---------------------------------------------------------------------------------
def test_d02_session_replay_fires_with_full_confidence() -> None:
    e = ev("SESSION_ANOMALY", user_id=U, session_id=S, ip="198.51.100.66",
           details={"changes": ["asn", "country", "user_agent"], "bound": {"ip": "203.0.113.10"}})
    f = SessionHijack().evaluate(e, MemoryContext([e]))
    assert f and f[0].confidence == 1.0 and f[0].session_id == S


def test_d02_no_changes_no_alert() -> None:
    e = ev("SESSION_ANOMALY", user_id=U, session_id=S, details={"changes": []})
    assert SessionHijack().evaluate(e, MemoryContext([e])) == []
    assert not SessionHijack().handles(ev("LOGIN"))


# D03 ---------------------------------------------------------------------------------
def test_d03_refresh_reuse_fires() -> None:
    e = ev("REFRESH_TOKEN_REUSE", user_id=U, session_id=S, details={"family_id": "f1"})
    assert RefreshTokenReuse().evaluate(e, MemoryContext([e]))[0].dedupe_key == "D03:f1"


def test_d03_ignores_normal_refresh() -> None:
    assert not RefreshTokenReuse().handles(ev("APP_TOKEN_REFRESH"))


# D04 ---------------------------------------------------------------------------------
def _ctx_with_user(state: str, deprov_minutes: float | None = None) -> MemoryContext:
    ctx = MemoryContext()
    ctx.users[U] = UserView(U, "asha", state, T0 - timedelta(days=90), None,
                            T0 + timedelta(minutes=deprov_minutes) if deprov_minutes is not None else None)
    return ctx


def test_d04_ghost_login_fires_for_deprovisioned_user() -> None:
    e = ev("LOGIN_ERROR", 10, user_id=U, outcome="FAILURE", details={"error": "user_disabled"})
    f = GhostAccount().evaluate(e, _ctx_with_user("DEPROVISIONED", 0))
    assert f and f[0].rule_key == "D04"


def test_d04_active_user_or_pre_deprovision_event_does_not_fire() -> None:
    e = ev("LOGIN", 10, user_id=U)
    assert GhostAccount().evaluate(e, _ctx_with_user("ACTIVE")) == []
    assert GhostAccount().evaluate(e, _ctx_with_user("DEPROVISIONED", 60)) == []  # event before deprovisioning
    assert not GhostAccount().handles(ev("SESSION_REVOKED"))  # workflow side effects never count


# D05 ---------------------------------------------------------------------------------
def test_d05_orphaned_account() -> None:
    ctx = MemoryContext(now=T0)
    stale, fresh = uuid.uuid4(), uuid.uuid4()
    ctx.users[stale] = UserView(stale, "frank", "ACTIVE", T0 - timedelta(days=200), T0 - timedelta(days=60), None)
    ctx.users[fresh] = UserView(fresh, "bob", "ACTIVE", T0 - timedelta(days=200), T0 - timedelta(days=1), None)
    found = OrphanedAccount().evaluate_periodic(ctx)
    assert [f.user_id for f in found] == [stale]


def test_d05_ignores_deprovisioned_and_new_accounts() -> None:
    ctx = MemoryContext(now=T0)
    a, b = uuid.uuid4(), uuid.uuid4()
    ctx.users[a] = UserView(a, "gone", "DEPROVISIONED", T0 - timedelta(days=200), None, T0)
    ctx.users[b] = UserView(b, "new", "ACTIVE", T0 - timedelta(days=3), None, None)
    assert OrphanedAccount().evaluate_periodic(ctx) == []


# D06 ---------------------------------------------------------------------------------
def test_d06_sensitive_grant_outside_workflow() -> None:
    e = ev("ROLE_GRANT", user_id=U, source="keycloak", details={"role": "admin"})
    f = PrivilegeEscalation().evaluate(e, MemoryContext([e]))
    assert f and f[0].confidence == 1.0


def test_d06_approved_grant_and_low_roles_do_not_fire() -> None:
    lc = uuid.uuid4()
    approved = ev("ROLE_GRANT", user_id=U, details={"role": "admin", "lifecycle_id": str(lc)})
    ctx = MemoryContext([approved])
    assert PrivilegeEscalation().evaluate(approved, ctx) == []
    ctx.grants[(U, "admin")] = GrantView("admin", "user:x", uuid.uuid4(), lc)
    kc_echo = ev("ROLE_GRANT", user_id=U, source="keycloak", details={"role": "admin", "via_identityshield": True})
    assert PrivilegeEscalation().evaluate(kc_echo, ctx) == []
    low = ev("ROLE_GRANT", user_id=U, source="keycloak", details={"role": "sales-crm"})
    assert PrivilegeEscalation().evaluate(low, MemoryContext([low])) == []


def test_d06_role_count_jump() -> None:
    evs = [ev("ROLE_GRANT", i, user_id=U, source="keycloak", details={"role": r})
           for i, r in enumerate(["sales-crm", "finance-viewer", "eng-developer"])]
    f = PrivilegeEscalation().evaluate(evs[-1], MemoryContext(evs))
    assert f and "jump" in f[0].title


# D07 / D08 ---------------------------------------------------------------------------
def test_d07_brute_force_threshold() -> None:
    fails = [ev("LOGIN_ERROR", i * 0.5, user_id=U, username="asha", ip="100.69.0.9", outcome="FAILURE") for i in range(5)]
    assert BruteForce().evaluate(fails[-1], MemoryContext(fails))
    assert BruteForce().evaluate(fails[3], MemoryContext(fails[:4])) == []


def test_d07_failures_spread_out_do_not_fire() -> None:
    fails = [ev("LOGIN_ERROR", i * 30, user_id=U, outcome="FAILURE") for i in range(6)]
    assert BruteForce().evaluate(fails[-1], MemoryContext(fails)) == []


def test_d08_credential_stuffing() -> None:
    fails = [ev("LOGIN_ERROR", i, username=f"user{i}", ip="100.65.0.7", outcome="FAILURE",
                details={"error": "user_not_found"}) for i in range(6)]
    f = CredentialStuffing().evaluate(fails[-1], MemoryContext(fails))
    assert f and f[0].evidence["distinct_accounts"] == 6


def test_d08_one_account_many_failures_is_not_stuffing() -> None:
    fails = [ev("LOGIN_ERROR", i, username="asha", ip="100.65.0.7", outcome="FAILURE") for i in range(8)]
    assert CredentialStuffing().evaluate(fails[-1], MemoryContext(fails)) == []


# D09 ---------------------------------------------------------------------------------
def test_d09_mfa_fatigue() -> None:
    prompts = [ev("MFA_DENIED", i, user_id=U) for i in range(5)]
    assert MfaFatigue().evaluate(prompts[-1], MemoryContext(prompts))


def test_d09_few_prompts_ok() -> None:
    prompts = [ev("MFA_CHALLENGE", i, user_id=U) for i in range(2)]
    assert MfaFatigue().evaluate(prompts[-1], MemoryContext(prompts)) == []


# D10 ---------------------------------------------------------------------------------
def _history(hour: int) -> list:
    return [ev("LOGIN", -60 * 24 * d + (hour - 9) * 60, user_id=U) for d in range(1, 15)]


def test_d10_off_hours_login() -> None:
    hist = _history(9)
    night = ev("LOGIN", -7 * 60, user_id=U)  # 02:00 UTC
    assert OffHoursAccess().evaluate(night, MemoryContext(hist + [night]))


def test_d10_normal_hours_and_cold_start() -> None:
    hist = _history(9)
    normal = ev("LOGIN", 30, user_id=U)  # 09:30 UTC
    assert OffHoursAccess().evaluate(normal, MemoryContext(hist + [normal])) == []
    night = ev("LOGIN", -7 * 60, user_id=U)
    assert OffHoursAccess().evaluate(night, MemoryContext(hist[:3] + [night])) == []  # not enough history


# D11 ---------------------------------------------------------------------------------
def test_d11_mass_access() -> None:
    reads = [ev("RESOURCE_ACCESS", i * 0.05, user_id=U, session_id=S, details={"resource": f"users:{i}"}) for i in range(60)]
    assert MassAccess().evaluate(reads[-1], MemoryContext(reads))


def test_d11_normal_volume() -> None:
    reads = [ev("RESOURCE_ACCESS", i, user_id=U, session_id=S) for i in range(10)]
    assert MassAccess().evaluate(reads[-1], MemoryContext(reads)) == []


# D12 ---------------------------------------------------------------------------------
def test_d12_leaver_sla_breach() -> None:
    ctx = MemoryContext(now=T0 + timedelta(hours=5))
    late = LeaverView(uuid.uuid4(), U, "COMPLETED", T0, T0 + timedelta(hours=3))
    stuck = LeaverView(uuid.uuid4(), U, "FAILED", T0, None)
    ctx.leavers = [late, stuck]
    found = DelayedDeprovisioning().evaluate_periodic(ctx)
    assert {f.evidence["lifecycle_id"] for f in found} == {str(late.id), str(stuck.id)}


def test_d12_within_sla_or_future() -> None:
    ctx = MemoryContext(now=T0 + timedelta(hours=5))
    ctx.leavers = [LeaverView(uuid.uuid4(), U, "COMPLETED", T0, T0 + timedelta(minutes=20)),
                   LeaverView(uuid.uuid4(), U, "SCHEDULED", T0 + timedelta(days=2), None)]
    assert DelayedDeprovisioning().evaluate_periodic(ctx) == []


def test_rule_params_override_defaults() -> None:
    fails = [ev("LOGIN_ERROR", i, user_id=U, outcome="FAILURE") for i in range(3)]
    assert BruteForce({"threshold": 3}).evaluate(fails[-1], MemoryContext(fails))
