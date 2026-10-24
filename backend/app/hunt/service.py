"""Threat hunting: saved (parameterized) hunts, ad hoc search, user timeline.

Hunt queries are stored as JSON, never as SQL:
  {"kind": "builtin", "name": "multi_country_logins", "params": {"window_hours": 24, "min_countries": 2}}
  {"kind": "filter",  "filters": {...SearchFilters...}, "group_by": "user", "min_count": 5}
Builtins are SQLAlchemy expressions with bound parameters. All queries run in a
tenant-bound transaction, so row-level security applies on top of the explicit
tenant filter.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import and_, distinct, extract, func, literal_column, select
from sqlalchemy.orm import Session

from app.core.security import utcnow
from app.core.tenancy import tenant_settings
from app.detection.rules.identity import ATTEMPT_TYPES
from app.models import (
    Alert, Event, LifecycleEvent, Role, Session as SessionRow, Tenant, User, UserRole,
)


class SearchFilters(BaseModel):
    types: list[str] = Field(default_factory=list, max_length=30)
    outcome: str | None = Field(default=None, pattern="^(SUCCESS|FAILURE)$")
    username: str | None = Field(default=None, max_length=254)
    user_id: uuid.UUID | None = None
    session_id: uuid.UUID | None = None
    ip: str | None = Field(default=None, max_length=64)
    country: str | None = Field(default=None, max_length=2)
    source: str | None = Field(default=None, max_length=20)
    since: datetime | None = None
    until: datetime | None = None
    since_hours: int | None = Field(default=None, ge=1, le=24 * 365)
    limit: int = Field(default=200, ge=1, le=2000)


# Constant JSON key rendered inline (not as a bind parameter) so SELECT and GROUP BY match.
COUNTRY = Event.geo.op("->>")(literal_column("'country'"))
GROUPABLE = {"user": Event.username, "ip": Event.ip, "type": Event.type, "country": COUNTRY}


def _event_row(e: Event) -> dict[str, Any]:
    return {
        "id": str(e.id), "ts": e.ts.isoformat(), "type": e.type, "outcome": e.outcome, "username": e.username,
        "user_id": str(e.user_id) if e.user_id else None, "session_id": str(e.session_id) if e.session_id else None,
        "ip": e.ip, "geo": e.geo, "asn": e.asn, "source": e.source, "details": e.details,
    }


def search_events(db: Session, tenant_id: uuid.UUID, f: SearchFilters, group_by: str | None = None,
                  min_count: int = 1) -> list[dict[str, Any]]:
    conds = [Event.tenant_id == tenant_id]
    if f.types:
        conds.append(Event.type.in_(f.types))
    if f.outcome:
        conds.append(Event.outcome == f.outcome)
    if f.username:
        conds.append(Event.username.ilike(f.username.replace("%", "").replace("_", r"\_") + "%"))
    if f.user_id:
        conds.append(Event.user_id == f.user_id)
    if f.session_id:
        conds.append(Event.session_id == f.session_id)
    if f.ip:
        conds.append(Event.ip == f.ip)
    if f.country:
        conds.append(COUNTRY == f.country.upper())
    if f.source:
        conds.append(Event.source == f.source)
    since = f.since or (utcnow() - timedelta(hours=f.since_hours) if f.since_hours else None)
    if since:
        conds.append(Event.ts >= since)
    if f.until:
        conds.append(Event.ts <= f.until)
    if group_by:
        col = GROUPABLE[group_by]
        q = (select(col.label("key"), func.count().label("count"), func.min(Event.ts), func.max(Event.ts),
                    func.count(distinct(Event.ip)), func.count(distinct(Event.username)))
             .where(and_(*conds)).group_by(col).having(func.count() >= min_count)
             .order_by(func.count().desc()).limit(f.limit))
        return [
            {"key": k, "count": c, "first_seen": fs.isoformat(), "last_seen": ls.isoformat(), "distinct_ips": di,
             "distinct_users": du}
            for k, c, fs, ls, di, du in db.execute(q).all()
        ]
    rows = db.execute(select(Event).where(and_(*conds)).order_by(Event.ts.desc()).limit(f.limit)).scalars()
    return [_event_row(e) for e in rows]


# ------------------------------------------------------------------------- builtins

Builtin = Callable[[Session, Tenant, dict[str, Any]], list[dict[str, Any]]]


def h_multi_country_logins(db: Session, t: Tenant, p: dict[str, Any]) -> list[dict[str, Any]]:
    since = utcnow() - timedelta(hours=int(p.get("window_hours", 24)))
    country = COUNTRY
    q = (select(Event.username, Event.user_id, func.count(distinct(country)), func.array_agg(distinct(country)))
         .where(Event.tenant_id == t.id, Event.type == "LOGIN", Event.outcome == "SUCCESS", Event.ts >= since,
                country.is_not(None))
         .group_by(Event.username, Event.user_id)
         .having(func.count(distinct(country)) >= int(p.get("min_countries", 2))))
    return [{"username": u, "user_id": str(uid), "countries": sorted(cs), "country_count": n}
            for u, uid, n, cs in db.execute(q).all()]


def h_dormant_then_active(db: Session, t: Tenant, p: dict[str, Any]) -> list[dict[str, Any]]:
    now = utcnow()
    recent_start = now - timedelta(days=int(p.get("recent_days", 7)))
    dormant = timedelta(days=int(p.get("dormant_days", 30)))
    logins = and_(Event.tenant_id == t.id, Event.type == "LOGIN", Event.outcome == "SUCCESS")
    recent = (select(Event.user_id, func.min(Event.ts).label("first_recent"))
              .where(logins, Event.ts >= recent_start, Event.user_id.is_not(None)).group_by(Event.user_id).subquery())
    out = []
    for uid, first_recent in db.execute(select(recent.c.user_id, recent.c.first_recent)).all():
        prev = db.execute(select(func.max(Event.ts)).where(logins, Event.user_id == uid, Event.ts < recent_start)
                          ).scalar_one_or_none()
        user = db.get(User, uid)
        if user is None:
            continue
        baseline = prev or user.created_at
        if first_recent - baseline >= dormant:
            out.append({"username": user.username, "user_id": str(uid), "previous_login": prev.isoformat() if prev
                        else None, "reactivated_at": first_recent.isoformat(),
                        "dormant_days": (first_recent - baseline).days})
    return out


def h_sessions_beyond_absolute(db: Session, t: Tenant, p: dict[str, Any]) -> list[dict[str, Any]]:
    hours = int(p.get("absolute_hours", tenant_settings(t).absolute_timeout_hours))
    cutoff = utcnow() - timedelta(hours=hours)
    q = (select(SessionRow, User.username).join(User, User.id == SessionRow.user_id)
         .where(SessionRow.tenant_id == t.id, SessionRow.revoked_at.is_(None), SessionRow.created_at < cutoff))
    return [{"username": un, "user_id": str(s.user_id), "session_id": str(s.id), "created_at": s.created_at.isoformat(),
             "age_hours": round((utcnow() - s.created_at).total_seconds() / 3600, 1), "ip": s.ip}
            for s, un in db.execute(q).all()]


def h_many_role_grants(db: Session, t: Tenant, p: dict[str, Any]) -> list[dict[str, Any]]:
    q = (select(User.username, User.id, User.department, func.count(), func.array_agg(Role.name))
         .join(UserRole, UserRole.user_id == User.id).join(Role, Role.id == UserRole.role_id)
         .where(User.tenant_id == t.id, User.state != "DEPROVISIONED")
         .group_by(User.username, User.id, User.department)
         .having(func.count() >= int(p.get("min_roles", 4))))
    return [{"username": u, "user_id": str(uid), "department": d, "role_count": n, "roles": sorted(rs)}
            for u, uid, d, n, rs in db.execute(q).all()]


def h_deprovisioned_activity(db: Session, t: Tenant, p: dict[str, Any]) -> list[dict[str, Any]]:
    q = (select(User.username, User.id, User.deprovisioned_at, func.count(), func.max(Event.ts),
                func.array_agg(distinct(Event.type)))
         .join(Event, Event.user_id == User.id)
         .where(User.tenant_id == t.id, User.state == "DEPROVISIONED", Event.ts > User.deprovisioned_at,
                Event.type.in_(sorted(ATTEMPT_TYPES)))
         .group_by(User.username, User.id, User.deprovisioned_at))
    return [{"username": u, "user_id": str(uid), "deprovisioned_at": d.isoformat() if d else None, "events": n,
             "last_activity": last.isoformat(), "types": sorted(ts)}
            for u, uid, d, n, last, ts in db.execute(q).all()]


def h_failing_ips(db: Session, t: Tenant, p: dict[str, Any]) -> list[dict[str, Any]]:
    since = utcnow() - timedelta(hours=int(p.get("window_hours", 24)))
    q = (select(Event.ip, func.count(), func.count(distinct(Event.username)), func.array_agg(distinct(Event.username)))
         .where(Event.tenant_id == t.id, Event.type == "LOGIN_ERROR", Event.ts >= since, Event.ip.is_not(None))
         .group_by(Event.ip).having(func.count(distinct(Event.username)) >= int(p.get("min_users", 5))))
    return [{"ip": ip, "failures": n, "distinct_users": du, "usernames": sorted(x for x in us if x)[:30]}
            for ip, n, du, us in db.execute(q).all()]


def h_off_hours_logins(db: Session, t: Tenant, p: dict[str, Any]) -> list[dict[str, Any]]:
    since = utcnow() - timedelta(days=int(p.get("days", 7)))
    hour = extract("hour", func.timezone("UTC", Event.ts))
    q = (select(Event).where(Event.tenant_id == t.id, Event.type == "LOGIN", Event.outcome == "SUCCESS",
                             Event.ts >= since, hour >= int(p.get("start_hour", 0)), hour < int(p.get("end_hour", 5)))
         .order_by(Event.ts.desc()).limit(500))
    return [{"username": e.username, "user_id": str(e.user_id) if e.user_id else None, "ts": e.ts.isoformat(),
             "ip": e.ip, "country": (e.geo or {}).get("country")} for e in db.execute(q).scalars()]


def h_token_abuse(db: Session, t: Tenant, p: dict[str, Any]) -> list[dict[str, Any]]:
    since = utcnow() - timedelta(days=int(p.get("days", 7)))
    q = (select(Event.username, Event.user_id, func.count(), func.array_agg(distinct(Event.type)),
                func.array_agg(distinct(Event.ip)))
         .where(Event.tenant_id == t.id, Event.ts >= since,
                Event.type.in_(["REFRESH_TOKEN_REUSE", "TOKEN_REJECTED", "SESSION_ANOMALY"]))
         .group_by(Event.username, Event.user_id))
    return [{"username": u, "user_id": str(uid) if uid else None, "events": n, "types": sorted(ts),
             "ips": sorted(x for x in ips if x)} for u, uid, n, ts, ips in db.execute(q).all()]


def h_sensitive_without_approval(db: Session, t: Tenant, p: dict[str, Any]) -> list[dict[str, Any]]:
    q = (select(User.username, User.id, Role.name, UserRole.granted_by, UserRole.granted_at)
         .join(UserRole, UserRole.user_id == User.id).join(Role, Role.id == UserRole.role_id)
         .where(User.tenant_id == t.id, Role.sensitivity == "HIGH", UserRole.approval_id.is_(None),
                UserRole.lifecycle_id.is_(None), UserRole.granted_by.notin_(["seed", "tenant-bootstrap"])))
    return [{"username": u, "user_id": str(uid), "role": r, "granted_by": gb, "granted_at": ga.isoformat()}
            for u, uid, r, gb, ga in db.execute(q).all()]


def h_never_logged_in(db: Session, t: Tenant, p: dict[str, Any]) -> list[dict[str, Any]]:
    cutoff = utcnow() - timedelta(days=int(p.get("days", 14)))
    q = select(User).where(User.tenant_id == t.id, User.state == "ACTIVE", User.last_login_at.is_(None),
                           User.created_at < cutoff)
    return [{"username": u.username, "user_id": str(u.id), "department": u.department,
             "created_at": u.created_at.isoformat()} for u in db.execute(q).scalars()]


BUILTINS: dict[str, Builtin] = {
    "multi_country_logins": h_multi_country_logins,
    "dormant_then_active": h_dormant_then_active,
    "sessions_beyond_absolute": h_sessions_beyond_absolute,
    "many_role_grants": h_many_role_grants,
    "deprovisioned_activity": h_deprovisioned_activity,
    "failing_ips_many_users": h_failing_ips,
    "off_hours_logins": h_off_hours_logins,
    "token_abuse": h_token_abuse,
    "sensitive_roles_without_approval": h_sensitive_without_approval,
    "never_logged_in": h_never_logged_in,
}

PREBUILT_HUNTS: list[dict[str, Any]] = [
    {"name": "Logins from multiple countries in 24h", "attack_technique": "T1078",
     "hypothesis": "An account used from several countries within a day is shared or compromised.",
     "query": {"kind": "builtin", "name": "multi_country_logins", "params": {"window_hours": 24, "min_countries": 2}}},
    {"name": "Dormant accounts that suddenly log in", "attack_technique": "T1078",
     "hypothesis": "Attackers revive forgotten accounts because nobody watches them.",
     "query": {"kind": "builtin", "name": "dormant_then_active", "params": {"dormant_days": 30, "recent_days": 7}}},
    {"name": "Sessions older than the absolute limit", "attack_technique": "T1550",
     "hypothesis": "A live session older than policy means a control failed or a token was minted outside it.",
     "query": {"kind": "builtin", "name": "sessions_beyond_absolute", "params": {}}},
    {"name": "Users with many role grants", "attack_technique": "T1098",
     "hypothesis": "Privilege creep: accounts accumulating roles beyond their department template.",
     "query": {"kind": "builtin", "name": "many_role_grants", "params": {"min_roles": 4}}},
    {"name": "Deprovisioned users with activity", "attack_technique": "T1078",
     "hypothesis": "Any activity after deprovisioning means the leaver process missed a credential.",
     "query": {"kind": "builtin", "name": "deprovisioned_activity", "params": {}}},
    {"name": "IPs failing against many accounts", "attack_technique": "T1110.004",
     "hypothesis": "One source failing across many accounts is credential stuffing or spraying.",
     "query": {"kind": "builtin", "name": "failing_ips_many_users", "params": {"window_hours": 24, "min_users": 5}}},
    {"name": "Off-hours successful logins", "attack_technique": "T1078",
     "hypothesis": "Logins between 00:00 and 05:00 UTC are unusual for this workforce.",
     "query": {"kind": "builtin", "name": "off_hours_logins", "params": {"start_hour": 0, "end_hour": 5, "days": 7}}},
    {"name": "Token replay and reuse", "attack_technique": "T1539",
     "hypothesis": "Rejected, replayed or reused tokens indicate stolen session material.",
     "query": {"kind": "builtin", "name": "token_abuse", "params": {"days": 7}}},
    {"name": "Sensitive roles granted outside the workflow", "attack_technique": "T1098",
     "hypothesis": "HIGH-sensitivity roles must come from an approved lifecycle request.",
     "query": {"kind": "builtin", "name": "sensitive_roles_without_approval", "params": {}}},
    {"name": "Active accounts that never logged in", "attack_technique": "T1078",
     "hypothesis": "Provisioned-but-unused accounts are orphan candidates for takeover.",
     "query": {"kind": "builtin", "name": "never_logged_in", "params": {"days": 14}}},
]


def run_query(db: Session, tenant: Tenant, query: dict[str, Any], overrides: dict[str, Any] | None = None
              ) -> list[dict[str, Any]]:
    kind = query.get("kind")
    if kind == "builtin":
        fn = BUILTINS.get(str(query.get("name")))
        if fn is None:
            raise ValueError(f"unknown builtin hunt {query.get('name')}")
        return fn(db, tenant, {**(query.get("params") or {}), **(overrides or {})})
    if kind == "filter":
        filters = SearchFilters(**{**(query.get("filters") or {}), **(overrides or {})})
        group_by = query.get("group_by")
        if group_by is not None and group_by not in GROUPABLE:
            raise ValueError("invalid group_by")
        return search_events(db, tenant.id, filters, group_by, int(query.get("min_count", 1)))
    raise ValueError("query.kind must be 'builtin' or 'filter'")


# ------------------------------------------------------------------------- timeline


def user_timeline(db: Session, tenant_id: uuid.UUID, user_id: uuid.UUID, limit: int = 300) -> list[dict[str, Any]]:
    """Lifecycle + session + event + alert history for one identity, newest first."""
    items: list[dict[str, Any]] = []
    for e in db.execute(select(Event).where(Event.tenant_id == tenant_id, Event.user_id == user_id)
                        .order_by(Event.ts.desc()).limit(limit)).scalars():
        items.append({"ts": e.ts, "category": "event", "type": e.type, "outcome": e.outcome,
                      "summary": f"{e.type} from {e.ip or '-'} ({(e.geo or {}).get('city', '?')})",
                      "ref": str(e.id), "data": {"ip": e.ip, "geo": e.geo, "source": e.source, "details": e.details,
                                                  "session_id": str(e.session_id) if e.session_id else None}})
    for lc in db.execute(select(LifecycleEvent).where(LifecycleEvent.tenant_id == tenant_id,
                                                      LifecycleEvent.user_id == user_id)).scalars():
        items.append({"ts": lc.created_at, "category": "lifecycle", "type": lc.kind, "outcome": lc.status,
                      "summary": f"{lc.kind} request ({lc.status}) by {lc.requested_by}", "ref": str(lc.id),
                      "data": {"access_diff": lc.access_diff, "steps": lc.steps}})
    for s in db.execute(select(SessionRow).where(SessionRow.tenant_id == tenant_id, SessionRow.user_id == user_id)
                        ).scalars():
        items.append({"ts": s.created_at, "category": "session", "type": "SESSION_START", "outcome": "SUCCESS",
                      "summary": f"Session from {s.ip} ({(s.geo or {}).get('city', '?')})", "ref": str(s.id),
                      "data": {"revoked_at": s.revoked_at, "revoke_reason": s.revoke_reason}})
        if s.revoked_at:
            items.append({"ts": s.revoked_at, "category": "session", "type": "SESSION_END", "outcome": "REVOKED",
                          "summary": f"Session ended: {s.revoke_reason}", "ref": str(s.id), "data": {}})
    for a in db.execute(select(Alert).where(Alert.tenant_id == tenant_id, Alert.user_id == user_id)).scalars():
        items.append({"ts": a.created_at, "category": "alert", "type": a.rule_key, "outcome": a.severity,
                      "summary": a.title, "ref": str(a.id), "data": {"risk": a.risk, "status": a.status}})
    items.sort(key=lambda i: i["ts"], reverse=True)
    for i in items:
        i["ts"] = i["ts"].isoformat()
    return items[:limit]
