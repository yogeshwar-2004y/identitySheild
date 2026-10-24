from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import case, func, select

from app.core.deps import Ctx, require_roles
from app.core.security import utcnow
from app.hunt.service import COUNTRY
from app.models import Alert, Event, LifecycleEvent, Session as SessionRow, User

router = APIRouter(tags=["overview"])


@router.get("/overview")
def overview(ctx: Ctx = Depends(require_roles("admin", "analyst"))) -> dict[str, Any]:
    db, now = ctx.db, utcnow()
    day_ago, week_ago = now - timedelta(hours=24), now - timedelta(days=7)

    open_by_sev = dict(db.execute(select(Alert.severity, func.count()).where(Alert.status == "OPEN")
                                  .group_by(Alert.severity)).all())
    users_by_state = dict(db.execute(select(User.state, func.count()).group_by(User.state)).all())
    active_sessions = db.execute(select(func.count()).select_from(SessionRow).where(
        SessionRow.revoked_at.is_(None), SessionRow.expires_at > now)).scalar_one()

    day = func.date_trunc("day", Alert.created_at)
    alerts_daily = [
        {"day": d.date().isoformat(), "total": t, "critical": c, "high": h}
        for d, t, c, h in db.execute(
            select(day, func.count(), func.sum(case((Alert.severity == "critical", 1), else_=0)),
                   func.sum(case((Alert.severity == "high", 1), else_=0)))
            .where(Alert.created_at >= week_ago).group_by(day).order_by(day)).all()
    ]
    hour = func.date_trunc("hour", Event.ts)
    logins_hourly = [
        {"hour": h.isoformat(), "success": s, "failure": f}
        for h, s, f in db.execute(
            select(hour, func.sum(case((Event.type == "LOGIN", 1), else_=0)),
                   func.sum(case((Event.type == "LOGIN_ERROR", 1), else_=0)))
            .where(Event.ts >= day_ago, Event.type.in_(["LOGIN", "LOGIN_ERROR"])).group_by(hour).order_by(hour)).all()
    ]
    by_rule = [{"rule_key": k, "count": c} for k, c in db.execute(
        select(Alert.rule_key, func.count()).where(Alert.created_at >= week_ago).group_by(Alert.rule_key)
        .order_by(func.count().desc())).all()]
    risky = [{"user_id": str(uid), "username": un, "max_risk": r, "alerts": n} for uid, un, r, n in db.execute(
        select(Alert.user_id, User.username, func.max(Alert.risk), func.count())
        .join(User, User.id == Alert.user_id).where(Alert.status == "OPEN")
        .group_by(Alert.user_id, User.username).order_by(func.max(Alert.risk).desc()).limit(8)).all()]
    countries = [{"country": c, "count": n} for c, n in db.execute(
        select(COUNTRY, func.count()).where(Event.ts >= week_ago, Event.type == "LOGIN", Event.geo.is_not(None))
        .group_by(COUNTRY).order_by(func.count().desc()).limit(10)).all()]
    lifecycle = dict(db.execute(select(LifecycleEvent.kind, func.count()).where(LifecycleEvent.created_at >= week_ago)
                                .group_by(LifecycleEvent.kind)).all())
    pending_approvals = db.execute(select(func.count()).select_from(LifecycleEvent).where(
        LifecycleEvent.status == "PENDING_APPROVAL")).scalar_one()
    recent = [{"id": str(a.id), "rule_key": a.rule_key, "title": a.title, "severity": a.severity, "risk": a.risk,
               "created_at": a.created_at.isoformat(), "status": a.status}
              for a in db.execute(select(Alert).order_by(Alert.created_at.desc()).limit(8)).scalars()]
    return {
        "kpis": {
            "open_alerts": sum(open_by_sev.values()), "critical_open": open_by_sev.get("critical", 0),
            "active_sessions": active_sessions, "active_users": users_by_state.get("ACTIVE", 0),
            "deprovisioned_users": users_by_state.get("DEPROVISIONED", 0), "pending_approvals": pending_approvals,
            "events_24h": db.execute(select(func.count()).select_from(Event).where(Event.ts >= day_ago)).scalar_one(),
        },
        "open_by_severity": open_by_sev, "users_by_state": users_by_state, "alerts_daily": alerts_daily,
        "logins_hourly": logins_hourly, "alerts_by_rule": by_rule, "risky_users": risky,
        "login_countries": countries, "lifecycle_7d": lifecycle, "recent_alerts": recent,
    }
