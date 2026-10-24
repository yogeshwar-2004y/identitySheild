"""SQL-backed DetectionContext. All queries run inside a tenant-bound session (RLS)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.core.security import utcnow
from app.detection.base import EventView, GrantView, LeaverView, UserView
from app.models import Event, LifecycleEvent, Role, User, UserRole


def to_view(e: Event) -> EventView:
    return EventView(
        id=e.id, ts=e.ts, type=e.type, user_id=e.user_id, session_id=e.session_id, username=e.username,
        ip=e.ip, geo=e.geo, asn=e.asn, ua_hash=e.user_agent_hash, outcome=e.outcome, source=e.source,
        details=e.details or {},
    )


def _user_view(u: User) -> UserView:
    return UserView(u.id, u.username, u.state, u.created_at, u.last_login_at, u.deprovisioned_at)


class SqlContext:
    def __init__(self, db: Session, tenant_id: uuid.UUID, now: datetime | None = None) -> None:
        self.db = db
        self.tenant_id = tenant_id
        self._now = now

    def now(self) -> datetime:
        return self._now or utcnow()

    def events(self, *, since: datetime, until: datetime | None = None, user_id: uuid.UUID | None = None,
               username: str | None = None, ip: str | None = None, session_id: uuid.UUID | None = None,
               types: list[str] | None = None, outcome: str | None = None, limit: int = 2000) -> list[EventView]:
        q = select(Event).where(Event.tenant_id == self.tenant_id, Event.ts >= since)
        if until is not None:
            q = q.where(Event.ts <= until)
        if user_id is not None:
            q = q.where(Event.user_id == user_id)
        if username is not None:
            q = q.where(Event.username == username)
        if ip is not None:
            q = q.where(Event.ip == ip)
        if session_id is not None:
            q = q.where(Event.session_id == session_id)
        if types:
            q = q.where(Event.type.in_(types))
        if outcome:
            q = q.where(Event.outcome == outcome)
        rows = self.db.execute(q.order_by(Event.ts.asc()).limit(limit)).scalars().all()
        return [to_view(e) for e in rows]

    def user(self, user_id: uuid.UUID) -> UserView | None:
        u = self.db.get(User, user_id)
        return _user_view(u) if u else None

    def user_grant(self, user_id: uuid.UUID, role: str) -> GrantView | None:
        row = self.db.execute(
            select(UserRole, Role.name).join(Role, Role.id == UserRole.role_id)
            .where(UserRole.user_id == user_id, Role.name == role)
        ).first()
        if not row:
            return None
        ur = row[0]
        return GrantView(role, ur.granted_by, ur.approval_id, ur.lifecycle_id)

    def role_sensitivity(self, role: str) -> str:
        v = self.db.execute(
            select(Role.sensitivity).where(Role.tenant_id == self.tenant_id, Role.name == role)
        ).scalar_one_or_none()
        return v or "LOW"

    def dormant_users(self, *, inactive_days: int) -> list[UserView]:
        cutoff = self.now() - timedelta(days=inactive_days)
        rows = self.db.execute(
            select(User).where(
                User.tenant_id == self.tenant_id, User.state == "ACTIVE",
                or_(User.last_login_at < cutoff, and_(User.last_login_at.is_(None), User.created_at < cutoff)),
            )
        ).scalars().all()
        return [_user_view(u) for u in rows]

    def leaver_requests(self, *, since: datetime) -> list[LeaverView]:
        rows = self.db.execute(
            select(LifecycleEvent).where(
                LifecycleEvent.tenant_id == self.tenant_id, LifecycleEvent.kind == "LEAVER",
                LifecycleEvent.created_at >= since,
                LifecycleEvent.status.notin_(["REJECTED", "CANCELLED"]),
            )
        ).scalars().all()
        out = []
        for r in rows:
            disabled = (r.steps or {}).get("disable_account", {}).get("at")
            out.append(LeaverView(
                r.id, r.user_id, r.status, r.effective_at or r.created_at,
                datetime.fromisoformat(disabled) if disabled else None,
            ))
        return out
