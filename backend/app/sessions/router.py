from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from app.core import redis as rds
from app.core.deps import Ctx, get_ctx, require_roles
from app.core.security import utcnow
from app.models import Session as SessionRow, User
from app.sessions.service import revoke_session

router = APIRouter(tags=["sessions"])


def session_out(s: SessionRow, current_sid: uuid.UUID | None = None, username: str | None = None) -> dict[str, Any]:
    now = utcnow()
    last = rds.last_seen(str(s.id))
    active = s.revoked_at is None and s.expires_at > now
    return {
        "id": str(s.id), "user_id": str(s.user_id), "username": username, "ip": s.ip, "geo": s.geo, "asn": s.asn,
        "ua_hash": s.ua_hash[:16], "user_agent": s.user_agent, "source": s.source,
        "created_at": s.created_at.isoformat(), "expires_at": s.expires_at.isoformat(),
        "last_activity": (datetime.fromtimestamp(last, tz=timezone.utc).isoformat()
                          if last else s.last_seen_at.isoformat()),
        "revoked_at": s.revoked_at.isoformat() if s.revoked_at else None, "revoke_reason": s.revoke_reason,
        "active": active, "current": current_sid == s.id, "claims_version": s.claims_version,
        "parent_session_id": str(s.parent_session_id) if s.parent_session_id else None,
    }


@router.get("/sessions")
def my_sessions(ctx: Ctx = Depends(get_ctx), include_revoked: bool = False) -> list[dict[str, Any]]:
    """The caller's own sessions (every user can see and kill their sessions)."""
    q = select(SessionRow).where(SessionRow.user_id == ctx.principal.user_id)
    if not include_revoked:
        q = q.where(SessionRow.revoked_at.is_(None), SessionRow.expires_at > utcnow())
    rows = ctx.db.execute(q.order_by(SessionRow.created_at.desc()).limit(100)).scalars()
    return [session_out(s, ctx.principal.sid) for s in rows]


@router.get("/sessions/all")
def all_sessions(ctx: Ctx = Depends(require_roles("admin", "analyst")), include_revoked: bool = False
                 ) -> list[dict[str, Any]]:
    q = select(SessionRow, User.username).join(User, User.id == SessionRow.user_id)
    if not include_revoked:
        q = q.where(SessionRow.revoked_at.is_(None), SessionRow.expires_at > utcnow())
    rows = ctx.db.execute(q.order_by(SessionRow.created_at.desc()).limit(300)).all()
    return [session_out(s, ctx.principal.sid, un) for s, un in rows]


@router.get("/users/{user_id}/sessions")
def user_sessions(user_id: uuid.UUID, ctx: Ctx = Depends(require_roles("admin", "analyst"))) -> list[dict[str, Any]]:
    rows = ctx.db.execute(select(SessionRow).where(SessionRow.user_id == user_id)
                          .order_by(SessionRow.created_at.desc()).limit(100)).scalars()
    return [session_out(s, ctx.principal.sid) for s in rows]


@router.delete("/sessions/{session_id}")
def kill_session(session_id: uuid.UUID, ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
    s = ctx.db.get(SessionRow, session_id)
    # 404 (not 403) for other users' sessions so session ids cannot be probed.
    if s is None or (s.user_id != ctx.principal.user_id and not ctx.principal.has("admin", "analyst")):
        raise HTTPException(404, detail="Session not found")
    revoke_session(ctx.db, ctx.tenant, s, reason="killed_by_user" if s.user_id == ctx.principal.user_id
                   else "killed_by_admin", actor=ctx.actor)
    return {"ok": True, "session": session_out(s, ctx.principal.sid)}
