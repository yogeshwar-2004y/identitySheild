from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.audit.service import verify_chain, write_audit
from app.core.deps import Ctx, require_roles
from app.models import AuditLog

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def list_audit(ctx: Ctx = Depends(require_roles("admin", "analyst")), action: str | None = Query(None, max_length=80),
               actor: str | None = Query(None, max_length=160), before_id: int | None = None,
               limit: int = Query(200, le=1000)) -> list[dict[str, Any]]:
    q = select(AuditLog)
    if action:
        q = q.where(AuditLog.action.startswith(action))
    if actor:
        q = q.where(AuditLog.actor.ilike(f"%{actor.replace('%', '')}%"))
    if before_id:
        q = q.where(AuditLog.id < before_id)
    rows = ctx.db.execute(q.order_by(AuditLog.id.desc()).limit(limit)).scalars()
    return [{"id": r.id, "ts": r.ts.isoformat(), "actor": r.actor, "action": r.action, "target": r.target,
             "detail": r.detail, "prev_hash": r.prev_hash, "hash": r.hash} for r in rows]


@router.get("/verify")
def verify(ctx: Ctx = Depends(require_roles("admin", "analyst"))) -> dict[str, Any]:
    result = verify_chain(ctx.db, ctx.tenant.id)
    write_audit(ctx.db, ctx.tenant.id, actor=ctx.actor, action="audit.verified", target="audit_log",
                detail={"valid": result["valid"], "checked": result["checked"],
                        "broken_at_id": result.get("broken_at_id")})
    return result
