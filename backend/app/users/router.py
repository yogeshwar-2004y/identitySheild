from __future__ import annotations

import secrets
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from app.audit.service import write_audit
from app.core.deps import Ctx, get_ctx, require_roles
from app.core.security import sha256_hex, utcnow
from app.events.service import record_event
from app.hunt.service import user_timeline
from app.lifecycle.service import current_roles
from app.models import Alert, ApiKey, Role, RoleTemplate, Session as SessionRow, User

router = APIRouter(tags=["users"])


def user_out(u: User, roles: list[str] | None = None) -> dict[str, Any]:
    return {
        "id": str(u.id), "username": u.username, "email": u.email, "full_name": u.full_name,
        "department": u.department, "state": u.state, "mfa_enrolled": u.mfa_enrolled,
        "created_at": u.created_at.isoformat(), "activated_at": u.activated_at.isoformat() if u.activated_at else None,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        "deprovisioned_at": u.deprovisioned_at.isoformat() if u.deprovisioned_at else None,
        "roles": roles,
    }


def _resource_access(ctx: Ctx, resource: str) -> None:
    """RESOURCE_ACCESS events feed detection D11 (mass access)."""
    if ctx.principal.sid:
        record_event(ctx.db, ctx.tenant, type="RESOURCE_ACCESS", user_id=ctx.principal.user_id,
                     session_id=ctx.principal.sid, ip=ctx.client.ip, ua_hash=ctx.client.ua_hash,
                     details={"resource": resource})


@router.get("/users")
def list_users(ctx: Ctx = Depends(require_roles("admin", "analyst", "hr")), q: str | None = Query(None, max_length=100),
               state: str | None = None, limit: int = Query(200, le=1000)) -> list[dict[str, Any]]:
    stmt = select(User)
    if q:
        like = f"%{q.replace('%', '').replace('_', '')}%"
        stmt = stmt.where(or_(User.username.ilike(like), User.email.ilike(like), User.full_name.ilike(like)))
    if state:
        stmt = stmt.where(User.state == state.upper())
    users = ctx.db.execute(stmt.order_by(User.username).limit(limit)).scalars().all()
    role_map: dict[uuid.UUID, list[str]] = {}
    from app.models import UserRole

    for uid, name in ctx.db.execute(select(UserRole.user_id, Role.name).join(Role, Role.id == UserRole.role_id)).all():
        role_map.setdefault(uid, []).append(name)
    _resource_access(ctx, "users:list")
    return [user_out(u, sorted(role_map.get(u.id, []))) for u in users]


@router.get("/users/{user_id}")
def get_user(user_id: uuid.UUID, ctx: Ctx = Depends(require_roles("admin", "analyst", "hr"))) -> dict[str, Any]:
    u = ctx.db.get(User, user_id)
    if u is None:
        raise HTTPException(404, detail="User not found")
    out = user_out(u, current_roles(ctx.db, u.id))
    out["active_sessions"] = ctx.db.execute(select(func.count()).select_from(SessionRow).where(
        SessionRow.user_id == u.id, SessionRow.revoked_at.is_(None), SessionRow.expires_at > utcnow())).scalar_one()
    out["open_alerts"] = ctx.db.execute(select(func.count()).select_from(Alert).where(
        Alert.user_id == u.id, Alert.status == "OPEN")).scalar_one()
    out["api_keys"] = [{"id": str(k.id), "name": k.name, "prefix": k.prefix, "revoked": k.revoked_at is not None}
                       for k in ctx.db.execute(select(ApiKey).where(ApiKey.user_id == u.id)).scalars()]
    _resource_access(ctx, f"users:{user_id}")
    return out


@router.get("/users/{user_id}/timeline")
def timeline(user_id: uuid.UUID, ctx: Ctx = Depends(require_roles("admin", "analyst")),
             limit: int = Query(300, le=1000)) -> dict[str, Any]:
    u = ctx.db.get(User, user_id)
    if u is None:
        raise HTTPException(404, detail="User not found")
    return {"user": user_out(u, current_roles(ctx.db, u.id)), "items": user_timeline(ctx.db, ctx.tenant.id, u.id, limit)}


@router.get("/roles")
def roles(ctx: Ctx = Depends(require_roles("admin", "analyst", "hr"))) -> dict[str, Any]:
    rs = ctx.db.execute(select(Role).order_by(Role.name)).scalars().all()
    by_id = {r.id: r.name for r in rs}
    templates = ctx.db.execute(select(RoleTemplate).order_by(RoleTemplate.department)).scalars().all()
    return {
        "roles": [{"id": str(r.id), "name": r.name, "sensitivity": r.sensitivity} for r in rs],
        "templates": [{"department": t.department, "roles": sorted(by_id[i] for i in t.role_ids if i in by_id)}
                      for t in templates],
    }


class ApiKeyIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)


@router.get("/api-keys")
def my_keys(ctx: Ctx = Depends(get_ctx)) -> list[dict[str, Any]]:
    keys = ctx.db.execute(select(ApiKey).where(ApiKey.user_id == ctx.principal.user_id)
                          .order_by(ApiKey.created_at.desc())).scalars()
    return [{"id": str(k.id), "name": k.name, "prefix": k.prefix, "created_at": k.created_at.isoformat(),
             "revoked_at": k.revoked_at.isoformat() if k.revoked_at else None} for k in keys]


@router.post("/api-keys", status_code=201)
def create_key(body: ApiKeyIn, ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
    if ctx.principal.kind != "session":
        raise HTTPException(403, detail="API keys cannot mint API keys")
    raw = f"isk_{ctx.tenant.realm}_{secrets.token_urlsafe(32)}"
    key = ApiKey(tenant_id=ctx.tenant.id, user_id=ctx.principal.user_id, name=body.name, prefix=raw[:12],
                 key_hash=sha256_hex(raw))
    ctx.db.add(key)
    ctx.db.flush()
    write_audit(ctx.db, ctx.tenant.id, actor=ctx.actor, action="api_key.created", target=f"api_key:{key.id}",
                detail={"name": body.name, "prefix": key.prefix})
    return {"id": str(key.id), "name": key.name, "key": raw, "note": "Shown once. Store it securely."}


@router.delete("/api-keys/{key_id}")
def revoke_key(key_id: uuid.UUID, ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
    key = ctx.db.get(ApiKey, key_id)
    if key is None or (key.user_id != ctx.principal.user_id and not ctx.principal.has("admin")):
        raise HTTPException(404, detail="Not found")
    if key.revoked_at is None:
        key.revoked_at = utcnow()
        write_audit(ctx.db, ctx.tenant.id, actor=ctx.actor, action="api_key.revoked", target=f"api_key:{key.id}")
    return {"ok": True}
