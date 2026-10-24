from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, EmailStr, Field, ValidationError
from sqlalchemy import select

from app.core import redis as rds
from app.core.deps import Ctx, require_roles
from app.core.security import decrypt_str, hmac_sha256_hex
from app.core.tenancy import get_tenant_by_realm
from app.db.session import platform_session, tenant_session
from app.lifecycle.service import (
    LifecycleError, decide_approval, execute_joiner, execute_leaver, execute_mover, submit_joiner, submit_leaver,
    submit_mover,
)
from app.models import Approval, LifecycleEvent, Tenant, User

router = APIRouter(prefix="/lifecycle", tags=["lifecycle"])

NAME = r"^[\w .'-]+$"
DEPT = r"^[A-Za-z][A-Za-z &-]{1,40}$"
ROLE = r"^[a-z][a-z0-9-]{1,40}$"


class JoinerIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=200, pattern=NAME)
    email: EmailStr
    username: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9._-]{1,60}$")
    department: str = Field(pattern=DEPT)
    extra_roles: list[str] = Field(default_factory=list, max_length=10)
    send_invite: bool = True
    require_mfa: bool = True
    lab_demo_password: bool = False


class MoverIn(BaseModel):
    user_id: uuid.UUID
    new_department: str | None = Field(default=None, pattern=DEPT)
    add_roles: list[str] = Field(default_factory=list, max_length=10)
    remove_roles: list[str] = Field(default_factory=list, max_length=10)
    reason: str = Field(default="", max_length=500)


class LeaverIn(BaseModel):
    user_id: uuid.UUID
    reason: str = Field(default="", max_length=500)
    effective_at: datetime | None = None


class DecisionIn(BaseModel):
    approve: bool
    reason: str = Field(default="", max_length=500)


def lc_out(lc: LifecycleEvent, user: User | None = None) -> dict[str, Any]:
    return {
        "id": str(lc.id), "kind": lc.kind, "status": lc.status, "requested_by": lc.requested_by,
        "user_id": str(lc.user_id) if lc.user_id else None,
        "user": {"username": user.username, "email": user.email, "state": user.state,
                 "department": user.department} if user else None,
        "payload": lc.payload, "steps": lc.steps, "access_diff": lc.access_diff, "error": lc.error,
        "attempts": lc.attempts, "approval_id": str(lc.approval_id) if lc.approval_id else None,
        "effective_at": lc.effective_at.isoformat() if lc.effective_at else None,
        "created_at": lc.created_at.isoformat() if lc.created_at else None,
        "completed_at": lc.completed_at.isoformat() if lc.completed_at else None,
    }


def _err(exc: LifecycleError) -> HTTPException:
    return HTTPException(exc.status, detail={"code": "lifecycle_error", "message": str(exc)})


@router.post("/joiner", status_code=201)
def joiner(body: JoinerIn, ctx: Ctx = Depends(require_roles("admin", "hr")),
           idempotency_key: str | None = Header(default=None, max_length=120)) -> dict[str, Any]:
    try:
        lc = submit_joiner(ctx.db, ctx.tenant, actor=ctx.actor, full_name=body.full_name, email=str(body.email),
                           department=body.department, username=body.username, extra_roles=body.extra_roles,
                           send_invite=body.send_invite, require_mfa=body.require_mfa,
                           lab_demo_password=body.lab_demo_password, idempotency_key=idempotency_key)
    except LifecycleError as exc:
        raise _err(exc)
    return lc_out(lc, ctx.db.get(User, lc.user_id))


@router.post("/mover", status_code=201)
def mover(body: MoverIn, ctx: Ctx = Depends(require_roles("admin", "hr")),
          idempotency_key: str | None = Header(default=None, max_length=120)) -> dict[str, Any]:
    try:
        lc = submit_mover(ctx.db, ctx.tenant, actor=ctx.actor, user_id=body.user_id,
                          new_department=body.new_department, add_roles=body.add_roles,
                          remove_roles=body.remove_roles, reason=body.reason, idempotency_key=idempotency_key)
    except LifecycleError as exc:
        raise _err(exc)
    return lc_out(lc, ctx.db.get(User, lc.user_id))


@router.post("/leaver", status_code=201)
def leaver(body: LeaverIn, ctx: Ctx = Depends(require_roles("admin", "hr")),
           idempotency_key: str | None = Header(default=None, max_length=120)) -> dict[str, Any]:
    if body.user_id == ctx.principal.user_id:
        raise HTTPException(400, detail={"code": "self_leaver", "message": "You cannot deprovision yourself"})
    try:
        lc = submit_leaver(ctx.db, ctx.tenant, actor=ctx.actor, user_id=body.user_id, reason=body.reason,
                           effective_at=body.effective_at, idempotency_key=idempotency_key)
    except LifecycleError as exc:
        raise _err(exc)
    lc_id = lc.id
    ctx.commit()
    if lc.status in ("APPROVED", "FAILED", "RUNNING"):
        execute_leaver(ctx.tenant.id, lc_id, actor=ctx.actor)
    ctx.db.expire_all()
    lc = ctx.db.get(LifecycleEvent, lc_id)
    assert lc is not None
    return lc_out(lc, ctx.db.get(User, lc.user_id))


@router.get("/requests")
def list_requests(ctx: Ctx = Depends(require_roles("admin", "hr", "analyst")), kind: str | None = None,
                  status: str | None = None, limit: int = Query(100, le=500)) -> list[dict[str, Any]]:
    q = select(LifecycleEvent, User).outerjoin(User, User.id == LifecycleEvent.user_id)
    if kind:
        q = q.where(LifecycleEvent.kind == kind.upper())
    if status:
        q = q.where(LifecycleEvent.status == status.upper())
    rows = ctx.db.execute(q.order_by(LifecycleEvent.created_at.desc()).limit(limit)).all()
    return [lc_out(lc, u) for lc, u in rows]


@router.get("/{lifecycle_id}")
def get_request(lifecycle_id: uuid.UUID, ctx: Ctx = Depends(require_roles("admin", "hr", "analyst"))) -> dict[str, Any]:
    lc = ctx.db.get(LifecycleEvent, lifecycle_id)
    if lc is None:
        raise HTTPException(404, detail="Not found")
    out = lc_out(lc, ctx.db.get(User, lc.user_id) if lc.user_id else None)
    if lc.approval_id:
        ap = ctx.db.get(Approval, lc.approval_id)
        if ap:
            out["approval"] = {"status": ap.status, "requested_by": ap.requested_by, "approver": ap.approver,
                               "reason": ap.reason, "decided_at": ap.decided_at.isoformat() if ap.decided_at else None}
    return out


@router.post("/{lifecycle_id}/approve")
def approve(lifecycle_id: uuid.UUID, body: DecisionIn, ctx: Ctx = Depends(require_roles("admin"))) -> dict[str, Any]:
    lc = ctx.db.get(LifecycleEvent, lifecycle_id)
    if lc is None:
        raise HTTPException(404, detail="Not found")
    try:
        decide_approval(ctx.db, ctx.tenant, lc, approver=ctx.actor, approve=body.approve, reason=body.reason)
    except LifecycleError as exc:
        raise _err(exc)
    return lc_out(lc, ctx.db.get(User, lc.user_id))


@router.post("/{lifecycle_id}/retry")
def retry(lifecycle_id: uuid.UUID, ctx: Ctx = Depends(require_roles("admin", "hr"))) -> dict[str, Any]:
    lc = ctx.db.get(LifecycleEvent, lifecycle_id)
    if lc is None:
        raise HTTPException(404, detail="Not found")
    if lc.status not in ("FAILED", "RUNNING"):
        raise HTTPException(409, detail={"code": "not_retryable", "message": f"Status is {lc.status}"})
    if lc.kind == "LEAVER":
        ctx.commit()
        execute_leaver(ctx.tenant.id, lc.id, actor=ctx.actor)
        ctx.db.expire_all()
        lc = ctx.db.get(LifecycleEvent, lifecycle_id)
        assert lc is not None
    elif lc.kind == "JOINER":
        execute_joiner(ctx.db, ctx.tenant, lc, actor=ctx.actor)
    else:
        execute_mover(ctx.db, ctx.tenant, lc, actor=ctx.actor)
    return lc_out(lc, ctx.db.get(User, lc.user_id))


# ----------------------------------------------------------------- HR webhook


class HrEmployee(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=200, pattern=NAME)
    department: str = Field(pattern=DEPT)


class HrEvent(BaseModel):
    event: str = Field(pattern="^(hire|transfer|terminate)$")
    employee: HrEmployee
    effective_at: datetime | None = None
    idempotency_key: str = Field(min_length=8, max_length=120)


@router.post("/webhook/hr", status_code=202)
async def hr_webhook(request: Request, x_tenant: str = Header(...), x_hr_timestamp: str = Header(...),
                     x_hr_signature: str = Header(...)) -> dict[str, Any]:
    """HR system integration. Authenticated by HMAC-SHA256 over `timestamp + "." + body`
    with the tenant's webhook secret; 5-minute replay window plus signature nonce."""
    body = await request.body()
    try:
        ts = int(x_hr_timestamp)
    except ValueError:
        raise HTTPException(401, detail="bad timestamp")
    if abs(time.time() - ts) > 300:
        raise HTTPException(401, detail="timestamp outside replay window")
    with platform_session() as pdb:
        tenant = get_tenant_by_realm(pdb, x_tenant)
        if tenant is None or not tenant.hr_webhook_secret_enc:
            raise HTTPException(401, detail="unknown tenant")
        secret, tenant_id = decrypt_str(tenant.hr_webhook_secret_enc), tenant.id
    expected = "sha256=" + hmac_sha256_hex(secret, x_hr_timestamp.encode() + b"." + body)
    import hmac as _hmac

    if not _hmac.compare_digest(expected, x_hr_signature):
        raise HTTPException(401, detail="bad signature")
    if not rds.get_redis().set(f"hr:nonce:{x_hr_signature}", "1", nx=True, ex=600):
        raise HTTPException(409, detail="replayed request")
    try:
        evt = HrEvent.model_validate_json(body)
    except ValidationError as exc:
        raise HTTPException(422, detail={"code": "validation_error",
                                         "errors": [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]})
    actor = "hr-webhook"
    with tenant_session(tenant_id) as db:
        t = db.get(Tenant, tenant_id)
        assert t is not None
        try:
            if evt.event == "hire":
                lc = submit_joiner(db, t, actor=actor, full_name=evt.employee.full_name, email=str(evt.employee.email),
                                   department=evt.employee.department, idempotency_key=evt.idempotency_key)
                return {"lifecycle_id": str(lc.id), "status": lc.status}
            user = db.execute(select(User).where(User.email == str(evt.employee.email).lower())).scalar_one_or_none()
            if user is None:
                raise HTTPException(404, detail="employee not found")
            if evt.event == "transfer":
                lc = submit_mover(db, t, actor=actor, user_id=user.id, new_department=evt.employee.department,
                                  add_roles=[], remove_roles=[], reason="HR transfer",
                                  idempotency_key=evt.idempotency_key)
                return {"lifecycle_id": str(lc.id), "status": lc.status}
            lc = submit_leaver(db, t, actor=actor, user_id=user.id, reason="HR termination",
                               effective_at=evt.effective_at, idempotency_key=evt.idempotency_key)
            lc_id, status = lc.id, lc.status
        except LifecycleError as exc:
            raise _err(exc)
    if status in ("APPROVED", "FAILED"):
        status = execute_leaver(tenant_id, lc_id, actor=actor)
    return {"lifecycle_id": str(lc_id), "status": status}
