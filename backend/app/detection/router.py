from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator
from typing import Any

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.audit.service import write_audit
from app.core.config import get_settings
from app.core.deps import Ctx, require_roles
from app.core.redis import alert_channel
from app.core.security import utcnow
from app.detection.rules import RULE_CLASSES
from app.models import Alert, DetectionRule, Event, User

router = APIRouter(tags=["detection"])


def alert_out(a: Alert, username: str | None = None) -> dict[str, Any]:
    return {
        "id": str(a.id), "rule_key": a.rule_key, "title": a.title, "severity": a.severity, "risk": a.risk,
        "status": a.status, "attack_technique": a.attack_technique, "user_id": str(a.user_id) if a.user_id else None,
        "username": username, "session_id": str(a.session_id) if a.session_id else None,
        "created_at": a.created_at.isoformat(), "updated_at": a.updated_at.isoformat() if a.updated_at else None,
        "notes": a.notes,
    }


@router.get("/alerts")
def list_alerts(ctx: Ctx = Depends(require_roles("admin", "analyst")), status: str | None = None,
                severity: str | None = None, rule_key: str | None = None, user_id: uuid.UUID | None = None,
                limit: int = Query(200, le=1000)) -> list[dict[str, Any]]:
    q = select(Alert, User.username).outerjoin(User, User.id == Alert.user_id)
    if status:
        q = q.where(Alert.status == status.upper())
    if severity:
        q = q.where(Alert.severity == severity.lower())
    if rule_key:
        q = q.where(Alert.rule_key == rule_key.upper())
    if user_id:
        q = q.where(Alert.user_id == user_id)
    rows = ctx.db.execute(q.order_by(Alert.created_at.desc()).limit(limit)).all()
    return [alert_out(a, u) for a, u in rows]


@router.get("/alerts/stream")
async def alert_stream(request: Request, ctx: Ctx = Depends(require_roles("admin", "analyst"))) -> StreamingResponse:
    """Server-sent events backed by Redis pub/sub. The SPA reads it with fetch() so the
    bearer token travels in a header, not in the URL."""
    channel = alert_channel(str(ctx.tenant.id))
    ctx.db.close()  # do not hold a DB connection for the life of the stream

    async def gen() -> AsyncIterator[str]:
        r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        ps = r.pubsub()
        await ps.subscribe(channel)
        try:
            yield "event: ready\ndata: {}\n\n"
            idle = 0
            while not await request.is_disconnected():
                msg = await ps.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg.get("type") == "message":
                    yield f"event: alert\ndata: {msg['data']}\n\n"
                    idle = 0
                else:
                    idle += 1
                    if idle >= 15:
                        yield ": keepalive\n\n"
                        idle = 0
                await asyncio.sleep(0)
        finally:
            await ps.unsubscribe(channel)
            await ps.aclose()
            await r.aclose()

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: uuid.UUID, ctx: Ctx = Depends(require_roles("admin", "analyst"))) -> dict[str, Any]:
    a = ctx.db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(404, detail="Alert not found")
    user = ctx.db.get(User, a.user_id) if a.user_id else None
    out = alert_out(a, user.username if user else None)
    out["evidence"] = a.evidence
    out["response"] = a.response
    out["user"] = {"id": str(user.id), "username": user.username, "email": user.email, "state": user.state,
                   "department": user.department} if user else None
    trig = a.evidence.get("trigger_event_id")
    if trig:
        ev = ctx.db.get(Event, uuid.UUID(trig))
        if ev:
            out["trigger_event"] = {"type": ev.type, "ts": ev.ts.isoformat(), "ip": ev.ip, "geo": ev.geo,
                                    "source": ev.source, "details": ev.details}
    return out


class AlertPatch(BaseModel):
    status: str | None = Field(default=None, pattern="^(OPEN|ACKNOWLEDGED|RESOLVED|FALSE_POSITIVE)$")
    notes: str | None = Field(default=None, max_length=4000)


@router.patch("/alerts/{alert_id}")
def patch_alert(alert_id: uuid.UUID, body: AlertPatch, ctx: Ctx = Depends(require_roles("admin", "analyst"))
                ) -> dict[str, Any]:
    a = ctx.db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(404, detail="Alert not found")
    before = a.status
    if body.status:
        a.status = body.status
    if body.notes is not None:
        a.notes = body.notes
    a.updated_at = utcnow()
    write_audit(ctx.db, ctx.tenant.id, actor=ctx.actor, action="alert.updated", target=f"alert:{a.id}",
                detail={"from": before, "to": a.status, "notes": bool(body.notes)})
    return alert_out(a)


def rule_out(r: DetectionRule) -> dict[str, Any]:
    cls = RULE_CLASSES.get(r.rule_key)
    return {"id": str(r.id), "rule_key": r.rule_key, "name": r.name, "severity": r.severity, "weight": r.weight,
            "attack_technique": r.attack_technique, "enabled": r.enabled, "params": r.params,
            "periodic": bool(cls and cls.periodic), "description": (cls.__doc__ or "").strip() if cls else "",
            "event_types": sorted(cls.event_types) if cls else []}


@router.get("/rules")
def list_rules(ctx: Ctx = Depends(require_roles("admin", "analyst"))) -> list[dict[str, Any]]:
    return [rule_out(r) for r in ctx.db.execute(select(DetectionRule).order_by(DetectionRule.rule_key)).scalars()]


class RulePatch(BaseModel):
    enabled: bool | None = None
    severity: str | None = Field(default=None, pattern="^(low|medium|high|critical)$")
    weight: int | None = Field(default=None, ge=0, le=100)
    params: dict[str, int | float] | None = None


@router.put("/rules/{rule_id}")
def update_rule(rule_id: uuid.UUID, body: RulePatch, ctx: Ctx = Depends(require_roles("admin"))) -> dict[str, Any]:
    r = ctx.db.get(DetectionRule, rule_id)
    if r is None:
        raise HTTPException(404, detail="Rule not found")
    before = rule_out(r)
    if body.enabled is not None:
        r.enabled = body.enabled
    if body.severity:
        r.severity = body.severity
    if body.weight is not None:
        r.weight = body.weight
    if body.params is not None:
        allowed = set(RULE_CLASSES[r.rule_key].default_params)
        bad = set(body.params) - allowed
        if bad:
            raise HTTPException(422, detail=f"Unknown params: {sorted(bad)}; allowed: {sorted(allowed)}")
        r.params = {**r.params, **body.params}
    write_audit(ctx.db, ctx.tenant.id, actor=ctx.actor, action="rule.updated", target=f"rule:{r.rule_key}",
                detail={"before": {k: before[k] for k in ("enabled", "severity", "weight", "params")},
                        "after": json.loads(json.dumps({k: rule_out(r)[k] for k in ("enabled", "severity", "weight",
                                                                                     "params")}))})
    return rule_out(r)
