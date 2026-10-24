"""LAB-ONLY endpoints used by the attack simulator and the headless demo.

Mounted only when LAB_MODE=true, and every call needs the X-Lab-Key header
(except /lab/scenarios/*, which requires an authenticated admin and injects
the key server-side so it never reaches the browser).
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.config import get_settings
from app.core.deps import Ctx, client_info, require_lab, require_roles
from app.core.keycloak import InvalidGrant, KeycloakError, KeycloakPlatformAdmin
from app.core.tenancy import get_tenant_by_realm, idp_for
from app.db.session import platform_session, tenant_session
from app.events.poller import poll_tenant
from app.events.service import record_event
from app.models import Tenant, User

log = logging.getLogger(__name__)
router = APIRouter(prefix="/lab", tags=["lab"])


class LabLogin(BaseModel):
    tenant: str = Field(pattern="^[a-z][a-z0-9-]{1,30}$")
    username: str = Field(min_length=1, max_length=120)
    password: str | None = Field(default=None, max_length=200)


def _tenant_id(realm: str) -> Any:
    with platform_session() as db:
        t = get_tenant_by_realm(db, realm)
        if t is None:
            raise HTTPException(404, detail="unknown tenant")
        return t.id


@router.post("/login", dependencies=[Depends(require_lab)])
def lab_login(body: LabLogin, request: Request) -> dict[str, Any]:
    """Password grant against Keycloak on behalf of the simulator. The synthetic client IP
    (X-Lab-Client-IP) is forwarded to Keycloak so its LOGIN / LOGIN_ERROR events carry it."""
    from app.auth.router import _complete_login, refresh_token_for_tenant, token_response
    from app.sessions.service import SessionError, user_role_names

    client = client_info(request)
    tenant_id = _tenant_id(body.tenant)
    password = body.password if body.password is not None else get_settings().demo_password
    result: dict[str, Any]
    with tenant_session(tenant_id) as db:
        tenant = db.get(Tenant, tenant_id)
        assert tenant is not None
        try:
            kc = idp_for(tenant).password_grant(username=body.username, password=password, forwarded_for=client.ip,
                                                user_agent=client.user_agent)
        except InvalidGrant as exc:
            result = {"ok": False, "error": (exc.body or {}).get("error_description", str(exc))
                      if isinstance(exc.body, dict) else str(exc)}
            kc = None
        except KeycloakError as exc:
            raise HTTPException(502, detail=f"identity provider error: {exc} {exc.body}")
        if kc is not None:
            claims = _unverified(kc["access_token"])
            user = db.execute(select(User).where(User.kc_user_id == claims.get("sub"))).scalar_one_or_none()
            if user is None or user.state in ("DEPROVISIONED", "SUSPENDED"):
                if user is not None:
                    record_event(db, tenant, type="TOKEN_REJECTED", user_id=user.id, ip=client.ip,
                                 ua_hash=client.ua_hash, outcome="FAILURE", details={"reason": f"user_{user.state}"})
                result = {"ok": False, "error": "account not active in IdentityShield"}
            else:
                try:
                    issued = _complete_login(db, tenant, user, client.ip, client.user_agent, kc, claims.get("sid"),
                                             "lab")
                except SessionError as exc:
                    raise HTTPException(409, detail=str(exc))
                roles = [r for r in user_role_names(db, user.id) if r in ("admin", "analyst", "hr", "user")]
                result = {"ok": True, **token_response(issued, roles),
                          "refresh_token": refresh_token_for_tenant(tenant.id, issued.refresh_token)}
    _poll_now(tenant_id)
    if not result["ok"]:
        raise HTTPException(401, detail=result["error"])
    return result


def _unverified(token: str) -> dict[str, Any]:
    import jwt

    return dict(jwt.decode(token, options={"verify_signature": False}))


def _poll_now(tenant_id: Any) -> None:
    """Pull Keycloak events immediately so the simulator sees detections without waiting."""
    try:
        poll_tenant(tenant_id, wait_lock=5)
    except Exception:
        log.exception("immediate poll failed")


class RogueGrant(BaseModel):
    tenant: str = Field(pattern="^[a-z][a-z0-9-]{1,30}$")
    username: str = Field(min_length=1, max_length=120)
    role: str = Field(pattern="^[a-z][a-z0-9-]{1,40}$")


@router.post("/rogue-role-grant", dependencies=[Depends(require_lab)])
def rogue_role_grant(body: RogueGrant) -> dict[str, Any]:
    tenant_id = _tenant_id(body.tenant)
    try:
        KeycloakPlatformAdmin().grant_realm_role_directly(body.tenant, body.username, body.role)
    except KeycloakError as exc:
        raise HTTPException(400, detail=str(exc))
    _poll_now(tenant_id)
    return {"ok": True, "granted": body.role, "to": body.username, "via": "keycloak admin console (bypass)"}


@router.post("/poll", dependencies=[Depends(require_lab)])
def poll(tenant: str) -> dict[str, Any]:
    return poll_tenant(_tenant_id(tenant), wait_lock=5)


# ---------------------------------------------------------------- UI scenario runner


class ScenarioIn(BaseModel):
    victim: str = Field(default="asha", pattern=r"^[a-z][a-z0-9._-]{1,60}$")


@router.get("/scenarios")
def scenarios(ctx: Ctx = Depends(require_roles("admin"))) -> dict[str, Any]:
    if not get_settings().lab_mode:
        raise HTTPException(404, detail="Not found")
    from simulator.scenarios import SCENARIOS

    return {"scenarios": [{"name": k, "expected": v.expected, "description": v.description}
                          for k, v in SCENARIOS.items()]}


@router.post("/scenarios/{name}")
def run_scenario(name: str, body: ScenarioIn, ctx: Ctx = Depends(require_roles("admin"))) -> dict[str, Any]:
    s = get_settings()
    if not s.lab_mode:
        raise HTTPException(404, detail="Not found")
    from simulator.client import LabClient
    from simulator.scenarios import SCENARIOS

    scenario = SCENARIOS.get(name)
    if scenario is None:
        raise HTTPException(404, detail="Unknown scenario")
    tenant_realm = ctx.tenant.realm
    ctx.commit()
    lines: list[str] = []
    client = LabClient("http://127.0.0.1:8000", s.lab_api_key, tenant_realm, log=lines.append)
    try:
        ok = scenario.run(client, victim=body.victim)
    except Exception as exc:  # report, do not 500
        lines.append(f"!! scenario error: {exc}")
        ok = False
    return {"scenario": name, "expected": scenario.expected, "ok": ok, "output": lines}


@router.get("/alerts", dependencies=[Depends(require_lab)])
def lab_alerts(tenant: str, rule_key: str, since_epoch: int) -> list[dict[str, Any]]:
    """Lets the simulator confirm the expected detection without holding a user session."""
    from datetime import datetime, timezone

    from app.models import Alert

    tenant_id = _tenant_id(tenant)
    since = datetime.fromtimestamp(since_epoch, tz=timezone.utc)
    with tenant_session(tenant_id) as db:
        rows = db.execute(select(Alert).where(Alert.rule_key == rule_key.upper(), Alert.created_at >= since)
                          .order_by(Alert.created_at.desc()).limit(20)).scalars()
        return [{"id": str(a.id), "rule_key": a.rule_key, "title": a.title, "severity": a.severity, "risk": a.risk,
                 "status": a.status, "response": a.response} for a in rows]
