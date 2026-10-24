from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.audit.service import write_audit
from app.core.deps import Ctx, get_ctx, require_platform, require_roles
from app.core.keycloak import KeycloakError
from app.core.security import decrypt_str, encrypt_str
from app.core.tenancy import TenantSettings, tenant_settings
from app.tenancy.service import ProvisioningError, provision_tenant

router = APIRouter(tags=["tenants"])


class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    realm: str = Field(min_length=2, max_length=31, pattern="^[a-z][a-z0-9-]+$")


@router.post("/tenants", status_code=201, dependencies=[Depends(require_platform)])
def create_tenant(body: TenantCreate) -> dict[str, Any]:
    """Platform operation (X-Platform-Key): creates the tenant row and its Keycloak realm."""
    try:
        t = provision_tenant(body.name, body.realm)
    except ProvisioningError as exc:
        raise HTTPException(422, detail=str(exc))
    except KeycloakError as exc:
        raise HTTPException(502, detail=f"Keycloak provisioning failed: {exc}")
    return {"id": str(t.id), "name": t.name, "realm": t.realm, "status": t.status}


@router.get("/tenants/me")
def my_tenant(ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
    t = ctx.tenant
    return {"id": str(t.id), "name": t.name, "realm": t.realm, "status": t.status,
            "settings": tenant_settings(t).model_dump(), "created_at": t.created_at.isoformat()}


@router.put("/tenants/me/settings")
def update_settings(body: TenantSettings, ctx: Ctx = Depends(require_roles("admin"))) -> dict[str, Any]:
    before = tenant_settings(ctx.tenant).model_dump()
    ctx.tenant.settings = body.model_dump()
    write_audit(ctx.db, ctx.tenant.id, actor=ctx.actor, action="tenant.settings_updated", target="tenant",
                detail={"before": before, "after": body.model_dump()})
    return {"settings": body.model_dump()}


@router.get("/tenants/me/hr-webhook")
def hr_webhook_info(ctx: Ctx = Depends(require_roles("admin"))) -> dict[str, Any]:
    secret = decrypt_str(ctx.tenant.hr_webhook_secret_enc) if ctx.tenant.hr_webhook_secret_enc else None
    write_audit(ctx.db, ctx.tenant.id, actor=ctx.actor, action="tenant.hr_secret_viewed", target="tenant")
    return {"url": "/api/lifecycle/webhook/hr", "tenant_header": ctx.tenant.realm, "secret": secret,
            "signature": "X-HR-Signature: sha256=HMAC_SHA256(secret, X-HR-Timestamp + '.' + body)"}


@router.post("/tenants/me/hr-webhook/rotate")
def rotate_hr_secret(ctx: Ctx = Depends(require_roles("admin"))) -> dict[str, Any]:
    secret = secrets.token_urlsafe(32)
    ctx.tenant.hr_webhook_secret_enc = encrypt_str(secret)
    write_audit(ctx.db, ctx.tenant.id, actor=ctx.actor, action="tenant.hr_secret_rotated", target="tenant")
    return {"secret": secret}
