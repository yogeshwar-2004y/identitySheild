"""Tenant context and per-tenant settings."""
from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.keycloak import TenantIdP, tenant_idp
from app.models import Tenant


class TenantSettings(BaseModel):
    """Session and lifecycle policy, configurable per tenant (PUT /tenants/me/settings)."""

    access_token_ttl_seconds: int = Field(default=300, ge=60, le=900)
    idle_timeout_minutes: int = Field(default=15, ge=5, le=240)
    absolute_timeout_hours: int = Field(default=8, ge=1, le=24)
    max_concurrent_sessions: int = Field(default=3, ge=1, le=20)
    concurrent_policy: str = Field(default="evict_oldest", pattern="^(evict_oldest|block)$")
    drift_policy: str = Field(default="detect", pattern="^(detect|revoke)$")
    leaver_sla_minutes: int = Field(default=60, ge=5, le=10080)
    require_mfa: bool = True


def tenant_settings(tenant: Tenant) -> TenantSettings:
    s = get_settings()
    base: dict[str, Any] = {
        "access_token_ttl_seconds": s.access_token_ttl_seconds,
        "idle_timeout_minutes": s.idle_timeout_minutes,
        "absolute_timeout_hours": s.absolute_timeout_hours,
        "max_concurrent_sessions": s.max_concurrent_sessions,
    }
    return TenantSettings(**{**base, **(tenant.settings or {})})


def idp_for(tenant: Tenant) -> TenantIdP:
    return tenant_idp(tenant.realm, tenant.client_secret_enc)


def get_tenant(db: Session, tenant_id: uuid.UUID | str) -> Tenant | None:
    return db.get(Tenant, uuid.UUID(str(tenant_id)))


def get_tenant_by_realm(db: Session, realm: str) -> Tenant | None:
    return db.execute(select(Tenant).where(Tenant.realm == realm)).scalar_one_or_none()
