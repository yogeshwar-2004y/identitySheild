from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.core.deps import Ctx, require_roles
from app.core.security import verify_hmac_signature
from app.core.tenancy import get_tenant_by_realm
from app.db.session import platform_session
from app.events.ingest import ingest_batch
from app.hunt.service import SearchFilters, search_events

router = APIRouter(tags=["events"])


class KeycloakBatch(BaseModel):
    realm: str = Field(pattern="^[a-z][a-z0-9-]{1,30}$")
    events: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)
    admin_events: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)


@router.post("/ingest/keycloak", status_code=202)
async def ingest_keycloak(request: Request, x_is_signature: str = Header(...)) -> dict[str, Any]:
    """Push endpoint for a Keycloak event-listener SPI (or any forwarder).
    Authenticated by HMAC-SHA256 of the raw body with INGEST_HMAC_SECRET."""
    body = await request.body()
    if not verify_hmac_signature(get_settings().ingest_hmac_secret, body, x_is_signature):
        raise HTTPException(401, detail="bad signature")
    batch = KeycloakBatch.model_validate_json(body)
    with platform_session() as db:
        tenant = get_tenant_by_realm(db, batch.realm)
        if tenant is None:
            raise HTTPException(404, detail="unknown realm")
        tenant_id = tenant.id
    return ingest_batch(tenant_id, batch.events, batch.admin_events)


@router.get("/events")
def list_events(
    ctx: Ctx = Depends(require_roles("admin", "analyst")),
    type: list[str] = Query(default=[]),
    outcome: str | None = Query(None, pattern="^(SUCCESS|FAILURE)$"),
    username: str | None = Query(None, max_length=254),
    user_id: uuid.UUID | None = None,
    ip: str | None = Query(None, max_length=64),
    since: datetime | None = None,
    limit: int = Query(200, ge=1, le=2000),
) -> list[dict[str, Any]]:
    f = SearchFilters(types=type, outcome=outcome, username=username, user_id=user_id, ip=ip, since=since, limit=limit)
    return search_events(ctx.db, ctx.tenant.id, f)
