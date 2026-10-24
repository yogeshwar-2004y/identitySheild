"""Pulls Keycloak user and admin events for each tenant (near real time, ~2 s).

Keycloak has no built-in webhook, so the default pipeline polls the admin
events API with the tenant's least-privilege service account (`view-events`).
Overlapping windows are safe: events are de-duplicated by Keycloak event id.
"""
from __future__ import annotations

import base64
import json
import logging
import time
import uuid

from sqlalchemy import select

from app.core import redis as rds
from app.core.tenancy import idp_for
from app.db.session import platform_session
from app.events.ingest import ingest_batch
from app.models import Tenant

log = logging.getLogger(__name__)
OVERLAP_MS = 5000


def _sa_user_id(idp: object) -> str | None:
    token_fn = getattr(idp, "_sa_token", None)
    if token_fn is None:
        return None
    try:
        payload = token_fn().split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return str(json.loads(base64.urlsafe_b64decode(payload))["sub"])
    except Exception:
        return None


def poll_tenant(tenant_id: uuid.UUID, wait_lock: float = 0.0) -> dict[str, int]:
    r = rds.get_redis()
    lock_key = f"poll:lock:{tenant_id}"
    deadline = time.time() + wait_lock
    while not r.set(lock_key, "1", nx=True, ex=30):
        if time.time() >= deadline:
            return {"stored": 0, "skipped": 0, "locked": 1}
        time.sleep(0.2)
    try:
        with platform_session() as db:
            t = db.get(Tenant, tenant_id)
            if t is None or t.status != "ACTIVE" or not t.client_secret_enc:
                return {"stored": 0, "skipped": 0}
            idp = idp_for(t)
            cursor, admin_cursor = t.kc_poll_cursor or 0, t.kc_admin_poll_cursor or 0
        user_events = [e for e in idp.login_events(500) if int(e.get("time", 0)) >= cursor - OVERLAP_MS]
        admin_events = [e for e in idp.admin_events(300) if int(e.get("time", 0)) >= admin_cursor - OVERLAP_MS]
        result = ingest_batch(tenant_id, user_events, admin_events, service_account_kc_id=_sa_user_id(idp))
        with platform_session() as db:
            t = db.get(Tenant, tenant_id)
            assert t is not None
            if user_events:
                t.kc_poll_cursor = max(cursor, max(int(e.get("time", 0)) for e in user_events))
            if admin_events:
                t.kc_admin_poll_cursor = max(admin_cursor, max(int(e.get("time", 0)) for e in admin_events))
        return result
    finally:
        r.delete(lock_key)


def active_tenant_ids() -> list[uuid.UUID]:
    with platform_session() as db:
        return list(db.execute(select(Tenant.id).where(Tenant.status == "ACTIVE")).scalars())
