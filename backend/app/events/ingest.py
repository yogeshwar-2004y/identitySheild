"""Keycloak event ingestion, shared by the HMAC webhook and the background poller."""
from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import tenant_session
from app.events.normalize import normalize_admin_event, normalize_user_event
from app.events.service import record_event
from app.models import Event, Role, Tenant, User, UserRole

log = logging.getLogger(__name__)


def _mirror_out_of_band_grant(db: Session, tenant: Tenant, kc_user_id: str | None, role: str) -> None:
    """A role granted directly in Keycloak (bypassing the workflow) is mirrored so that
    hunts and the user view show the true access. Detection D06 has already run."""
    if not kc_user_id:
        return
    user = db.execute(select(User).where(User.kc_user_id == kc_user_id)).scalar_one_or_none()
    r = db.execute(select(Role).where(Role.tenant_id == tenant.id, Role.name == role)).scalar_one_or_none()
    if user is None or r is None:
        return
    if db.get(UserRole, {"user_id": user.id, "role_id": r.id}) is None:
        db.add(UserRole(tenant_id=tenant.id, user_id=user.id, role_id=r.id, granted_by="idp:out_of_band"))
        db.flush()


def _seen(db: Session, source_id: str) -> bool:
    return db.execute(select(Event.id).where(Event.source == "keycloak", Event.source_id == source_id)
                      ).first() is not None


def ingest_batch(tenant_id: uuid.UUID, user_events: list[dict[str, Any]], admin_events: list[dict[str, Any]],
                 service_account_kc_id: str | None = None) -> dict[str, int]:
    stored = skipped = 0
    with tenant_session(tenant_id) as db:
        tenant = db.get(Tenant, tenant_id)
        assert tenant is not None
        for raw in sorted(user_events, key=lambda e: e.get("time", 0)):
            norm = normalize_user_event(raw)
            if norm is None:
                skipped += 1
                continue
            with db.begin_nested():
                if record_event(db, tenant, **norm) is not None:
                    stored += 1
                else:
                    skipped += 1
        for raw in sorted(admin_events, key=lambda e: e.get("time", 0)):
            for norm in normalize_admin_event(raw):
                actor_kc = (norm["details"].get("actor") or {}).get("actor_kc_user_id")
                via_api = service_account_kc_id is not None and actor_kc == service_account_kc_id
                norm["details"]["via_identityshield"] = via_api
                with db.begin_nested():
                    # Mirror first, so the DB reflects the IdP's real state before detection runs
                    # (and before an automated `revert_role` response removes it again).
                    if norm["type"] == "ROLE_GRANT" and not via_api and not _seen(db, norm["source_id"]):
                        _mirror_out_of_band_grant(db, tenant, norm.get("kc_user_id"), str(norm["details"].get("role")))
                    # Changes made through IdentityShield's own service account already produced
                    # app-level events with workflow context; only out-of-band changes are detected.
                    ev = record_event(db, tenant, **norm, detect=not via_api)
                if ev is None:
                    skipped += 1
                    continue
                stored += 1
    return {"stored": stored, "skipped": skipped}
