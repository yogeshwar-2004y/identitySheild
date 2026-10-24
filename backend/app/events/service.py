"""Event storage + hand-off to the detection engine (in-process, same transaction)."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core import geoip
from app.core.security import utcnow
from app.models import Event, Session as SessionRow, Tenant, User

log = logging.getLogger(__name__)


def record_event(
    db: Session,
    tenant: Tenant,
    *,
    type: str,
    user_id: uuid.UUID | None = None,
    session_id: uuid.UUID | None = None,
    username: str | None = None,
    ip: str | None = None,
    ua_hash: str | None = None,
    outcome: str = "SUCCESS",
    source: str = "app",
    source_id: str | None = None,
    details: dict[str, Any] | None = None,
    ts: datetime | None = None,
    kc_user_id: str | None = None,
    kc_session_id: str | None = None,
    detect: bool = True,
) -> Event | None:
    """Normalizes, enriches (GeoIP), stores and runs detection. Returns None for duplicates."""
    if user_id is None and kc_user_id:
        user_id = db.execute(
            select(User.id).where(User.tenant_id == tenant.id, User.kc_user_id == kc_user_id)
        ).scalar_one_or_none()
    if user_id is not None and username is None:
        username = db.execute(select(User.username).where(User.id == user_id)).scalar_one_or_none()
    if session_id is None and kc_session_id:
        session_id = db.execute(
            select(SessionRow.id).where(SessionRow.tenant_id == tenant.id, SessionRow.kc_session_id == kc_session_id)
            .order_by(SessionRow.created_at.desc()).limit(1)
        ).scalar_one_or_none()
    geo = geoip.lookup(ip)
    values = {
        "id": uuid.uuid4(),
        "tenant_id": tenant.id,
        "ts": ts or utcnow(),
        "type": type,
        "user_id": user_id,
        "session_id": session_id,
        "username": username,
        "ip": ip,
        "geo": geo.as_dict() if geo else None,
        "asn": geo.asn if geo else None,
        "user_agent_hash": ua_hash,
        "outcome": outcome,
        "source": source,
        "source_id": source_id or str(uuid.uuid4()),
        "details": {**(details or {}), **({"kc_user_id": kc_user_id} if kc_user_id and not user_id else {})},
    }
    stmt = insert(Event).values(**values).on_conflict_do_nothing(constraint="uq_events_source").returning(Event.id)
    new_id = db.execute(stmt).scalar_one_or_none()
    if new_id is None:
        return None  # already ingested (poller overlap / webhook retry)
    event = db.get(Event, new_id)
    assert event is not None
    if type == "LOGIN" and outcome == "SUCCESS" and user_id is not None:
        user = db.get(User, user_id)
        if user is not None and (user.last_login_at is None or event.ts > user.last_login_at):
            user.last_login_at = event.ts
    if detect:
        from app.detection.engine import process_event

        process_event(db, tenant, event)
    return event
