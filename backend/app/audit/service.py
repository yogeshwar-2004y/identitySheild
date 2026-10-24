"""Tamper-evident audit log.

Each row stores `hash = SHA256(prev_hash || canonical_json(entry))` where
`prev_hash` is the hash of the previous row of the same tenant. Changing,
deleting or reordering any row breaks every hash after it, which
`verify_chain` reports. Writers take a per-tenant advisory lock so two
concurrent transactions cannot fork the chain.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.security import canonical_json, utcnow
from app.models import AuditLog

GENESIS = "0" * 64


def _entry_payload(tenant_id: uuid.UUID, ts: datetime, actor: str, action: str, target: str, detail: dict[str, Any]) -> str:
    return canonical_json(
        {
            "tenant_id": str(tenant_id),
            "ts": ts.isoformat(),
            "actor": actor,
            "action": action,
            "target": target,
            "detail": detail,
        }
    )


def compute_hash(prev_hash: str, payload: str) -> str:
    return hashlib.sha256((prev_hash + payload).encode()).hexdigest()


def write_audit(
    db: Session,
    tenant_id: uuid.UUID,
    *,
    actor: str,
    action: str,
    target: str = "",
    detail: dict[str, Any] | None = None,
) -> AuditLog:
    detail = detail or {}
    # Serialise writers per tenant for the rest of this transaction.
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"audit:{tenant_id}"})
    prev = db.execute(
        select(AuditLog.hash).where(AuditLog.tenant_id == tenant_id).order_by(AuditLog.id.desc()).limit(1)
    ).scalar_one_or_none()
    prev_hash = prev or GENESIS
    now = utcnow()
    ts = now.replace(microsecond=(now.microsecond // 1000) * 1000)
    # Round-trip detail through canonical JSON so what we hash is exactly what JSONB stores back.

    detail = json.loads(canonical_json(detail))
    row = AuditLog(
        tenant_id=tenant_id,
        ts=ts,
        actor=actor,
        action=action,
        target=target,
        detail=detail,
        prev_hash=prev_hash,
        hash=compute_hash(prev_hash, _entry_payload(tenant_id, ts, actor, action, target, detail)),
    )
    db.add(row)
    db.flush()
    return row


def verify_chain(db: Session, tenant_id: uuid.UUID) -> dict[str, Any]:
    prev_hash = GENESIS
    checked = 0
    rows = db.execute(
        select(AuditLog).where(AuditLog.tenant_id == tenant_id).order_by(AuditLog.id.asc())
    ).scalars()
    for row in rows:
        expected = compute_hash(
            prev_hash, _entry_payload(row.tenant_id, row.ts, row.actor, row.action, row.target, row.detail)
        )
        if row.prev_hash != prev_hash or row.hash != expected:
            return {
                "valid": False,
                "checked": checked,
                "broken_at_id": row.id,
                "reason": "prev_hash mismatch" if row.prev_hash != prev_hash else "content hash mismatch",
            }
        prev_hash = row.hash
        checked += 1
    return {"valid": True, "checked": checked, "broken_at_id": None, "head": prev_hash}
