"""Detection engine: runs enabled rules, scores findings, creates alerts, triggers response."""
from __future__ import annotations

import logging
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import write_audit
from app.core.pubsub import queue_publish
from app.core.redis import alert_channel
from app.core.security import utcnow
from app.detection.base import Finding, Rule
from app.detection.context import SqlContext, to_view
from app.detection.rules import RULE_CLASSES
from app.detection.scoring import alert_severity, contribution, decide
from app.models import Alert, DetectionRule, Event, ResponsePlaybook, Tenant

log = logging.getLogger(__name__)


def load_rules(db: Session, tenant_id: uuid.UUID) -> list[tuple[Rule, DetectionRule | None]]:
    rows = {r.rule_key: r for r in db.execute(
        select(DetectionRule).where(DetectionRule.tenant_id == tenant_id)
    ).scalars()}
    out: list[tuple[Rule, DetectionRule | None]] = []
    for key, cls in RULE_CLASSES.items():
        row = rows.get(key)
        if row is not None and not row.enabled:
            continue
        out.append((cls(row.params if row else None), row))
    return out


def process_event(db: Session, tenant: Tenant, event: Event) -> list[Alert]:
    view = to_view(event)
    ctx = SqlContext(db, tenant.id)
    alerts: list[Alert] = []
    for rule, row in load_rules(db, tenant.id):
        if rule.periodic or not rule.handles(view):
            continue
        try:
            findings = rule.evaluate(view, ctx)
        except Exception:  # one broken rule must not stop ingestion
            log.exception("rule %s failed", rule.key)
            continue
        for f in findings:
            alert = raise_alert(db, tenant, rule, row, f, trigger_event_id=event.id)
            if alert is not None:
                alerts.append(alert)
    return alerts


def run_periodic(db: Session, tenant: Tenant) -> list[Alert]:
    ctx = SqlContext(db, tenant.id)
    alerts: list[Alert] = []
    for rule, row in load_rules(db, tenant.id):
        if not rule.periodic:
            continue
        for f in rule.evaluate_periodic(ctx):
            alert = raise_alert(db, tenant, rule, row, f)
            if alert is not None:
                alerts.append(alert)
    return alerts


def _carry(db: Session, tenant_id: uuid.UUID, f: Finding) -> float:
    since = utcnow() - timedelta(hours=1)
    q = select(Alert.response).where(Alert.tenant_id == tenant_id, Alert.status == "OPEN", Alert.created_at >= since)
    if f.session_id is not None:
        q = q.where(Alert.session_id == f.session_id)
    elif f.user_id is not None:
        q = q.where(Alert.user_id == f.user_id, Alert.session_id.is_(None))
    else:
        return 0.0
    return float(sum((r or {}).get("contribution", 0) for r in db.execute(q).scalars()))


def raise_alert(db: Session, tenant: Tenant, rule: Rule, row: DetectionRule | None, f: Finding,
                trigger_event_id: uuid.UUID | None = None) -> Alert | None:
    if f.dedupe_key:
        dup = db.execute(
            select(Alert.id).where(Alert.tenant_id == tenant.id, Alert.dedupe_key == f.dedupe_key,
                                   Alert.created_at >= utcnow() - timedelta(days=1)).limit(1)
        ).scalar_one_or_none()
        if dup is not None:
            return None
    weight = row.weight if row else rule.weight
    severity = row.severity if row else rule.severity
    carry = _carry(db, tenant.id, f)
    decision = decide(weight, f.confidence, carry)

    playbook = db.execute(
        select(ResponsePlaybook).where(ResponsePlaybook.tenant_id == tenant.id, ResponsePlaybook.rule_key == rule.key)
    ).scalar_one_or_none()
    actions = list(decision.actions)
    mode = "DRY_RUN"
    if playbook is not None and playbook.enabled:
        mode = playbook.mode
        actions += [a for a in playbook.actions if a not in actions]

    alert = Alert(
        tenant_id=tenant.id, rule_key=rule.key, title=f.title, severity=alert_severity(severity, decision.tier),
        attack_technique=rule.attack_technique, user_id=f.user_id, session_id=f.session_id, risk=decision.risk,
        status="OPEN", evidence={**f.evidence, "confidence": f.confidence,
                                 "trigger_event_id": str(trigger_event_id) if trigger_event_id else None},
        response={"contribution": contribution(weight, f.confidence), "carry": carry, "tier": decision.tier,
                  "planned_actions": actions, "mode": mode, "results": []},
        dedupe_key=f.dedupe_key,
    )
    db.add(alert)
    db.flush()
    write_audit(db, tenant.id, actor=f"detection:{rule.key}", action="alert.created", target=f"alert:{alert.id}",
                detail={"rule": rule.key, "risk": decision.risk, "severity": alert.severity,
                        "user_id": str(f.user_id) if f.user_id else None})

    from app.response.engine import execute_actions

    results = execute_actions(db, tenant, alert, actions, mode)
    alert.response = {**alert.response, "results": results}
    queue_publish(db, alert_channel(str(tenant.id)), alert_payload(alert))
    return alert


def alert_payload(a: Alert) -> dict[str, Any]:
    return {
        "id": str(a.id), "rule_key": a.rule_key, "title": a.title, "severity": a.severity, "risk": a.risk,
        "status": a.status, "user_id": str(a.user_id) if a.user_id else None,
        "session_id": str(a.session_id) if a.session_id else None, "created_at": (a.created_at or utcnow()).isoformat(),
        "attack_technique": a.attack_technique,
    }
