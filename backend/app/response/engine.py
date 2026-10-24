"""Response engine (architecture section 8).

Every action is audited with a reference to the triggering alert. In DRY_RUN
mode actions are only recorded as "would run"; in ACTIVE mode they execute.
Failures are captured per action and never abort the remaining actions.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import write_audit
from app.core import redis as rds
from app.core.pubsub import queue_publish, run_after_commit
from app.core.tenancy import idp_for
from app.models import Alert, Role, Session as SessionRow, Tenant, User, UserRole

log = logging.getLogger(__name__)

AVAILABLE_ACTIONS = {
    "revoke_session": "Revoke the session that triggered the alert",
    "revoke_all_sessions": "Revoke every session of the user (Keycloak logout included)",
    "force_mfa": "Require MFA: add CONFIGURE_TOTP if not enrolled, force re-authentication",
    "lock_account": "Disable the account in Keycloak and set state SUSPENDED",
    "notify": "Push a notification to the dashboard (and admin webhook if configured)",
    "revert_role": "Remove a sensitive role that was granted outside the workflow",
}


def _revoke_session(db: Session, tenant: Tenant, alert: Alert) -> str:
    from app.sessions.service import revoke_all_user_sessions, revoke_session

    if alert.session_id:
        s = db.get(SessionRow, alert.session_id)
        if s is None:
            return "session not found"
        revoke_session(db, tenant, s, reason=f"auto_response:{alert.rule_key}", actor=f"response:{alert.id}")
        return f"session {s.id} revoked"
    if alert.user_id:
        user = db.get(User, alert.user_id)
        if user:
            n = revoke_all_user_sessions(db, tenant, user, reason=f"auto_response:{alert.rule_key}",
                                         actor=f"response:{alert.id}")
            return f"no session on alert; revoked {n} user sessions"
    return "no session or user on alert"


def _revoke_all(db: Session, tenant: Tenant, alert: Alert) -> str:
    from app.sessions.service import revoke_all_user_sessions

    user = db.get(User, alert.user_id) if alert.user_id else None
    if user is None:
        return "no user on alert"
    n = revoke_all_user_sessions(db, tenant, user, reason=f"auto_response:{alert.rule_key}",
                                 actor=f"response:{alert.id}")
    return f"{n} sessions revoked"


def _force_mfa(db: Session, tenant: Tenant, alert: Alert) -> str:
    user = db.get(User, alert.user_id) if alert.user_id else None
    if user is None or not user.kc_user_id:
        return "no user on alert"
    idp = idp_for(tenant)
    enrolled = idp.has_otp(user.kc_user_id)
    if not enrolled:
        idp.add_required_actions(user.kc_user_id, ["CONFIGURE_TOTP"])
    # Step-up is scoped to the risky session when there is one: its next refresh fails with
    # step_up_required and the user must re-authenticate through Keycloak (with OTP).
    scope = f"session:{alert.session_id}" if alert.session_id else f"user:{user.id}"
    rds.get_redis().set(f"stepup:{scope}", str(alert.id), ex=9 * 3600)
    return f"step-up required for {scope.split(':')[0]}" + ("" if enrolled else "; CONFIGURE_TOTP required action added")


def _lock(db: Session, tenant: Tenant, alert: Alert) -> str:
    from app.events.service import record_event

    user = db.get(User, alert.user_id) if alert.user_id else None
    if user is None:
        return "no user on alert"
    if user.kc_user_id:
        # Disabling a user makes Keycloak call our back-channel logout endpoint synchronously,
        # so it must not happen while this transaction holds locks (see core/pubsub.py).
        idp, kc_uid = idp_for(tenant), user.kc_user_id
        run_after_commit(db, lambda: idp.set_enabled(kc_uid, False), f"kc disable {kc_uid}")
    if user.state != "DEPROVISIONED":
        user.state = "SUSPENDED"
    rds.revoke_user_tokens_before(str(user.id))
    record_event(db, tenant, type="ACCOUNT_LOCKED", user_id=user.id, details={"alert_id": str(alert.id)},
                 detect=False)
    return f"account {user.username} disabled ({user.state})"


def _notify(db: Session, tenant: Tenant, alert: Alert) -> str:
    queue_publish(db, f"notify:{tenant.id}", {"alert_id": str(alert.id), "title": alert.title,
                                               "severity": alert.severity})
    return "dashboard notified"


def _revert_role(db: Session, tenant: Tenant, alert: Alert) -> str:
    role = str(alert.evidence.get("role") or "")
    user = db.get(User, alert.user_id) if alert.user_id else None
    if not role or user is None:
        return "no role/user on alert"
    if user.kc_user_id:
        idp_for(tenant).remove_realm_roles(user.kc_user_id, [role])
    role_id = db.execute(select(Role.id).where(Role.tenant_id == tenant.id, Role.name == role)).scalar_one_or_none()
    if role_id:
        ur = db.get(UserRole, {"user_id": user.id, "role_id": role_id})
        if ur:
            db.delete(ur)
    return f"role {role} removed from {user.username}"


HANDLERS: dict[str, Callable[[Session, Tenant, Alert], str]] = {
    "revoke_session": _revoke_session,
    "revoke_all_sessions": _revoke_all,
    "force_mfa": _force_mfa,
    "lock_account": _lock,
    "notify": _notify,
    "revert_role": _revert_role,
}


def execute_actions(db: Session, tenant: Tenant, alert: Alert, actions: list[str], mode: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for action in actions:
        handler = HANDLERS.get(action)
        if handler is None:
            results.append({"action": action, "status": "unknown_action"})
            continue
        if mode != "ACTIVE":
            status, detail = "dry_run", "would run (playbook in DRY_RUN mode)"
        else:
            try:
                with db.begin_nested():  # a failing action rolls back only itself
                    detail = handler(db, tenant, alert)
                status = "done"
            except Exception as exc:
                log.exception("response action %s failed", action)
                status, detail = "failed", str(exc)
        results.append({"action": action, "status": status, "detail": detail})
        write_audit(db, tenant.id, actor=f"response:{alert.rule_key}", action=f"response.{action}",
                    target=f"alert:{alert.id}", detail={"mode": mode, "status": status, "detail": detail,
                                                        "user_id": str(alert.user_id) if alert.user_id else None})
    return results
