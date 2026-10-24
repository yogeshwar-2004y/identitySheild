"""Identity lifecycle: Joiner / Mover / Leaver (architecture section 5).

Every workflow is a `lifecycle_events` row whose `steps` JSON records each
completed step. Steps are individually idempotent and are skipped on retry
once recorded, so a workflow that fails half-way can be retried safely
(`POST /lifecycle/{id}/retry`) and will resume where it stopped.

The Leaver runs each step in its own committed transaction: a crash after
"disable" still leaves the account disabled, and Keycloak calls that trigger
back-channel logout never run while we hold database locks.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.audit.service import write_audit
from app.core import redis as rds
from app.core.config import get_settings
from app.core.security import utcnow
from app.core.tenancy import idp_for
from app.db.session import tenant_session
from app.events.service import record_event
from app.models import (
    ApiKey, Approval, LifecycleEvent, Role, RoleTemplate, Session as SessionRow, Tenant, User, UserRole,
)
from app.sessions.service import active_sessions, revoke_all_user_sessions

log = logging.getLogger(__name__)


class LifecycleError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


# ------------------------------------------------------------------ helpers


def _roles_by_name(db: Session, tenant_id: uuid.UUID) -> dict[str, Role]:
    return {r.name: r for r in db.execute(select(Role).where(Role.tenant_id == tenant_id)).scalars()}


def template_roles(db: Session, tenant_id: uuid.UUID, department: str) -> list[str]:
    tpl = db.execute(select(RoleTemplate).where(RoleTemplate.tenant_id == tenant_id,
                                                RoleTemplate.department == department)).scalar_one_or_none()
    if tpl is None:
        return ["user"]
    ids = set(tpl.role_ids)
    return sorted(r.name for r in _roles_by_name(db, tenant_id).values() if r.id in ids)


def current_roles(db: Session, user_id: uuid.UUID) -> list[str]:
    return sorted(db.execute(select(Role.name).join(UserRole, UserRole.role_id == Role.id)
                             .where(UserRole.user_id == user_id)).scalars())


def _mark(lc: LifecycleEvent, step: str, **data: Any) -> None:
    lc.steps = {**(lc.steps or {}), step: {"at": utcnow().isoformat(), **data}}
    lc.updated_at = utcnow()


def _done(lc: LifecycleEvent, step: str) -> bool:
    return step in (lc.steps or {})


def _grant(db: Session, tenant: Tenant, user: User, role: Role, *, actor: str, lc: LifecycleEvent,
           approval_id: uuid.UUID | None) -> None:
    if db.get(UserRole, {"user_id": user.id, "role_id": role.id}) is None:
        db.add(UserRole(tenant_id=tenant.id, user_id=user.id, role_id=role.id, granted_by=actor,
                        approval_id=approval_id, lifecycle_id=lc.id))
        db.flush()
    record_event(db, tenant, type="ROLE_GRANT", user_id=user.id, source="app",
                 source_id=f"lc:{lc.id}:grant:{role.name}",
                 details={"role": role.name, "lifecycle_id": str(lc.id), "actor": actor,
                          "approval_id": str(approval_id) if approval_id else None})


def _revoke(db: Session, tenant: Tenant, user: User, role: Role, *, actor: str, lc: LifecycleEvent) -> None:
    ur = db.get(UserRole, {"user_id": user.id, "role_id": role.id})
    if ur is not None:
        db.delete(ur)
        db.flush()
    record_event(db, tenant, type="ROLE_REVOKE", user_id=user.id, source="app",
                 source_id=f"lc:{lc.id}:revoke:{role.name}",
                 details={"role": role.name, "lifecycle_id": str(lc.id), "actor": actor})


def _needs_approval(db: Session, tenant_id: uuid.UUID, added: list[str]) -> list[str]:
    roles = _roles_by_name(db, tenant_id)
    return [r for r in added if r in roles and roles[r].sensitivity == "HIGH"]


def _existing_by_key(db: Session, tenant_id: uuid.UUID, key: str | None) -> LifecycleEvent | None:
    if not key:
        return None
    return db.execute(select(LifecycleEvent).where(LifecycleEvent.tenant_id == tenant_id,
                                                   LifecycleEvent.idempotency_key == key)).scalar_one_or_none()


# ------------------------------------------------------------------ JOINER


def submit_joiner(db: Session, tenant: Tenant, *, actor: str, full_name: str, email: str, department: str,
                  username: str | None = None, extra_roles: list[str] | None = None, send_invite: bool = True,
                  require_mfa: bool = True, lab_demo_password: bool = False,
                  idempotency_key: str | None = None) -> LifecycleEvent:
    existing = _existing_by_key(db, tenant.id, idempotency_key)
    if existing:
        return existing
    email = email.strip().lower()
    username = (username or email.split("@")[0]).strip().lower()
    if db.execute(select(User.id).where(User.tenant_id == tenant.id, User.email == email)).scalar_one_or_none():
        raise LifecycleError(f"A user with email {email} already exists", 409)
    roles = _roles_by_name(db, tenant.id)
    unknown = [r for r in (extra_roles or []) if r not in roles]
    if unknown:
        raise LifecycleError(f"Unknown roles: {', '.join(unknown)}")
    if lab_demo_password and not get_settings().lab_mode:
        raise LifecycleError("lab_demo_password is only available in LAB_MODE")

    target = sorted(set(template_roles(db, tenant.id, department)) | set(extra_roles or []))
    sensitive = _needs_approval(db, tenant.id, sorted(set(extra_roles or [])))
    user = User(tenant_id=tenant.id, username=username, email=email, full_name=full_name, department=department,
                state="PENDING")
    db.add(user)
    db.flush()
    lc = LifecycleEvent(
        tenant_id=tenant.id, user_id=user.id, kind="JOINER", requested_by=actor, idempotency_key=idempotency_key,
        status="PENDING_APPROVAL" if sensitive else "APPROVED",
        payload={"full_name": full_name, "email": email, "username": username, "department": department,
                 "roles": target, "send_invite": send_invite, "require_mfa": require_mfa,
                 "lab_demo_password": lab_demo_password},
        access_diff={"added": target, "removed": [], "sensitive": sensitive},
    )
    db.add(lc)
    db.flush()
    write_audit(db, tenant.id, actor=actor, action="lifecycle.joiner.requested", target=f"user:{user.id}",
                detail={"email": email, "department": department, "roles": target, "lifecycle_id": str(lc.id)})
    if sensitive:
        _create_approval(db, tenant, lc, actor, "JOINER_SENSITIVE_ROLES")
        return lc
    execute_joiner(db, tenant, lc, actor=actor)
    return lc


def execute_joiner(db: Session, tenant: Tenant, lc: LifecycleEvent, *, actor: str) -> None:
    user = db.get(User, lc.user_id)
    assert user is not None
    p = lc.payload
    idp = idp_for(tenant)
    lc.status, lc.attempts = "RUNNING", lc.attempts + 1
    try:
        if not _done(lc, "create_account"):
            actions = []
            if p.get("lab_demo_password"):
                password = get_settings().demo_password
            else:
                password = None
                actions += ["VERIFY_EMAIL", "UPDATE_PASSWORD"]
            if p.get("require_mfa", True):
                actions.append("CONFIGURE_TOTP")
            first, _, last = str(p["full_name"]).partition(" ")
            kc_id = idp.create_user(username=p["username"], email=p["email"], first_name=first,
                                    last_name=last or "-", required_actions=actions, password=password)
            user.kc_user_id = kc_id
            _mark(lc, "create_account", kc_user_id=kc_id, required_actions=actions)
        if not _done(lc, "assign_roles"):
            roles = _roles_by_name(db, tenant.id)
            names = [r for r in p["roles"] if r in roles]
            assert user.kc_user_id
            idp.add_realm_roles(user.kc_user_id, names)
            for name in names:
                _grant(db, tenant, user, roles[name], actor=actor, lc=lc, approval_id=lc.approval_id)
            _mark(lc, "assign_roles", roles=names)
        if not _done(lc, "invite"):
            sent = False
            if p.get("send_invite") and not p.get("lab_demo_password") and user.kc_user_id:
                try:
                    idp.send_actions_email(user.kc_user_id, lc.steps["create_account"]["required_actions"])
                    sent = True
                except Exception as exc:  # invite can be re-sent; not a reason to fail provisioning
                    log.warning("invite email failed: %s", exc)
            _mark(lc, "invite", sent=sent)
        lc.status, lc.error, lc.completed_at = "COMPLETED", None, utcnow()
        record_event(db, tenant, type="LIFECYCLE_JOINER", user_id=user.id, details={"lifecycle_id": str(lc.id),
                                                                                    "roles": p["roles"]}, detect=False)
        write_audit(db, tenant.id, actor=actor, action="lifecycle.joiner.completed", target=f"user:{user.id}",
                    detail={"lifecycle_id": str(lc.id), "steps": list(lc.steps)})
    except Exception as exc:
        lc.status, lc.error = "FAILED", str(exc)
        write_audit(db, tenant.id, actor=actor, action="lifecycle.joiner.failed", target=f"user:{user.id}",
                    detail={"lifecycle_id": str(lc.id), "error": str(exc), "completed_steps": list(lc.steps or {})})


# ------------------------------------------------------------------ MOVER


def submit_mover(db: Session, tenant: Tenant, *, actor: str, user_id: uuid.UUID, new_department: str | None,
                 add_roles: list[str], remove_roles: list[str], reason: str = "",
                 idempotency_key: str | None = None) -> LifecycleEvent:
    existing = _existing_by_key(db, tenant.id, idempotency_key)
    if existing:
        return existing
    user = db.get(User, user_id)
    if user is None:
        raise LifecycleError("User not found", 404)
    if user.state not in ("ACTIVE", "PENDING"):
        raise LifecycleError(f"Cannot move a {user.state} user", 409)
    roles = _roles_by_name(db, tenant.id)
    unknown = [r for r in add_roles + remove_roles if r not in roles]
    if unknown:
        raise LifecycleError(f"Unknown roles: {', '.join(unknown)}")
    current = set(current_roles(db, user.id))
    target = set(current)
    if new_department and new_department != user.department:
        target -= set(template_roles(db, tenant.id, user.department))
        target |= set(template_roles(db, tenant.id, new_department))
    target |= set(add_roles)
    target -= set(remove_roles)
    target.add("user")
    diff = {"added": sorted(target - current), "removed": sorted(current - target), "unchanged": sorted(current & target)}
    sensitive = _needs_approval(db, tenant.id, diff["added"])
    diff["sensitive"] = sensitive
    lc = LifecycleEvent(
        tenant_id=tenant.id, user_id=user.id, kind="MOVER", requested_by=actor, idempotency_key=idempotency_key,
        status="PENDING_APPROVAL" if sensitive else "APPROVED",
        payload={"from_department": user.department, "to_department": new_department or user.department,
                 "reason": reason, "target_roles": sorted(target)},
        access_diff=diff,
    )
    db.add(lc)
    db.flush()
    write_audit(db, tenant.id, actor=actor, action="lifecycle.mover.requested", target=f"user:{user.id}",
                detail={"lifecycle_id": str(lc.id), "access_diff": diff})
    if sensitive:
        _create_approval(db, tenant, lc, actor, "MOVER_SENSITIVE_ROLES")
        return lc
    execute_mover(db, tenant, lc, actor=actor)
    return lc


def execute_mover(db: Session, tenant: Tenant, lc: LifecycleEvent, *, actor: str) -> None:
    user = db.get(User, lc.user_id)
    assert user is not None
    idp = idp_for(tenant)
    diff = lc.access_diff or {}
    roles = _roles_by_name(db, tenant.id)
    lc.status, lc.attempts = "RUNNING", lc.attempts + 1
    try:
        if not _done(lc, "apply_roles"):
            if user.kc_user_id:
                idp.remove_realm_roles(user.kc_user_id, diff.get("removed", []))
                idp.add_realm_roles(user.kc_user_id, diff.get("added", []))
            for name in diff.get("removed", []):
                _revoke(db, tenant, user, roles[name], actor=actor, lc=lc)
            for name in diff.get("added", []):
                _grant(db, tenant, user, roles[name], actor=actor, lc=lc, approval_id=lc.approval_id)
            user.department = lc.payload.get("to_department") or user.department
            _mark(lc, "apply_roles", added=diff.get("added", []), removed=diff.get("removed", []))
        if not _done(lc, "reissue_sessions"):
            # Tokens carry roles: bump the claims version so current access tokens are refused
            # ("claims_changed") and the next refresh issues a brand-new session id.
            count = 0
            for s in active_sessions(db, user.id):
                s.reissue_required = True
                rds.set_claims_version(str(s.id), s.claims_version + 1)
                count += 1
            _mark(lc, "reissue_sessions", sessions=count)
        lc.status, lc.error, lc.completed_at = "COMPLETED", None, utcnow()
        record_event(db, tenant, type="LIFECYCLE_MOVER", user_id=user.id, details={"lifecycle_id": str(lc.id),
                                                                                   "access_diff": diff}, detect=False)
        write_audit(db, tenant.id, actor=actor, action="lifecycle.mover.completed", target=f"user:{user.id}",
                    detail={"lifecycle_id": str(lc.id), "access_diff": diff})
    except Exception as exc:
        lc.status, lc.error = "FAILED", str(exc)
        write_audit(db, tenant.id, actor=actor, action="lifecycle.mover.failed", target=f"user:{user.id}",
                    detail={"lifecycle_id": str(lc.id), "error": str(exc)})


# ------------------------------------------------------------------ approvals


def _create_approval(db: Session, tenant: Tenant, lc: LifecycleEvent, actor: str, kind: str) -> Approval:
    ap = Approval(tenant_id=tenant.id, lifecycle_id=lc.id, request_type=kind, requested_by=actor)
    db.add(ap)
    db.flush()
    lc.approval_id = ap.id
    write_audit(db, tenant.id, actor=actor, action="approval.requested", target=f"lifecycle:{lc.id}",
                detail={"approval_id": str(ap.id), "type": kind, "sensitive": (lc.access_diff or {}).get("sensitive")})
    return ap


def decide_approval(db: Session, tenant: Tenant, lc: LifecycleEvent, *, approver: str, approve: bool,
                    reason: str = "") -> LifecycleEvent:
    if lc.status != "PENDING_APPROVAL" or lc.approval_id is None:
        raise LifecycleError("Request is not awaiting approval", 409)
    ap = db.get(Approval, lc.approval_id)
    assert ap is not None
    if ap.requested_by == approver:
        raise LifecycleError("Separation of duties: requester cannot approve their own request", 403)
    ap.approver, ap.decided_at, ap.reason = approver, utcnow(), reason
    ap.status = "APPROVED" if approve else "REJECTED"
    write_audit(db, tenant.id, actor=approver, action=f"approval.{ap.status.lower()}", target=f"lifecycle:{lc.id}",
                detail={"approval_id": str(ap.id), "reason": reason})
    if not approve:
        lc.status = "REJECTED"
        if lc.kind == "JOINER":
            user = db.get(User, lc.user_id)
            if user is not None and user.kc_user_id is None:
                user.state = "DEPROVISIONED"  # never activated; retained for audit
                user.deprovisioned_at = utcnow()
        return lc
    lc.status = "APPROVED"
    if lc.kind == "JOINER":
        execute_joiner(db, tenant, lc, actor=approver)
    elif lc.kind == "MOVER":
        execute_mover(db, tenant, lc, actor=approver)
    return lc


# ------------------------------------------------------------------ LEAVER


LEAVER_STEPS = ["disable_account", "revoke_sessions", "revoke_tokens", "remove_roles", "revoke_api_keys",
                "mark_deprovisioned", "verify"]


def submit_leaver(db: Session, tenant: Tenant, *, actor: str, user_id: uuid.UUID, reason: str = "",
                  effective_at: datetime | None = None, idempotency_key: str | None = None) -> LifecycleEvent:
    existing = _existing_by_key(db, tenant.id, idempotency_key)
    if existing:
        return existing
    user = db.get(User, user_id)
    if user is None:
        raise LifecycleError("User not found", 404)
    open_leaver = db.execute(select(LifecycleEvent).where(
        LifecycleEvent.user_id == user.id, LifecycleEvent.kind == "LEAVER",
        LifecycleEvent.status.in_(["SCHEDULED", "RUNNING", "FAILED", "APPROVED", "COMPLETED"]),
    ).order_by(LifecycleEvent.created_at.desc()).limit(1)).scalar_one_or_none()
    if open_leaver is not None and (open_leaver.status != "COMPLETED" or user.state == "DEPROVISIONED"):
        return open_leaver  # idempotent: one leaver per identity
    scheduled = effective_at is not None and effective_at > utcnow()
    lc = LifecycleEvent(
        tenant_id=tenant.id, user_id=user.id, kind="LEAVER", requested_by=actor, idempotency_key=idempotency_key,
        status="SCHEDULED" if scheduled else "APPROVED", effective_at=effective_at,
        payload={"reason": reason, "roles_before": current_roles(db, user.id)},
        access_diff={"added": [], "removed": current_roles(db, user.id)},
    )
    db.add(lc)
    db.flush()
    write_audit(db, tenant.id, actor=actor, action="lifecycle.leaver.requested", target=f"user:{user.id}",
                detail={"lifecycle_id": str(lc.id), "reason": reason,
                        "effective_at": effective_at.isoformat() if effective_at else None})
    return lc


def execute_leaver(tenant_id: uuid.UUID, lifecycle_id: uuid.UUID, *, actor: str) -> str:
    """Runs (or resumes) a leaver. Each step commits on its own. Returns the final status."""
    with tenant_session(tenant_id) as db:
        lc = db.get(LifecycleEvent, lifecycle_id)
        if lc is None or lc.kind != "LEAVER":
            raise LifecycleError("Leaver request not found", 404)
        if lc.status == "COMPLETED":
            return "COMPLETED"
        if lc.status == "SCHEDULED" and lc.effective_at and lc.effective_at > utcnow():
            return "SCHEDULED"
        lc.status, lc.attempts, lc.error = "RUNNING", lc.attempts + 1, None
        steps_done = set((lc.steps or {}).keys())
    for step in LEAVER_STEPS:
        if step in steps_done:
            continue
        try:
            with tenant_session(tenant_id) as db:
                tenant = db.get(Tenant, tenant_id)
                lc = db.get(LifecycleEvent, lifecycle_id)
                assert tenant is not None and lc is not None
                user = db.get(User, lc.user_id)
                assert user is not None
                data = _LEAVER_HANDLERS[step](db, tenant, user, lc, actor)
                _mark(lc, step, **data)
                write_audit(db, tenant_id, actor=actor, action=f"lifecycle.leaver.{step}", target=f"user:{user.id}",
                            detail={"lifecycle_id": str(lifecycle_id), **data})
        except Exception as exc:
            log.warning("leaver %s failed at %s: %s", lifecycle_id, step, exc)
            with tenant_session(tenant_id) as db:
                lc = db.get(LifecycleEvent, lifecycle_id)
                assert lc is not None
                lc.status, lc.error, lc.updated_at = "FAILED", f"{step}: {exc}", utcnow()
                write_audit(db, tenant_id, actor=actor, action="lifecycle.leaver.failed",
                            target=f"user:{lc.user_id}", detail={"lifecycle_id": str(lifecycle_id), "step": step,
                                                                  "error": str(exc)})
            return "FAILED"
    with tenant_session(tenant_id) as db:
        tenant = db.get(Tenant, tenant_id)
        lc = db.get(LifecycleEvent, lifecycle_id)
        assert lc is not None and tenant is not None
        lc.status, lc.completed_at = "COMPLETED", utcnow()
        record_event(db, tenant, type="LIFECYCLE_LEAVER", user_id=lc.user_id,
                     details={"lifecycle_id": str(lifecycle_id)}, detect=False)
        write_audit(db, tenant_id, actor=actor, action="lifecycle.leaver.completed", target=f"user:{lc.user_id}",
                    detail={"lifecycle_id": str(lifecycle_id), "verification": (lc.steps or {}).get("verify")})
    return "COMPLETED"


def _step_disable(db: Session, tenant: Tenant, user: User, lc: LifecycleEvent, actor: str) -> dict[str, Any]:
    if user.kc_user_id:
        idp_for(tenant).set_enabled(user.kc_user_id, False)
    if user.state != "DEPROVISIONED":
        user.state = "SUSPENDED"
    record_event(db, tenant, type="USER_DISABLE", user_id=user.id, details={"lifecycle_id": str(lc.id)}, detect=False)
    return {"kc_disabled": bool(user.kc_user_id)}


def _step_revoke_sessions(db: Session, tenant: Tenant, user: User, lc: LifecycleEvent, actor: str) -> dict[str, Any]:
    n = revoke_all_user_sessions(db, tenant, user, reason="leaver", actor=actor)
    return {"sessions_revoked": n}


def _step_revoke_tokens(db: Session, tenant: Tenant, user: User, lc: LifecycleEvent, actor: str) -> dict[str, Any]:
    rds.revoke_user_tokens_before(str(user.id))
    jtis = 0
    for (sid,) in db.execute(select(SessionRow.id).where(SessionRow.user_id == user.id)).all():
        rds.revoke_sid(str(sid))
        for jti, ttl in rds.outstanding_jtis(str(sid)):
            rds.revoke_jti(jti, ttl + 5)
            jtis += 1
    return {"jtis_revoked": jtis, "user_cutoff": True}


def _step_remove_roles(db: Session, tenant: Tenant, user: User, lc: LifecycleEvent, actor: str) -> dict[str, Any]:
    names = current_roles(db, user.id)
    kc_names: list[str] = []
    if user.kc_user_id:
        idp = idp_for(tenant)
        kc_names = idp.get_realm_roles(user.kc_user_id)
        idp.remove_realm_roles(user.kc_user_id, kc_names)
    roles = _roles_by_name(db, tenant.id)
    for name in names:
        _revoke(db, tenant, user, roles[name], actor=actor, lc=lc)
    return {"roles_removed": sorted(set(names) | set(kc_names))}


def _step_revoke_api_keys(db: Session, tenant: Tenant, user: User, lc: LifecycleEvent, actor: str) -> dict[str, Any]:
    res = db.execute(update(ApiKey).where(ApiKey.user_id == user.id, ApiKey.revoked_at.is_(None))
                     .values(revoked_at=utcnow()))
    return {"api_keys_revoked": res.rowcount or 0}  # type: ignore[attr-defined]


def _step_mark(db: Session, tenant: Tenant, user: User, lc: LifecycleEvent, actor: str) -> dict[str, Any]:
    user.state = "DEPROVISIONED"
    user.deprovisioned_at = user.deprovisioned_at or utcnow()
    return {"state": "DEPROVISIONED"}


def _step_verify(db: Session, tenant: Tenant, user: User, lc: LifecycleEvent, actor: str) -> dict[str, Any]:
    """Independent re-check of the outcome. Raises (so the workflow is FAILED and retryable) on any gap."""
    checks: dict[str, bool] = {}
    checks["db_state_deprovisioned"] = user.state == "DEPROVISIONED"
    checks["no_active_sessions"] = len(active_sessions(db, user.id)) == 0
    checks["no_roles"] = len(current_roles(db, user.id)) == 0
    checks["no_active_api_keys"] = db.execute(
        select(ApiKey.id).where(ApiKey.user_id == user.id, ApiKey.revoked_at.is_(None)).limit(1)
    ).scalar_one_or_none() is None
    checks["token_cutoff_set"] = bool(rds.get_redis().get(f"revoked:user:{user.id}"))
    if user.kc_user_id:
        idp = idp_for(tenant)
        checks["idp_disabled"] = not idp.is_enabled(user.kc_user_id)
        checks["idp_no_sessions"] = len(idp.user_sessions(user.kc_user_id)) == 0
        checks["idp_no_roles"] = len(idp.get_realm_roles(user.kc_user_id)) == 0
    failed = [k for k, ok in checks.items() if not ok]
    if failed:
        raise LifecycleError(f"verification failed: {', '.join(failed)}")
    return {"checks": checks}


_LEAVER_HANDLERS = {
    "disable_account": _step_disable,
    "revoke_sessions": _step_revoke_sessions,
    "revoke_tokens": _step_revoke_tokens,
    "remove_roles": _step_remove_roles,
    "revoke_api_keys": _step_revoke_api_keys,
    "mark_deprovisioned": _step_mark,
    "verify": _step_verify,
}


def due_scheduled_leavers(db: Session) -> list[uuid.UUID]:
    return list(db.execute(select(LifecycleEvent.id).where(
        LifecycleEvent.kind == "LEAVER", LifecycleEvent.status == "SCHEDULED", LifecycleEvent.effective_at <= utcnow(),
    )).scalars())
