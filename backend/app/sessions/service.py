"""Session registry, refresh-token rotation with reuse detection, revocation.

Design (architecture section 4):
* every login creates a new server-side session row (prevents session fixation);
* access tokens live 5 minutes and are bound to the session id (`sid`);
* refresh tokens are single use; each refresh rotates the token, and presenting
  an already-rotated token revokes the whole family (session) and emits
  REFRESH_TOKEN_REUSE (detection D03);
* idle (15 min) and absolute (8 h) timeouts are enforced at refresh time and on
  every request (Redis last-seen);
* revocation writes the `sid` and every outstanding `jti` to Redis, which the
  auth dependency checks on each request.
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import write_audit
from app.core import geoip
from app.core import redis as rds
from app.core.keycloak import InvalidGrant, KeycloakError
from app.core.pubsub import run_after_commit
from app.core.security import (
    decrypt_str, encrypt_str, issue_access_token, new_opaque_token, sha256_hex, ua_hash, utcnow,
)
from app.core.tenancy import idp_for, tenant_settings
from app.events.service import record_event
from app.models import RefreshFamily, RefreshToken, Role, Session as SessionRow, Tenant, User, UserRole

log = logging.getLogger(__name__)

APP_ROLES = ("admin", "analyst", "hr", "user")


class SessionError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class IssuedTokens:
    session: SessionRow
    user: User
    access_token: str
    access_expires_at: datetime
    refresh_token: str


def user_role_names(db: Session, user_id: uuid.UUID) -> list[str]:
    rows = db.execute(
        select(Role.name).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user_id)
    ).scalars().all()
    return sorted(rows)


def binding_of(s: SessionRow) -> dict[str, Any]:
    return {"ip": s.ip, "asn": s.asn, "country": (s.geo or {}).get("country"), "ua_hash": s.ua_hash,
            "tenant_id": str(s.tenant_id), "user_id": str(s.user_id)}


def _cache_binding(s: SessionRow, ttl: int) -> None:
    rds.get_redis().set(f"sess:bind:{s.id}", json.dumps(binding_of(s)), ex=ttl)


def get_cached_binding(sid: str) -> dict[str, Any] | None:
    raw = rds.get_redis().get(f"sess:bind:{sid}")
    return json.loads(raw) if raw else None


def active_sessions(db: Session, user_id: uuid.UUID) -> list[SessionRow]:
    now = utcnow()
    return list(db.execute(
        select(SessionRow).where(SessionRow.user_id == user_id, SessionRow.revoked_at.is_(None),
                                 SessionRow.expires_at > now).order_by(SessionRow.created_at.asc())
    ).scalars())


# ------------------------------------------------------------------ creation / issue


def create_session(
    db: Session, tenant: Tenant, user: User, *, ip: str, user_agent: str, kc_tokens: dict[str, Any] | None,
    kc_session_id: str | None, source: str = "browser", parent: SessionRow | None = None,
) -> tuple[SessionRow, str]:
    cfg = tenant_settings(tenant)
    now = utcnow()

    # Concurrent session cap.
    live = active_sessions(db, user.id)
    if parent is None and len(live) >= cfg.max_concurrent_sessions:
        if cfg.concurrent_policy == "block":
            raise SessionError("session_limit", "Concurrent session limit reached")
        for old in live[: len(live) - cfg.max_concurrent_sessions + 1]:
            revoke_session(db, tenant, old, reason="concurrent_session_cap", actor="system")

    geo = geoip.lookup(ip)
    s = SessionRow(
        id=uuid.uuid4(), tenant_id=tenant.id, user_id=user.id, kc_session_id=kc_session_id, ip=ip,
        geo=geo.as_dict() if geo else None, asn=geo.asn if geo else None, ua_hash=ua_hash(user_agent),
        user_agent=(user_agent or "")[:400], source=source,
        claims_version=(parent.claims_version + 1) if parent else 1,
        parent_session_id=parent.id if parent else None,
        kc_refresh_enc=encrypt_str(kc_tokens["refresh_token"]) if kc_tokens and kc_tokens.get("refresh_token") else
        (parent.kc_refresh_enc if parent else None),
        kc_id_token_enc=encrypt_str(kc_tokens["id_token"]) if kc_tokens and kc_tokens.get("id_token") else
        (parent.kc_id_token_enc if parent else None),
        created_at=now, last_seen_at=now,
        expires_at=parent.expires_at if parent else now + timedelta(hours=cfg.absolute_timeout_hours),
    )
    db.add(s)
    db.flush()

    refresh = new_opaque_token()
    fam = RefreshFamily(tenant_id=tenant.id, session_id=s.id, current_token_hash=sha256_hex(refresh))
    db.add(fam)
    db.flush()
    db.add(RefreshToken(token_hash=sha256_hex(refresh), tenant_id=tenant.id, family_id=fam.id))

    ttl = int((s.expires_at - now).total_seconds()) + 60
    _cache_binding(s, ttl)
    rds.touch_session(str(s.id), cfg.idle_timeout_minutes * 60)
    rds.set_claims_version(str(s.id), s.claims_version)

    record_event(db, tenant, type="SESSION_CREATED", user_id=user.id, session_id=s.id, ip=ip,
                 ua_hash=s.ua_hash, details={"source": source, "reissued_from": str(parent.id) if parent else None})
    write_audit(db, tenant.id, actor=f"user:{user.username}", action="session.created", target=f"session:{s.id}",
                detail={"ip": ip, "geo": s.geo, "source": source,
                        "parent_session_id": str(parent.id) if parent else None})
    return s, refresh


def issue_access(db: Session, tenant: Tenant, s: SessionRow, user: User) -> tuple[str, datetime]:
    cfg = tenant_settings(tenant)
    roles = [r for r in user_role_names(db, user.id) if r in APP_ROLES]
    token, jti, exp = issue_access_token(
        user_id=user.id, tenant_id=tenant.id, session_id=s.id, roles=roles, email=user.email,
        claims_version=s.claims_version, ttl_seconds=cfg.access_token_ttl_seconds, not_after=s.expires_at,
    )
    rds.track_session_jti(str(s.id), jti, int((exp - utcnow()).total_seconds()) + 5)
    return token, exp


def login(db: Session, tenant: Tenant, user: User, *, ip: str, user_agent: str, kc_tokens: dict[str, Any] | None,
          kc_session_id: str | None, source: str = "browser") -> IssuedTokens:
    s, refresh = create_session(db, tenant, user, ip=ip, user_agent=user_agent, kc_tokens=kc_tokens,
                                kc_session_id=kc_session_id, source=source)
    access, exp = issue_access(db, tenant, s, user)
    return IssuedTokens(s, user, access, exp, refresh)


# ------------------------------------------------------------------ refresh rotation


def _descendants(db: Session, s: SessionRow) -> list[SessionRow]:
    out: list[SessionRow] = []
    frontier = [s.id]
    while frontier:
        children = list(db.execute(select(SessionRow).where(SessionRow.parent_session_id.in_(frontier))).scalars())
        out += children
        frontier = [c.id for c in children]
    return out


def rotate_refresh(db: Session, tenant: Tenant, presented: str, *, ip: str, user_agent: str) -> IssuedTokens:
    cfg = tenant_settings(tenant)
    now = utcnow()
    h = sha256_hex(presented)
    tok = db.execute(select(RefreshToken).where(RefreshToken.token_hash == h).with_for_update()).scalar_one_or_none()
    if tok is None:
        raise SessionError("invalid_refresh", "Unknown refresh token")
    fam = db.execute(select(RefreshFamily).where(RefreshFamily.id == tok.family_id).with_for_update()).scalar_one()
    s = db.get(SessionRow, fam.session_id)
    assert s is not None
    user = db.get(User, s.user_id)
    assert user is not None

    if tok.rotated_at is not None or fam.current_token_hash != h:
        # REUSE: an old refresh token came back. Either the legitimate client or an attacker
        # holds a stolen copy; we cannot tell which, so the whole family dies.
        fam.reused_at = now
        record_event(db, tenant, type="REFRESH_TOKEN_REUSE", user_id=user.id, session_id=s.id, ip=ip,
                     ua_hash=ua_hash(user_agent), outcome="FAILURE",
                     details={"family_id": str(fam.id), "rotated_at": tok.rotated_at.isoformat() if tok.rotated_at
                              else None})
        # The family includes any sessions re-issued from this one (Mover / privilege change).
        for victim in [s, *_descendants(db, s)]:
            if victim.revoked_at is None:
                revoke_session(db, tenant, victim, reason="refresh_token_reuse", actor="system")
        raise SessionError("refresh_reuse", "Refresh token reuse detected; session revoked")

    if s.revoked_at is not None or fam.revoked_at is not None:
        record_event(db, tenant, type="TOKEN_REJECTED", user_id=user.id, session_id=s.id, ip=ip,
                     ua_hash=ua_hash(user_agent), outcome="FAILURE", details={"reason": "session_revoked",
                                                                                "kind": "refresh"})
        raise SessionError("session_revoked", "Session has been revoked")
    if user.state not in ("ACTIVE", "PENDING"):
        revoke_session(db, tenant, s, reason=f"user_{user.state.lower()}", actor="system")
        record_event(db, tenant, type="TOKEN_REJECTED", user_id=user.id, session_id=s.id, ip=ip,
                     ua_hash=ua_hash(user_agent), outcome="FAILURE", details={"reason": f"user_{user.state}",
                                                                                "kind": "refresh"})
        raise SessionError("user_inactive", "Account is not active")
    if now >= s.expires_at:
        revoke_session(db, tenant, s, reason="absolute_timeout", actor="system")
        raise SessionError("absolute_timeout", "Session reached its absolute lifetime")
    last = rds.last_seen(str(s.id))
    if last is None or now.timestamp() - last > cfg.idle_timeout_minutes * 60:
        revoke_session(db, tenant, s, reason="idle_timeout", actor="system")
        raise SessionError("idle_timeout", "Session idle for too long")
    if rds.get_redis().exists(f"stepup:user:{user.id}", f"stepup:session:{s.id}"):
        revoke_session(db, tenant, s, reason="step_up_required", actor="system")
        raise SessionError("step_up_required", "Re-authentication with MFA required")

    # Keep the Keycloak SSO session in lock-step: if an admin killed it there (or disabled
    # the user), our session dies too.
    if s.kc_refresh_enc:
        try:
            kc = idp_for(tenant).refresh(decrypt_str(s.kc_refresh_enc))
            if kc.get("refresh_token"):
                s.kc_refresh_enc = encrypt_str(kc["refresh_token"])
            if kc.get("id_token"):
                s.kc_id_token_enc = encrypt_str(kc["id_token"])
        except InvalidGrant:
            revoke_session(db, tenant, s, reason="idp_session_ended", actor="system", call_idp=False)
            raise SessionError("idp_session_ended", "Identity provider session ended")
        except KeycloakError:
            log.warning("keycloak refresh unavailable for session %s", s.id)
            raise SessionError("idp_unavailable", "Identity provider unavailable")

    tok.rotated_at = now
    target = s
    if s.reissue_required:
        # Privilege changed (Mover): new session id + new family, old one closed.
        target, new_refresh = create_session(db, tenant, user, ip=s.ip, user_agent=s.user_agent, kc_tokens=None,
                                             kc_session_id=s.kc_session_id, source=s.source, parent=s)
        revoke_session(db, tenant, s, reason="reissued_after_privilege_change", actor="system", call_idp=False)
    else:
        new_refresh = new_opaque_token()
        fam.current_token_hash = sha256_hex(new_refresh)
        db.add(RefreshToken(token_hash=sha256_hex(new_refresh), tenant_id=tenant.id, family_id=fam.id))
    target.last_seen_at = now
    rds.touch_session(str(target.id), cfg.idle_timeout_minutes * 60)
    access, exp = issue_access(db, tenant, target, user)
    record_event(db, tenant, type="APP_TOKEN_REFRESH", user_id=user.id, session_id=target.id, ip=ip,
                 ua_hash=ua_hash(user_agent), details={"reissued": target.id != s.id})
    return IssuedTokens(target, user, access, exp, new_refresh)


# ------------------------------------------------------------------ revocation


def revoke_session(db: Session, tenant: Tenant, s: SessionRow, *, reason: str, actor: str,
                   call_idp: bool = True) -> None:
    """Idempotent. Postgres + Redis + Keycloak, in that order of authority."""
    now = utcnow()
    already = s.revoked_at is not None
    if not already:
        s.revoked_at = now
        s.revoke_reason = reason
    for fam in db.execute(select(RefreshFamily).where(RefreshFamily.session_id == s.id)).scalars():
        if fam.revoked_at is None:
            fam.revoked_at = now
    rds.revoke_sid(str(s.id))
    for jti, ttl in rds.outstanding_jtis(str(s.id)):
        rds.revoke_jti(jti, ttl + 5)
    idp_result = "skipped"
    if call_idp and s.kc_session_id:
        idp, kc_sid = idp_for(tenant), s.kc_session_id
        run_after_commit(db, lambda: idp.delete_session(kc_sid), f"kc delete session {kc_sid}")
        idp_result = "scheduled_after_commit"
    if already:
        return
    record_event(db, tenant, type="SESSION_REVOKED", user_id=s.user_id, session_id=s.id, ip=s.ip,
                 details={"reason": reason, "actor": actor})
    write_audit(db, tenant.id, actor=actor, action="session.revoked", target=f"session:{s.id}",
                detail={"reason": reason, "user_id": str(s.user_id), "idp": idp_result})


def revoke_all_user_sessions(db: Session, tenant: Tenant, user: User, *, reason: str, actor: str) -> int:
    count = 0
    for s in active_sessions(db, user.id):
        revoke_session(db, tenant, s, reason=reason, actor=actor)
        count += 1
    # Belt and braces: kill any Keycloak session we never saw, and reject every token issued so far.
    rds.revoke_user_tokens_before(str(user.id))
    if user.kc_user_id:
        idp, kc_uid = idp_for(tenant), user.kc_user_id
        run_after_commit(db, lambda: idp.logout_user(kc_uid), f"kc logout user {kc_uid}")
    return count
