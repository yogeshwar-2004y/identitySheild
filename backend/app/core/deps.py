"""Request dependencies: the "gateway" checks every protected endpoint goes through.

`get_ctx` performs, in order:
  1. bearer token (or API key) parsing and signature/expiry validation;
  2. tenant lookup (must be ACTIVE) and binding the DB transaction to the tenant (RLS);
  3. revocation check in Redis (`jti`, `sid`, per-user cut-off);
  4. claims-version check (roles changed by a Mover -> token must be refreshed);
  5. idle-timeout check (Redis last-seen) and absolute-timeout check (token `exp` <= session end);
  6. device / network drift check against the session binding (detection D02);
  7. per-user rate limit.
Routes then add RBAC with `require_roles(...)`.
"""
from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import redis as rds
from app.core.config import get_settings
from app.core.security import AccessClaims, constant_time_equals, decode_access_token, sha256_hex, ua_hash, utcnow
from app.core.tenancy import tenant_settings
from app.db.session import _factory_, bind_tenant
from app.models import ApiKey, Session as SessionRow, Tenant, User


@dataclass
class ClientInfo:
    ip: str
    user_agent: str

    @property
    def ua_hash(self) -> str:
        return ua_hash(self.user_agent)


@dataclass
class Principal:
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    roles: list[str]
    email: str
    sid: uuid.UUID | None = None
    jti: str | None = None
    exp: int = 0
    kind: str = "session"  # session | api_key

    def has(self, *roles: str) -> bool:
        return bool(set(roles) & set(self.roles))


@dataclass
class Ctx:
    db: Session
    tenant: Tenant
    principal: Principal
    client: ClientInfo
    flags: dict[str, object] = field(default_factory=dict)

    @property
    def actor(self) -> str:
        return f"user:{self.principal.email}"

    def commit(self) -> None:
        """Commit now and re-bind the tenant (SET LOCAL does not survive a commit)."""
        self.db.commit()
        self.db.begin()
        bind_tenant(self.db, self.tenant.id)


def is_lab_request(request: Request) -> bool:
    s = get_settings()
    key = request.headers.get("x-lab-key")
    return bool(s.lab_mode and s.lab_api_key and key and constant_time_equals(key, s.lab_api_key))


def client_info(request: Request) -> ClientInfo:
    ip = request.client.host if request.client else "0.0.0.0"
    # LAB ONLY: the simulator labels its traffic with a synthetic source IP.
    if is_lab_request(request) and request.headers.get("x-lab-client-ip"):
        ip = request.headers["x-lab-client-ip"]
    return ClientInfo(ip=ip, user_agent=request.headers.get("user-agent", "")[:400])


def _unauthorized(code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=401, detail={"code": code, "message": message},
        headers={"WWW-Authenticate": f'Bearer error="invalid_token", error_description="{code}"',
                 "Cache-Control": "no-store"},
    )


def _record_rejection(db: Session, tenant: Tenant, claims: AccessClaims, client: ClientInfo, reason: str) -> None:
    from app.events.service import record_event

    record_event(db, tenant, type="TOKEN_REJECTED", user_id=uuid.UUID(claims.sub), session_id=uuid.UUID(claims.sid),
                 ip=client.ip, ua_hash=client.ua_hash, outcome="FAILURE", details={"reason": reason, "jti": claims.jti})
    db.commit()


def _api_key_principal(db: Session, raw_key: str) -> tuple[Principal, Tenant]:
    """X-API-Key: personal access token. Tenant is derived from the key row itself."""
    from app.sessions.service import APP_ROLES, user_role_names

    if not raw_key.startswith("isk_") or len(raw_key) < 20:
        raise _unauthorized("invalid_api_key", "Invalid API key")
    prefix = raw_key[:12]
    tenant_hint = raw_key.split("_")[1] if raw_key.count("_") >= 2 else ""
    tenant = db.execute(select(Tenant).where(Tenant.realm == tenant_hint)).scalar_one_or_none()
    if tenant is None:
        raise _unauthorized("invalid_api_key", "Invalid API key")
    bind_tenant(db, tenant.id)
    key = db.execute(select(ApiKey).where(ApiKey.key_hash == sha256_hex(raw_key))).scalar_one_or_none()
    if key is None or key.revoked_at is not None or not key.prefix == prefix:
        raise _unauthorized("invalid_api_key", "API key revoked or unknown")
    user = db.get(User, key.user_id)
    if user is None or user.state != "ACTIVE":
        raise _unauthorized("user_inactive", "Account is not active")
    key.last_used_at = utcnow()
    roles = [r for r in user_role_names(db, user.id) if r in APP_ROLES]
    return Principal(user_id=user.id, tenant_id=tenant.id, roles=roles, email=user.email, kind="api_key"), tenant


def get_ctx(request: Request) -> Iterator[Ctx]:
    settings = get_settings()
    client = client_info(request)
    db = _factory_()()
    db.begin()
    try:
        auth = request.headers.get("authorization", "")
        api_key = request.headers.get("x-api-key")
        if api_key and not auth:
            principal, tenant = _api_key_principal(db, api_key)
        else:
            if not auth.lower().startswith("bearer "):
                raise _unauthorized("missing_token", "Bearer token required")
            try:
                claims = decode_access_token(auth[7:].strip())
            except jwt.ExpiredSignatureError:
                raise _unauthorized("token_expired", "Access token expired")
            except jwt.PyJWTError:
                raise _unauthorized("invalid_token", "Access token invalid")

            tenant = db.get(Tenant, uuid.UUID(claims.tenant_id))
            if tenant is None or tenant.status != "ACTIVE":
                raise _unauthorized("tenant_inactive", "Tenant not active")
            bind_tenant(db, tenant.id)
            cfg = tenant_settings(tenant)
            iat = claims.iat

            # 3. revocation list
            if rds.is_revoked(claims.jti, claims.sid, claims.sub, iat):
                _record_rejection(db, tenant, claims, client, "revoked")
                raise _unauthorized("token_revoked", "Token or session has been revoked")
            # 4. claims version (role change)
            current_ver = rds.claims_version(claims.sid)
            if current_ver is not None and claims.ver < current_ver:
                raise _unauthorized("claims_changed", "Privileges changed; refresh required")
            # 5. idle timeout
            last = rds.last_seen(claims.sid)
            if last is None or time.time() - last > cfg.idle_timeout_minutes * 60:
                s = db.get(SessionRow, uuid.UUID(claims.sid))
                if s is not None and s.revoked_at is None:
                    from app.sessions.service import revoke_session

                    revoke_session(db, tenant, s, reason="idle_timeout", actor="system")
                    db.commit()
                raise _unauthorized("idle_timeout", "Session idle timeout")
            # 6. session binding: the sid must belong to this tenant and user (defense in depth),
            #    and device / network drift is reported to detection (D02).
            from app.sessions.service import get_cached_binding

            bound = get_cached_binding(claims.sid)
            if bound is None or bound.get("tenant_id") != claims.tenant_id or bound.get("user_id") != claims.sub:
                raise _unauthorized("session_mismatch", "Token does not match a live session")
            _drift_check(db, tenant, claims, client, request)
            if rds.is_revoked(claims.jti, claims.sid, claims.sub, iat):
                raise _unauthorized("token_revoked", "Session revoked by automated response")
            rds.touch_session(claims.sid, cfg.idle_timeout_minutes * 60)
            principal = Principal(
                user_id=uuid.UUID(claims.sub), tenant_id=tenant.id, roles=claims.roles, email=claims.email,
                sid=uuid.UUID(claims.sid), jti=claims.jti, exp=claims.exp,
            )
        # 7. per-user rate limit
        if rds.rate_limited(f"api:{principal.user_id}", settings.rate_limit_api_per_minute):
            raise HTTPException(status_code=429, detail={"code": "rate_limited", "message": "Too many requests"})
        yield Ctx(db=db, tenant=tenant, principal=principal, client=client)
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _drift_check(db: Session, tenant: Tenant, claims: AccessClaims, client: ClientInfo, request: Request) -> None:
    from app.core import geoip
    from app.events.service import record_event
    from app.sessions.service import get_cached_binding

    bound = get_cached_binding(claims.sid)
    if not bound:
        return
    geo = geoip.lookup(client.ip)
    changes: list[str] = []
    if bound.get("ua_hash") and bound["ua_hash"] != client.ua_hash:
        changes.append("user_agent")
    if geo and bound.get("asn") and geo.asn != bound["asn"]:
        changes.append("asn")
    if geo and bound.get("country") and geo.country != bound["country"]:
        changes.append("country")
    if not changes:
        return
    # Only report a given drift once per session per minute to avoid flooding.
    key = f"drift:{claims.sid}:{client.ip}:{client.ua_hash[:8]}"
    if not rds.get_redis().set(key, "1", nx=True, ex=60):
        return
    record_event(db, tenant, type="SESSION_ANOMALY", user_id=uuid.UUID(claims.sub), session_id=uuid.UUID(claims.sid),
                 ip=client.ip, ua_hash=client.ua_hash, outcome="FAILURE",
                 details={"bound": bound, "changes": changes, "path": request.url.path})
    if tenant_settings(tenant).drift_policy == "revoke":
        s = db.get(SessionRow, uuid.UUID(claims.sid))
        if s is not None:
            from app.sessions.service import revoke_session

            revoke_session(db, tenant, s, reason="device_drift", actor="system")
    db.commit()
    db.begin()
    bind_tenant(db, tenant.id)


def require_roles(*roles: str) -> Callable[[Ctx], Ctx]:
    def checker(ctx: Ctx = Depends(get_ctx)) -> Ctx:
        if not ctx.principal.has(*roles):
            raise HTTPException(status_code=403, detail={"code": "forbidden",
                                                         "message": f"Requires one of: {', '.join(roles)}"})
        return ctx

    return checker


def require_lab(request: Request) -> None:
    if not get_settings().lab_mode:
        raise HTTPException(status_code=404, detail="Not found")
    if not is_lab_request(request):
        raise HTTPException(status_code=401, detail={"code": "lab_key_required", "message": "X-Lab-Key required"})


def require_platform(request: Request) -> None:
    key = request.headers.get("x-platform-key", "")
    if not key or not constant_time_equals(key, get_settings().platform_api_key):
        raise HTTPException(status_code=401, detail={"code": "platform_key_required", "message": "Platform key required"})
