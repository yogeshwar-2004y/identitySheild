"""Authentication endpoints (backend-for-frontend).

The browser never sees Keycloak tokens. Flow:
  GET  /auth/login?tenant=acme   -> 302 to Keycloak (code flow + PKCE S256, state, nonce)
  GET  /auth/callback            -> code exchange, ID token validation, new app session,
                                    refresh token in an HttpOnly cookie, 302 to the SPA
  POST /auth/refresh             -> rotates the refresh token, returns a 5-minute access token
                                    (the SPA keeps it in memory only)
  POST /auth/logout[-all]        -> safe logout (section 4.1)
  POST /auth/backchannel-logout  -> called by Keycloak when an SSO session ends elsewhere
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import uuid
from typing import Any

import jwt
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import write_audit
from app.core import redis as rds
from app.core.config import get_settings
from app.core.deps import Ctx, client_info, get_ctx
from app.core.pubsub import run_after_commit
from app.core.keycloak import InvalidGrant, KeycloakError
from app.core.security import constant_time_equals, decrypt_str, utcnow
from app.core.tenancy import get_tenant_by_realm, idp_for
from app.db.session import _factory_, bind_tenant, platform_session, tenant_session
from app.events.service import record_event
from app.models import Session as SessionRow, Tenant, User
from app.sessions.service import (
    IssuedTokens, SessionError, login as session_login, revoke_all_user_sessions, revoke_session, rotate_refresh,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


# ------------------------------------------------------------------ helpers


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _redirect_uri() -> str:
    return f"{get_settings().public_url}/api/auth/callback"


def refresh_token_for_tenant(tenant_id: uuid.UUID, opaque: str) -> str:
    # The tenant id prefix lets /auth/refresh bind the right tenant (RLS) before lookup.
    return f"{tenant_id}.{opaque}"


def split_refresh(value: str) -> tuple[uuid.UUID, str]:
    try:
        tid, token = value.split(".", 1)
        return uuid.UUID(tid), token
    except ValueError:
        raise HTTPException(401, detail={"code": "invalid_refresh", "message": "Malformed refresh token"})


def set_session_cookies(resp: Response, issued: IssuedTokens) -> None:
    s = get_settings()
    max_age = int((issued.session.expires_at - utcnow()).total_seconds())
    resp.set_cookie(
        s.refresh_cookie_name, refresh_token_for_tenant(issued.session.tenant_id, issued.refresh_token),
        max_age=max_age, path="/", secure=s.cookie_secure, httponly=True, samesite="strict",
    )
    # Double-submit CSRF token: readable by the SPA, echoed in X-CSRF-Token on cookie-authenticated calls.
    resp.set_cookie(s.csrf_cookie_name, secrets.token_urlsafe(24), max_age=max_age, path="/",
                    secure=s.cookie_secure, httponly=False, samesite="strict")


def clear_session_cookies(resp: Response) -> None:
    s = get_settings()
    for name, http_only in ((s.refresh_cookie_name, True), (s.csrf_cookie_name, False)):
        resp.delete_cookie(name, path="/", secure=s.cookie_secure, httponly=http_only, samesite="strict")


def _check_csrf(request: Request) -> None:
    s = get_settings()
    cookie = request.cookies.get(s.csrf_cookie_name, "")
    header = request.headers.get("x-csrf-token", "")
    if not cookie or not header or not constant_time_equals(cookie, header):
        raise HTTPException(403, detail={"code": "csrf", "message": "CSRF token missing or invalid"})


def _rate_limit(request: Request, bucket: str) -> None:
    ip = client_info(request).ip
    if rds.rate_limited(f"{bucket}:{ip}", get_settings().rate_limit_auth_per_minute):
        raise HTTPException(429, detail={"code": "rate_limited", "message": "Too many attempts"})


def token_response(issued: IssuedTokens, roles: list[str]) -> dict[str, Any]:
    u = issued.user
    return {
        "access_token": issued.access_token,
        "token_type": "Bearer",
        "expires_at": issued.access_expires_at.isoformat(),
        "session_id": str(issued.session.id),
        "session_expires_at": issued.session.expires_at.isoformat(),
        "user": {"id": str(u.id), "email": u.email, "username": u.username, "full_name": u.full_name,
                 "department": u.department, "state": u.state, "roles": roles},
    }


# ------------------------------------------------------------------ login / callback


@router.get("/login")
def login(request: Request, tenant: str) -> RedirectResponse:
    _rate_limit(request, "auth-login")
    with platform_session() as db:
        t = get_tenant_by_realm(db, tenant.strip().lower())
        if t is None or t.status != "ACTIVE":
            return RedirectResponse(f"{get_settings().public_url}/login?error=unknown_tenant", 302, headers=NO_STORE)
        idp = idp_for(t)
        tenant_id = t.id
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    verifier, challenge = _pkce_pair()
    rds.get_redis().set(f"oidc:state:{state}", json.dumps({"tenant_id": str(tenant_id), "nonce": nonce,
                                                           "verifier": verifier}), ex=600)
    url = idp.authorization_url(state=state, nonce=nonce, code_challenge=challenge, redirect_uri=_redirect_uri())
    return RedirectResponse(url, 302, headers=NO_STORE)


@router.get("/callback")
def callback(request: Request, state: str = "", code: str = "", error: str = "") -> RedirectResponse:
    public = get_settings().public_url
    if error:
        return RedirectResponse(f"{public}/login?error={error}", 302, headers=NO_STORE)
    raw = rds.get_redis().getdel(f"oidc:state:{state}") if state else None  # one-time use
    if not raw or not code:
        return RedirectResponse(f"{public}/login?error=invalid_state", 302, headers=NO_STORE)
    st = json.loads(raw)
    client = client_info(request)
    with tenant_session(st["tenant_id"]) as db:
        tenant = db.get(Tenant, uuid.UUID(st["tenant_id"]))
        assert tenant is not None
        idp = idp_for(tenant)
        try:
            kc = idp.exchange_code(code=code, code_verifier=st["verifier"], redirect_uri=_redirect_uri())
            id_claims = idp.verify_id_token(kc["id_token"], st["nonce"])
        except (KeycloakError, jwt.PyJWTError, KeyError) as exc:
            log.warning("callback failed: %s", exc)
            return RedirectResponse(f"{public}/login?error=login_failed", 302, headers=NO_STORE)
        user = db.execute(select(User).where(User.kc_user_id == id_claims["sub"])).scalar_one_or_none()
        if user is None:
            write_audit(db, tenant.id, actor="system", action="auth.unprovisioned_login",
                        target=f"kc:{id_claims['sub']}", detail={"username": id_claims.get("preferred_username")})
            rt = kc.get("refresh_token", "")
            run_after_commit(db, lambda: idp.end_session(rt), "kc end session")
            return RedirectResponse(f"{public}/login?error=not_provisioned", 302, headers=NO_STORE)
        if user.state in ("DEPROVISIONED", "SUSPENDED"):
            record_event(db, tenant, type="TOKEN_REJECTED", user_id=user.id, ip=client.ip, ua_hash=client.ua_hash,
                         outcome="FAILURE", details={"reason": f"user_{user.state}", "kind": "login"})
            rt = kc.get("refresh_token", "")
            run_after_commit(db, lambda: idp.end_session(rt), "kc end session")
            return RedirectResponse(f"{public}/login?error=account_inactive", 302, headers=NO_STORE)
        issued = _complete_login(db, tenant, user, client.ip, client.user_agent, kc, id_claims.get("sid"), "browser")
        resp = RedirectResponse(f"{public}/auth/complete", 302, headers=NO_STORE)
        set_session_cookies(resp, issued)
        return resp


def _complete_login(db: Session, tenant: Tenant, user: User, ip: str, ua: str, kc: dict[str, Any],
                    kc_sid: str | None, source: str) -> IssuedTokens:
    if user.state == "PENDING":
        # Joiner completes on first successful login (Keycloak has already enforced the
        # required actions: verify email, set password, enrol TOTP).
        user.state = "ACTIVE"
        user.activated_at = utcnow()
        write_audit(db, tenant.id, actor=f"user:{user.username}", action="user.activated", target=f"user:{user.id}",
                    detail={"via": source})
    if user.kc_user_id and source == "browser":
        try:
            user.mfa_enrolled = idp_for(tenant).has_otp(user.kc_user_id)
        except KeycloakError:
            pass
    rds.get_redis().delete(f"stepup:user:{user.id}")  # a fresh Keycloak login satisfies a pending step-up
    issued = session_login(db, tenant, user, ip=ip, user_agent=ua, kc_tokens=kc, kc_session_id=kc_sid, source=source)
    write_audit(db, tenant.id, actor=f"user:{user.username}", action="auth.login", target=f"session:{issued.session.id}",
                detail={"ip": ip, "source": source, "mfa_enrolled": user.mfa_enrolled})
    return issued


# ------------------------------------------------------------------ refresh


class RefreshBody(BaseModel):
    refresh_token: str | None = None


@router.post("/refresh")
def refresh(request: Request, body: RefreshBody | None = None) -> JSONResponse:
    _rate_limit(request, "auth-refresh")
    s = get_settings()
    cookie_value = request.cookies.get(s.refresh_cookie_name)
    if cookie_value:
        _check_csrf(request)
        presented = cookie_value
    elif body and body.refresh_token:
        presented = body.refresh_token  # non-browser clients (simulator, demo script)
    else:
        raise HTTPException(401, detail={"code": "no_refresh", "message": "Not signed in"}, headers=NO_STORE)
    tenant_id, opaque = split_refresh(presented)
    client = client_info(request)
    db = _factory_()()
    db.begin()
    try:
        bind_tenant(db, tenant_id)
        tenant = db.get(Tenant, tenant_id)
        if tenant is None:
            raise HTTPException(401, detail={"code": "invalid_refresh", "message": "Unknown tenant"})
        try:
            issued = rotate_refresh(db, tenant, opaque, ip=client.ip, user_agent=client.user_agent)
        except SessionError as exc:
            db.commit()  # persist the revocation / reuse evidence before refusing
            resp = JSONResponse({"detail": {"code": exc.code, "message": str(exc)}}, status_code=401, headers=NO_STORE)
            clear_session_cookies(resp)
            return resp
        from app.sessions.service import user_role_names

        roles = [r for r in user_role_names(db, issued.user.id) if r in ("admin", "analyst", "hr", "user")]
        payload = token_response(issued, roles)
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    if not cookie_value:
        payload["refresh_token"] = refresh_token_for_tenant(tenant_id, issued.refresh_token)
    resp = JSONResponse(payload, headers=NO_STORE)
    if cookie_value:
        set_session_cookies(resp, issued)
    return resp


# ------------------------------------------------------------------ logout


def _session_from_request(request: Request) -> tuple[uuid.UUID, uuid.UUID] | None:
    """(tenant_id, session_id) from the bearer token (expired is fine) or the refresh cookie."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        try:
            data = jwt.decode(auth[7:], get_settings().jwt_secret, algorithms=["HS256"], audience="identityshield",
                              options={"verify_exp": False})
            return uuid.UUID(data["tenant_id"]), uuid.UUID(data["sid"])
        except (jwt.PyJWTError, KeyError, ValueError):
            pass
    cookie = request.cookies.get(get_settings().refresh_cookie_name)
    if cookie:
        tid, opaque = split_refresh(cookie)
        from app.core.security import sha256_hex
        from app.models import RefreshFamily, RefreshToken

        with tenant_session(tid) as db:
            fam_id = db.execute(select(RefreshToken.family_id).where(RefreshToken.token_hash == sha256_hex(opaque))
                                ).scalar_one_or_none()
            if fam_id:
                fam = db.get(RefreshFamily, fam_id)
                if fam:
                    return tid, fam.session_id
    return None


def _logout(request: Request, everywhere: bool) -> JSONResponse:
    s = get_settings()
    if request.cookies.get(s.refresh_cookie_name):
        _check_csrf(request)
    found = _session_from_request(request)
    logout_url = f"{s.public_url}/login?logged_out=1"
    revoked = 0
    if found:
        tenant_id, sid = found
        with tenant_session(tenant_id) as db:
            tenant = db.get(Tenant, tenant_id)
            sess = db.get(SessionRow, sid)
            if tenant and sess:
                user = db.get(User, sess.user_id)
                idp = idp_for(tenant)
                id_token = decrypt_str(sess.kc_id_token_enc) if sess.kc_id_token_enc else None
                kc_refresh = decrypt_str(sess.kc_refresh_enc) if sess.kc_refresh_enc else None
                actor = f"user:{user.username}" if user else "user"
                if everywhere and user:
                    revoked = revoke_all_user_sessions(db, tenant, user, reason="logout_all", actor=actor)
                else:
                    revoke_session(db, tenant, sess, reason="logout", actor=actor)
                    revoked = 1
                # End the Keycloak SSO session (after commit, see core/pubsub.py); Keycloak then
                # fans out back-channel logout to every client of that session.
                if kc_refresh:
                    run_after_commit(db, lambda: idp.end_session(kc_refresh), "kc end session")
                record_event(db, tenant, type="LOGOUT", user_id=sess.user_id, session_id=sess.id,
                             ip=client_info(request).ip, details={"everywhere": everywhere, "source": "app"},
                             detect=False)
                write_audit(db, tenant.id, actor=actor, action="auth.logout_all" if everywhere else "auth.logout",
                            target=f"session:{sess.id}", detail={"sessions_revoked": revoked})
                # Front-channel hop clears the Keycloak browser cookie as well.
                logout_url = idp.end_session_url(id_token_hint=id_token,
                                                 post_logout_redirect_uri=f"{s.public_url}/login")
    resp = JSONResponse({"ok": True, "sessions_revoked": revoked, "logout_url": logout_url},
                        headers={**NO_STORE, "Clear-Site-Data": '"cache", "cookies", "storage"'})
    clear_session_cookies(resp)
    return resp


@router.post("/logout")
def logout(request: Request) -> JSONResponse:
    return _logout(request, everywhere=False)


@router.post("/logout-all")
def logout_all(request: Request) -> JSONResponse:
    return _logout(request, everywhere=True)


@router.post("/backchannel-logout")
def backchannel_logout(logout_token: str = Form(...)) -> Response:
    """OIDC Back-Channel Logout 1.0. Keycloak calls this when an SSO session ends."""
    try:
        unverified = jwt.decode(logout_token, options={"verify_signature": False})
        realm = str(unverified["iss"]).rstrip("/").split("/realms/")[-1]
    except (jwt.PyJWTError, KeyError):
        raise HTTPException(400, detail="invalid logout token")
    with platform_session() as pdb:
        tenant = get_tenant_by_realm(pdb, realm)
        tenant_id = tenant.id if tenant else None
    if tenant_id is None:
        raise HTTPException(400, detail="unknown realm")
    with tenant_session(tenant_id) as db:
        tenant = db.get(Tenant, tenant_id)
        assert tenant is not None
        try:
            claims = idp_for(tenant).verify_logout_token(logout_token)
        except (KeycloakError, jwt.PyJWTError) as exc:
            raise HTTPException(400, detail=f"invalid logout token: {exc}")
        q = select(SessionRow).where(SessionRow.revoked_at.is_(None))
        if claims.get("sid"):
            q = q.where(SessionRow.kc_session_id == claims["sid"])
        else:
            uid = db.execute(select(User.id).where(User.kc_user_id == claims.get("sub"))).scalar_one_or_none()
            q = q.where(SessionRow.user_id == uid)
        # SKIP LOCKED: rows being revoked right now by another request (which triggered this
        # callback) are already handled; waiting on them would deadlock with Keycloak.
        for sess in db.execute(q.with_for_update(skip_locked=True)).scalars().all():
            revoke_session(db, tenant, sess, reason="backchannel_logout", actor="keycloak", call_idp=False)
    return Response(status_code=200, headers=NO_STORE)


@router.get("/me")
def me(ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
    user = ctx.db.get(User, ctx.principal.user_id)
    assert user is not None
    return {
        "id": str(user.id), "email": user.email, "username": user.username, "full_name": user.full_name,
        "department": user.department, "state": user.state, "roles": ctx.principal.roles,
        "session_id": str(ctx.principal.sid) if ctx.principal.sid else None,
        "tenant": {"id": str(ctx.tenant.id), "name": ctx.tenant.name, "realm": ctx.tenant.realm},
        "lab_mode": get_settings().lab_mode,
    }
