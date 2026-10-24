"""Normalization of Keycloak events into the common event schema (architecture section 6)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.core.security import ua_hash

# Keycloak user-event type -> normalized type
KC_TYPE_MAP = {
    "LOGIN": "LOGIN",
    "LOGIN_ERROR": "LOGIN_ERROR",
    "LOGOUT": "LOGOUT",
    "LOGOUT_ERROR": "LOGOUT",
    "CODE_TO_TOKEN": "CODE_TO_TOKEN",
    "CODE_TO_TOKEN_ERROR": "CODE_TO_TOKEN",
    "REFRESH_TOKEN": "TOKEN_REFRESH",
    "REFRESH_TOKEN_ERROR": "TOKEN_REFRESH_ERROR",
    "UPDATE_TOTP": "MFA_ENROLLED",
    "UPDATE_CREDENTIAL": "CREDENTIAL_UPDATE",
    "REMOVE_TOTP": "MFA_REMOVED",
    "REMOVE_CREDENTIAL": "CREDENTIAL_REMOVED",
    "UPDATE_PASSWORD": "PASSWORD_UPDATE",
    "VERIFY_EMAIL": "EMAIL_VERIFIED",
    "SEND_VERIFY_EMAIL": "EMAIL_SENT",
    "EXECUTE_ACTIONS": "REQUIRED_ACTIONS_SENT",
    "USER_DISABLED_BY_TEMPORARY_LOCKOUT": "USER_LOCKOUT",
    "USER_DISABLED_BY_PERMANENT_LOCKOUT": "USER_LOCKOUT",
}
OTP_ERRORS = {"invalid_user_credentials_otp", "invalid_totp", "invalid_otp"}


def _ts(ms: int | float | None) -> datetime:
    if not ms:
        return datetime.now(timezone.utc)
    return datetime.fromtimestamp(float(ms) / 1000, tz=timezone.utc)


def normalize_user_event(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Returns kwargs for events.service.record_event, or None for event types we ignore."""
    kc_type = str(raw.get("type", ""))
    norm = KC_TYPE_MAP.get(kc_type)
    if norm is None:
        return None
    details = dict(raw.get("details") or {})
    error = raw.get("error")
    if error:
        details["error"] = error
    # OTP failures surface as LOGIN_ERROR; treat them as MFA denials for D09.
    if kc_type == "LOGIN_ERROR" and (error in OTP_ERRORS or details.get("credential_type") == "otp"):
        norm = "MFA_DENIED"
    outcome = "FAILURE" if (error or kc_type.endswith("_ERROR")) else "SUCCESS"
    ua = details.pop("user_agent", None) or details.get("userAgent")
    return {
        "type": norm,
        "ts": _ts(raw.get("time")),
        "kc_user_id": raw.get("userId"),
        "kc_session_id": raw.get("sessionId"),
        "username": details.get("username"),
        "ip": raw.get("ipAddress"),
        "ua_hash": ua_hash(ua) if ua else None,
        "outcome": outcome,
        "source": "keycloak",
        "source_id": str(raw.get("id") or f"{raw.get('time')}:{kc_type}:{raw.get('userId')}:{raw.get('sessionId')}"),
        "details": {**details, "kc_type": kc_type, "client_id": raw.get("clientId")},
    }


def normalize_admin_event(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Admin events (role mappings, user updates). One admin event can grant several roles."""
    import json as _json

    rtype = raw.get("resourceType")
    op = raw.get("operationType")
    path = str(raw.get("resourcePath") or "")
    parts = path.split("/")
    kc_user_id = parts[1] if len(parts) > 1 and parts[0] == "users" else None
    auth = raw.get("authDetails") or {}
    base = {
        "ts": _ts(raw.get("time")),
        "kc_user_id": kc_user_id,
        "ip": auth.get("ipAddress"),
        "outcome": "SUCCESS",
        "source": "keycloak",
    }
    sid = str(raw.get("id") or f"{raw.get('time')}:{path}:{op}")
    actor = {"actor_kc_user_id": auth.get("userId"), "actor_client": auth.get("clientId")}
    if rtype == "REALM_ROLE_MAPPING" and op in ("CREATE", "DELETE"):
        try:
            roles = [r.get("name") for r in _json.loads(raw.get("representation") or "[]")]
        except ValueError:
            roles = []
        kind = "ROLE_GRANT" if op == "CREATE" else "ROLE_REVOKE"
        return [
            {**base, "type": kind, "source_id": f"{sid}:{role}", "details": {"role": role, "actor": actor, "path": path}}
            for role in roles
        ]
    if rtype == "USER" and kc_user_id:
        kind = {"CREATE": "USER_CREATE", "UPDATE": "USER_UPDATE", "DELETE": "USER_DELETE"}.get(str(op))
        if kind:
            return [{**base, "type": kind, "source_id": sid, "details": {"actor": actor, "path": path}}]
    return []
