"""Test doubles: an in-memory Keycloak (TenantIdP) and an in-memory DetectionContext."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from app.core.keycloak import InvalidGrant, KeycloakError
from app.detection.base import EventView, GrantView, LeaverView, UserView

FAKE_KEY = "fake-idp-signing-key-for-tests-only-0123456789"


@dataclass
class FakeUser:
    id: str
    username: str
    email: str
    password: str | None
    enabled: bool = True
    roles: set[str] = field(default_factory=set)
    required_actions: list[str] = field(default_factory=list)
    otp: bool = False


class FakeIdP:
    """Behaves like the subset of Keycloak the app uses, and records what was called."""

    def __init__(self, realm: str) -> None:
        self.realm = realm
        self.users: dict[str, FakeUser] = {}
        self.sessions: dict[str, str] = {}  # kc session id -> kc user id
        self.refresh_tokens: dict[str, str] = {}  # refresh token -> kc session id
        self.events: list[dict[str, Any]] = []
        self.admin_event_log: list[dict[str, Any]] = []
        self.calls: list[tuple[str, Any]] = []
        self.fail_next: dict[str, int] = {}
        self.codes: dict[str, str] = {}  # auth code -> kc user id

    # -- helpers ---------------------------------------------------------------------
    def _maybe_fail(self, op: str) -> None:
        self.calls.append((op, None))
        if self.fail_next.get(op, 0) > 0:
            self.fail_next[op] -= 1
            raise KeycloakError(f"injected failure in {op}", 500)

    def _event(self, type_: str, user_id: str | None, ip: str | None, error: str | None = None,
               session_id: str | None = None, **details: Any) -> None:
        self.events.append({
            "id": str(uuid.uuid4()), "time": int(time.time() * 1000), "type": type_, "realmId": self.realm,
            "clientId": "identityshield-web", "userId": user_id, "sessionId": session_id, "ipAddress": ip,
            "error": error, "details": details,
        })

    def _tokens(self, user: FakeUser, sid: str | None = None) -> dict[str, Any]:
        sid = sid or str(uuid.uuid4())
        self.sessions[sid] = user.id
        rt = f"kc-rt-{uuid.uuid4()}"
        self.refresh_tokens[rt] = sid
        now = int(time.time())
        claims = {"sub": user.id, "sid": sid, "iat": now, "exp": now + 300, "preferred_username": user.username}
        return {"access_token": jwt.encode(claims, FAKE_KEY, algorithm="HS256"),
                "id_token": jwt.encode({**claims, "nonce": "n"}, FAKE_KEY, algorithm="HS256"),
                "refresh_token": rt}

    def add_user(self, username: str, password: str = "pw", roles: list[str] | None = None) -> str:
        kc_id = str(uuid.uuid4())
        self.users[kc_id] = FakeUser(kc_id, username, f"{username}@x.test", password, roles=set(roles or []))
        return kc_id

    # -- admin -----------------------------------------------------------------------
    def create_user(self, *, username: str, email: str, first_name: str, last_name: str,
                    required_actions: list[str], password: str | None = None) -> str:
        self._maybe_fail("create_user")
        for u in self.users.values():
            if u.username == username:
                return u.id
        kc_id = str(uuid.uuid4())
        self.users[kc_id] = FakeUser(kc_id, username, email, password, required_actions=list(required_actions))
        return kc_id

    def find_user(self, *, username: str) -> dict[str, Any] | None:
        for u in self.users.values():
            if u.username == username:
                return {"id": u.id, "username": u.username}
        return None

    def set_enabled(self, kc_user_id: str, enabled: bool) -> None:
        self._maybe_fail("set_enabled")
        self.users[kc_user_id].enabled = enabled
        if not enabled:
            self.logout_user(kc_user_id)

    def is_enabled(self, kc_user_id: str) -> bool:
        return self.users[kc_user_id].enabled

    def add_required_actions(self, kc_user_id: str, actions: list[str]) -> None:
        u = self.users[kc_user_id]
        u.required_actions = sorted(set(u.required_actions) | set(actions))

    def send_actions_email(self, kc_user_id: str, actions: list[str]) -> None:
        self.calls.append(("send_actions_email", kc_user_id))

    def get_realm_roles(self, kc_user_id: str) -> list[str]:
        return sorted(self.users[kc_user_id].roles)

    def add_realm_roles(self, kc_user_id: str, role_names: list[str]) -> None:
        self._maybe_fail("add_realm_roles")
        self.users[kc_user_id].roles |= set(role_names)

    def remove_realm_roles(self, kc_user_id: str, role_names: list[str]) -> None:
        self._maybe_fail("remove_realm_roles")
        self.users[kc_user_id].roles -= set(role_names)

    def logout_user(self, kc_user_id: str) -> None:
        self.calls.append(("logout_user", kc_user_id))
        for sid in [s for s, u in self.sessions.items() if u == kc_user_id]:
            del self.sessions[sid]

    def delete_session(self, kc_session_id: str) -> None:
        self.calls.append(("delete_session", kc_session_id))
        self.sessions.pop(kc_session_id, None)

    def user_sessions(self, kc_user_id: str) -> list[dict[str, Any]]:
        return [{"id": s} for s, u in self.sessions.items() if u == kc_user_id]

    def has_otp(self, kc_user_id: str) -> bool:
        return self.users[kc_user_id].otp

    def login_events(self, max_results: int = 300) -> list[dict[str, Any]]:
        return list(reversed(self.events))[:max_results]

    def admin_events(self, max_results: int = 300) -> list[dict[str, Any]]:
        return list(reversed(self.admin_event_log))[:max_results]

    # -- oidc ------------------------------------------------------------------------
    def authorization_url(self, *, state: str, nonce: str, code_challenge: str, redirect_uri: str) -> str:
        self.last_auth = {"state": state, "nonce": nonce, "code_challenge": code_challenge}
        return f"http://kc.test/realms/{self.realm}/auth?state={state}"

    def exchange_code(self, *, code: str, code_verifier: str, redirect_uri: str) -> dict[str, Any]:
        uid = self.codes.pop(code, None)
        if uid is None:
            raise InvalidGrant("bad code", 400, {"error": "invalid_grant"})
        user = self.users[uid]
        self._event("LOGIN", uid, "203.0.113.10")
        return self._tokens(user)

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        sid = self.refresh_tokens.pop(refresh_token, None)
        if sid is None or sid not in self.sessions or not self.users[self.sessions[sid]].enabled:
            raise InvalidGrant("refresh rejected", 400, {"error": "invalid_grant"})
        return self._tokens(self.users[self.sessions[sid]], sid)

    def end_session(self, refresh_token: str) -> None:
        self.calls.append(("end_session", refresh_token))
        sid = self.refresh_tokens.pop(refresh_token, None)
        if sid:
            self.sessions.pop(sid, None)

    def password_grant(self, *, username: str, password: str, forwarded_for: str | None,
                       user_agent: str | None) -> dict[str, Any]:
        user = next((u for u in self.users.values() if u.username == username), None)
        if user is None:
            self._event("LOGIN_ERROR", None, forwarded_for, "user_not_found", username=username)
            raise InvalidGrant("bad", 401, {"error": "invalid_grant", "error_description": "Invalid user credentials"})
        if not user.enabled:
            self._event("LOGIN_ERROR", user.id, forwarded_for, "user_disabled", username=username)
            raise InvalidGrant("bad", 400, {"error": "invalid_grant", "error_description": "Account disabled"})
        if user.password != password:
            self._event("LOGIN_ERROR", user.id, forwarded_for, "invalid_user_credentials", username=username)
            raise InvalidGrant("bad", 401, {"error": "invalid_grant", "error_description": "Invalid user credentials"})
        tokens = self._tokens(user)
        sid = jwt.decode(tokens["access_token"], FAKE_KEY, algorithms=["HS256"])["sid"]
        self._event("LOGIN", user.id, forwarded_for, session_id=sid, username=username)
        return tokens

    def verify_id_token(self, id_token: str, nonce: str | None) -> dict[str, Any]:
        return dict(jwt.decode(id_token, FAKE_KEY, algorithms=["HS256"]))

    def verify_logout_token(self, logout_token: str) -> dict[str, Any]:
        claims = dict(jwt.decode(logout_token, FAKE_KEY, algorithms=["HS256"], options={"verify_aud": False}))
        if "http://schemas.openid.net/event/backchannel-logout" not in claims.get("events", {}):
            raise KeycloakError("not a logout token")
        return claims

    def logout_token(self, sid: str) -> str:
        return jwt.encode({"iss": f"http://localhost:8080/realms/{self.realm}", "sid": sid, "iat": int(time.time()),
                           "events": {"http://schemas.openid.net/event/backchannel-logout": {}}},
                          FAKE_KEY, algorithm="HS256")

    def end_session_url(self, *, id_token_hint: str | None, post_logout_redirect_uri: str) -> str:
        return f"http://kc.test/realms/{self.realm}/logout"


# ================================================================== detection context


T0 = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)


def ev(type_: str, minutes: float = 0, **kw: Any) -> EventView:
    """Synthetic event `minutes` after T0."""
    return EventView(id=uuid.uuid4(), ts=T0 + timedelta(minutes=minutes), type=type_, **kw)


class MemoryContext:
    def __init__(self, events: list[EventView] | None = None, now: datetime | None = None) -> None:
        self.ev = list(events or [])
        self._now = now or T0 + timedelta(days=1)
        self.users: dict[uuid.UUID, UserView] = {}
        self.grants: dict[tuple[uuid.UUID, str], GrantView] = {}
        self.sensitivity: dict[str, str] = {"admin": "HIGH", "eng-prod-access": "HIGH"}
        self.leavers: list[LeaverView] = []

    def now(self) -> datetime:
        return self._now

    def events(self, *, since: datetime, until: datetime | None = None, user_id: uuid.UUID | None = None,
               username: str | None = None, ip: str | None = None, session_id: uuid.UUID | None = None,
               types: list[str] | None = None, outcome: str | None = None, limit: int = 2000) -> list[EventView]:
        out = [
            e for e in self.ev
            if e.ts >= since and (until is None or e.ts <= until)
            and (user_id is None or e.user_id == user_id) and (username is None or e.username == username)
            and (ip is None or e.ip == ip) and (session_id is None or e.session_id == session_id)
            and (not types or e.type in types) and (outcome is None or e.outcome == outcome)
        ]
        return sorted(out, key=lambda e: e.ts)[:limit]

    def user(self, user_id: uuid.UUID) -> UserView | None:
        return self.users.get(user_id)

    def user_grant(self, user_id: uuid.UUID, role: str) -> GrantView | None:
        return self.grants.get((user_id, role))

    def role_sensitivity(self, role: str) -> str:
        return self.sensitivity.get(role, "LOW")

    def dormant_users(self, *, inactive_days: int) -> list[UserView]:
        cutoff = self._now - timedelta(days=inactive_days)
        return [u for u in self.users.values() if u.state == "ACTIVE" and
                ((u.last_login_at and u.last_login_at < cutoff) or (not u.last_login_at and u.created_at < cutoff))]

    def leaver_requests(self, *, since: datetime) -> list[LeaverView]:
        return [lv for lv in self.leavers if lv.triggered_at >= since]
