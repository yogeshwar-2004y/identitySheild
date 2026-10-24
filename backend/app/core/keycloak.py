"""Keycloak integration.

Two clients with different privileges:

* `KeycloakPlatformAdmin` uses the master-realm admin and is used ONLY by the
  tenancy service to create realms and rotate client secrets.
* `TenantKeycloak` uses the tenant's own confidential client. Its service
  account holds only `manage-users`, `view-users`, `query-users` and
  `view-events` in that one realm (least privilege), and it also performs the
  OIDC calls (code exchange, refresh, logout).

`TenantIdP` is the protocol the rest of the app depends on, so tests can use
an in-memory fake (see tests/fakes.py).
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlencode

import httpx
import jwt

from app.core.config import get_settings

ADMIN_TIMEOUT = httpx.Timeout(10.0)


class KeycloakError(Exception):
    def __init__(self, message: str, status: int | None = None, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class InvalidGrant(KeycloakError):
    """Credentials, refresh token or code rejected by Keycloak."""


class TenantIdP(Protocol):
    realm: str

    # admin (service account)
    def create_user(self, *, username: str, email: str, first_name: str, last_name: str,
                    required_actions: list[str], password: str | None = None) -> str: ...
    def find_user(self, *, username: str) -> dict[str, Any] | None: ...
    def set_enabled(self, kc_user_id: str, enabled: bool) -> None: ...
    def add_required_actions(self, kc_user_id: str, actions: list[str]) -> None: ...
    def send_actions_email(self, kc_user_id: str, actions: list[str]) -> None: ...
    def get_realm_roles(self, kc_user_id: str) -> list[str]: ...
    def add_realm_roles(self, kc_user_id: str, role_names: list[str]) -> None: ...
    def remove_realm_roles(self, kc_user_id: str, role_names: list[str]) -> None: ...
    def logout_user(self, kc_user_id: str) -> None: ...
    def delete_session(self, kc_session_id: str) -> None: ...
    def user_sessions(self, kc_user_id: str) -> list[dict[str, Any]]: ...
    def has_otp(self, kc_user_id: str) -> bool: ...
    def is_enabled(self, kc_user_id: str) -> bool: ...
    def login_events(self, max_results: int = 300) -> list[dict[str, Any]]: ...
    def admin_events(self, max_results: int = 300) -> list[dict[str, Any]]: ...
    # oidc
    def authorization_url(self, *, state: str, nonce: str, code_challenge: str, redirect_uri: str) -> str: ...
    def exchange_code(self, *, code: str, code_verifier: str, redirect_uri: str) -> dict[str, Any]: ...
    def refresh(self, refresh_token: str) -> dict[str, Any]: ...
    def end_session(self, refresh_token: str) -> None: ...
    def password_grant(self, *, username: str, password: str, forwarded_for: str | None,
                       user_agent: str | None) -> dict[str, Any]: ...
    def verify_id_token(self, id_token: str, nonce: str | None) -> dict[str, Any]: ...
    def verify_logout_token(self, logout_token: str) -> dict[str, Any]: ...
    def end_session_url(self, *, id_token_hint: str | None, post_logout_redirect_uri: str) -> str: ...


def _raise_for(resp: httpx.Response, what: str) -> None:
    if resp.status_code >= 400:
        try:
            body = resp.json()
        except ValueError:
            body = resp.text
        if resp.status_code in (400, 401) and isinstance(body, dict) and body.get("error") in (
            "invalid_grant", "invalid_client", "unauthorized_client",
        ):
            raise InvalidGrant(f"{what}: {body.get('error_description') or body.get('error')}", resp.status_code, body)
        raise KeycloakError(f"{what} failed with HTTP {resp.status_code}", resp.status_code, body)


# ============================================================================ tenant


class TenantKeycloak:
    def __init__(self, realm: str, client_secret: str) -> None:
        s = get_settings()
        self.realm = realm
        self.client_id = s.oidc_client_id
        self.client_secret = client_secret
        self.internal = s.keycloak_internal_url.rstrip("/")
        self.public = s.keycloak_public_url.rstrip("/")
        self._token: str | None = None
        self._token_exp = 0.0
        self._lock = threading.Lock()

    # ---- urls
    @property
    def _oidc(self) -> str:
        return f"{self.internal}/realms/{self.realm}/protocol/openid-connect"

    @property
    def _admin(self) -> str:
        return f"{self.internal}/admin/realms/{self.realm}"

    @property
    def issuer(self) -> str:
        return f"{self.public}/realms/{self.realm}"

    # ---- service-account token (client credentials)
    def _sa_token(self) -> str:
        with self._lock:
            if self._token and time.time() < self._token_exp - 15:
                return self._token
            resp = httpx.post(
                f"{self._oidc}/token",
                data={"grant_type": "client_credentials"},
                auth=(self.client_id, self.client_secret),
                timeout=ADMIN_TIMEOUT,
            )
            _raise_for(resp, "service account token")
            data = resp.json()
            self._token = data["access_token"]
            self._token_exp = time.time() + int(data.get("expires_in", 60))
            return self._token

    def _req(self, method: str, path: str, what: str, **kw: Any) -> httpx.Response:
        resp = httpx.request(
            method, f"{self._admin}{path}", headers={"Authorization": f"Bearer {self._sa_token()}"},
            timeout=ADMIN_TIMEOUT, **kw,
        )
        _raise_for(resp, what)
        return resp

    # ---- users
    def create_user(self, *, username: str, email: str, first_name: str, last_name: str,
                    required_actions: list[str], password: str | None = None) -> str:
        rep: dict[str, Any] = {
            "username": username, "email": email, "firstName": first_name, "lastName": last_name,
            "enabled": True, "emailVerified": "VERIFY_EMAIL" not in required_actions,
            "requiredActions": required_actions,
        }
        if password:
            rep["credentials"] = [{"type": "password", "value": password, "temporary": False}]
        resp = httpx.post(
            f"{self._admin}/users", json=rep, headers={"Authorization": f"Bearer {self._sa_token()}"},
            timeout=ADMIN_TIMEOUT,
        )
        if resp.status_code == 409:  # already exists: idempotent re-run
            existing = self.find_user(username=username)
            if existing:
                return str(existing["id"])
        _raise_for(resp, "create user")
        return resp.headers["Location"].rstrip("/").split("/")[-1]

    def find_user(self, *, username: str) -> dict[str, Any] | None:
        resp = self._req("GET", "/users", "find user", params={"username": username, "exact": "true"})
        users = resp.json()
        return users[0] if users else None

    def set_enabled(self, kc_user_id: str, enabled: bool) -> None:
        self._req("PUT", f"/users/{kc_user_id}", "set enabled", json={"enabled": enabled})

    def is_enabled(self, kc_user_id: str) -> bool:
        return bool(self._req("GET", f"/users/{kc_user_id}", "get user").json().get("enabled"))

    def add_required_actions(self, kc_user_id: str, actions: list[str]) -> None:
        user = self._req("GET", f"/users/{kc_user_id}", "get user").json()
        merged = sorted(set(user.get("requiredActions", [])) | set(actions))
        self._req("PUT", f"/users/{kc_user_id}", "required actions", json={"requiredActions": merged})

    def send_actions_email(self, kc_user_id: str, actions: list[str]) -> None:
        s = get_settings()
        self._req(
            "PUT", f"/users/{kc_user_id}/execute-actions-email", "actions email", json=actions,
            params={"client_id": self.client_id, "redirect_uri": f"{s.public_url}/", "lifespan": 86400},
        )

    def _role_reps(self, names: list[str]) -> list[dict[str, Any]]:
        reps = []
        for name in names:
            reps.append(self._req("GET", f"/roles/{name}", "get role").json())
        return reps

    def get_realm_roles(self, kc_user_id: str) -> list[str]:
        resp = self._req("GET", f"/users/{kc_user_id}/role-mappings/realm", "get roles")
        return sorted(r["name"] for r in resp.json() if not r["name"].startswith("default-roles"))

    def add_realm_roles(self, kc_user_id: str, role_names: list[str]) -> None:
        if role_names:
            self._req("POST", f"/users/{kc_user_id}/role-mappings/realm", "add roles", json=self._role_reps(role_names))

    def remove_realm_roles(self, kc_user_id: str, role_names: list[str]) -> None:
        if role_names:
            self._req("DELETE", f"/users/{kc_user_id}/role-mappings/realm", "remove roles",
                      json=self._role_reps(role_names))

    def logout_user(self, kc_user_id: str) -> None:
        self._req("POST", f"/users/{kc_user_id}/logout", "logout user")

    def delete_session(self, kc_session_id: str) -> None:
        resp = httpx.delete(
            f"{self._admin}/sessions/{kc_session_id}", headers={"Authorization": f"Bearer {self._sa_token()}"},
            timeout=ADMIN_TIMEOUT,
        )
        if resp.status_code != 404:  # already gone is fine
            _raise_for(resp, "delete session")

    def user_sessions(self, kc_user_id: str) -> list[dict[str, Any]]:
        return list(self._req("GET", f"/users/{kc_user_id}/sessions", "user sessions").json())

    def has_otp(self, kc_user_id: str) -> bool:
        creds = self._req("GET", f"/users/{kc_user_id}/credentials", "credentials").json()
        return any(c.get("type") == "otp" for c in creds)

    def login_events(self, max_results: int = 300) -> list[dict[str, Any]]:
        return list(self._req("GET", "/events", "events", params={"first": 0, "max": max_results}).json())

    def admin_events(self, max_results: int = 300) -> list[dict[str, Any]]:
        return list(self._req("GET", "/admin-events", "admin events", params={"first": 0, "max": max_results}).json())

    # ---- OIDC
    def authorization_url(self, *, state: str, nonce: str, code_challenge: str, redirect_uri: str) -> str:
        q = urlencode({
            "client_id": self.client_id, "response_type": "code", "scope": "openid email profile",
            "redirect_uri": redirect_uri, "state": state, "nonce": nonce,
            "code_challenge": code_challenge, "code_challenge_method": "S256",
        })
        return f"{self.public}/realms/{self.realm}/protocol/openid-connect/auth?{q}"

    def _token_call(self, data: dict[str, str], what: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
        resp = httpx.post(f"{self._oidc}/token", data=data, auth=(self.client_id, self.client_secret),
                          headers=headers or {}, timeout=ADMIN_TIMEOUT)
        _raise_for(resp, what)
        return dict(resp.json())

    def exchange_code(self, *, code: str, code_verifier: str, redirect_uri: str) -> dict[str, Any]:
        return self._token_call({"grant_type": "authorization_code", "code": code,
                                 "code_verifier": code_verifier, "redirect_uri": redirect_uri}, "code exchange")

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        return self._token_call({"grant_type": "refresh_token", "refresh_token": refresh_token}, "refresh")

    def end_session(self, refresh_token: str) -> None:
        # Ends the SSO session server-side; Keycloak then sends back-channel logout to every client.
        resp = httpx.post(f"{self._oidc}/logout", data={"refresh_token": refresh_token},
                          auth=(self.client_id, self.client_secret), timeout=ADMIN_TIMEOUT)
        if resp.status_code not in (200, 204, 400):  # 400 = session already gone
            _raise_for(resp, "end session")

    def password_grant(self, *, username: str, password: str, forwarded_for: str | None,
                       user_agent: str | None) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if forwarded_for:
            # LAB: Keycloak trusts X-Forwarded-For (KC_PROXY_HEADERS=xforwarded), so its events
            # carry the simulator's synthetic source IP.
            headers["X-Forwarded-For"] = forwarded_for
        if user_agent:
            headers["User-Agent"] = user_agent
        return self._token_call({"grant_type": "password", "username": username, "password": password,
                                 "scope": "openid"}, "password grant", headers)

    _jwks_cache: dict[str, tuple[float, Any]] = {}

    def _jwk_client_key(self, token: str) -> Any:
        key = f"{self.realm}"
        cached = TenantKeycloak._jwks_cache.get(key)
        if not cached or time.time() - cached[0] > 300:
            jwks = httpx.get(f"{self._oidc}/certs", timeout=ADMIN_TIMEOUT).json()
            TenantKeycloak._jwks_cache[key] = (time.time(), jwks)
            cached = TenantKeycloak._jwks_cache[key]
        kid = jwt.get_unverified_header(token).get("kid")
        for k in cached[1].get("keys", []):
            if k.get("kid") == kid and k.get("use", "sig") == "sig":
                return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k))
        TenantKeycloak._jwks_cache.pop(key, None)
        raise KeycloakError("signing key not found")

    def verify_id_token(self, id_token: str, nonce: str | None) -> dict[str, Any]:
        claims = jwt.decode(id_token, self._jwk_client_key(id_token), algorithms=["RS256"],
                            audience=self.client_id, issuer=self.issuer)
        if nonce is not None and claims.get("nonce") != nonce:
            raise KeycloakError("nonce mismatch")
        return dict(claims)

    def verify_logout_token(self, logout_token: str) -> dict[str, Any]:
        claims = jwt.decode(logout_token, self._jwk_client_key(logout_token), algorithms=["RS256"],
                            audience=self.client_id, issuer=self.issuer)
        if "http://schemas.openid.net/event/backchannel-logout" not in (claims.get("events") or {}):
            raise KeycloakError("not a back-channel logout token")
        if "nonce" in claims:
            raise KeycloakError("logout token must not contain nonce")
        return dict(claims)

    def end_session_url(self, *, id_token_hint: str | None, post_logout_redirect_uri: str) -> str:
        params = {"client_id": self.client_id, "post_logout_redirect_uri": post_logout_redirect_uri}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        return f"{self.public}/realms/{self.realm}/protocol/openid-connect/logout?{urlencode(params)}"


# ============================================================================ platform


TEMPLATE_PATH = Path(__file__).resolve().parents[2] / "keycloak" / "realm-export.json"


def load_realm_template(realm: str, display_name: str) -> dict[str, Any]:
    """Reads keycloak/realm-export.json and adapts it to a new tenant realm."""
    s = get_settings()
    path = TEMPLATE_PATH if TEMPLATE_PATH.exists() else Path("/app/keycloak/realm-export.json")
    raw = path.read_text()
    raw = raw.replace("${PUBLIC_URL}", s.public_url).replace("${API_INTERNAL_URL}", s.api_internal_url)
    rep = json.loads(raw)
    rep["realm"] = realm
    rep["displayName"] = display_name
    rep.pop("id", None)
    return dict(rep)


class KeycloakPlatformAdmin:
    def __init__(self) -> None:
        s = get_settings()
        self.base = s.keycloak_internal_url.rstrip("/")
        self.username = s.kc_admin_username
        self.password = s.kc_admin_password

    def _token(self) -> str:
        resp = httpx.post(
            f"{self.base}/realms/master/protocol/openid-connect/token",
            data={"grant_type": "password", "client_id": "admin-cli", "username": self.username,
                  "password": self.password},
            timeout=ADMIN_TIMEOUT,
        )
        _raise_for(resp, "master admin token")
        return str(resp.json()["access_token"])

    def _req(self, method: str, path: str, what: str, token: str, **kw: Any) -> httpx.Response:
        resp = httpx.request(method, f"{self.base}/admin/realms{path}",
                             headers={"Authorization": f"Bearer {token}"}, timeout=ADMIN_TIMEOUT, **kw)
        _raise_for(resp, what)
        return resp

    def realm_exists(self, realm: str) -> bool:
        token = self._token()
        resp = httpx.get(f"{self.base}/admin/realms/{realm}", headers={"Authorization": f"Bearer {token}"},
                         timeout=ADMIN_TIMEOUT)
        return resp.status_code == 200

    def create_realm(self, rep: dict[str, Any]) -> None:
        self._req("POST", "", "create realm", self._token(), json=rep)

    def ensure_realm_config(self, realm: str, rep: dict[str, Any]) -> None:
        """Re-applies session/event settings on an existing realm (idempotent adopt)."""
        keys = [
            "accessTokenLifespan", "ssoSessionIdleTimeout", "ssoSessionMaxLifespan", "revokeRefreshToken",
            "refreshTokenMaxReuse", "eventsEnabled", "eventsExpiration", "enabledEventTypes",
            "adminEventsEnabled", "adminEventsDetailsEnabled", "bruteForceProtected", "failureFactor",
            "smtpServer", "passwordPolicy", "sslRequired",
        ]
        self._req("PUT", f"/{realm}", "update realm", self._token(), json={k: rep[k] for k in keys if k in rep})

    def _client_uuid(self, realm: str, client_id: str, token: str) -> str:
        clients = self._req("GET", f"/{realm}/clients", "find client", token, params={"clientId": client_id}).json()
        if not clients:
            raise KeycloakError(f"client {client_id} missing in realm {realm}")
        return str(clients[0]["id"])

    def rotate_client_secret(self, realm: str, client_id: str) -> str:
        token = self._token()
        cid = self._client_uuid(realm, client_id, token)
        resp = self._req("POST", f"/{realm}/clients/{cid}/client-secret", "rotate secret", token)
        return str(resp.json()["value"])

    SERVICE_ACCOUNT_ROLES = ["manage-users", "view-users", "query-users", "view-events", "view-realm"]

    def ensure_service_account_roles(self, realm: str, client_id: str) -> None:
        """Least privilege for the tenant's service account: user management, read-only
        realm view (role definitions) and event read. Nothing else in realm-management."""
        token = self._token()
        cid = self._client_uuid(realm, client_id, token)
        sa = self._req("GET", f"/{realm}/clients/{cid}/service-account-user", "sa user", token).json()
        rm = self._client_uuid(realm, "realm-management", token)
        have = {r["name"] for r in self._req("GET", f"/{realm}/users/{sa['id']}/role-mappings/clients/{rm}",
                                             "sa roles", token).json()}
        missing = [n for n in self.SERVICE_ACCOUNT_ROLES if n not in have]
        if missing:
            reps = [self._req("GET", f"/{realm}/clients/{rm}/roles/{n}", "rm role", token).json() for n in missing]
            self._req("POST", f"/{realm}/users/{sa['id']}/role-mappings/clients/{rm}", "grant sa roles", token,
                      json=reps)

    def grant_realm_role_directly(self, realm: str, username: str, role: str) -> None:
        """LAB ONLY (simulator `privesc`): an "attacker" with Keycloak console access grants a
        role directly in the IdP, bypassing IdentityShield's approval workflow."""
        token = self._token()
        users = self._req("GET", f"/{realm}/users", "find user", token,
                          params={"username": username, "exact": "true"}).json()
        if not users:
            raise KeycloakError(f"user {username} not found")
        rep = self._req("GET", f"/{realm}/roles/{role}", "get role", token).json()
        self._req("POST", f"/{realm}/users/{users[0]['id']}/role-mappings/realm", "grant role", token, json=[rep])

    def configure_lab_direct_grant(self, realm: str, client_id: str, enabled: bool) -> None:
        """LAB ONLY. Enables the password grant on the client with a flow that skips OTP,
        so the simulator and headless demo can log users in without a browser.
        Disabled (and the override removed) when LAB_MODE is off."""
        token = self._token()
        cid = self._client_uuid(realm, client_id, token)
        client = self._req("GET", f"/{realm}/clients/{cid}", "get client", token).json()
        if not enabled:
            client["directAccessGrantsEnabled"] = False
            client.setdefault("authenticationFlowBindingOverrides", {}).pop("direct_grant", None)
            self._req("PUT", f"/{realm}/clients/{cid}", "update client", token, json=client)
            return
        flows = self._req("GET", f"/{realm}/authentication/flows", "flows", token).json()
        flow = next((f for f in flows if f["alias"] == "lab direct grant"), None)
        if flow is None:
            self._req("POST", f"/{realm}/authentication/flows", "create flow", token, json={
                "alias": "lab direct grant", "providerId": "basic-flow", "topLevel": True, "builtIn": False,
                "description": "LAB ONLY: username + password, no OTP",
            })
            for provider in ("direct-grant-validate-username", "direct-grant-validate-password"):
                self._req("POST", f"/{realm}/authentication/flows/lab%20direct%20grant/executions/execution",
                          "add execution", token, json={"provider": provider})
            execs = self._req("GET", f"/{realm}/authentication/flows/lab%20direct%20grant/executions",
                              "executions", token).json()
            for ex in execs:
                ex["requirement"] = "REQUIRED"
                self._req("PUT", f"/{realm}/authentication/flows/lab%20direct%20grant/executions",
                          "set requirement", token, json=ex)
            flows = self._req("GET", f"/{realm}/authentication/flows", "flows", token).json()
            flow = next(f for f in flows if f["alias"] == "lab direct grant")
        client["directAccessGrantsEnabled"] = True
        client.setdefault("authenticationFlowBindingOverrides", {})["direct_grant"] = flow["id"]
        self._req("PUT", f"/{realm}/clients/{cid}", "update client", token, json=client)


# ============================================================================ provider

_overrides: dict[str, TenantIdP] = {}
_cache: dict[str, TenantKeycloak] = {}


def tenant_idp(realm: str, encrypted_secret: str | None) -> TenantIdP:
    """Returns the IdP client for a tenant. Tests register fakes with `override_idp`."""
    if realm in _overrides:
        return _overrides[realm]
    if "*" in _overrides:
        return _overrides["*"]
    from app.core.security import decrypt_str

    if not encrypted_secret:
        raise KeycloakError(f"tenant {realm} has no client secret; run provisioning")
    cached = _cache.get(realm)
    secret = decrypt_str(encrypted_secret)
    if cached is None or cached.client_secret != secret:
        cached = TenantKeycloak(realm, secret)
        _cache[realm] = cached
    return cached


def override_idp(realm: str, idp: TenantIdP | None) -> None:
    if idp is None:
        _overrides.pop(realm, None)
    else:
        _overrides[realm] = idp
