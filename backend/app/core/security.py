"""Token, hashing and encryption primitives.

Access tokens are short-lived HS256 JWTs issued by this API after Keycloak has
authenticated the user (backend-for-frontend pattern). They carry `sid`
(application session id), `jti`, `tenant_id` and `roles`. Refresh tokens are
opaque random strings; only their SHA-256 hash is stored.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def sha256_hex(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def ua_hash(user_agent: str | None) -> str:
    return sha256_hex((user_agent or "").strip())


def new_opaque_token() -> str:
    return secrets.token_urlsafe(48)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def hmac_sha256_hex(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def verify_hmac_signature(secret: str, body: bytes, header_value: str | None) -> bool:
    """Accepts `sha256=<hex>` headers. Constant-time comparison."""
    if not header_value or not header_value.startswith("sha256="):
        return False
    expected = hmac_sha256_hex(secret, body)
    return hmac.compare_digest(expected, header_value.removeprefix("sha256="))


# --------------------------------------------------------------------------- JWT


@dataclass(frozen=True)
class AccessClaims:
    sub: str  # internal user id
    tenant_id: str
    sid: str
    jti: str
    roles: list[str]
    ver: int
    exp: int
    iat: int
    email: str


def issue_access_token(
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session_id: uuid.UUID,
    roles: list[str],
    email: str,
    claims_version: int,
    ttl_seconds: int,
    not_after: datetime | None = None,
) -> tuple[str, str, datetime]:
    """Returns (token, jti, expires_at). Expiry never exceeds the session's absolute limit."""
    s = get_settings()
    now = utcnow()
    exp = now + timedelta(seconds=ttl_seconds)
    if not_after is not None and exp > not_after:
        exp = not_after
    jti = str(uuid.uuid4())
    payload: dict[str, Any] = {
        "iss": s.jwt_issuer,
        "aud": "identityshield",
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "sid": str(session_id),
        "jti": jti,
        "roles": roles,
        "email": email,
        "ver": claims_version,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, s.jwt_secret, algorithm="HS256"), jti, exp


def decode_access_token(token: str) -> AccessClaims:
    s = get_settings()
    data = jwt.decode(
        token,
        s.jwt_secret,
        algorithms=["HS256"],  # pinned: never accept "none" or asymmetric confusion
        audience="identityshield",
        issuer=s.jwt_issuer,
        options={"require": ["exp", "iat", "sub", "jti"]},
    )
    return AccessClaims(
        sub=data["sub"],
        tenant_id=data["tenant_id"],
        sid=data["sid"],
        jti=data["jti"],
        roles=list(data.get("roles", [])),
        ver=int(data.get("ver", 0)),
        exp=int(data["exp"]),
        iat=int(data["iat"]),
        email=data.get("email", ""),
    )


# --------------------------------------------------------------- encryption at rest


def _aes() -> AESGCM:
    key = base64.b64decode(get_settings().encryption_key)
    if len(key) != 32:
        raise RuntimeError("ENCRYPTION_KEY must be 32 bytes, base64 encoded")
    return AESGCM(key)


def encrypt_str(plaintext: str) -> str:
    nonce = os.urandom(12)
    ct = _aes().encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_str(token: str) -> str:
    raw = base64.b64decode(token)
    return _aes().decrypt(raw[:12], raw[12:], None).decode()


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
