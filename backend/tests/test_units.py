"""Pure-function tests: scoring, normalization, crypto, JWT, simulator guard."""
from __future__ import annotations

import time
import uuid

import jwt
import pytest

from app.core import geoip
from app.core.security import (
    decode_access_token, decrypt_str, encrypt_str, hmac_sha256_hex, issue_access_token, verify_hmac_signature,
)
from app.detection.scoring import alert_severity, decide
from app.events.normalize import normalize_admin_event, normalize_user_event
from simulator.client import UnsafeTarget, assert_lab_target


def test_risk_tiers() -> None:
    assert decide(25, 0.6).actions == []
    assert decide(60, 1.0).actions == ["force_mfa"]
    assert decide(80, 1.0).tier == "high" and "revoke_session" in decide(80, 1.0).actions
    d = decide(95, 1.0)
    assert d.tier == "critical" and d.actions[:2] == ["revoke_all_sessions", "lock_account"]
    assert decide(80, 1.0, carry=50).risk == 100  # clamped


def test_alert_severity_escalates_with_tier() -> None:
    assert alert_severity("medium", "critical") == "critical"
    assert alert_severity("high", "low") == "high"


def test_normalize_keycloak_login_error_and_otp() -> None:
    raw = {"id": "e1", "time": int(time.time() * 1000), "type": "LOGIN_ERROR", "userId": "kc1", "ipAddress": "1.2.3.4",
           "error": "invalid_user_credentials", "details": {"username": "asha"}}
    n = normalize_user_event(raw)
    assert n and n["type"] == "LOGIN_ERROR" and n["outcome"] == "FAILURE" and n["username"] == "asha"
    otp = normalize_user_event({**raw, "error": "invalid_totp"})
    assert otp and otp["type"] == "MFA_DENIED"
    assert normalize_user_event({**raw, "type": "CLIENT_LOGIN"}) is None


def test_normalize_admin_role_mapping() -> None:
    raw = {"id": "a1", "time": 1, "operationType": "CREATE", "resourceType": "REALM_ROLE_MAPPING",
           "resourcePath": "users/kc1/role-mappings/realm", "representation": '[{"name":"admin"},{"name":"hr"}]',
           "authDetails": {"userId": "attacker", "ipAddress": "10.0.0.5"}}
    out = normalize_admin_event(raw)
    assert [o["details"]["role"] for o in out] == ["admin", "hr"] and out[0]["kc_user_id"] == "kc1"
    assert normalize_admin_event({**raw, "resourceType": "CLIENT"}) == []


def test_encryption_roundtrip_and_tamper() -> None:
    blob = encrypt_str("client-secret")
    assert blob != "client-secret" and decrypt_str(blob) == "client-secret"
    with pytest.raises(Exception):
        decrypt_str(blob[:-4] + "AAAA")


def test_access_token_claims_and_cap() -> None:
    from datetime import timedelta

    from app.core.security import utcnow

    cap = utcnow() + timedelta(seconds=30)
    tok, jti, exp = issue_access_token(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), session_id=uuid.uuid4(),
                                       roles=["user"], email="a@b", claims_version=2, ttl_seconds=300, not_after=cap)
    c = decode_access_token(tok)
    assert c.jti == jti and c.ver == 2 and exp <= cap
    forged = jwt.encode({"sub": "x"}, "wrong-key-wrong-key-wrong-key-wrong", algorithm="HS256")
    with pytest.raises(jwt.PyJWTError):
        decode_access_token(forged)
    none_alg = jwt.encode({"sub": "x"}, None, algorithm="none")
    with pytest.raises(jwt.PyJWTError):
        decode_access_token(none_alg)


def test_hmac_signature() -> None:
    sig = "sha256=" + hmac_sha256_hex("s3cret", b"body")
    assert verify_hmac_signature("s3cret", b"body", sig)
    assert not verify_hmac_signature("s3cret", b"body2", sig)
    assert not verify_hmac_signature("s3cret", b"body", None)


def test_geoip_lab_table() -> None:
    assert geoip.lookup("203.0.113.9").country == "IN"  # type: ignore[union-attr]
    assert geoip.lookup("198.51.100.9").country == "US"  # type: ignore[union-attr]
    assert geoip.lookup("8.8.8.8") is None and geoip.lookup("not-an-ip") is None
    assert 12000 < geoip.haversine_km(11.0, 76.9, 40.7, -74.0) < 14500


@pytest.mark.parametrize("url", ["http://localhost:8000", "http://127.0.0.1:8000", "http://[::1]:8000"])
def test_simulator_allows_lab_targets(url: str) -> None:
    assert_lab_target(url)


@pytest.mark.parametrize("url", ["https://example.com", "http://8.8.8.8", "http://api.evil.com", "ftp://localhost",
                                 "http://10.0.0.1.nip.io"])
def test_simulator_refuses_external_targets(url: str) -> None:
    with pytest.raises(UnsafeTarget):
        assert_lab_target(url)
