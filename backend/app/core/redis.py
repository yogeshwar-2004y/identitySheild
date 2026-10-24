"""Redis: token/session revocation list, idle tracking, rate limits, OIDC state, alert pub/sub."""
from __future__ import annotations

import time

import redis

from app.core.config import get_settings

_client: redis.Redis | None = None


def get_redis() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.Redis.from_url(get_settings().redis_url, decode_responses=True)
    return _client


def set_redis(client: redis.Redis) -> None:
    global _client
    _client = client


# ---- revocation list ---------------------------------------------------------------

def revoke_jti(jti: str, ttl_seconds: int) -> None:
    get_redis().set(f"revoked:jti:{jti}", "1", ex=max(int(ttl_seconds), 1))


def revoke_sid(sid: str, ttl_seconds: int = 9 * 3600) -> None:
    # Kept slightly longer than the absolute session limit so no token for the sid can outlive it.
    get_redis().set(f"revoked:sid:{sid}", "1", ex=max(int(ttl_seconds), 1))


def revoke_user_tokens_before(user_id: str, ttl_seconds: int = 9 * 3600) -> None:
    """Rejects every access token for this user issued before now (used by Leaver and lock)."""
    get_redis().set(f"revoked:user:{user_id}", str(int(time.time())), ex=ttl_seconds)


def is_revoked(jti: str, sid: str, user_id: str, issued_at: int) -> bool:
    r = get_redis()
    pipe = r.pipeline()
    pipe.exists(f"revoked:jti:{jti}")
    pipe.exists(f"revoked:sid:{sid}")
    pipe.get(f"revoked:user:{user_id}")
    jti_hit, sid_hit, user_cutoff = pipe.execute()
    if jti_hit or sid_hit:
        return True
    return bool(user_cutoff and issued_at <= int(user_cutoff))


def track_session_jti(sid: str, jti: str, ttl_seconds: int) -> None:
    """Remember outstanding jtis per session so logout/leaver can revoke each one explicitly."""
    r = get_redis()
    key = f"sess:jtis:{sid}"
    r.zadd(key, {jti: time.time() + ttl_seconds})
    r.expire(key, 9 * 3600)


def outstanding_jtis(sid: str) -> list[tuple[str, int]]:
    now = time.time()
    rows = get_redis().zrangebyscore(f"sess:jtis:{sid}", now, "+inf", withscores=True)
    return [(jti, int(score - now)) for jti, score in rows]


# ---- idle tracking -----------------------------------------------------------------

def touch_session(sid: str, idle_seconds: int) -> None:
    get_redis().set(f"sess:last:{sid}", str(int(time.time())), ex=idle_seconds + 60)


def last_seen(sid: str) -> int | None:
    v = get_redis().get(f"sess:last:{sid}")
    return int(v) if v else None


def claims_version(sid: str) -> int | None:
    v = get_redis().get(f"sess:ver:{sid}")
    return int(v) if v else None


def set_claims_version(sid: str, version: int) -> None:
    get_redis().set(f"sess:ver:{sid}", str(version), ex=9 * 3600)


# ---- rate limiting (fixed window) --------------------------------------------------

def rate_limited(bucket: str, limit: int, window_seconds: int = 60) -> bool:
    r = get_redis()
    key = f"rl:{bucket}:{int(time.time() // window_seconds)}"
    count = r.incr(key)
    if count == 1:
        r.expire(key, window_seconds + 5)
    return count > limit


def alert_channel(tenant_id: str) -> str:
    return f"alerts:{tenant_id}"
