"""Detection rule framework.

Rules are small classes that look at one normalized event (stream rules) or at
the tenant state (periodic rules) through a `DetectionContext`. The context is
a protocol: production uses SQL (`detection/context.py`), unit tests use an
in-memory list of synthetic events (`tests/fakes.py`), so every rule can be
tested with hand-written event sequences.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Protocol


@dataclass(frozen=True)
class EventView:
    id: uuid.UUID
    ts: datetime
    type: str
    user_id: uuid.UUID | None = None
    session_id: uuid.UUID | None = None
    username: str | None = None
    ip: str | None = None
    geo: dict[str, Any] | None = None
    asn: str | None = None
    ua_hash: str | None = None
    outcome: str = "SUCCESS"
    source: str = "app"
    details: dict[str, Any] = field(default_factory=dict)

    def brief(self) -> dict[str, Any]:
        return {
            "event_id": str(self.id), "ts": self.ts.isoformat(), "type": self.type, "ip": self.ip,
            "geo": self.geo, "asn": self.asn, "outcome": self.outcome, "username": self.username,
            "session_id": str(self.session_id) if self.session_id else None,
        }


@dataclass(frozen=True)
class UserView:
    id: uuid.UUID
    username: str
    state: str
    created_at: datetime
    last_login_at: datetime | None
    deprovisioned_at: datetime | None


@dataclass(frozen=True)
class GrantView:
    role: str
    granted_by: str
    approval_id: uuid.UUID | None
    lifecycle_id: uuid.UUID | None


@dataclass(frozen=True)
class LeaverView:
    id: uuid.UUID
    user_id: uuid.UUID | None
    status: str
    triggered_at: datetime
    disabled_at: datetime | None


@dataclass
class Finding:
    rule_key: str
    title: str
    confidence: float
    evidence: dict[str, Any]
    user_id: uuid.UUID | None = None
    session_id: uuid.UUID | None = None
    dedupe_key: str | None = None


class DetectionContext(Protocol):
    def now(self) -> datetime: ...
    def events(self, *, since: datetime, until: datetime | None = None, user_id: uuid.UUID | None = None,
               username: str | None = None, ip: str | None = None, session_id: uuid.UUID | None = None,
               types: list[str] | None = None, outcome: str | None = None,
               limit: int = 2000) -> list[EventView]: ...
    def user(self, user_id: uuid.UUID) -> UserView | None: ...
    def user_grant(self, user_id: uuid.UUID, role: str) -> GrantView | None: ...
    def role_sensitivity(self, role: str) -> str: ...
    def dormant_users(self, *, inactive_days: int) -> list[UserView]: ...
    def leaver_requests(self, *, since: datetime) -> list[LeaverView]: ...


class Rule:
    key: ClassVar[str]
    name: ClassVar[str]
    severity: ClassVar[str]  # low|medium|high|critical
    attack_technique: ClassVar[str]
    weight: ClassVar[int]
    default_params: ClassVar[dict[str, Any]] = {}
    event_types: ClassVar[frozenset[str]] = frozenset()
    periodic: ClassVar[bool] = False

    def __init__(self, params: dict[str, Any] | None = None) -> None:
        self.params = {**self.default_params, **(params or {})}

    def handles(self, event: EventView) -> bool:
        return event.type in self.event_types

    def evaluate(self, event: EventView, ctx: DetectionContext) -> list[Finding]:
        return []

    def evaluate_periodic(self, ctx: DetectionContext) -> list[Finding]:
        return []

    def finding(self, title: str, confidence: float, evidence: dict[str, Any], *,
                user_id: uuid.UUID | None = None, session_id: uuid.UUID | None = None,
                dedupe_key: str | None = None) -> Finding:
        return Finding(self.key, title, max(0.0, min(1.0, confidence)), evidence, user_id, session_id, dedupe_key)
