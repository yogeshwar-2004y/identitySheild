"""Risk scoring (architecture section 7.1).

risk = clamp(weight * confidence + carry, 0, 100)

`carry` is the summed contribution of other OPEN alerts on the same session in
the last hour (or on the same user, for alerts without a session). Scoping the
carry to the session keeps one noisy day from locking a user out, while a
session that trips several rules escalates quickly.
"""
from __future__ import annotations

from dataclasses import dataclass

TIERS = [
    (90, "critical", ["revoke_all_sessions", "lock_account", "notify"]),
    (70, "high", ["revoke_session", "notify"]),
    (40, "medium", ["force_mfa"]),
    (0, "low", []),
]


@dataclass(frozen=True)
class RiskDecision:
    risk: int
    tier: str
    actions: list[str]


def clamp(value: float) -> int:
    return int(max(0, min(100, round(value))))


def contribution(weight: int, confidence: float) -> float:
    return weight * confidence


def decide(weight: int, confidence: float, carry: float = 0.0) -> RiskDecision:
    risk = clamp(contribution(weight, confidence) + carry)
    for floor, tier, actions in TIERS:
        if risk >= floor:
            return RiskDecision(risk, tier, list(actions))
    return RiskDecision(risk, "low", [])  # pragma: no cover


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def alert_severity(rule_severity: str, tier: str) -> str:
    """An alert is at least as severe as its rule, and escalates with the risk tier."""
    return max(rule_severity, tier, key=lambda s: SEVERITY_ORDER.get(s, 0))
