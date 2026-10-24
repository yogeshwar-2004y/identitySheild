"""Session-abuse rules: D02 session replay / hijack, D03 refresh token reuse, D11 mass access."""
from __future__ import annotations

from datetime import timedelta

from app.detection.base import DetectionContext, EventView, Finding, Rule


class SessionHijack(Rule):
    key = "D02"
    name = "Session replay / hijack"
    severity = "high"
    attack_technique = "T1539 Steal Web Session Cookie"
    weight = 80
    # SESSION_ANOMALY is emitted by the auth dependency when a token is used from a
    # network/device that differs from the one the session was bound to at login.
    event_types = frozenset({"SESSION_ANOMALY"})

    def evaluate(self, event: EventView, ctx: DetectionContext) -> list[Finding]:
        d = event.details
        changes = set(d.get("changes", []))
        if not changes:
            return []
        if "user_agent" in changes and ({"asn", "country"} & changes):
            confidence = 1.0
        elif {"asn", "country"} & changes:
            confidence = 0.9
        elif "user_agent" in changes:
            confidence = 0.75
        else:
            confidence = 0.5
        return [self.finding(
            f"Session token replayed from new {'/'.join(sorted(changes))} ({d.get('bound', {}).get('ip')} -> {event.ip})",
            confidence,
            {"bound": d.get("bound"), "observed": {"ip": event.ip, "geo": event.geo, "asn": event.asn,
                                                     "ua_hash": event.ua_hash}, "changes": sorted(changes),
             "path": d.get("path")},
            user_id=event.user_id, session_id=event.session_id, dedupe_key=f"D02:{event.session_id}",
        )]


class RefreshTokenReuse(Rule):
    key = "D03"
    name = "Refresh token reuse"
    severity = "high"
    attack_technique = "T1528 / T1550 Steal / Use Application Access Token"
    weight = 80
    event_types = frozenset({"REFRESH_TOKEN_REUSE"})

    def evaluate(self, event: EventView, ctx: DetectionContext) -> list[Finding]:
        return [self.finding(
            "Rotated refresh token presented again; session family revoked",
            1.0,
            {"reuse": event.brief(), "family_id": event.details.get("family_id"),
             "rotated_at": event.details.get("rotated_at")},
            user_id=event.user_id, session_id=event.session_id, dedupe_key=f"D03:{event.details.get('family_id')}",
        )]


class MassAccess(Rule):
    key = "D11"
    name = "Mass access"
    severity = "medium"
    attack_technique = "T1530 / T1087 Data from Cloud Storage / Account Discovery"
    weight = 50
    default_params = {"threshold": 60, "window_minutes": 10}
    event_types = frozenset({"RESOURCE_ACCESS"})

    def evaluate(self, event: EventView, ctx: DetectionContext) -> list[Finding]:
        if not event.session_id:
            return []
        since = event.ts - timedelta(minutes=self.params["window_minutes"])
        hits = ctx.events(since=since, until=event.ts, session_id=event.session_id, types=["RESOURCE_ACCESS"])
        if len(hits) < self.params["threshold"]:
            return []
        resources = sorted({str(e.details.get("resource")) for e in hits})
        return [self.finding(
            f"Mass access: {len(hits)} resource reads in {self.params['window_minutes']} min",
            0.8,
            {"reads": len(hits), "resources": resources[:30]},
            user_id=event.user_id, session_id=event.session_id, dedupe_key=f"D11:{event.session_id}",
        )]
