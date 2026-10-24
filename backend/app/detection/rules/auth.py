"""Authentication-pattern rules: D01 impossible travel, D07 brute force,
D08 credential stuffing, D09 MFA fatigue, D10 off-hours access."""
from __future__ import annotations

from datetime import timedelta

from app.core.geoip import haversine_km
from app.detection.base import DetectionContext, EventView, Finding, Rule


class ImpossibleTravel(Rule):
    key = "D01"
    name = "Impossible travel"
    severity = "high"
    attack_technique = "T1078 Valid Accounts"
    weight = 60
    default_params = {"max_speed_kmh": 900, "lookback_hours": 24, "min_distance_km": 300}
    event_types = frozenset({"LOGIN"})

    def evaluate(self, event: EventView, ctx: DetectionContext) -> list[Finding]:
        if event.outcome != "SUCCESS" or not event.user_id or not event.geo or "lat" not in event.geo:
            return []
        since = event.ts - timedelta(hours=self.params["lookback_hours"])
        prior = [
            e for e in ctx.events(since=since, until=event.ts, user_id=event.user_id, types=["LOGIN"],
                                  outcome="SUCCESS")
            if e.id != event.id and e.geo and "lat" in e.geo
        ]
        if not prior:
            return []
        prev = max(prior, key=lambda e: e.ts)
        km = haversine_km(prev.geo["lat"], prev.geo["lon"], event.geo["lat"], event.geo["lon"])  # type: ignore[index]
        if km < self.params["min_distance_km"]:
            return []
        hours = max((event.ts - prev.ts).total_seconds() / 3600, 1 / 3600)
        speed = km / hours
        if speed <= self.params["max_speed_kmh"]:
            return []
        confidence = 1.0 if speed > 2 * self.params["max_speed_kmh"] else 0.8
        return [self.finding(
            f"Impossible travel: {prev.geo.get('city')} -> {event.geo.get('city')} at {int(speed)} km/h",
            confidence,
            {"previous_login": prev.brief(), "current_login": event.brief(), "distance_km": round(km, 1),
             "elapsed_minutes": round(hours * 60, 1), "implied_speed_kmh": int(speed)},
            user_id=event.user_id, session_id=event.session_id, dedupe_key=f"D01:{event.user_id}:{event.id}",
        )]


class BruteForce(Rule):
    key = "D07"
    name = "Brute force"
    severity = "high"
    attack_technique = "T1110.001 Password Guessing"
    weight = 50
    default_params = {"threshold": 5, "window_minutes": 10}
    event_types = frozenset({"LOGIN_ERROR"})

    def evaluate(self, event: EventView, ctx: DetectionContext) -> list[Finding]:
        if event.details.get("error") in ("user_not_found",) and not event.user_id:
            return []  # unknown usernames are credential stuffing (D08), not guessing one account
        since = event.ts - timedelta(minutes=self.params["window_minutes"])
        if event.user_id:
            fails = ctx.events(since=since, until=event.ts, user_id=event.user_id, types=["LOGIN_ERROR"])
        elif event.username:
            fails = ctx.events(since=since, until=event.ts, username=event.username, types=["LOGIN_ERROR"])
        else:
            return []
        if len(fails) < self.params["threshold"]:
            return []
        ips = sorted({e.ip for e in fails if e.ip})
        bucket = int(event.ts.timestamp() // (self.params["window_minutes"] * 60))
        return [self.finding(
            f"Brute force: {len(fails)} failed logins for {event.username or event.user_id} "
            f"in {self.params['window_minutes']} min",
            0.9 if len(ips) <= 2 else 0.7,
            {"failures": len(fails), "source_ips": ips, "window_minutes": self.params["window_minutes"],
             "sample": [e.brief() for e in fails[-5:]]},
            user_id=event.user_id, dedupe_key=f"D07:{event.user_id or event.username}:{bucket}",
        )]


class CredentialStuffing(Rule):
    key = "D08"
    name = "Credential stuffing"
    severity = "high"
    attack_technique = "T1110.004 Credential Stuffing"
    weight = 50
    default_params = {"distinct_users": 5, "window_minutes": 10}
    event_types = frozenset({"LOGIN_ERROR"})

    def evaluate(self, event: EventView, ctx: DetectionContext) -> list[Finding]:
        if not event.ip:
            return []
        since = event.ts - timedelta(minutes=self.params["window_minutes"])
        fails = ctx.events(since=since, until=event.ts, ip=event.ip, types=["LOGIN_ERROR"])
        users = sorted({(e.username or str(e.user_id)).lower() for e in fails if e.username or e.user_id})
        if len(users) < self.params["distinct_users"]:
            return []
        bucket = int(event.ts.timestamp() // (self.params["window_minutes"] * 60))
        return [self.finding(
            f"Credential stuffing: {event.ip} failed against {len(users)} accounts",
            1.0 if len(users) >= 2 * self.params["distinct_users"] else 0.8,
            {"source_ip": event.ip, "geo": event.geo, "distinct_accounts": len(users), "accounts": users[:25],
             "failures": len(fails)},
            dedupe_key=f"D08:{event.ip}:{bucket}",
        )]


class MfaFatigue(Rule):
    key = "D09"
    name = "MFA fatigue"
    severity = "high"
    attack_technique = "T1621 MFA Request Generation"
    weight = 60
    default_params = {"threshold": 5, "window_minutes": 10}
    event_types = frozenset({"MFA_CHALLENGE", "MFA_DENIED"})

    def evaluate(self, event: EventView, ctx: DetectionContext) -> list[Finding]:
        if not event.user_id:
            return []
        since = event.ts - timedelta(minutes=self.params["window_minutes"])
        prompts = ctx.events(since=since, until=event.ts, user_id=event.user_id,
                             types=["MFA_CHALLENGE", "MFA_DENIED"])
        if len(prompts) < self.params["threshold"]:
            return []
        denied = sum(1 for e in prompts if e.type == "MFA_DENIED")
        bucket = int(event.ts.timestamp() // (self.params["window_minutes"] * 60))
        return [self.finding(
            f"MFA fatigue: {len(prompts)} MFA prompts ({denied} denied) in {self.params['window_minutes']} min",
            0.9 if denied >= 3 else 0.7,
            {"prompts": len(prompts), "denied": denied, "source_ips": sorted({e.ip for e in prompts if e.ip})},
            user_id=event.user_id, dedupe_key=f"D09:{event.user_id}:{bucket}",
        )]


class OffHoursAccess(Rule):
    key = "D10"
    name = "Off-hours access"
    severity = "low"
    attack_technique = "T1078 Valid Accounts"
    weight = 25
    default_params = {"history_days": 30, "min_history": 10, "tolerance_hours": 1}
    event_types = frozenset({"LOGIN"})

    def evaluate(self, event: EventView, ctx: DetectionContext) -> list[Finding]:
        if event.outcome != "SUCCESS" or not event.user_id:
            return []
        since = event.ts - timedelta(days=self.params["history_days"])
        history = [e for e in ctx.events(since=since, until=event.ts, user_id=event.user_id, types=["LOGIN"],
                                         outcome="SUCCESS") if e.id != event.id]
        if len(history) < self.params["min_history"]:
            return []  # not enough data to learn working hours
        hours = {e.ts.hour for e in history}
        tol = self.params["tolerance_hours"]
        h = event.ts.hour
        if any(((h + d) % 24) in hours for d in range(-tol, tol + 1)):
            return []
        return [self.finding(
            f"Off-hours login at {h:02d}:00 UTC (learned hours: {sorted(hours)})",
            0.6,
            {"login": event.brief(), "learned_hours_utc": sorted(hours), "history_size": len(history)},
            user_id=event.user_id, session_id=event.session_id, dedupe_key=f"D10:{event.id}",
        )]
