"""Identity-governance rules: D04 ghost account, D05 orphaned account,
D06 privilege escalation, D12 delayed deprovisioning."""
from __future__ import annotations

from datetime import timedelta

from app.detection.base import DetectionContext, EventView, Finding, Rule

# Event types that mean "someone tried to use this identity". Workflow side
# effects of deprovisioning (SESSION_REVOKED, USER_DISABLE...) are excluded.
ATTEMPT_TYPES = frozenset({
    "LOGIN", "LOGIN_ERROR", "CODE_TO_TOKEN", "TOKEN_REFRESH", "TOKEN_REFRESH_ERROR", "APP_TOKEN_REFRESH",
    "TOKEN_REJECTED", "SESSION_ANOMALY", "RESOURCE_ACCESS", "MFA_CHALLENGE", "MFA_DENIED", "API_KEY_USE",
})


class GhostAccount(Rule):
    key = "D04"
    name = "Ghost account activity"
    severity = "critical"
    attack_technique = "T1078 Valid Accounts"
    weight = 95
    event_types = ATTEMPT_TYPES

    def evaluate(self, event: EventView, ctx: DetectionContext) -> list[Finding]:
        if not event.user_id:
            return []
        user = ctx.user(event.user_id)
        if not user or user.state != "DEPROVISIONED":
            return []
        if user.deprovisioned_at and event.ts < user.deprovisioned_at:
            return []
        minute = int(event.ts.timestamp() // 300)
        return [self.finding(
            f"Deprovisioned account {user.username} used: {event.type} from {event.ip}",
            1.0,
            {"attempt": event.brief(), "deprovisioned_at": user.deprovisioned_at.isoformat()
             if user.deprovisioned_at else None, "error": event.details.get("error")},
            user_id=event.user_id, session_id=event.session_id, dedupe_key=f"D04:{event.user_id}:{event.type}:{minute}",
        )]


class OrphanedAccount(Rule):
    key = "D05"
    name = "Orphaned active account"
    severity = "medium"
    attack_technique = "T1078 Valid Accounts"
    weight = 30
    default_params = {"inactive_days": 45}
    periodic = True

    def evaluate_periodic(self, ctx: DetectionContext) -> list[Finding]:
        out = []
        day = ctx.now().date().isoformat()
        for u in ctx.dormant_users(inactive_days=self.params["inactive_days"]):
            last = u.last_login_at.isoformat() if u.last_login_at else "never"
            out.append(self.finding(
                f"Active account {u.username} unused for {self.params['inactive_days']}+ days (last login: {last})",
                0.7,
                {"username": u.username, "last_login_at": last, "created_at": u.created_at.isoformat()},
                user_id=u.id, dedupe_key=f"D05:{u.id}:{day[:7]}",
            ))
        return out


def _workflow_grant(e: EventView) -> bool:
    return bool(e.details.get("lifecycle_id")) or bool(e.details.get("via_identityshield"))


class PrivilegeEscalation(Rule):
    key = "D06"
    name = "Privilege escalation"
    severity = "critical"
    attack_technique = "T1098 Account Manipulation"
    weight = 85
    default_params = {"jump_threshold": 3, "window_minutes": 10}
    event_types = frozenset({"ROLE_GRANT"})

    def evaluate(self, event: EventView, ctx: DetectionContext) -> list[Finding]:
        if not event.user_id:
            return []
        role = str(event.details.get("role", ""))
        findings: list[Finding] = []
        if role and ctx.role_sensitivity(role) == "HIGH":
            grant = ctx.user_grant(event.user_id, role)
            via_workflow = bool(event.details.get("lifecycle_id")) or (
                grant is not None and (grant.lifecycle_id or grant.approval_id or grant.granted_by == "seed")
            )
            if not via_workflow:
                findings.append(self.finding(
                    f"Sensitive role '{role}' granted outside the approved workflow",
                    1.0,
                    {"grant": event.brief(), "role": role, "actor": event.details.get("actor"),
                     "recorded_grant": None if grant is None else grant.granted_by},
                    user_id=event.user_id, dedupe_key=f"D06:{event.user_id}:{role}",
                ))
        if _workflow_grant(event):
            return findings  # approved Joiner/Mover grants never count toward a "jump"
        since = event.ts - timedelta(minutes=self.params["window_minutes"])
        grants = [e for e in ctx.events(since=since, until=event.ts, user_id=event.user_id, types=["ROLE_GRANT"])
                  if not _workflow_grant(e)]
        distinct = {str(e.details.get("role")) for e in grants}
        if len(distinct) >= self.params["jump_threshold"] and not findings:
            bucket = int(event.ts.timestamp() // (self.params["window_minutes"] * 60))
            findings.append(self.finding(
                f"Abnormal role count jump: {len(distinct)} roles granted in {self.params['window_minutes']} min",
                0.7,
                {"roles": sorted(distinct)},
                user_id=event.user_id, dedupe_key=f"D06:jump:{event.user_id}:{bucket}",
            ))
        return findings


class DelayedDeprovisioning(Rule):
    key = "D12"
    name = "Delayed deprovisioning"
    severity = "medium"
    attack_technique = "Process control (leaver SLA)"
    weight = 40
    default_params = {"sla_minutes": 60, "lookback_days": 30}
    periodic = True

    def evaluate_periodic(self, ctx: DetectionContext) -> list[Finding]:
        now = ctx.now()
        sla = timedelta(minutes=self.params["sla_minutes"])
        out = []
        for lv in ctx.leaver_requests(since=now - timedelta(days=self.params["lookback_days"])):
            if lv.triggered_at > now:
                continue  # scheduled for the future
            done_at = lv.disabled_at or now
            delay = done_at - lv.triggered_at
            if delay <= sla:
                continue
            out.append(self.finding(
                f"Leaver not disabled within SLA ({int(delay.total_seconds() // 60)} min > "
                f"{self.params['sla_minutes']} min)",
                1.0 if lv.disabled_at is None else 0.6,
                {"lifecycle_id": str(lv.id), "status": lv.status, "triggered_at": lv.triggered_at.isoformat(),
                 "disabled_at": lv.disabled_at.isoformat() if lv.disabled_at else None},
                user_id=lv.user_id, dedupe_key=f"D12:{lv.id}",
            ))
        return out
