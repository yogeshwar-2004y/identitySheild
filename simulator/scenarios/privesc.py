"""An attacker with Keycloak console access grants the HIGH-sensitivity `admin` role
straight in the IdP, bypassing IdentityShield's approval workflow. The Keycloak admin
event is ingested and checked against approved grants. Expect D06 Privilege
escalation (critical) and an automatic revert of the role."""
from __future__ import annotations

from simulator.client import LabClient


def run(c: LabClient, victim: str = "asha") -> bool:
    c.log("[privesc] expected detection: D06 Privilege escalation (T1098)")
    c.log(f"  1. grant realm role 'admin' to {victim} directly in Keycloak (no lifecycle request, no approval)")
    r = c.rogue_grant(victim, "admin")
    c.log(f"     -> {r.status_code} {r.text[:160]}")
    if r.status_code != 200:
        return False
    return c.report("D06", timeout=20)
