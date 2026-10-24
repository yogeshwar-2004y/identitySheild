"""After the Leaver workflow, someone tries the deprovisioned account's still-known
password from an unfamiliar network. Keycloak refuses (account disabled), and the
attempt itself is the signal. Expect D04 Ghost account activity (critical)."""
from __future__ import annotations

from simulator.client import ATTACKER_UA, LabClient


def run(c: LabClient, victim: str = "asha") -> bool:
    c.log("[ghost_login] expected detection: D04 Ghost account activity (critical)")
    c.log(f"  1. login attempt as deprovisioned user {victim} from 100.67.0.5 (Moscow, RU)")
    r = c.login(victim, ip="100.67.0.5", ua=ATTACKER_UA)
    c.log(f"     -> {r.status_code} {r.text[:120]}")
    if r.status_code == 200:
        c.log("  !! login succeeded: the account is not deprovisioned (run the Leaver first)")
    return c.report("D04", timeout=20)
