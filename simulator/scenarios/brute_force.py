"""Password guessing against one account (8 failures from one IP in a minute),
then credential stuffing: one IP failing across many different usernames.
Expect D07 Brute force and D08 Credential stuffing."""
from __future__ import annotations

from simulator.client import ATTACKER_UA, LabClient

stuffing_doc = """One IP tries leaked username/password pairs against 12 different accounts.
Expect D08 Credential stuffing (T1110.004)."""

LEAKED = ["j.smith", "maria.g", "dev-ops", "kim.lee", "p.patel", "backup", "omar.k", "test1", "svc-ci",
          "ana.r", "li.wei", "bob"]


def _guess(c: LabClient, victim: str) -> None:
    c.log(f"  1. 8 wrong passwords for {victim} from 100.69.0.9 (Sydney, AU)")
    for i in range(8):
        r = c.login(victim, ip="100.69.0.9", ua=ATTACKER_UA, password=f"Summer2026!{i}")
        c.log(f"     attempt {i + 1}: {r.status_code}")


def _stuff(c: LabClient) -> None:
    c.log(f"  2. credential stuffing: {len(LEAKED)} usernames from 100.65.0.7 (Sao Paulo, BR)")
    for u in LEAKED:
        r = c.login(u, ip="100.65.0.7", ua=ATTACKER_UA, password="Password123!")
        c.log(f"     {u}: {r.status_code}")


def run(c: LabClient, victim: str = "asha") -> bool:
    c.log("[brute_force] expected detections: D07 Brute force (T1110.001), D08 Credential stuffing (T1110.004)")
    _guess(c, victim)
    d07 = c.report("D07")
    _stuff(c)
    d08 = c.report("D08")
    return d07 and d08


def run_stuffing(c: LabClient, victim: str = "asha") -> bool:
    c.log("[credential_stuffing] expected detection: D08 Credential stuffing (T1110.004)")
    _stuff(c)
    return c.report("D08")
