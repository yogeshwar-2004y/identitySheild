"""Victim logs in from the office (IN, Chrome). An attacker replays the stolen access
token from another network (US, scripted client). Expect D02 -> risk >= 70 -> session
auto-revoked, so the replay and every later use of that session return 401."""
from __future__ import annotations

from simulator.client import ATTACKER_UA, CHROME_UA, LabClient

VICTIM_IP = "203.0.113.10"
ATTACKER_IP = "198.51.100.66"


def run(c: LabClient, victim: str = "asha") -> bool:
    c.log(f"[stolen_session] expected detection: D02 Session replay / hijack (T1539)")
    c.log(f"  1. {victim} logs in from {VICTIM_IP} (Coimbatore, IN) with a desktop browser")
    r = c.login(victim, ip=VICTIM_IP, ua=CHROME_UA)
    if r.status_code != 200:
        c.log(f"  !! victim login failed ({r.status_code}): {r.text[:200]}")
        return False
    token = r.json()["access_token"]
    sid = r.json()["session_id"]
    c.log(f"     session {sid[:8]}... bound to {VICTIM_IP} / Chrome")
    r = c.get("/auth/me", token=token, ip=VICTIM_IP, ua=CHROME_UA)
    c.log(f"  2. victim uses the app normally: GET /auth/me -> {r.status_code}")
    c.log(f"  3. attacker replays the same bearer token from {ATTACKER_IP} (New York, US) with a script")
    r = c.get("/auth/me", token=token, ip=ATTACKER_IP, ua=ATTACKER_UA)
    c.log(f"     replay GET /auth/me -> {r.status_code} {r.json().get('detail', '') if r.status_code != 200 else ''}")
    r2 = c.get("/sessions", token=token, ip=ATTACKER_IP, ua=ATTACKER_UA)
    c.log(f"  4. second replay GET /sessions -> {r2.status_code}")
    r3 = c.get("/auth/me", token=token, ip=VICTIM_IP, ua=CHROME_UA)
    c.log(f"  5. even the victim's copy of the token is now dead: GET /auth/me -> {r3.status_code}")
    detected = c.report("D02")
    return detected and r2.status_code == 401
