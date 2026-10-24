"""Two successful logins for the same account, minutes apart, from Coimbatore (IN) and
New York (US): ~13,000 km in under a minute. Expect D01 Impossible travel."""
from __future__ import annotations

import time

from simulator.client import CHROME_UA, LabClient


def run(c: LabClient, victim: str = "asha") -> bool:
    c.log("[impossible_travel] expected detection: D01 Impossible travel (T1078)")
    c.log(f"  1. {victim} logs in from 203.0.113.25 (Coimbatore, IN)")
    r = c.login(victim, ip="203.0.113.25", ua=CHROME_UA)
    if r.status_code != 200:
        c.log(f"  !! login failed ({r.status_code}): {r.text[:200]}")
        return False
    time.sleep(1.2)
    c.log(f"  2. 1 s later {victim} logs in from 198.51.100.20 (New York, US)")
    r = c.login(victim, ip="198.51.100.20", ua=CHROME_UA)
    c.log(f"     second login -> {r.status_code}")
    return c.report("D01")
