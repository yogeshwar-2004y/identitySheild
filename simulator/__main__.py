"""CLI: python -m simulator <scenario> --i-understand-lab-only [--api URL] [--tenant acme] [--victim asha]"""
from __future__ import annotations

import argparse
import os
import sys

from simulator.client import LabClient, UnsafeTarget
from simulator.scenarios import SCENARIOS


def main() -> int:
    p = argparse.ArgumentParser(prog="simulator", description="IdentityShield attack simulator (LAB ONLY)")
    p.add_argument("scenario", choices=[*SCENARIOS, "all", "list"])
    p.add_argument("--api", default=os.environ.get("SIM_API_URL", "http://localhost:8000"))
    p.add_argument("--tenant", default="acme")
    p.add_argument("--victim", default="asha")
    p.add_argument("--i-understand-lab-only", dest="ack", action="store_true",
                   help="required: confirms this runs only against your local lab")
    a = p.parse_args()
    if a.scenario == "list":
        for s in SCENARIOS.values():
            print(f"{s.name:20s} expects {s.expected:10s} {s.description.splitlines()[0] if s.description else ''}")
        return 0
    if not a.ack:
        print("Refusing to run: pass --i-understand-lab-only to confirm the target is your local lab.")
        return 2
    key = os.environ.get("LAB_API_KEY")
    if not key:
        print("LAB_API_KEY is not set (see .env).")
        return 2
    try:
        client = LabClient(a.api, key, a.tenant)
    except UnsafeTarget as exc:
        print(f"Refusing to run: {exc}")
        return 2
    names = [s for s in SCENARIOS if s != "credential_stuffing"] if a.scenario == "all" else [a.scenario]
    ok = True
    for name in names:
        ok = SCENARIOS[name].run(client, victim=a.victim) and ok
        print()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
