"""Scenario registry. Each scenario prints what it does and the detection it expects."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from simulator.client import LabClient
from simulator.scenarios import brute_force, ghost_login, impossible_travel, privesc, stolen_session


@dataclass(frozen=True)
class Scenario:
    name: str
    expected: str
    description: str
    run: Callable[..., bool]


SCENARIOS: dict[str, Scenario] = {
    s.name: s for s in [
        Scenario("stolen_session", "D02", stolen_session.__doc__ or "", stolen_session.run),
        Scenario("impossible_travel", "D01", impossible_travel.__doc__ or "", impossible_travel.run),
        Scenario("ghost_login", "D04", ghost_login.__doc__ or "", ghost_login.run),
        Scenario("brute_force", "D07 + D08", brute_force.__doc__ or "", brute_force.run),
        Scenario("credential_stuffing", "D08", brute_force.stuffing_doc, brute_force.run_stuffing),
        Scenario("privesc", "D06", privesc.__doc__ or "", privesc.run),
    ]
}

__all__ = ["SCENARIOS", "Scenario", "LabClient"]
