"""Offline GeoIP enrichment for the lab (no external calls).

A small CIDR table maps documentation/test ranges to fixed locations so demo
scenarios are deterministic. Private/loopback addresses are treated as the
lab's home office. Swap `lookup` for a MaxMind GeoLite2 reader in production.
"""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from functools import lru_cache
from typing import Any


@dataclass(frozen=True)
class GeoInfo:
    country: str
    city: str
    lat: float
    lon: float
    asn: str

    def as_dict(self) -> dict[str, Any]:
        return {"country": self.country, "city": self.city, "lat": self.lat, "lon": self.lon}


_TABLE: list[tuple[str, GeoInfo]] = [
    ("203.0.113.0/24", GeoInfo("IN", "Coimbatore", 11.0168, 76.9558, "AS64500")),
    ("198.51.100.0/24", GeoInfo("US", "New York", 40.7128, -74.0060, "AS64501")),
    ("192.0.2.0/24", GeoInfo("DE", "Frankfurt", 50.1109, 8.6821, "AS64502")),
    ("100.64.0.0/16", GeoInfo("SG", "Singapore", 1.3521, 103.8198, "AS64503")),
    ("100.65.0.0/16", GeoInfo("BR", "Sao Paulo", -23.5505, -46.6333, "AS64504")),
    ("100.66.0.0/16", GeoInfo("GB", "London", 51.5074, -0.1278, "AS64505")),
    ("100.67.0.0/16", GeoInfo("RU", "Moscow", 55.7558, 37.6173, "AS64506")),
    ("100.68.0.0/16", GeoInfo("IN", "Bengaluru", 12.9716, 77.5946, "AS64507")),
    ("100.69.0.0/16", GeoInfo("AU", "Sydney", -33.8688, 151.2093, "AS64508")),
    # Lab-internal addresses: Docker networks, loopback, private LAN.
    ("10.0.0.0/8", GeoInfo("IN", "Coimbatore", 11.0168, 76.9558, "AS-LAB")),
    ("172.16.0.0/12", GeoInfo("IN", "Coimbatore", 11.0168, 76.9558, "AS-LAB")),
    ("192.168.0.0/16", GeoInfo("IN", "Coimbatore", 11.0168, 76.9558, "AS-LAB")),
    ("127.0.0.0/8", GeoInfo("IN", "Coimbatore", 11.0168, 76.9558, "AS-LAB")),
]
_NETS = [(ipaddress.ip_network(cidr), info) for cidr, info in _TABLE]


@lru_cache(maxsize=4096)
def lookup(ip: str | None) -> GeoInfo | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, info in _NETS:
        if addr.version == net.version and addr in net:
            return info
    return None


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))
