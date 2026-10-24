"""HTTP client for the lab API, with a hard guard against non-lab targets."""
from __future__ import annotations

import ipaddress
import socket
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import httpx

CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
ATTACKER_UA = "python-requests/2.31 (stolen-cookie-replay)"
DOCKER_NETS = [ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"),
               ipaddress.ip_network("10.0.0.0/8")]


class UnsafeTarget(Exception):
    pass


def assert_lab_target(base_url: str) -> None:
    """Allow only localhost or a Docker-network service name. Refuse everything else."""
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    if parsed.scheme not in ("http", "https") or not host:
        raise UnsafeTarget(f"invalid target URL: {base_url}")
    if host == "localhost":
        return
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return
        raise UnsafeTarget(f"refusing non-loopback IP target {host}")
    except ValueError:
        pass
    if "." in host:
        raise UnsafeTarget(f"refusing external hostname {host}; only localhost or a Docker service name is allowed")
    try:  # single-label name: must resolve to a loopback or Docker bridge address
        resolved = ipaddress.ip_address(socket.gethostbyname(host))
    except (socket.gaierror, ValueError) as exc:
        raise UnsafeTarget(f"cannot resolve {host}: {exc}")
    if resolved.is_loopback or any(resolved in n for n in DOCKER_NETS):
        return
    raise UnsafeTarget(f"{host} resolves to {resolved}, which is not a lab address")


class LabClient:
    def __init__(self, base_url: str, lab_key: str, tenant: str, log: Callable[[str], None] = print) -> None:
        assert_lab_target(base_url)
        self.base = base_url.rstrip("/")
        self.key = lab_key
        self.tenant = tenant
        self.log = log
        self.http = httpx.Client(timeout=30)
        self.started = time.time()

    def _headers(self, ip: str | None, ua: str | None, token: str | None = None) -> dict[str, str]:
        h = {"X-Lab-Key": self.key}
        if ip:
            h["X-Lab-Client-IP"] = ip
        if ua:
            h["User-Agent"] = ua
        if token:
            h["Authorization"] = f"Bearer {token}"
        return h

    def login(self, username: str, *, ip: str, ua: str = CHROME_UA, password: str | None = None) -> httpx.Response:
        body: dict[str, Any] = {"tenant": self.tenant, "username": username}
        if password is not None:
            body["password"] = password
        return self.http.post(f"{self.base}/lab/login", json=body, headers=self._headers(ip, ua))

    def get(self, path: str, *, token: str, ip: str, ua: str) -> httpx.Response:
        return self.http.get(f"{self.base}{path}", headers=self._headers(ip, ua, token))

    def refresh(self, refresh_token: str, *, ip: str, ua: str) -> httpx.Response:
        return self.http.post(f"{self.base}/auth/refresh", json={"refresh_token": refresh_token},
                              headers=self._headers(ip, ua))

    def rogue_grant(self, username: str, role: str) -> httpx.Response:
        return self.http.post(f"{self.base}/lab/rogue-role-grant",
                              json={"tenant": self.tenant, "username": username, "role": role},
                              headers=self._headers(None, None))

    def alerts_since(self, rule_key: str) -> list[dict[str, Any]]:
        r = self.http.get(f"{self.base}/lab/alerts", params={"tenant": self.tenant, "rule_key": rule_key,
                                                              "since_epoch": int(self.started) - 2},
                          headers=self._headers(None, None))
        r.raise_for_status()
        return list(r.json())

    def wait_for_alert(self, rule_key: str, timeout: float = 15) -> list[dict[str, Any]]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.http.post(f"{self.base}/lab/poll", params={"tenant": self.tenant}, headers=self._headers(None, None))
            alerts = self.alerts_since(rule_key)
            if alerts:
                return alerts
            time.sleep(1.5)
        return []

    def report(self, rule_key: str, timeout: float = 15) -> bool:
        alerts = self.wait_for_alert(rule_key, timeout)
        if not alerts:
            self.log(f"  RESULT: no {rule_key} alert observed (check worker logs)")
            return False
        for a in alerts[:3]:
            actions = ", ".join(f"{x['action']}={x['status']}" for x in a.get("response", {}).get("results", []))
            self.log(f"  RESULT: {a['rule_key']} [{a['severity']}] risk={a['risk']} :: {a['title']}")
            if actions:
                self.log(f"          response: {actions}")
        return True
