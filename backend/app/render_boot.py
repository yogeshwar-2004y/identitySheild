"""Start-up helpers for hosted deployments (Render) where there is one managed Postgres database.

    python -m app.render_boot env    # print `export ...` lines: runtime + migration URLs
    python -m app.render_boot db     # create / update the RLS-bound runtime role

Render hands out a single owner connection string (RENDER_DATABASE_URL). The API must not use
it directly: the owner bypasses row-level security. So the owner creates a separate runtime role
(APP_DB_ROLE, default `is_app`) and runs migrations; the API then connects as that role.
"""
from __future__ import annotations

import logging
import os
import re
import shlex
import sys
import time
from urllib.parse import quote, urlsplit, urlunsplit

log = logging.getLogger("render_boot")

ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def app_role() -> str:
    role = os.environ.get("APP_DB_ROLE", "is_app")
    if not ROLE_RE.match(role):
        raise SystemExit(f"APP_DB_ROLE {role!r} is not a valid role name")
    return role


def _sqlalchemy(url: str) -> str:
    """postgres://... or postgresql://... -> postgresql+psycopg://..."""
    parts = urlsplit(url)
    return urlunsplit(("postgresql+psycopg", *parts[1:]))


def derive_urls(owner_url: str, role: str, role_password: str) -> dict[str, str]:
    parts = urlsplit(owner_url)
    if not parts.hostname or not parts.path.strip("/"):
        raise SystemExit("RENDER_DATABASE_URL must look like postgresql://user:pass@host[:port]/db")
    host = parts.hostname + (f":{parts.port}" if parts.port else "")
    runtime = urlunsplit((parts.scheme, f"{role}:{quote(role_password, safe='')}@{host}", parts.path, parts.query, ""))
    return {"MIGRATION_DATABASE_URL": _sqlalchemy(owner_url), "DATABASE_URL": _sqlalchemy(runtime)}


def public_url(host: str) -> str:
    """Render service host (slug like `identityshield-api-ci54`) -> https://<slug>.onrender.com."""
    host = host.strip().rstrip("/")
    if host.startswith(("http://", "https://")):
        return host
    return f"https://{host if '.' in host else host + '.onrender.com'}"


def service_urls(env: dict[str, str]) -> dict[str, str]:
    """Browser-facing URLs of the sibling services. Render adds a random suffix to a service name
    that is already taken, so they come from the Blueprint's `fromService: host` references (and
    this service's own RENDER_EXTERNAL_URL) instead of being hard-coded. They take priority over
    values left behind by an older Blueprint; drop the reference to set a URL by hand."""
    derived: dict[str, str] = {}
    if env.get("WEB_SERVICE_HOST"):
        derived["PUBLIC_URL"] = public_url(env["WEB_SERVICE_HOST"])
    if env.get("KC_SERVICE_HOST"):
        kc = public_url(env["KC_SERVICE_HOST"])
        derived["KEYCLOAK_PUBLIC_URL"] = kc
        derived["KEYCLOAK_INTERNAL_URL"] = kc
    if env.get("RENDER_EXTERNAL_URL"):
        derived["API_INTERNAL_URL"] = env["RENDER_EXTERNAL_URL"].rstrip("/")  # back-channel logout target
    return derived


def _env_urls() -> dict[str, str]:
    owner = os.environ.get("RENDER_DATABASE_URL")
    password = os.environ.get("IS_APP_DB_PASSWORD")
    if not owner or not password:
        raise SystemExit("RENDER_DATABASE_URL and IS_APP_DB_PASSWORD are required")
    return {**derive_urls(owner, app_role(), password), **service_urls(dict(os.environ))}


def ensure_runtime_role() -> None:
    """Idempotent: the runtime role exists, can log in, is not superuser, cannot bypass RLS."""
    import psycopg
    from psycopg import sql

    role = app_role()
    owner = os.environ["RENDER_DATABASE_URL"]
    password = os.environ["IS_APP_DB_PASSWORD"]
    for attempt in range(30):  # the database may still be starting on first deploy
        try:
            conn = psycopg.connect(owner, autocommit=True)
            break
        except psycopg.OperationalError as exc:
            log.warning("database not reachable yet (%s), retrying", exc)
            time.sleep(min(2 + attempt, 10))
    else:
        raise SystemExit("database unreachable")
    with conn:
        exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
        verb = "ALTER" if exists else "CREATE"
        conn.execute(sql.SQL(verb + " ROLE {} WITH LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {}").format(
            sql.Identifier(role), sql.Literal(password)))
        db = conn.execute("SELECT current_database()").fetchone()[0]  # type: ignore[index]
        conn.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(db), sql.Identifier(role)))
        conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
    log.info("runtime role %s %s", role, "updated" if exists else "created")


def wait_for_keycloak(timeout_s: int = 900) -> bool:
    import httpx

    from app.core.config import get_settings

    url = f"{get_settings().keycloak_internal_url.rstrip('/')}/realms/master"
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=30).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(10)
    return False


def seed_once() -> None:
    """Loads the demo tenants the first time the deployment starts (no shell on Render free)."""
    from sqlalchemy import select

    from app.db.session import platform_session
    from app.models import Tenant

    with platform_session() as db:
        status = db.execute(select(Tenant.status).where(Tenant.realm == "globex")).scalar_one_or_none()
    if status == "ACTIVE":
        return
    log.info("first start: waiting for Keycloak, then seeding demo data")
    if not wait_for_keycloak():
        log.error("Keycloak did not become ready; demo data not seeded (restarting the API retries)")
        return
    from app.seed import main as seed_main

    seed_main()


def main(argv: list[str]) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "env":
        urls = _env_urls()
        for key, value in urls.items():
            print(f"export {key}={shlex.quote(value)}")
        for key in ("PUBLIC_URL", "KEYCLOAK_PUBLIC_URL", "API_INTERNAL_URL"):
            print(f"echo {shlex.quote(f'{key}=' + urls.get(key, os.environ.get(key, '(unset)')))} >&2")
    elif cmd == "db":
        ensure_runtime_role()
    else:
        raise SystemExit("usage: python -m app.render_boot env|db")


if __name__ == "__main__":
    main(sys.argv)
