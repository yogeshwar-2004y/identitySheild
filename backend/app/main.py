"""IdentityShield API entry point."""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.audit.router import router as audit_router
from app.auth.router import router as auth_router
from app.core.config import get_settings
from app.core.redis import get_redis
from app.db.session import platform_session
from app.detection.router import router as detection_router
from app.events.router import router as events_router
from app.hunt.router import router as hunt_router
from app.lab.router import router as lab_router
from app.lifecycle.router import router as lifecycle_router
from app.overview.router import router as overview_router
from app.response.router import router as response_router
from app.sessions.router import router as sessions_router
from app.tenancy.router import router as tenancy_router
from app.users.router import router as users_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

MAX_BODY_BYTES = 1_000_000

# Endpoints reachable without a bearer token. Everything else must depend on get_ctx
# (enforced by tests/test_route_security.py).
PUBLIC_PATHS = {
    "/health/live", "/health/ready", "/auth/login", "/auth/callback", "/auth/refresh", "/auth/logout",
    "/auth/logout-all", "/auth/backchannel-logout", "/ingest/keycloak", "/lifecycle/webhook/hr", "/tenants",
    "/lab/login", "/lab/rogue-role-grant", "/lab/poll", "/lab/alerts",
}


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    s = get_settings()
    if s.embed_worker:  # single-service hosting (Render free tier): no separate worker process
        from app.worker import start_embedded, stop_embedded

        start_embedded(seed=s.seed_on_start)
        yield
        stop_embedded()
    else:
        yield


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title="IdentityShield API", version="1.0.0", lifespan=lifespan,
                  docs_url="/docs" if s.lab_mode else None, redoc_url=None, openapi_url="/openapi.json")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[s.public_url],  # strict: only the dashboard origin
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "Idempotency-Key"],
        max_age=600,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Any:
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "request too large"}, status_code=413)
        response = await call_next(request)
        h = response.headers
        h.setdefault("Cache-Control", "no-store")  # no authenticated content in any cache (back button)
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        if not request.url.path.startswith("/docs"):
            h["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        if s.cookie_secure:
            h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [{"loc": e.get("loc"), "msg": e.get("msg")} for e in exc.errors()]
        return JSONResponse({"detail": {"code": "validation_error", "errors": errors}}, status_code=422)

    @app.get("/health/live", tags=["health"])
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready", tags=["health"])
    def ready() -> JSONResponse:
        checks: dict[str, str] = {}
        try:
            with platform_session() as db:
                db.execute(text("SELECT 1"))
            checks["postgres"] = "ok"
        except Exception as exc:  # pragma: no cover
            checks["postgres"] = f"error: {type(exc).__name__}"
        try:
            get_redis().ping()
            checks["redis"] = "ok"
        except Exception as exc:  # pragma: no cover
            checks["redis"] = f"error: {type(exc).__name__}"
        ok = all(v == "ok" for v in checks.values())
        return JSONResponse({"status": "ok" if ok else "degraded", "checks": checks}, status_code=200 if ok else 503)

    for r in (auth_router, sessions_router, users_router, lifecycle_router, events_router, detection_router,
              hunt_router, response_router, audit_router, tenancy_router, overview_router):
        app.include_router(r)
    if s.lab_mode:
        app.include_router(lab_router)
    return app


app = create_app()
