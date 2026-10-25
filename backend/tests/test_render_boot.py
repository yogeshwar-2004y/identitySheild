"""Hosted (Render) start-up helpers: URL derivation for the RLS-bound runtime role."""
import pytest

from app.render_boot import app_role, derive_urls


def test_derive_urls_switches_user_and_driver() -> None:
    urls = derive_urls("postgresql://owner:ownerpw@dpg-abc-a/identityshield", "is_app", "p+/w=")
    assert urls["MIGRATION_DATABASE_URL"] == "postgresql+psycopg://owner:ownerpw@dpg-abc-a/identityshield"
    # runtime role, password URL-encoded, same host and database
    assert urls["DATABASE_URL"] == "postgresql+psycopg://is_app:p%2B%2Fw%3D@dpg-abc-a/identityshield"


def test_derive_urls_keeps_port_and_query() -> None:
    urls = derive_urls("postgres://o:x@db.example:6543/app?sslmode=require", "is_app", "pw")
    assert urls["DATABASE_URL"] == "postgresql+psycopg://is_app:pw@db.example:6543/app?sslmode=require"


def test_derive_urls_rejects_missing_database() -> None:
    with pytest.raises(SystemExit):
        derive_urls("postgresql://o:x@host", "is_app", "pw")


def test_role_name_is_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_DB_ROLE", "is_app; DROP TABLE users")
    with pytest.raises(SystemExit):
        app_role()
    monkeypatch.setenv("APP_DB_ROLE", "tenant_rt")
    assert app_role() == "tenant_rt"


def test_service_urls_from_render_hosts() -> None:
    from app.render_boot import service_urls

    env = {"WEB_SERVICE_HOST": "identityshield-web-ci54", "KC_SERVICE_HOST": "identityshield-kc-ab12",
           "RENDER_EXTERNAL_URL": "https://identityshield-api-x9.onrender.com/"}
    assert service_urls(env) == {
        "PUBLIC_URL": "https://identityshield-web-ci54.onrender.com",
        "KEYCLOAK_PUBLIC_URL": "https://identityshield-kc-ab12.onrender.com",
        "KEYCLOAK_INTERNAL_URL": "https://identityshield-kc-ab12.onrender.com",
        "API_INTERNAL_URL": "https://identityshield-api-x9.onrender.com",
    }


def test_render_hosts_override_stale_urls() -> None:
    from app.render_boot import service_urls

    env = {"WEB_SERVICE_HOST": "identityshield-web-ci54", "PUBLIC_URL": "https://identityshield-web.onrender.com"}
    assert service_urls(env) == {"PUBLIC_URL": "https://identityshield-web-ci54.onrender.com"}
    assert service_urls({"PUBLIC_URL": "https://shield.example.com"}) == {}
