"""Tenant onboarding: one Keycloak realm per tenant + default policy rows.

Idempotent: re-running for an existing tenant adopts the realm, re-applies the
session/event settings, rotates the client secret and fills in any missing
defaults without touching customised rows.
"""
from __future__ import annotations

import logging
import re
import secrets
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import write_audit
from app.core.config import get_settings
from app.core.keycloak import KeycloakPlatformAdmin, load_realm_template
from app.core.security import encrypt_str
from app.db.session import platform_session, tenant_session
from app.detection.rules import RULE_CLASSES
from app.hunt.service import PREBUILT_HUNTS
from app.models import DetectionRule, HuntQuery, ResponsePlaybook, Role, RoleTemplate, Tenant

log = logging.getLogger(__name__)

REALM_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}$")

HIGH_SENSITIVITY = {"admin", "analyst", "eng-prod-access", "finance-approver"}

DEPARTMENT_TEMPLATES: dict[str, list[str]] = {
    "Engineering": ["user", "eng-developer"],
    "Finance": ["user", "finance-viewer"],
    "Sales": ["user", "sales-crm"],
    "HR": ["user", "hr"],
    "Security": ["user", "analyst"],
    "IT": ["user", "admin"],
}

# Rule -> extra playbook actions beyond the risk tier. ACTIVE for the demo-critical rules.
DEFAULT_PLAYBOOKS: dict[str, tuple[list[str], str]] = {
    "D01": (["notify"], "ACTIVE"),
    "D02": (["revoke_session", "notify"], "ACTIVE"),
    "D03": (["revoke_session", "notify"], "ACTIVE"),
    "D04": (["revoke_all_sessions", "lock_account", "notify"], "ACTIVE"),
    "D05": ([], "DRY_RUN"),
    "D06": (["revert_role", "notify"], "ACTIVE"),
    "D07": (["notify"], "ACTIVE"),
    "D08": (["notify"], "ACTIVE"),
    "D09": (["notify"], "ACTIVE"),
    "D10": ([], "DRY_RUN"),
    "D11": (["notify"], "DRY_RUN"),
    "D12": (["notify"], "ACTIVE"),
}


class ProvisioningError(Exception):
    pass


def provision_tenant(name: str, realm: str, *, settings: dict[str, Any] | None = None,
                     admin: KeycloakPlatformAdmin | None = None) -> Tenant:
    realm = realm.strip().lower()
    if not REALM_RE.match(realm) or realm == "master":
        raise ProvisioningError("realm must be 2-31 chars: lowercase letters, digits, dashes")
    s = get_settings()
    admin = admin or KeycloakPlatformAdmin()

    with platform_session() as db:
        tenant = db.execute(select(Tenant).where(Tenant.realm == realm)).scalar_one_or_none()
        if tenant is None:
            tenant = Tenant(name=name, realm=realm, status="PROVISIONING", settings=settings or {})
            db.add(tenant)
            db.flush()
        tenant_id = tenant.id

    rep = load_realm_template(realm, name)
    if s.lab_mode:
        # LAB ONLY: the lab runs on plain-HTTP localhost and the simulator labels traffic with
        # public test-net IPs, which `external` would force onto HTTPS. Production keeps `external`.
        rep["sslRequired"] = "none"
    if admin.realm_exists(realm):
        admin.ensure_realm_config(realm, rep)
        created = False
    else:
        admin.create_realm(rep)
        created = True
    admin.ensure_service_account_roles(realm, s.oidc_client_id)
    secret = admin.rotate_client_secret(realm, s.oidc_client_id)
    admin.configure_lab_direct_grant(realm, s.oidc_client_id, enabled=s.lab_mode)

    with platform_session() as db:
        tenant = db.get(Tenant, tenant_id)
        assert tenant is not None
        tenant.client_secret_enc = encrypt_str(secret)
        if not tenant.hr_webhook_secret_enc:
            tenant.hr_webhook_secret_enc = encrypt_str(secrets.token_urlsafe(32))
        tenant.status = "ACTIVE"
        tenant.name = name

    with tenant_session(tenant_id) as db:
        seed_tenant_defaults(db, tenant_id, [r["name"] for r in rep.get("roles", {}).get("realm", [])])
        write_audit(db, tenant_id, actor="platform", action="tenant.provisioned", target=f"realm:{realm}",
                    detail={"realm_created": created, "lab_direct_grant": s.lab_mode})
        tenant = db.get(Tenant, tenant_id)
        assert tenant is not None
        db.expunge(tenant)
        return tenant


def seed_tenant_defaults(db: Session, tenant_id: Any, role_names: list[str]) -> None:
    existing_roles = {r.name: r for r in db.execute(select(Role).where(Role.tenant_id == tenant_id)).scalars()}
    for name in role_names:
        if name not in existing_roles:
            role = Role(tenant_id=tenant_id, name=name, sensitivity="HIGH" if name in HIGH_SENSITIVITY else "LOW")
            db.add(role)
            existing_roles[name] = role
    db.flush()

    have_templates = set(db.execute(select(RoleTemplate.department).where(RoleTemplate.tenant_id == tenant_id))
                         .scalars())
    for dept, roles in DEPARTMENT_TEMPLATES.items():
        if dept not in have_templates:
            db.add(RoleTemplate(tenant_id=tenant_id, department=dept,
                                role_ids=[existing_roles[r].id for r in roles if r in existing_roles]))

    have_rules = set(db.execute(select(DetectionRule.rule_key).where(DetectionRule.tenant_id == tenant_id)).scalars())
    for key, cls in RULE_CLASSES.items():
        if key not in have_rules:
            db.add(DetectionRule(tenant_id=tenant_id, rule_key=key, name=cls.name, severity=cls.severity,
                                 attack_technique=cls.attack_technique, weight=cls.weight, enabled=True,
                                 params=dict(cls.default_params)))

    have_pb = set(db.execute(select(ResponsePlaybook.rule_key).where(ResponsePlaybook.tenant_id == tenant_id))
                  .scalars())
    for key, (actions, mode) in DEFAULT_PLAYBOOKS.items():
        if key not in have_pb:
            db.add(ResponsePlaybook(tenant_id=tenant_id, rule_key=key, actions=actions, mode=mode))

    have_hunts = set(db.execute(select(HuntQuery.name).where(HuntQuery.tenant_id == tenant_id)).scalars())
    for h in PREBUILT_HUNTS:
        if h["name"] not in have_hunts:
            db.add(HuntQuery(tenant_id=tenant_id, name=h["name"], hypothesis=h["hypothesis"], query=h["query"],
                             attack_technique=h["attack_technique"], prebuilt=True, created_by="system"))
    db.flush()
