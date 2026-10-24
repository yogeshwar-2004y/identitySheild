"""ORM models. Every table except `tenants` carries `tenant_id` and is protected by
Postgres row-level security (see alembic migration 0001)."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Index,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def _tenant_fk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True)


def _ts(nullable: bool = False, default: bool = True) -> Mapped[Any]:
    if default:
        return mapped_column(DateTime(timezone=True), nullable=nullable, server_default=func.now())
    return mapped_column(DateTime(timezone=True), nullable=nullable)


# ----------------------------------------------------------------------------- tenancy


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(200))
    realm: Mapped[str] = mapped_column(String(63), unique=True)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    client_secret_enc: Mapped[str | None] = mapped_column(Text)
    hr_webhook_secret_enc: Mapped[str | None] = mapped_column(Text)
    kc_poll_cursor: Mapped[int] = mapped_column(BigInteger, default=0)
    kc_admin_poll_cursor: Mapped[int] = mapped_column(BigInteger, default=0)
    created_at: Mapped[datetime] = _ts()


# ----------------------------------------------------------------------------- identity


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email"),
        UniqueConstraint("tenant_id", "kc_user_id"),
        Index("ix_users_tenant_state", "tenant_id", "state"),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    kc_user_id: Mapped[str | None] = mapped_column(String(64))
    username: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(254))
    full_name: Mapped[str] = mapped_column(String(200), default="")
    department: Mapped[str] = mapped_column(String(80), default="")
    state: Mapped[str] = mapped_column(String(20), default="PENDING")  # PENDING|ACTIVE|SUSPENDED|DEPROVISIONED
    mfa_enrolled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = _ts()
    activated_at: Mapped[datetime | None] = _ts(nullable=True, default=False)
    last_login_at: Mapped[datetime | None] = _ts(nullable=True, default=False)
    deprovisioned_at: Mapped[datetime | None] = _ts(nullable=True, default=False)


class Role(Base):
    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    name: Mapped[str] = mapped_column(String(80))
    sensitivity: Mapped[str] = mapped_column(String(10), default="LOW")  # LOW|HIGH
    description: Mapped[str] = mapped_column(String(300), default="")


class RoleTemplate(Base):
    __tablename__ = "role_templates"
    __table_args__ = (UniqueConstraint("tenant_id", "department"),)
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    department: Mapped[str] = mapped_column(String(80))
    role_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)


class UserRole(Base):
    __tablename__ = "user_roles"
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), primary_key=True)
    role_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("roles.id"), primary_key=True)
    granted_by: Mapped[str] = mapped_column(String(120))
    granted_at: Mapped[datetime] = _ts()
    approval_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    lifecycle_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))


class ApiKey(Base):
    """Personal access tokens. Revoked by the Leaver workflow."""

    __tablename__ = "api_keys"
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    prefix: Mapped[str] = mapped_column(String(16), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = _ts()
    last_used_at: Mapped[datetime | None] = _ts(nullable=True, default=False)
    revoked_at: Mapped[datetime | None] = _ts(nullable=True, default=False)


# ----------------------------------------------------------------------------- sessions


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = (Index("ix_sessions_user_revoked", "user_id", "revoked_at"),)
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    kc_session_id: Mapped[str | None] = mapped_column(String(64), index=True)
    ip: Mapped[str] = mapped_column(String(64))
    geo: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    asn: Mapped[str | None] = mapped_column(String(32))
    ua_hash: Mapped[str] = mapped_column(String(64))
    user_agent: Mapped[str] = mapped_column(String(400), default="")
    source: Mapped[str] = mapped_column(String(20), default="browser")
    claims_version: Mapped[int] = mapped_column(Integer, default=1)
    reissue_required: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    kc_refresh_enc: Mapped[str | None] = mapped_column(Text)
    kc_id_token_enc: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _ts()
    last_seen_at: Mapped[datetime] = _ts()
    expires_at: Mapped[datetime] = _ts(default=False)
    revoked_at: Mapped[datetime | None] = _ts(nullable=True, default=False)
    revoke_reason: Mapped[str | None] = mapped_column(String(80))


class RefreshFamily(Base):
    __tablename__ = "refresh_families"
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("sessions.id"), index=True)
    current_token_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = _ts()
    reused_at: Mapped[datetime | None] = _ts(nullable=True, default=False)
    revoked_at: Mapped[datetime | None] = _ts(nullable=True, default=False)


class RefreshToken(Base):
    """Every refresh token ever issued in a family (hash only), so reuse of a rotated one is detectable."""

    __tablename__ = "refresh_tokens"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    family_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("refresh_families.id"), index=True)
    issued_at: Mapped[datetime] = _ts()
    rotated_at: Mapped[datetime | None] = _ts(nullable=True, default=False)


# ----------------------------------------------------------------------------- events


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_tenant_ts", "tenant_id", "ts"),
        Index("ix_events_tenant_user_ts", "tenant_id", "user_id", "ts"),
        Index("ix_events_tenant_ip_ts", "tenant_id", "ip", "ts"),
        Index("ix_events_tenant_type_ts", "tenant_id", "type", "ts"),
        UniqueConstraint("tenant_id", "source", "source_id", name="uq_events_source"),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    ts: Mapped[datetime] = _ts(default=False)
    type: Mapped[str] = mapped_column(String(40))
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    username: Mapped[str | None] = mapped_column(String(254))
    ip: Mapped[str | None] = mapped_column(String(64))
    geo: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    asn: Mapped[str | None] = mapped_column(String(32))
    user_agent_hash: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(10), default="SUCCESS")
    source: Mapped[str] = mapped_column(String(20), default="app")
    source_id: Mapped[str | None] = mapped_column(String(80))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    ingested_at: Mapped[datetime] = _ts()


# ----------------------------------------------------------------------------- lifecycle


class LifecycleEvent(Base):
    __tablename__ = "lifecycle_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key"),
        Index("ix_lifecycle_tenant_status", "tenant_id", "status"),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    kind: Mapped[str] = mapped_column(String(10))  # JOINER|MOVER|LEAVER
    status: Mapped[str] = mapped_column(String(20))
    requested_by: Mapped[str] = mapped_column(String(120))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    steps: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    access_diff: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    idempotency_key: Mapped[str | None] = mapped_column(String(120))
    approval_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    effective_at: Mapped[datetime | None] = _ts(nullable=True, default=False)
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = _ts()
    completed_at: Mapped[datetime | None] = _ts(nullable=True, default=False)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    lifecycle_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    request_type: Mapped[str] = mapped_column(String(40))
    requested_by: Mapped[str] = mapped_column(String(120))
    approver: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(20), default="PENDING")  # PENDING|APPROVED|REJECTED
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _ts()
    decided_at: Mapped[datetime | None] = _ts(nullable=True, default=False)


# ----------------------------------------------------------------------------- detection


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (UniqueConstraint("tenant_id", "rule_key"),)
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    rule_key: Mapped[str] = mapped_column(String(10))
    name: Mapped[str] = mapped_column(String(120))
    severity: Mapped[str] = mapped_column(String(10))
    attack_technique: Mapped[str] = mapped_column(String(60))
    weight: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_tenant_status_sev", "tenant_id", "status", "severity"),
        Index("ix_alerts_tenant_created", "tenant_id", "created_at"),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    rule_key: Mapped[str] = mapped_column(String(10))
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(10))
    attack_technique: Mapped[str] = mapped_column(String(60), default="")
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    risk: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="OPEN")
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    response: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    dedupe_key: Mapped[str | None] = mapped_column(String(200), index=True)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = _ts()


class ResponsePlaybook(Base):
    __tablename__ = "response_playbooks"
    __table_args__ = (UniqueConstraint("tenant_id", "rule_key"),)
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    rule_key: Mapped[str] = mapped_column(String(10))
    actions: Mapped[list[str]] = mapped_column(JSONB, default=list)
    mode: Mapped[str] = mapped_column(String(10), default="DRY_RUN")  # DRY_RUN|ACTIVE
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


# ----------------------------------------------------------------------------- hunting


class HuntQuery(Base):
    __tablename__ = "hunt_queries"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    name: Mapped[str] = mapped_column(String(160))
    hypothesis: Mapped[str] = mapped_column(Text)
    query: Mapped[dict[str, Any]] = mapped_column(JSONB)
    attack_technique: Mapped[str] = mapped_column(String(60), default="")
    prebuilt: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = _ts()


class HuntRun(Base):
    __tablename__ = "hunt_runs"
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    hunt_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hunt_queries.id"), index=True)
    run_at: Mapped[datetime] = _ts()
    run_by: Mapped[str] = mapped_column(String(120))
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    results: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    verdict: Mapped[str] = mapped_column(String(20), default="PENDING")  # PENDING|CONFIRMED|BENIGN|INCONCLUSIVE
    notes: Mapped[str | None] = mapped_column(Text)


# ----------------------------------------------------------------------------- audit


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_tenant_id", "tenant_id", "id"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    ts: Mapped[datetime] = _ts(default=False)
    actor: Mapped[str] = mapped_column(String(160))
    action: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(String(200), default="")
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


TENANT_TABLES = [
    "users", "roles", "role_templates", "user_roles", "api_keys", "sessions", "refresh_families",
    "refresh_tokens", "events", "lifecycle_events", "approvals", "detection_rules", "alerts",
    "response_playbooks", "hunt_queries", "hunt_runs", "audit_log",
]
