"""Row-level security policies and least-privilege grants for the runtime role.

Revision ID: 0002
Revises: 0001
"""
import os
import re

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TENANT_TABLES = [
    "users", "roles", "role_templates", "user_roles", "api_keys", "sessions", "refresh_families",
    "refresh_tokens", "events", "lifecycle_events", "approvals", "detection_rules", "alerts",
    "response_playbooks", "hunt_queries", "hunt_runs", "audit_log",
]

# Append-only tables: the runtime role may read and insert, never change history.
APPEND_ONLY = {"audit_log", "events"}

# NULLIF turns an unset setting into NULL, and `tenant_id = NULL` matches nothing:
# a connection that never bound a tenant sees zero rows (fail closed).
# Runtime role (created by infra/postgres/init.sh locally, app.render_boot on Render).
APP_ROLE = os.environ.get("APP_DB_ROLE", "is_app")
if not re.match(r"^[a-z_][a-z0-9_]{0,62}$", APP_ROLE):
    raise RuntimeError(f"invalid APP_DB_ROLE {APP_ROLE!r}")

POLICY = "tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid"


def upgrade() -> None:
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON tenants TO {APP_ROLE}")
    for table in TENANT_TABLES:
        privileges = "SELECT, INSERT" if table in APPEND_ONLY else "SELECT, INSERT, UPDATE, DELETE"
        op.execute(f"GRANT {privileges} ON {table} TO {APP_ROLE}")
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} USING ({POLICY}) WITH CHECK ({POLICY})"
        )
    op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}")


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
        op.execute(f"REVOKE ALL ON {table} FROM {APP_ROLE}")
    op.execute(f"REVOKE ALL ON tenants FROM {APP_ROLE}")
