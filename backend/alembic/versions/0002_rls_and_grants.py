"""Row-level security policies and least-privilege grants for the runtime role.

Revision ID: 0002
Revises: 0001
"""
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
POLICY = "tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid"


def upgrade() -> None:
    op.execute("GRANT SELECT, INSERT, UPDATE ON tenants TO is_app")
    for table in TENANT_TABLES:
        privileges = "SELECT, INSERT" if table in APPEND_ONLY else "SELECT, INSERT, UPDATE, DELETE"
        op.execute(f"GRANT {privileges} ON {table} TO is_app")
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} USING ({POLICY}) WITH CHECK ({POLICY})"
        )
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO is_app")


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
        op.execute(f"REVOKE ALL ON {table} FROM is_app")
    op.execute("REVOKE ALL ON tenants FROM is_app")
