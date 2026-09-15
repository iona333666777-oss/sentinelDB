"""Создание базовой схемы RBAC SentinelDB."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("roles", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(64), nullable=False), sa.Column("description", sa.Text()), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False), sa.PrimaryKeyConstraint("id", name="pk_roles"), sa.UniqueConstraint("name", name="uq_roles_name"), schema="public")
    op.create_table("permissions", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(128), nullable=False), sa.Column("description", sa.Text()), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False), sa.PrimaryKeyConstraint("id", name="pk_permissions"), sa.UniqueConstraint("name", name="uq_permissions_name"), schema="public")
    op.create_table("users", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("username", sa.String(64), nullable=False), sa.Column("password_hash", sa.String(512), nullable=False), sa.Column("email", sa.String(320)), sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False), sa.Column("last_login_at", sa.DateTime(timezone=True)), sa.PrimaryKeyConstraint("id", name="pk_users"), sa.UniqueConstraint("username", name="uq_users_username"), sa.UniqueConstraint("email", name="uq_users_email"), schema="public")
    op.create_index("ix_users_username", "users", ["username"], unique=False, schema="public")
    op.create_table("role_permissions", sa.Column("role_id", sa.Integer(), nullable=False), sa.Column("permission_id", sa.Integer(), nullable=False), sa.ForeignKeyConstraint(["role_id"], ["public.roles.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["permission_id"], ["public.permissions.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("role_id", "permission_id", name="pk_role_permissions"), schema="public")
    op.create_table("user_roles", sa.Column("user_id", sa.Integer(), nullable=False), sa.Column("role_id", sa.Integer(), nullable=False), sa.ForeignKeyConstraint(["user_id"], ["public.users.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["role_id"], ["public.roles.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("user_id", "role_id", name="pk_user_roles"), schema="public")
    op.create_table("objects", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("owner_id", sa.Integer(), nullable=False), sa.Column("title", sa.String(255), nullable=False), sa.Column("content", sa.Text(), nullable=False), sa.Column("classification", sa.String(32), server_default="internal", nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False), sa.ForeignKeyConstraint(["owner_id"], ["public.users.id"], ondelete="RESTRICT"), schema="public")
    op.create_index("ix_objects_owner_id", "objects", ["owner_id"], unique=False, schema="public")
    op.create_table("audit_log", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("user_id", sa.Integer()), sa.Column("action", sa.String(64), nullable=False), sa.Column("table_name", sa.String(128)), sa.Column("record_id", sa.Integer()), sa.Column("details", postgresql.JSONB()), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False), sa.ForeignKeyConstraint(["user_id"], ["public.users.id"], ondelete="SET NULL"), schema="public")


def downgrade() -> None:
    for table in ("audit_log", "objects", "user_roles", "role_permissions", "users", "permissions", "roles"):
        op.drop_table(table, schema="public")
