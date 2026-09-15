"""Отдельный канал регистрации подозрительных действий, включая SELECT."""

from alembic import op

revision = "0005_suspicious_activity"
down_revision = "0004_encryption_and_rls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # audit_log получает DML через триггеры, а этот канал явно фиксирует SELECT и виртуальные IP ботов.
    op.execute("""
    CREATE TABLE public.suspicious_activity (
        id BIGSERIAL PRIMARY KEY,
        event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        source_ip INET NOT NULL,
        app_user TEXT,
        attack_type TEXT NOT NULL CHECK (attack_type IN (
            'brute_force', 'sql_injection', 'mass_read',
            'new_ip_login', 'privilege_escalation', 'suspicious_delete'
        )),
        query_text TEXT,
        target_table TEXT,
        details JSONB,
        severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical'))
    )
    """)
    for name, expression in (
        ("event_time", "event_time DESC"),
        ("attack_type", "attack_type"),
        ("source_ip", "source_ip"),
        ("app_user", "app_user"),
    ):
        op.execute(f"CREATE INDEX ix_suspicious_activity_{name} ON public.suspicious_activity ({expression})")
    # app_user может только добавлять события и не может прочитать собственный след.
    op.execute("""
    CREATE OR REPLACE FUNCTION public.prevent_suspicious_mutation()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
        RAISE EXCEPTION 'suspicious_activity is append-only: operation % is forbidden', TG_OP
            USING ERRCODE = '42501';
    END;
    $$;
    CREATE TRIGGER trg_suspicious_activity_immutable
    BEFORE UPDATE OR DELETE ON public.suspicious_activity
    FOR EACH ROW EXECUTE FUNCTION public.prevent_suspicious_mutation();
    REVOKE ALL ON public.suspicious_activity FROM PUBLIC;
    REVOKE ALL ON public.suspicious_activity FROM app_admin, app_analyst, app_user, app_readonly;
    GRANT SELECT, INSERT ON public.suspicious_activity TO app_admin;
    GRANT SELECT ON public.suspicious_activity TO app_analyst;
    GRANT INSERT ON public.suspicious_activity TO app_user;
    GRANT USAGE, SELECT ON SEQUENCE public.suspicious_activity_id_seq TO app_admin, app_user;
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_suspicious_activity_immutable ON public.suspicious_activity")
    op.execute("DROP FUNCTION IF EXISTS public.prevent_suspicious_mutation()")
    op.execute("DROP TABLE IF EXISTS public.suspicious_activity CASCADE")
