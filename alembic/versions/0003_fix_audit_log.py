"""Замена журнала аудита на расширенный формат событий."""

from alembic import op

revision = "0003_fix_audit_log"
down_revision = "0002_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Данные старого журнала малозначимы для проекта на этом этапе, поэтому таблица заменяется целиком.
    for table in ("users", "roles", "permissions", "objects"):
        op.execute(f"DROP TRIGGER IF EXISTS trg_audit_{table} ON public.{table}")
    op.execute("DROP TABLE IF EXISTS public.audit_log CASCADE")
    op.execute("""
    CREATE TABLE public.audit_log (
        id BIGSERIAL PRIMARY KEY,
        event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        username TEXT NOT NULL,
        "session_user" TEXT,
        table_name TEXT NOT NULL,
        operation TEXT NOT NULL CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
        record_id TEXT,
        old_data JSONB,
        new_data JSONB,
        client_ip INET,
        txid BIGINT
    )
    """)
    op.execute("CREATE INDEX ix_audit_log_event_time ON public.audit_log (event_time DESC)")
    op.execute("CREATE INDEX ix_audit_log_table_name ON public.audit_log (table_name)")
    op.execute("CREATE INDEX ix_audit_log_username ON public.audit_log (username)")
    op.execute("CREATE INDEX ix_audit_log_operation ON public.audit_log (operation)")

    # SECURITY DEFINER позволяет триггеру записывать аудит независимо от прав вызывающего пользователя.
    op.execute("""
    CREATE OR REPLACE FUNCTION public.log_action()
    RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public
    AS $$
    DECLARE
        old_payload JSONB;
        new_payload JSONB;
        key_value TEXT;
    BEGIN
        IF TG_OP = 'INSERT' THEN
            new_payload := to_jsonb(NEW);
            key_value := NEW.id::text;
        ELSIF TG_OP = 'UPDATE' THEN
            old_payload := to_jsonb(OLD);
            new_payload := to_jsonb(NEW);
            key_value := NEW.id::text;
        ELSE
            old_payload := to_jsonb(OLD);
            key_value := OLD.id::text;
        END IF;

        -- Хеши паролей не должны попадать в журнал даже в составе снимка строки.
        IF TG_TABLE_NAME = 'users' THEN
            old_payload := old_payload - 'password_hash';
            new_payload := new_payload - 'password_hash';
        END IF;

        INSERT INTO public.audit_log
            (event_time, username, "session_user", table_name, operation, record_id,
             old_data, new_data, client_ip, txid)
        VALUES
            (NOW(), current_user, session_user, TG_TABLE_NAME, TG_OP, key_value,
             old_payload, new_payload, inet_client_addr(), txid_current());

        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END;
    $$;
    """)
    for table in ("users", "roles", "permissions", "objects"):
        op.execute(f"""
        CREATE TRIGGER trg_audit_{table}
        AFTER INSERT OR UPDATE OR DELETE ON public.{table}
        FOR EACH ROW EXECUTE FUNCTION public.log_action();
        """)
    op.execute("""
    CREATE OR REPLACE FUNCTION public.prevent_audit_mutation()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
        RAISE EXCEPTION 'audit_log is append-only: operation % is forbidden', TG_OP
            USING ERRCODE = '42501';
    END;
    $$;
    """
    )
    op.execute("""
    CREATE TRIGGER trg_audit_log_immutable
    BEFORE UPDATE OR DELETE ON public.audit_log
    FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_mutation();
    REVOKE ALL ON public.audit_log FROM PUBLIC;
    REVOKE ALL ON public.audit_log FROM app_admin, app_analyst;
    GRANT SELECT, INSERT ON public.audit_log TO app_admin;
    GRANT SELECT ON public.audit_log TO app_analyst;
    GRANT USAGE, SELECT ON SEQUENCE public.audit_log_id_seq TO app_admin;
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_audit_log_immutable ON public.audit_log")
    for table in ("users", "roles", "permissions", "objects"):
        op.execute(f"DROP TRIGGER IF EXISTS trg_audit_{table} ON public.{table}")
    op.execute("DROP FUNCTION IF EXISTS public.prevent_audit_mutation()")
    op.execute("DROP FUNCTION IF EXISTS public.log_action()")
    op.execute("DROP TABLE IF EXISTS public.audit_log CASCADE")
