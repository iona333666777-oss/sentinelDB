"""Аудит изменений и защита журнала от изменения."""

from alembic import op

revision = "0002_audit"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Функция получает идентификатор пользователя из параметра текущей сессии приложения.
    op.execute("""
    CREATE OR REPLACE FUNCTION public.log_action()
    RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public
    AS $$
    DECLARE
        changed_row jsonb;
        record_key integer;
        actor_id integer;
    BEGIN
        actor_id := NULLIF(current_setting('app.user_id', true), '')::integer;
        IF TG_OP = 'DELETE' THEN
            changed_row := to_jsonb(OLD);
            record_key := OLD.id;
        ELSE
            changed_row := to_jsonb(NEW);
            record_key := NEW.id;
        END IF;
        -- Хеш пароля никогда не должен попадать в журнал аудита.
        IF TG_TABLE_NAME = 'users' THEN
            changed_row := changed_row - 'password_hash';
        END IF;

        INSERT INTO public.audit_log (user_id, action, table_name, record_id, details)
        VALUES (actor_id, TG_OP, TG_TABLE_NAME, record_key, changed_row);
        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    END;
    $$;
    """)
    # Отдельная функция запрещает UPDATE/DELETE даже если вызывающий имеет обычные права таблицы.
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
    """)
    for table in ("users", "roles", "permissions", "objects"):
        op.execute(f"""
        DROP TRIGGER IF EXISTS trg_audit_{table} ON public.{table};
        CREATE TRIGGER trg_audit_{table}
        AFTER INSERT OR UPDATE OR DELETE ON public.{table}
        FOR EACH ROW EXECUTE FUNCTION public.log_action();
        """)
    op.execute("""
    DROP TRIGGER IF EXISTS trg_audit_log_immutable ON public.audit_log;
    CREATE TRIGGER trg_audit_log_immutable
    BEFORE UPDATE OR DELETE ON public.audit_log
    FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_mutation();
    REVOKE UPDATE, DELETE ON public.audit_log FROM PUBLIC;
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_audit_log_immutable ON public.audit_log")
    for table in ("users", "roles", "permissions", "objects"):
        op.execute(f"DROP TRIGGER IF EXISTS trg_audit_{table} ON public.{table}")
    op.execute("DROP FUNCTION IF EXISTS public.prevent_audit_mutation()")
    op.execute("DROP FUNCTION IF EXISTS public.log_action()")
