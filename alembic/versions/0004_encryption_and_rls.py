"""Шифрование чувствительных полей и RLS для объектов."""

from alembic import op

revision = "0004_encryption_and_rls"
down_revision = "0003_fix_audit_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # pgp_sym_encrypt хранит формат OpenPGP с солью и контролем целостности, что безопаснее raw AES.
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute("""
    CREATE OR REPLACE FUNCTION public.encrypt_text(plaintext TEXT, key TEXT)
    RETURNS BYTEA
    LANGUAGE plpgsql
    STRICT
    AS $$
    BEGIN
        RETURN pgp_sym_encrypt(plaintext, key, 'cipher-algo=aes256');
    END;
    $$;
    """)
    op.execute("""
    CREATE OR REPLACE FUNCTION public.decrypt_text(ciphertext BYTEA, key TEXT)
    RETURNS TEXT
    LANGUAGE plpgsql
    STRICT
    AS $$
    BEGIN
        RETURN pgp_sym_decrypt(ciphertext, key);
    END;
    $$;
    """)

    # На этапе разработки данных мало: старые plaintext-колонки удаляются без переноса содержимого.
    op.execute("ALTER TABLE public.users DROP CONSTRAINT IF EXISTS uq_users_email")
    op.execute("ALTER TABLE public.users DROP COLUMN IF EXISTS email")
    op.execute("ALTER TABLE public.users ADD COLUMN IF NOT EXISTS email_enc BYTEA")
    op.execute("ALTER TABLE public.objects DROP COLUMN IF EXISTS content")
    op.execute("ALTER TABLE public.objects ADD COLUMN IF NOT EXISTS content_enc BYTEA")

    # RLS применяется в БД, поэтому ограничение действует для любого клиента, а не только Python-кода.
    op.execute("ALTER TABLE public.objects ENABLE ROW LEVEL SECURITY")
    # FORCE не позволяет владельцу таблицы случайно обходить политики в обычной работе.
    op.execute("ALTER TABLE public.objects FORCE ROW LEVEL SECURITY")
    for policy in (
        "objects_admin_all",
        "objects_analyst_read",
        "objects_user_own",
        "objects_readonly_read",
    ):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON public.objects")
    op.execute("""
    CREATE POLICY objects_admin_all ON public.objects
    FOR ALL TO app_admin USING (true) WITH CHECK (true)
    """)
    op.execute("""
    CREATE POLICY objects_analyst_read ON public.objects
    FOR SELECT TO app_analyst USING (true)
    """)
    op.execute("""
    CREATE POLICY objects_user_own ON public.objects
    FOR ALL TO app_user
    USING (owner_id = NULLIF(current_setting('app.current_user_id', true), '')::integer)
    WITH CHECK (owner_id = NULLIF(current_setting('app.current_user_id', true), '')::integer)
    """)
    op.execute("""
    CREATE POLICY objects_readonly_read ON public.objects
    FOR SELECT TO app_readonly USING (true)
    """)

    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON public.objects TO app_user")
    op.execute("GRANT SELECT ON public.objects TO app_analyst, app_readonly")
    op.execute("GRANT ALL PRIVILEGES ON public.objects TO app_admin")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE public.objects_id_seq TO app_user, app_admin")
    op.execute("GRANT EXECUTE ON FUNCTION public.encrypt_text(TEXT, TEXT) TO app_admin, app_user")
    op.execute("GRANT EXECUTE ON FUNCTION public.decrypt_text(BYTEA, TEXT) TO app_admin, app_user, app_analyst, app_readonly")


def downgrade() -> None:
    for policy in (
        "objects_admin_all",
        "objects_analyst_read",
        "objects_user_own",
        "objects_readonly_read",
    ):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON public.objects")
    op.execute("ALTER TABLE public.objects NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE public.objects DISABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE public.objects DROP COLUMN IF EXISTS content_enc")
    op.execute("ALTER TABLE public.objects ADD COLUMN IF NOT EXISTS content TEXT")
    op.execute("ALTER TABLE public.users DROP COLUMN IF EXISTS email_enc")
    op.execute("ALTER TABLE public.users ADD COLUMN IF NOT EXISTS email VARCHAR(320)")
    op.execute("ALTER TABLE public.users ADD CONSTRAINT uq_users_email UNIQUE (email)")
    op.execute("DROP FUNCTION IF EXISTS public.decrypt_text(BYTEA, TEXT)")
    op.execute("DROP FUNCTION IF EXISTS public.encrypt_text(TEXT, TEXT)")
    # Расширение не удаляется: оно может использоваться другими объектами базы.
