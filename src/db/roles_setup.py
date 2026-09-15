"""Создание ролей PostgreSQL и выдача минимально необходимых прав."""

import secrets
import string

from sqlalchemy import text

from src.db.session import engine

PG_ROLES = ("app_admin", "app_analyst", "app_user", "app_readonly")


def _password(length: int = 32) -> str:
    """Генерирует пароль без сохранения в файлах или исходном коде."""

    alphabet = string.ascii_letters + string.digits + "-_+=@"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def setup_roles() -> None:
    """Создает роли и печатает сгенерированные пароли ровно один раз."""

    credentials: dict[str, str] = {}
    with engine.begin() as connection:
        for role_name in PG_ROLES:
            password = _password()
            credentials[role_name] = password
            exists = connection.scalar(text("SELECT 1 FROM pg_roles WHERE rolname = :name"), {"name": role_name})
            if exists:
                connection.execute(text(f'ALTER ROLE "{role_name}" PASSWORD :password'), {"password": password})
            else:
                # Имена берутся только из PG_ROLES (whitelist), а пароль передается bind-параметром.
                connection.execute(text(f'CREATE ROLE "{role_name}" LOGIN PASSWORD :password'), {"password": password})
        connection.execute(text('GRANT USAGE ON SCHEMA public TO "app_admin", "app_analyst", "app_user", "app_readonly"'))
        connection.execute(text('GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "app_admin"'))
        connection.execute(text('GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "app_admin"'))
        connection.execute(text('GRANT SELECT ON ALL TABLES IN SCHEMA public TO "app_analyst"'))
        connection.execute(text('GRANT INSERT ON TABLE public.audit_log TO "app_analyst"'))
        connection.execute(text('GRANT SELECT, INSERT, UPDATE ON TABLE public.objects TO "app_user"'))
        connection.execute(text('GRANT SELECT ON TABLE public.objects TO "app_readonly"'))
    print("Пароли PostgreSQL-ролей. Сохраните их сейчас; повторный запуск генерирует новые пароли.")
    for role_name, password in credentials.items():
        print(f"{role_name}: {password}")


if __name__ == "__main__":
    setup_roles()
