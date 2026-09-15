"""Минимальный ручной сценарий проверки назначения разрешений."""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from sqlalchemy import select

from src.db.models import Permission, Role, User
from src.db.session import SessionLocal
from src.security.passwords import hash_password


def main() -> None:
    """Создает пользователя user, назначает роль и печатает его разрешения."""

    username = f"rbac_check_{secrets.token_hex(4)}"
    with SessionLocal.begin() as session:
        role = session.scalar(select(Role).where(Role.name == "user"))
        if role is None:
            raise RuntimeError("Роль user отсутствует: сначала запустите python -m src.db.seed")
        user = User(username=username, password_hash=hash_password(secrets.token_urlsafe(24)), roles=[role])
        session.add(user)
        session.flush()
        permission_names = sorted(permission.name for assigned_role in user.roles for permission in assigned_role.permissions)
        print(f"Пользователь: {user.username}")
        print("Разрешения: " + ", ".join(permission_names))


if __name__ == "__main__":
    main()
