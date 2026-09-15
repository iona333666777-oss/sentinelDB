"""Идемпотентное заполнение ролей, разрешений и тестового администратора."""

import os

from sqlalchemy import select

from src.db.models import Permission, Role, User
from src.db.session import SessionLocal
from src.security.passwords import hash_password

PERMISSIONS = {
    "read:objects": "Чтение защищаемых объектов",
    "write:objects": "Создание и изменение защищаемых объектов",
    "delete:objects": "Удаление защищаемых объектов",
    "read:audit": "Чтение журнала аудита",
    "manage:users": "Управление пользователями",
}
ROLE_PERMISSIONS = {
    "readonly": {"read:objects"},
    "user": {"read:objects", "write:objects"},
    "analyst": {"read:objects", "read:audit"},
    "admin": set(PERMISSIONS),
}


def seed() -> None:
    """Создает справочники и admin из переменных окружения."""

    admin_username = os.getenv("SENTINEL_ADMIN_USERNAME", "admin")
    admin_password = os.getenv("SENTINEL_ADMIN_PASSWORD")
    if not admin_password:
        raise RuntimeError("Задайте SENTINEL_ADMIN_PASSWORD в .env; пароль не хранится в коде")
    with SessionLocal.begin() as session:
        permissions = {}
        for name, description in PERMISSIONS.items():
            permission = session.scalar(select(Permission).where(Permission.name == name))
            if permission is None:
                permission = Permission(name=name, description=description)
                session.add(permission)
            permissions[name] = permission
        roles = {}
        for name, permission_names in ROLE_PERMISSIONS.items():
            role = session.scalar(select(Role).where(Role.name == name))
            if role is None:
                role = Role(name=name, description=f"Приложенческая роль {name}")
                session.add(role)
            role.permissions = [permissions[p] for p in permission_names]
            roles[name] = role
        admin = session.scalar(select(User).where(User.username == admin_username))
        if admin is None:
            session.add(User(username=admin_username, password_hash=hash_password(admin_password), roles=[roles["admin"]]))
        elif not any(role.name == "admin" for role in admin.roles):
            admin.roles.append(roles["admin"])
    print(f"Seed завершен. Пользователь {admin_username!r} создан/обновлен.")


if __name__ == "__main__":
    seed()
