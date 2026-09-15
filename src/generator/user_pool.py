"""Идемпотентное создание виртуальных пользователей генератора."""

from sqlalchemy import select

from src.db.models import Role, User
from src.db.session import SessionLocal
from src.generator.config import ATTACK_USERNAME, NORMAL_USERNAMES, get_virtual_password
from src.security.passwords import hash_password


def ensure_virtual_users(*, include_attacker: bool = False) -> dict[str, int]:
    """Создает пять normal_user и, при необходимости, отдельного атакующего."""

    password = get_virtual_password()
    usernames = (*NORMAL_USERNAMES, ATTACK_USERNAME) if include_attacker else NORMAL_USERNAMES
    result: dict[str, int] = {}
    with SessionLocal.begin() as session:
        role = session.scalar(select(Role).where(Role.name == "user"))
        if role is None:
            raise RuntimeError("Приложенческая роль user отсутствует; сначала выполните seed")
        for username in usernames:
            user = session.scalar(select(User).where(User.username == username))
            if user is None:
                user = User(username=username, password_hash=hash_password(password), roles=[role])
                session.add(user)
                session.flush()
            elif role not in user.roles:
                user.roles.append(role)
            result[username] = user.id
    return result


if __name__ == "__main__":
    users = ensure_virtual_users()
    print(f"Созданы/проверены виртуальные пользователи: {', '.join(users)}")
