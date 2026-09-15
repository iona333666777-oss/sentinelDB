"""Интеграционная проверка политик Row-Level Security."""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

from sqlalchemy import delete, select, update

sys.path.insert(0, str(Path(__file__).parents[1]))

from src.db.models import ProtectedObject, User
from src.db.rls import get_visible_objects, set_database_role
from src.db.session import SessionLocal, set_current_user
from src.security.passwords import hash_password


def _new_user(suffix: str) -> User:
    """Создает пользователя с безопасным случайным тестовым паролем."""

    return User(username=f"rls_{suffix}", password_hash=hash_password(secrets.token_urlsafe(24)))


def main() -> None:
    """Проверяет видимость владельца, администратора и запрет чужого UPDATE."""

    first_user = _new_user(secrets.token_hex(5))
    second_user = _new_user(secrets.token_hex(5))
    with SessionLocal.begin() as session:
        session.add_all((first_user, second_user))
        session.flush()
        first_object = ProtectedObject(owner_id=first_user.id, title="Объект первого", classification="internal")
        first_object.set_content("Секрет первого пользователя")
        second_object = ProtectedObject(owner_id=second_user.id, title="Объект второго", classification="internal")
        second_object.set_content("Секрет второго пользователя")
        session.add_all((first_object, second_object))
        session.flush()
        first_user_id, second_user_id = first_user.id, second_user.id
        first_object_id, second_object_id = first_object.id, second_object.id

    with SessionLocal.begin() as session:
        visible = get_visible_objects(session, first_user_id, "app_user")
        if [item.id for item in visible] != [first_object_id]:
            raise AssertionError("app_user видит чужие объекты или не видит свой объект")

    with SessionLocal.begin() as session:
        set_database_role(session, "app_admin")
        visible_ids = set(session.scalars(select(ProtectedObject.id)))
        if not {first_object_id, second_object_id}.issubset(visible_ids):
            raise AssertionError("app_admin не видит оба тестовых объекта")

    with SessionLocal.begin() as session:
        set_database_role(session, "app_user")
        set_current_user(session, first_user_id)
        result = session.execute(
            update(ProtectedObject).where(ProtectedObject.id == second_object_id).values(title="Чужое изменение")
        )
        if result.rowcount != 0:
            raise AssertionError("app_user смог изменить чужой объект")

    # SET LOCAL ROLE сбрасывается с транзакцией, поэтому очистка идет от исходного владельца подключения.
    with SessionLocal.begin() as session:
        session.execute(delete(ProtectedObject).where(ProtectedObject.id.in_((first_object_id, second_object_id))))
        session.execute(delete(User).where(User.id.in_((first_user_id, second_user_id))))

    print("RLS: app_user видит свой объект, app_admin видит оба, чужой UPDATE затронул 0 строк")


if __name__ == "__main__":
    main()
