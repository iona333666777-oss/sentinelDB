"""Вспомогательные операции для работы с политиками RLS."""

from __future__ import annotations

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import ProtectedObject
from .session import set_current_user

_DATABASE_ROLES = frozenset({"app_admin", "app_analyst", "app_user", "app_readonly"})


def set_database_role(session: Session, role_name: str) -> None:
    """Переключает PostgreSQL-роль только на время текущей транзакции."""

    if role_name not in _DATABASE_ROLES:
        raise ValueError("Недопустимая роль PostgreSQL")
    # Идентификаторы нельзя передать bind-параметром, поэтому используется строгий whitelist.
    session.execute(text(f'SET LOCAL ROLE "{role_name}"'))


def get_visible_objects(session: Session, user_id: int, role_name: str = "app_user") -> list[ProtectedObject]:
    """Возвращает объекты, доступные роли и пользователю по политикам RLS."""

    set_database_role(session, role_name)
    set_current_user(session, user_id)
    return list(session.scalars(select(ProtectedObject).order_by(ProtectedObject.id)))
