"""Имитация повышения привилегий от лица app_user."""

import logging

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from src.db.rls import set_database_role
from src.db.session import SessionLocal, set_current_user
from src.generator.logging_utils import write_event
from src.generator.suspicious import record_suspicious


def _attempt(logger: logging.Logger, attacker_id: int, source_ip: str, action: str, statement: str) -> None:
    """Выполняет одну ожидаемо отклоненную операцию в отдельной транзакции."""

    try:
        with SessionLocal.begin() as session:
            set_database_role(session, "app_user")
            set_current_user(session, attacker_id)
            session.execute(text(statement))
        write_event(logger, "attack_user", action, "UNEXPECTED_SUCCESS", "проверьте GRANT")
    except SQLAlchemyError as error:
        write_event(logger, "attack_user", action, "DENIED", f"db_error={type(error).__name__}")
    record_suspicious(source_ip, "attack_bot", "privilege_escalation", query_text=statement, target_table="user_roles" if "user_roles" in statement else "roles", details={"action": action}, severity="critical")


def run_privilege_escalation(logger: logging.Logger, attacker_id: int, source_ip: str) -> None:
    """Проверяет запрет изменения системных таблиц RBAC."""

    _attempt(logger, attacker_id, source_ip, "PRIV_ESC_USER_ROLES", "INSERT INTO public.user_roles (user_id, role_id) VALUES (-1, -1)")
    _attempt(logger, attacker_id, source_ip, "PRIV_ESC_ROLES", "UPDATE public.roles SET name='superadmin' WHERE name='user'")
