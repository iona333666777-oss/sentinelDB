"""Имитация подозрительных удалений, ограниченных защитой БД."""

import logging

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from src.db.rls import set_database_role
from src.db.session import SessionLocal, set_current_user
from src.generator.logging_utils import write_event
from src.generator.suspicious import record_suspicious


def run_suspicious_delete(logger: logging.Logger, attacker_id: int, source_ip: str) -> None:
    """Пытается удалить чужие объекты и неизменяемый аудит."""

    try:
        with SessionLocal.begin() as session:
            set_database_role(session, "app_user")
            set_current_user(session, attacker_id)
            result = session.execute(text("DELETE FROM public.objects WHERE owner_id != :owner_id"), {"owner_id": attacker_id})
        write_event(logger, "attack_user", "DELETE_FOREIGN_OBJECTS", "FILTERED", f"rows={result.rowcount}")
    except SQLAlchemyError as error:
        write_event(logger, "attack_user", "DELETE_FOREIGN_OBJECTS", "DENIED", f"db_error={type(error).__name__}")
    record_suspicious(source_ip, "attack_bot", "suspicious_delete", query_text="DELETE FROM public.objects WHERE owner_id != :owner_id", target_table="objects", details={"owner_id": attacker_id}, severity="high")

    try:
        with SessionLocal.begin() as session:
            set_database_role(session, "app_user")
            session.execute(text("DELETE FROM public.audit_log WHERE id = 1"))
        write_event(logger, "attack_user", "DELETE_AUDIT", "UNEXPECTED_SUCCESS", "id=1")
    except SQLAlchemyError as error:
        write_event(logger, "attack_user", "DELETE_AUDIT", "DENIED", f"db_error={type(error).__name__}")
    record_suspicious(source_ip, "attack_bot", "suspicious_delete", query_text="DELETE FROM public.audit_log WHERE id = 1", target_table="audit_log", details={"record_id": 1}, severity="high")
