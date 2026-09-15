"""Ограниченная учебная симуляция SQL-инъекций."""

import logging
import random

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from src.db.rls import set_database_role
from src.db.session import SessionLocal, set_current_user
from src.generator.logging_utils import write_event
from src.generator.suspicious import record_suspicious

PAYLOADS = ("' OR '1'='1", "admin'--", "'; DROP TABLE users;--")


def run_sql_injection(logger: logging.Logger, attacker_id: int, source_ip: str) -> None:
    """Выполняет только безопасный SELECT, намеренно собранный без параметров."""

    payload = random.choice(PAYLOADS)
    if "DROP TABLE" in payload.upper():
        # Учебная сигнатура фиксируется, но DDL не отправляется: разрушительные команды запрещены ТЗ.
        write_event(logger, "attack_user", "SQL_INJECTION", "BLOCKED", f"payload={payload!r} safety_guard=ddl")
        record_suspicious(source_ip, "attack_bot", "sql_injection", query_text=payload, target_table="objects", details={"payload": payload, "signature": "destructive_ddl_blocked"}, severity="critical")
        return
    # Намеренно небезопасная конкатенация нужна для характерной IDS-сигнатуры; запрос остается SELECT.
    query = text(f"SELECT id, owner_id, title FROM public.objects WHERE title = '{payload}'")
    try:
        with SessionLocal.begin() as session:
            set_database_role(session, "app_user")
            set_current_user(session, attacker_id)
            rows = session.execute(query).all()
        write_event(logger, "attack_user", "SQL_INJECTION", "EXECUTED", f"payload={payload!r} rows={len(rows)}")
    except SQLAlchemyError as error:
        write_event(logger, "attack_user", "SQL_INJECTION", "DENIED", f"payload={payload!r} db_error={type(error).__name__}")
    record_suspicious(source_ip, "attack_bot", "sql_injection", query_text=str(query), target_table="objects", details={"payload": payload, "signature": "tautology_or_comment"}, severity="critical")
