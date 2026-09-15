"""Имитация массовой выгрузки объектов."""

import logging
import random
import time

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from src.db.rls import set_database_role
from src.db.session import SessionLocal, set_current_user
from src.generator.logging_utils import write_event
from src.generator.suspicious import record_suspicious


def run_mass_read(logger: logging.Logger, attacker_id: int, source_ip: str) -> None:
    """Выполняет 50-200 быстрых SELECT в одной транзакции."""

    count = random.randint(50, 200)
    total_rows = 0
    started = time.monotonic()
    try:
        with SessionLocal.begin() as session:
            set_database_role(session, "app_user")
            set_current_user(session, attacker_id)
            for _ in range(count):
                total_rows += len(session.execute(text("SELECT * FROM public.objects")).all())
        write_event(logger, "attack_user", "MASS_READ", "EXECUTED", f"queries={count} rows={total_rows}")
    except SQLAlchemyError as error:
        write_event(logger, "attack_user", "MASS_READ", "ERROR", f"queries={count} db_error={type(error).__name__}")
    record_suspicious(source_ip, "attack_bot", "mass_read", query_text="SELECT * FROM public.objects", target_table="objects", details={"count": count, "duration_s": round(time.monotonic() - started, 3)}, severity="medium")
