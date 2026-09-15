"""Имитация серии неудачных попыток входа."""

import logging
import random

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from src.db.models import User
from src.db.rls import set_database_role
from src.db.session import SessionLocal
from src.generator.logging_utils import write_event
from src.generator.suspicious import record_suspicious


def run_brute_force(logger: logging.Logger, virtual_ip: str) -> None:
    """Выполняет 5-10 SELECT с разными несуществующими именами."""

    for attempt in range(random.randint(5, 10)):
        username = f"unknown_{random.randint(1000, 9999)}"
        try:
            with SessionLocal.begin() as session:
                set_database_role(session, "app_user")
                session.scalar(select(User.id).where(User.username == username))
            write_event(logger, username, "BRUTE_FORCE", "MISS", f"ip={virtual_ip} attempt={attempt + 1}")
        except SQLAlchemyError as error:
            write_event(logger, username, "BRUTE_FORCE", "DENIED", f"ip={virtual_ip} db_error={type(error).__name__}")
        record_suspicious(virtual_ip, "attack_bot", "brute_force", query_text=f"SELECT id FROM users WHERE username = '{username}'", target_table="users", details={"attempt": attempt + 1}, severity="high")
