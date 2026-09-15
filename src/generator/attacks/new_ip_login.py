"""Имитация входа с нового виртуального IP."""

import logging

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from src.db.models import User
from src.db.rls import set_database_role
from src.db.session import SessionLocal
from src.generator.logging_utils import write_event
from src.generator.suspicious import record_suspicious


def run_new_ip_login(logger: logging.Logger, attacker_id: int, source_ip: str) -> None:
    """Выполняет SELECT users и записывает логическую IP-метку атаки."""

    query_text = "SELECT id FROM public.users WHERE username = 'attack_user'"
    try:
        with SessionLocal.begin() as session:
            set_database_role(session, "app_user")
            session.scalar(select(User.id).where(User.id == attacker_id))
        result = "OK"
    except SQLAlchemyError as error:
        result = "DENIED"
        write_event(logger, "attack_user", "NEW_IP_LOGIN", result, f"virtual_ip={source_ip} db_error={type(error).__name__}")
    else:
        write_event(logger, "attack_user", "NEW_IP_LOGIN", result, f"virtual_ip={source_ip}")
    record_suspicious(source_ip, "attack_bot", "new_ip_login", query_text=query_text, target_table="users", details={"virtual_ip": source_ip}, severity="low")
