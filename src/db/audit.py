"""SQLAlchemy API для явной записи действий в журнал аудита."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .models import AuditLog


def log_action(
    session: Session,
    *,
    action: str,
    table_name: str,
    record_id: str | None = None,
    username: str = "application",
    session_user: str | None = None,
    old_data: Mapping[str, Any] | None = None,
    new_data: Mapping[str, Any] | None = None,
    client_ip: str | None = None,
    txid: int | None = None,
) -> AuditLog:
    """Добавляет событие аудита через ORM; commit остается ответственностью вызывающего кода."""

    if not action or len(action) > 64:
        raise ValueError("action должен быть непустым и не длиннее 64 символов")
    entry = AuditLog(
        username=username,
        session_user=session_user,
        operation=action,
        table_name=table_name,
        record_id=record_id,
        old_data=dict(old_data) if old_data is not None else None,
        new_data=dict(new_data) if new_data is not None else None,
        client_ip=client_ip,
        txid=txid,
    )
    session.add(entry)
    session.flush()
    return entry


def get_recent_events(session: Session, limit: int = 100) -> list[AuditLog]:
    """Возвращает последние события, начиная с самых новых."""

    if limit < 1:
        raise ValueError("limit должен быть положительным")
    return list(session.scalars(select(AuditLog).order_by(AuditLog.event_time.desc()).limit(limit)))


def get_events_by_table(session: Session, table_name: str) -> list[AuditLog]:
    """Возвращает события указанной таблицы."""

    return list(session.scalars(select(AuditLog).where(AuditLog.table_name == table_name).order_by(AuditLog.event_time.desc())))


def get_events_by_user(session: Session, username: str) -> list[AuditLog]:
    """Возвращает события указанного PostgreSQL-пользователя."""

    return list(session.scalars(select(AuditLog).where(AuditLog.username == username).order_by(AuditLog.event_time.desc())))


def get_events_by_ip(session: Session, ip: str) -> list[AuditLog]:
    """Возвращает события по IP клиента для последующего анализа IDS."""

    return list(session.scalars(select(AuditLog).where(AuditLog.client_ip == ip).order_by(AuditLog.event_time.desc())))


def get_suspicious_events(session: Session) -> list[AuditLog]:
    """Возвращает удаления и обновления ролей/разрешений."""

    role_tables = ("roles", "permissions", "role_permissions", "user_roles")
    condition = or_(AuditLog.operation == "DELETE", (AuditLog.operation == "UPDATE") & AuditLog.table_name.in_(role_tables))
    return list(session.scalars(select(AuditLog).where(condition).order_by(AuditLog.event_time.desc())))
