"""Запись событий генератора в отдельный канал suspicious_activity."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from src.db.models import SuspiciousActivity
from src.db.rls import set_database_role
from src.db.session import SessionLocal

_ATTACK_TYPES = {
    "brute_force",
    "sql_injection",
    "mass_read",
    "new_ip_login",
    "privilege_escalation",
    "suspicious_delete",
}
_SEVERITIES = {"low", "medium", "high", "critical"}


def log_suspicious(
    session: Session,
    source_ip: str,
    app_user: str | None,
    attack_type: str,
    query_text: str | None = None,
    target_table: str | None = None,
    details: Mapping[str, Any] | None = None,
    severity: str = "medium",
) -> SuspiciousActivity:
    """Добавляет событие; app_user получает INSERT, но не SELECT этой таблицы."""

    if attack_type not in _ATTACK_TYPES:
        raise ValueError(f"Неизвестный тип атаки: {attack_type}")
    if severity not in _SEVERITIES:
        raise ValueError(f"Недопустимая критичность: {severity}")
    entry = SuspiciousActivity(
        source_ip=source_ip,
        app_user=app_user,
        attack_type=attack_type,
        query_text=query_text,
        target_table=target_table,
        details=dict(details) if details is not None else None,
        severity=severity,
    )
    # Core INSERT таблицы без RETURNING позволяет app_user иметь INSERT, но не SELECT на таблицу.
    session.execute(
        SuspiciousActivity.__table__.insert().inline().values(
            source_ip=entry.source_ip,
            app_user=entry.app_user,
            attack_type=entry.attack_type,
            query_text=entry.query_text,
            target_table=entry.target_table,
            details=entry.details,
            severity=entry.severity,
        )
    )
    return entry


def record_suspicious(
    source_ip: str,
    app_user: str | None,
    attack_type: str,
    *,
    query_text: str | None = None,
    target_table: str | None = None,
    details: Mapping[str, Any] | None = None,
    severity: str = "medium",
) -> bool:
    """Записывает событие отдельной транзакцией под app_user и не ломает цикл бота."""

    try:
        with SessionLocal.begin() as session:
            set_database_role(session, "app_user")
            log_suspicious(session, source_ip, app_user, attack_type, query_text, target_table, details, severity)
        return True
    except SQLAlchemyError:
        return False
