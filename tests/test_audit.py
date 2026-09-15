"""Интеграционные проверки триггерного аудита и append-only журнала."""

from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

sys.path.insert(0, str(Path(__file__).parents[1]))

from src.db.audit import get_events_by_table, get_recent_events, get_suspicious_events
from src.db.models import AuditLog, Permission
from src.db.session import SessionLocal


def main() -> None:
    """Проверяет INSERT в справочник, запись аудита и запрет UPDATE/DELETE."""

    with SessionLocal.begin() as session:
        permission = Permission(name="audit_test:temporary", description="Временная запись теста")
        session.add(permission)
        session.flush()
        audit_entry = session.scalar(select(AuditLog).where(AuditLog.table_name == "permissions", AuditLog.record_id == str(permission.id)).order_by(AuditLog.id.desc()))
        if audit_entry is None:
            raise AssertionError("Триггер permissions не создал запись в audit_log")
        if audit_entry.operation != "INSERT" or audit_entry.new_data is None or audit_entry.event_time is None:
            raise AssertionError("Событие аудита не содержит новые обязательные поля")
        if not get_events_by_table(session, "permissions"):
            raise AssertionError("Фильтр по таблице не вернул событие")
        if not get_recent_events(session, 5):
            raise AssertionError("Фильтр последних событий не вернул событие")
        print(f"Триггер записал событие: {audit_entry.operation} {audit_entry.table_name} id={audit_entry.record_id}")
        permission_id = permission.id

    with SessionLocal() as session:
        try:
            session.execute(text("UPDATE public.audit_log SET operation = 'UPDATE' WHERE id = :id"), {"id": audit_entry.id})
            session.commit()
        except DBAPIError:
            session.rollback()
            print("Защита audit_log от UPDATE работает")
        else:
            raise AssertionError("UPDATE audit_log неожиданно разрешен")
        try:
            session.execute(text("DELETE FROM public.audit_log WHERE id = :id"), {"id": audit_entry.id})
            session.commit()
        except DBAPIError:
            session.rollback()
            print("Защита audit_log от DELETE работает")
        else:
            raise AssertionError("DELETE audit_log неожиданно разрешен")
        session.execute(text("DELETE FROM public.permissions WHERE id = :id"), {"id": permission_id})
        session.commit()


if __name__ == "__main__":
    main()
