"""Интеграционная проверка канала suspicious_activity."""

from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

sys.path.insert(0, str(Path(__file__).parents[1]))

from src.db.models import SuspiciousActivity
from src.db.session import SessionLocal
from src.generator.attacks import (
    run_brute_force,
    run_mass_read,
    run_new_ip_login,
    run_privilege_escalation,
    run_sql_injection,
    run_suspicious_delete,
)
from src.generator.config import LOG_DIR
from src.generator.logging_utils import create_bot_logger
from src.generator.user_pool import ensure_virtual_users


def main() -> None:
    """Запускает атаки и проверяет шесть типов записей и неизменяемость."""

    attacker_id = ensure_virtual_users(include_attacker=True)["attack_user"]
    logger = create_bot_logger("sentineldb.suspicious_test", LOG_DIR / "suspicious_test.log")
    source_ip = "203.0.113.42"
    run_brute_force(logger, source_ip)
    run_sql_injection(logger, attacker_id, source_ip)
    run_mass_read(logger, attacker_id, source_ip)
    run_privilege_escalation(logger, attacker_id, source_ip)
    run_suspicious_delete(logger, attacker_id, source_ip)
    run_new_ip_login(logger, attacker_id, source_ip)

    with SessionLocal() as session:
        types = set(session.scalars(select(SuspiciousActivity.attack_type).where(SuspiciousActivity.source_ip == source_ip)))
        expected = {"brute_force", "sql_injection", "mass_read", "privilege_escalation", "suspicious_delete", "new_ip_login"}
        if not expected.issubset(types):
            raise AssertionError(f"Не все типы записаны в suspicious_activity: {expected - types}")
        first_id = session.scalar(select(SuspiciousActivity.id).where(SuspiciousActivity.source_ip == source_ip).order_by(SuspiciousActivity.id).limit(1))
        try:
            session.execute(text("UPDATE public.suspicious_activity SET severity = 'critical' WHERE id = :id"), {"id": first_id})
            session.commit()
        except DBAPIError:
            session.rollback()
        else:
            raise AssertionError("UPDATE suspicious_activity неожиданно разрешен")
        try:
            session.execute(text("DELETE FROM public.suspicious_activity WHERE id = :id"), {"id": first_id})
            session.commit()
        except DBAPIError:
            session.rollback()
        else:
            raise AssertionError("DELETE suspicious_activity неожиданно разрешен")

    print("suspicious_activity: все типы атак записаны, UPDATE/DELETE запрещены")


if __name__ == "__main__":
    main()
