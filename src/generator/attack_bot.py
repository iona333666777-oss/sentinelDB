"""Генератор учебного атакующего трафика."""

from __future__ import annotations

import random
import threading

from src.generator.attacks import (
    run_brute_force,
    run_mass_read,
    run_privilege_escalation,
    run_sql_injection,
    run_suspicious_delete,
    run_new_ip_login,
)
from src.generator.config import ATTACK_INTERVAL_MAX, ATTACK_INTERVAL_MIN, ATTACK_USERNAME, ATTACK_WEIGHTS, LOG_DIR
from src.generator.logging_utils import create_bot_logger, write_event
from src.generator.user_pool import ensure_virtual_users


class AttackBot:
    """Выполняет взвешенный набор атак исключительно под ролью app_user."""

    def __init__(self) -> None:
        self.logger = create_bot_logger("sentineldb.attack_bot", LOG_DIR / "attack_bot.log")
        self.attacker_id = ensure_virtual_users(include_attacker=True)[ATTACK_USERNAME]
        # RFC 5737 203.0.113.0/24 предназначен для документации и безопасен как виртуальный IP.
        self.virtual_ip = f"203.0.113.{random.randint(1, 254)}"
        self.stop_event = threading.Event()

    def stop(self) -> None:
        """Запрашивает корректное завершение цикла."""

        self.stop_event.set()

    def _new_ip_login(self) -> None:
        """Имитирует вход с нового виртуального IP и пишет его в suspicious_activity."""

        self.virtual_ip = f"203.0.113.{random.randint(1, 254)}"
        run_new_ip_login(self.logger, self.attacker_id, self.virtual_ip)

    def run_once(self) -> None:
        """Выбирает и выполняет одну атаку согласно заданным весам."""

        names, weights = zip(*ATTACK_WEIGHTS.items())
        attack = random.choices(names, weights=weights, k=1)[0]
        # app_user используется намеренно: результат отражает реальные ограничения RLS и GRANT.
        if attack == "brute_force":
            run_brute_force(self.logger, self.virtual_ip)
        elif attack == "sql_injection":
            run_sql_injection(self.logger, self.attacker_id, self.virtual_ip)
        elif attack == "privilege_escalation":
            run_privilege_escalation(self.logger, self.attacker_id, self.virtual_ip)
        elif attack == "mass_read":
            run_mass_read(self.logger, self.attacker_id, self.virtual_ip)
        elif attack == "suspicious_delete":
            run_suspicious_delete(self.logger, self.attacker_id, self.virtual_ip)
        else:
            self._new_ip_login()

    def run(self) -> None:
        """Работает до Ctrl+C, продолжая цикл после отклоненных атак."""

        write_event(self.logger, ATTACK_USERNAME, "START", "OK", f"virtual_ip={self.virtual_ip}")
        try:
            while not self.stop_event.is_set():
                self.run_once()
                self.stop_event.wait(random.uniform(ATTACK_INTERVAL_MIN, ATTACK_INTERVAL_MAX))
        except KeyboardInterrupt:
            self.stop()
        finally:
            write_event(self.logger, ATTACK_USERNAME, "STOP", "OK", "генератор остановлен")
