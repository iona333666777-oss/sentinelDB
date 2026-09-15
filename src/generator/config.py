"""Конфигурация генераторов из переменных окружения."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = PROJECT_ROOT / "logs"
NORMAL_USERNAMES = tuple(f"normal_user_{number}" for number in range(1, 6))
ATTACK_USERNAME = "attack_user"


def _positive_int(name: str, default: int) -> int:
    """Читает положительное целое с понятной ошибкой конфигурации."""

    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as error:
        raise RuntimeError(f"{name} должен быть целым числом") from error
    if value < 0:
        raise RuntimeError(f"{name} не должен быть отрицательным")
    return value


NORMAL_INTERVAL_MIN = _positive_int("NORMAL_BOT_INTERVAL_MIN", 3)
NORMAL_INTERVAL_MAX = _positive_int("NORMAL_BOT_INTERVAL_MAX", 7)
ATTACK_INTERVAL_MIN = _positive_int("ATTACK_BOT_INTERVAL_MIN", 10)
ATTACK_INTERVAL_MAX = _positive_int("ATTACK_BOT_INTERVAL_MAX", 20)

if NORMAL_INTERVAL_MIN > NORMAL_INTERVAL_MAX:
    raise RuntimeError("NORMAL_BOT_INTERVAL_MIN не должен превышать NORMAL_BOT_INTERVAL_MAX")
if ATTACK_INTERVAL_MIN > ATTACK_INTERVAL_MAX:
    raise RuntimeError("ATTACK_BOT_INTERVAL_MIN не должен превышать ATTACK_BOT_INTERVAL_MAX")

NORMAL_ACTION_WEIGHTS = {
    "login": 20,
    "read": 40,
    "update": 25,
    "logout": 15,
}
ATTACK_WEIGHTS = {
    "brute_force": 30,
    "sql_injection": 20,
    "privilege_escalation": 15,
    "mass_read": 20,
    "suspicious_delete": 10,
    "new_ip_login": 5,
}


def get_virtual_password() -> str:
    """Возвращает пароль виртуальных пользователей только из .env."""

    password = os.getenv("SENTINEL_NORMAL_PASSWORD")
    if not password:
        raise RuntimeError("Переменная SENTINEL_NORMAL_PASSWORD не задана в .env")
    return password
