"""Единая настройка файловых журналов генераторов."""

import logging
from pathlib import Path


def create_bot_logger(name: str, path: Path) -> logging.Logger:
    """Создает файловый logger без дублирования обработчиков."""

    path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(handler)
    return logger


def write_event(logger: logging.Logger, user: str, action: str, result: str, details: str) -> None:
    """Записывает событие в установленном формате."""

    logger.info("[%s] [%s] [%s] %s", user, action, result, details)
