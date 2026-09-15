"""Шифрование полей средствами pgcrypto через SQLAlchemy."""

from __future__ import annotations

import os

from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError


def get_key() -> str:
    """Читает и проверяет 32-байтовый hex-ключ из окружения."""

    load_dotenv()
    key = os.getenv("SENTINEL_DB_KEY")
    if not key:
        raise RuntimeError("Переменная SENTINEL_DB_KEY не задана в .env")
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError as error:
        raise RuntimeError("SENTINEL_DB_KEY должен быть корректной hex-строкой") from error
    if len(key_bytes) != 32:
        raise RuntimeError("SENTINEL_DB_KEY должен содержать ровно 32 байта (64 hex-символа)")
    return key


def encrypt_field(plaintext: str) -> bytes:
    """Шифрует строку через pgp_sym_encrypt, не сохраняя ключ в коде."""

    if not isinstance(plaintext, str):
        raise TypeError("Шифруемое значение должно быть строкой")
    from src.db.session import engine

    try:
        with engine.connect() as connection:
            encrypted = connection.scalar(
                text("SELECT public.encrypt_text(:plaintext, :key)"),
                {"plaintext": plaintext, "key": get_key()},
            )
    except SQLAlchemyError as error:
        raise RuntimeError("Не удалось зашифровать поле средствами PostgreSQL") from error
    return bytes(encrypted)


def decrypt_field(ciphertext: bytes) -> str:
    """Расшифровывает BYTEA через pgp_sym_decrypt с ключом из окружения."""

    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise TypeError("Шифротекст должен иметь бинарный тип")
    from src.db.session import engine

    try:
        with engine.connect() as connection:
            value = connection.scalar(
                text("SELECT public.decrypt_text(:ciphertext, :key)"),
                {"ciphertext": bytes(ciphertext), "key": get_key()},
            )
    except SQLAlchemyError as error:
        raise RuntimeError("Не удалось расшифровать поле средствами PostgreSQL") from error
    return str(value)
