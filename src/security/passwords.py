"""Безопасное хеширование паролей."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Argon2id выбран вместо bcrypt как современный memory-hard алгоритм, устойчивый к GPU-атакам.
_PASSWORD_HASHER = PasswordHasher()


def hash_password(password: str) -> str:
    """Возвращает Argon2-хеш; исходный пароль никуда не сохраняется."""

    if not password:
        raise ValueError("Пароль не должен быть пустым")
    return _PASSWORD_HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Проверяет пароль и возвращает False для неверного или поврежденного хеша."""

    try:
        return _PASSWORD_HASHER.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
