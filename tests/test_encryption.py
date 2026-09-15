"""Интеграционная проверка шифрования email через pgcrypto."""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).parents[1]))

from src.db.models import User
from src.db.session import SessionLocal
from src.security.passwords import hash_password


def main() -> None:
    """Проверяет бинарное хранение и обратимую расшифровку email."""

    suffix = secrets.token_hex(6)
    source_email = f"encryption-{suffix}@example.test"
    user = User(username=f"encryption_{suffix}", password_hash=hash_password(secrets.token_urlsafe(24)))
    user.set_email(source_email)

    with SessionLocal.begin() as session:
        session.add(user)
        session.flush()
        user_id = user.id
        stored_value = session.scalar(select(User.email_enc).where(User.id == user_id))
        if not isinstance(stored_value, bytes):
            raise AssertionError("email_enc должен возвращаться из PostgreSQL как bytes")
        if source_email.encode() in stored_value:
            raise AssertionError("email_enc содержит исходный email в открытом виде")

    with SessionLocal.begin() as session:
        stored_user = session.get(User, user_id)
        if stored_user is None or stored_user.email != source_email:
            raise AssertionError("Расшифрованный email не совпадает с исходным")
        session.delete(stored_user)

    print("Шифрование email: BYTEA не содержит plaintext, расшифровка корректна")


if __name__ == "__main__":
    main()
