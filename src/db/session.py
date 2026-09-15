"""Создание SQLAlchemy engine и сессий."""

import os
from collections.abc import Generator

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import text

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Переменная DATABASE_URL не задана в .env")

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)


def get_session() -> Generator[Session, None, None]:
    """Возвращает сессию и гарантированно закрывает ее после использования."""

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def set_current_user(session: Session, user_id: int) -> None:
    """Устанавливает идентификатор пользователя для RLS в текущей транзакции."""

    if user_id < 1:
        raise ValueError("user_id должен быть положительным")
    # current_setting(..., true) читается при запросе, поэтому SET LOCAL обязан быть в той же транзакции.
    session.execute(
        text("SELECT set_config('app.current_user_id', :user_id, true)"),
        {"user_id": str(user_id)},
    )
