"""Создание SQLAlchemy engine и сессий."""

import os
from collections.abc import Generator

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

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
