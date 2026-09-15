"""
Модуль проверки подключения к PostgreSQL.
На данном этапе — просто sanity-check: работает ли связка Python + SQLAlchemy + PostgreSQL.
"""

import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

# Загружаем переменные из .env
load_dotenv()

# Читаем DSN из переменных окружения
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL не задан в .env")

# Создаём движок SQLAlchemy
engine = create_engine(DATABASE_URL, echo=False)

# Открываем соединение и выполняем простой запрос
with engine.connect() as connection:
    result = connection.execute(text("SELECT version();"))
    version = result.scalar()
    print("Подключение успешно!")
    print("Версия PostgreSQL:", version)