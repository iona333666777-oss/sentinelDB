# SentinelDB, модуль 1

Схема использует SQLAlchemy 2.x и Alembic. Приложенческие роли (`admin`, `analyst`, `user`, `readonly`) хранятся в таблицах и независимы от ролей PostgreSQL (`app_admin`, `app_analyst`, `app_user`, `app_readonly`). Такое разделение позволяет менять права приложения без выдачи серверных привилегий. Связи M:N выбраны вместо `ENUM`-поля: пользователь может иметь несколько ролей, а разрешение можно переиспользовать в разных ролях.

Пароли приложения хешируются Argon2id: это memory-hard алгоритм, лучше сопротивляющийся перебору на GPU, чем bcrypt. В коде нет plaintext-паролей или DSN: они задаются в `.env`.

## Запуск в Windows PowerShell

```powershell
cd path\to\sentineldb
..\.venv\Scripts\Activate.ps1
pip install "sqlalchemy>=2.0" alembic python-dotenv argon2-cffi "psycopg[binary]"
Copy-Item .env.example .env
# Отредактируйте .env и задайте DATABASE_URL и SENTINEL_ADMIN_PASSWORD.
alembic upgrade head
python -m src.db.roles_setup
python -m src.db.seed
psql -U postgres -h 127.0.0.1 -d sentineldb -c "\du"
python tests\test_rbac.py
```

Если миграция уже была применена до исправления M:N-моделей, пересоздайте ее в рабочем окружении:

```powershell
alembic downgrade base
alembic revision --autogenerate -m "fix m2m tables"
alembic upgrade head
```

После автогенерации проверьте ревизию вручную: в ней должны быть `public.role_permissions` и `public.user_roles` с внешними ключами на соответствующие таблицы.

`roles_setup.py` генерирует случайные пароли ролей PostgreSQL и печатает каждый пароль один раз. Пароли не записываются в файлы; при повторном запуске они будут заменены, поэтому сохраните вывод сразу.

## Ручные проверки

- `alembic upgrade head` создает все таблицы в `public` и таблицу `alembic_version`.
- `python -m src.db.seed` повторно запускается без дубликатов и создает admin с Argon2-хешем.
- `python -m src.db.roles_setup` создает/обновляет четыре серверные роли и выдает GRANT.
- `psql ... -c "\du"` показывает роли `app_admin`, `app_analyst`, `app_user`, `app_readonly`.
- `python tests\test_rbac.py` создает пользователя с ролью `user` и выводит `read:objects, write:objects`.

RLS, шифрование полей и триггеры аудита намеренно не включены: это последующие модули проекта.
