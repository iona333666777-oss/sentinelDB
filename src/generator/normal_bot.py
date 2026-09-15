"""Генератор обычной пользовательской активности."""

from __future__ import annotations

import random
import threading
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError

from src.db.models import ProtectedObject, User
from src.db.rls import set_database_role
from src.db.session import SessionLocal, set_current_user
from src.generator.config import LOG_DIR, NORMAL_ACTION_WEIGHTS, NORMAL_INTERVAL_MAX, NORMAL_INTERVAL_MIN, NORMAL_USERNAMES
from src.generator.logging_utils import create_bot_logger, write_event
from src.generator.user_pool import ensure_virtual_users


class NormalBot:
    """Выполняет случайные действия пяти виртуальных пользователей."""

    def __init__(self) -> None:
        self.logger = create_bot_logger("sentineldb.normal_bot", LOG_DIR / "normal_bot.log")
        all_users = ensure_virtual_users()
        self.users = {username: all_users[username] for username in NORMAL_USERNAMES}
        self.stop_event = threading.Event()
        self.cycle = 0

    def stop(self) -> None:
        """Запрашивает корректное завершение цикла."""

        self.stop_event.set()

    def _database_action(self, username: str, action: str) -> None:
        """Выполняет одно действие в короткой автоматически закрываемой сессии."""

        user_id = self.users[username]
        try:
            with SessionLocal.begin() as session:
                set_database_role(session, "app_user")
                set_current_user(session, user_id)
                if action == "login":
                    session.scalar(select(User.id).where(User.username == username))
                    session.execute(update(User).where(User.id == user_id).values(last_login_at=datetime.now(timezone.utc)))
                    details = "SELECT users и обновление last_login_at"
                elif action == "read":
                    rows = list(session.scalars(select(ProtectedObject).where(ProtectedObject.owner_id == user_id)))
                    details = f"objects={len(rows)}"
                elif action == "create":
                    item = ProtectedObject(owner_id=user_id, title=f"Документ {self.cycle}", classification="internal")
                    item.set_content(f"Обычные данные пользователя {username}, цикл {self.cycle}")
                    session.add(item)
                    details = "создан новый объект"
                elif action == "update":
                    object_id = session.scalar(
                        select(ProtectedObject.id).where(ProtectedObject.owner_id == user_id).order_by(ProtectedObject.id).limit(1)
                    )
                    if object_id is None:
                        details = "нет объекта для обновления"
                    else:
                        session.execute(update(ProtectedObject).where(ProtectedObject.id == object_id).values(title=f"Обновлено в цикле {self.cycle}"))
                        details = f"object_id={object_id}"
                else:
                    details = "локальная сессия завершена"
            write_event(self.logger, username, action.upper(), "OK", details)
        except SQLAlchemyError as error:
            # Ошибка прав или RLS записывается, после чего следующий цикл продолжает работу.
            write_event(self.logger, username, action.upper(), "ERROR", f"db_error={type(error).__name__}")

    def run_once(self) -> None:
        """Выполняет один цикл; каждый третий цикл создает объект."""

        self.cycle += 1
        username = random.choice(tuple(self.users))
        if self.cycle % 3 == 0:
            action = "create"
        else:
            actions, weights = zip(*NORMAL_ACTION_WEIGHTS.items())
            action = random.choices(actions, weights=weights, k=1)[0]
        self._database_action(username, action)

    def run(self) -> None:
        """Работает до Ctrl+C со случайными интервалами, похожими на действия человека."""

        write_event(self.logger, "normal_bot", "START", "OK", "генератор запущен")
        try:
            while not self.stop_event.is_set():
                self.run_once()
                # Случайный интервал не дает нормальному трафику выглядеть как точное расписание робота.
                self.stop_event.wait(random.uniform(NORMAL_INTERVAL_MIN, NORMAL_INTERVAL_MAX))
        except KeyboardInterrupt:
            self.stop()
        finally:
            write_event(self.logger, "normal_bot", "STOP", "OK", "генератор остановлен")
