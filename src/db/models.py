"""ORM-модели схемы SentinelDB."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, Column, DateTime, ForeignKey, String, Table, Text, text
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin
from src.security.crypto import decrypt_field, encrypt_field


# M:N-таблицы объявлены как Core Table: relationship(secondary=...) ожидает именно такой объект.
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", ForeignKey("public.roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", ForeignKey("public.permissions.id", ondelete="CASCADE"), primary_key=True),
    schema="public",
)
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", ForeignKey("public.users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", ForeignKey("public.roles.id", ondelete="CASCADE"), primary_key=True),
    schema="public",
)


class Role(Base, TimestampMixin):
    """Роль приложения, независимая от роли PostgreSQL."""

    __tablename__ = "roles"
    __table_args__ = {"schema": "public"}
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    permissions: Mapped[list[Permission]] = relationship(secondary=role_permissions, back_populates="roles")
    users: Mapped[list[User]] = relationship(secondary=user_roles, back_populates="roles")


class Permission(Base, TimestampMixin):
    """Атомарное разрешение приложения, например ``read:objects``."""

    __tablename__ = "permissions"
    __table_args__ = {"schema": "public"}
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    roles: Mapped[list[Role]] = relationship(secondary=role_permissions, back_populates="permissions")


class User(Base, TimestampMixin):
    """Пользователь приложения; пароль хранится только в виде Argon2-хеша."""

    __tablename__ = "users"
    __table_args__ = {"schema": "public"}
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    email_enc: Mapped[bytes | None] = mapped_column(nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    roles: Mapped[list[Role]] = relationship(secondary=user_roles, back_populates="users")
    objects: Mapped[list[ProtectedObject]] = relationship(back_populates="owner")

    @property
    def email(self) -> str | None:
        """Расшифровывает email только при явном обращении к свойству."""

        return decrypt_field(self.email_enc) if self.email_enc is not None else None

    def set_email(self, value: str | None) -> None:
        """Шифрует email до помещения значения в ORM-модель."""

        self.email_enc = encrypt_field(value) if value is not None else None


class ProtectedObject(Base, TimestampMixin):
    """Условные защищаемые данные, принадлежащие пользователю."""

    __tablename__ = "objects"
    __table_args__ = {"schema": "public"}
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("public.users.id", ondelete="RESTRICT"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content_enc: Mapped[bytes | None] = mapped_column(nullable=True)
    classification: Mapped[str] = mapped_column(String(32), default="internal", server_default="internal", nullable=False)
    owner: Mapped[User] = relationship(back_populates="objects")

    @property
    def content(self) -> str | None:
        """Расшифровывает содержимое объекта по запросу приложения."""

        return decrypt_field(self.content_enc) if self.content_enc is not None else None

    def set_content(self, value: str) -> None:
        """Шифрует содержимое перед сохранением объекта."""

        self.content_enc = encrypt_field(value)


class AuditLog(Base):
    """Неизменяемый журнал событий базы данных."""

    __tablename__ = "audit_log"
    __table_args__ = {"schema": "public"}
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"), nullable=False)
    username: Mapped[str] = mapped_column(Text, nullable=False)
    session_user: Mapped[str | None] = mapped_column(Text)
    table_name: Mapped[str] = mapped_column(Text, nullable=False)
    operation: Mapped[str] = mapped_column(Text, nullable=False)
    record_id: Mapped[str | None] = mapped_column(Text)
    old_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    new_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    client_ip: Mapped[str | None] = mapped_column(INET)
    txid: Mapped[int | None] = mapped_column(BigInteger)


class SuspiciousActivity(Base):
    """Канал событий, которые не фиксируются DML-триггерами, например SELECT."""

    __tablename__ = "suspicious_activity"
    __table_args__ = {"schema": "public"}
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"), nullable=False)
    source_ip: Mapped[str] = mapped_column(INET, nullable=False)
    app_user: Mapped[str | None] = mapped_column(Text)
    attack_type: Mapped[str] = mapped_column(Text, nullable=False)
    query_text: Mapped[str | None] = mapped_column(Text)
    target_table: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    severity: Mapped[str] = mapped_column(Text, server_default="medium", nullable=False)
