"""ORM-модели схемы SentinelDB."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Table, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin


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
    email: Mapped[str | None] = mapped_column(String(320), unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    roles: Mapped[list[Role]] = relationship(secondary=user_roles, back_populates="users")
    objects: Mapped[list[ProtectedObject]] = relationship(back_populates="owner")


class ProtectedObject(Base, TimestampMixin):
    """Условные защищаемые данные, принадлежащие пользователю."""

    __tablename__ = "objects"
    __table_args__ = {"schema": "public"}
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("public.users.id", ondelete="RESTRICT"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    classification: Mapped[str] = mapped_column(String(32), default="internal", server_default="internal", nullable=False)
    owner: Mapped[User] = relationship(back_populates="objects")


class AuditLog(Base):
    """Журнал аудита для будущих триггеров Модуля 2."""

    __tablename__ = "audit_log"
    __table_args__ = {"schema": "public"}
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("public.users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    table_name: Mapped[str | None] = mapped_column(String(128))
    record_id: Mapped[int | None] = mapped_column()
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"), nullable=False)
