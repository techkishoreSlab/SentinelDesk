"""Async SQLAlchemy engine and session management."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings


class Database:
    def __init__(self, settings: Settings) -> None:
        self.engine: AsyncEngine = create_async_engine(
            settings.database_url.get_secret_value(),
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_pre_ping=True,
            pool_timeout=5,
            connect_args={"timeout": 5, "command_timeout": 15},
        )
        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False)

    async def ping(self, timeout_seconds: float = 2.0) -> bool:
        try:
            async with asyncio.timeout(timeout_seconds), self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        except Exception:  # noqa: BLE001 - readiness reports any failure as not ready
            return False
        return True

    async def dispose(self) -> None:
        await self.engine.dispose()


def get_database(request: Request) -> Database:
    db: Database = request.app.state.db
    return db


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    async with get_database(request).sessionmaker() as session:
        yield session
