from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.database.models import Base


class Database:
    """Async engine + session factory wrapper."""

    def __init__(self, url: str, echo: bool = False) -> None:
        self.url = url
        self._engine: AsyncEngine | None = None
        self._factory: async_sessionmaker[AsyncSession] | None = None
        self._echo = echo

    def _ensure_sqlite_path(self) -> None:
        prefix = "sqlite+aiosqlite:///"
        if self.url.startswith(prefix):
            raw_path = self.url[len(prefix) :].split("?")[0]
            if raw_path and raw_path != ":memory:":
                Path(raw_path).parent.mkdir(parents=True, exist_ok=True)

    async def connect(self) -> None:
        if self._engine is not None:
            return
        self._ensure_sqlite_path()
        self._engine = create_async_engine(self.url, echo=self._echo, pool_pre_ping=True)
        self._factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def disconnect(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._factory = None

    @property
    def factory(self) -> async_sessionmaker[AsyncSession]:
        if self._factory is None:
            raise RuntimeError("database is not connected; call connect() first")
        return self._factory

    async def create_all(self) -> None:
        async with self._engine.begin() as conn:  # type: ignore[union-attr]
            await conn.run_sync(Base.metadata.create_all)

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
