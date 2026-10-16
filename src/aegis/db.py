"""PostgreSQL access helpers. The runtime role is subject to RLS; tenant scope is set per transaction."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from psycopg import AsyncConnection
from psycopg.rows import DictRow, dict_row
from psycopg_pool import AsyncConnectionPool

Conn = AsyncConnection[DictRow]


def create_pool(dsn: str, *, min_size: int = 1, max_size: int = 10) -> AsyncConnectionPool[Conn]:
    return AsyncConnectionPool(
        dsn,
        min_size=min_size,
        max_size=max_size,
        open=False,
        timeout=5.0,
        kwargs={"row_factory": dict_row, "autocommit": False, "connect_timeout": 5},
        connection_class=AsyncConnection[DictRow],
    )


@asynccontextmanager
async def transaction(pool: AsyncConnectionPool[Conn]) -> AsyncIterator[Conn]:
    async with pool.connection() as conn, conn.transaction():
        yield conn


@asynccontextmanager
async def tenant_transaction(pool: AsyncConnectionPool[Conn], tenant_id: str) -> AsyncIterator[Conn]:
    """Transaction with ``aegis.tenant_id`` set (transaction-local) so RLS policies apply."""
    if not tenant_id:
        raise ValueError("tenant_id required")
    async with pool.connection() as conn, conn.transaction():
        await conn.execute("SELECT set_config('aegis.tenant_id', %s, true)", (tenant_id,))
        yield conn


async def ping(pool: AsyncConnectionPool[Conn]) -> bool:
    try:
        async with transaction(pool) as conn:
            row: dict[str, Any] | None = await (await conn.execute("SELECT 1 AS ok")).fetchone()
            return bool(row and row["ok"] == 1)
    except Exception:
        return False
