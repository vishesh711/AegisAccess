"""Protected resource adapter.

Called ONLY after an allow decision has been recorded. It still enforces tenant isolation itself
(explicit ``tenant_id`` predicate + RLS via ``aegis.tenant_id``), so a PEP bug cannot read another
tenant's rows. Every executed operation writes a ``resource_side_effects`` row in the same
transaction; tests use those rows to prove that denied requests produced zero side effects.
"""

from __future__ import annotations

import re
import uuid
from collections import Counter
from dataclasses import dataclass
from typing import Any

from psycopg_pool import AsyncConnectionPool

from aegis.approvals import consume
from aegis.db import Conn, tenant_transaction, transaction

RESOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")


@dataclass(frozen=True, slots=True)
class ResourceMeta:
    """Non-sensitive attributes used as policy input (never title/body)."""

    id: str
    tenant_id: str
    kind: str
    classification: str
    department: str

    def to_policy(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "kind": self.kind,
            "classification": self.classification,
            "department": self.department,
        }


@dataclass(frozen=True, slots=True)
class Document:
    id: str
    title: str
    body: str
    classification: str


@dataclass(frozen=True, slots=True)
class SearchHit:
    meta: ResourceMeta
    title: str


def valid_resource_id(value: str) -> bool:
    return bool(RESOURCE_ID_RE.fullmatch(value))


async def get_metadata(pool: AsyncConnectionPool[Conn], resource_id: str) -> ResourceMeta | None:
    if not valid_resource_id(resource_id):
        return None
    async with transaction(pool) as conn:
        cur = await conn.execute("SELECT * FROM resource_metadata(%s)", (resource_id,))
        row = await cur.fetchone()
    if row is None:
        return None
    return ResourceMeta(
        id=row["id"],
        tenant_id=row["tenant_id"],
        kind=row["kind"],
        classification=row["classification"],
        department=row["department"],
    )


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


_SIDE_EFFECT = """
INSERT INTO resource_side_effects
    (kind, tenant_id, resource_id, principal_id, agent_id, task_id, correlation_id, request_id)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
"""


class DocumentStore:
    def __init__(self, pool: AsyncConnectionPool[Conn]) -> None:
        self._pool = pool
        # In-process spy counter (unit/integration tests); the DB table is the durable evidence.
        self.calls: Counter[str] = Counter()

    async def read(
        self,
        *,
        tenant_id: str,
        resource_id: str,
        principal_id: str,
        correlation_id: uuid.UUID,
        request_id: uuid.UUID,
        agent_id: str | None = None,
        task_id: uuid.UUID | None = None,
    ) -> Document | None:
        self.calls["read"] += 1
        async with tenant_transaction(self._pool, tenant_id) as conn:
            cur = await conn.execute(
                "SELECT id, title, body, classification FROM resources WHERE id = %s AND tenant_id = %s",
                (resource_id, tenant_id),
            )
            row = await cur.fetchone()
            if row is None:
                return None
            await conn.execute(
                _SIDE_EFFECT,
                (
                    "document_read",
                    tenant_id,
                    resource_id,
                    principal_id,
                    agent_id,
                    task_id,
                    correlation_id,
                    request_id,
                ),
            )
        return Document(
            id=row["id"], title=row["title"], body=row["body"], classification=row["classification"]
        )

    async def search_candidates(self, *, tenant_id: str, query: str, limit: int) -> list[SearchHit]:
        """Title-only match inside ONE tenant. Results still need per-item authorization."""
        self.calls["search_candidates"] += 1
        async with tenant_transaction(self._pool, tenant_id) as conn:
            cur = await conn.execute(
                "SELECT id, tenant_id, kind, classification, department, title FROM resources "
                "WHERE tenant_id = %s AND title ILIKE %s ESCAPE '\\' ORDER BY id LIMIT %s",
                (tenant_id, f"%{_escape_like(query)}%", limit),
            )
            rows = await cur.fetchall()
        return [
            SearchHit(
                meta=ResourceMeta(
                    id=r["id"],
                    tenant_id=r["tenant_id"],
                    kind=r["kind"],
                    classification=r["classification"],
                    department=r["department"],
                ),
                title=r["title"],
            )
            for r in rows
        ]

    async def record_search(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        agent_id: str | None,
        task_id: uuid.UUID | None,
        correlation_id: uuid.UUID,
        request_id: uuid.UUID,
    ) -> None:
        self.calls["search"] += 1
        async with tenant_transaction(self._pool, tenant_id) as conn:
            await conn.execute(
                _SIDE_EFFECT,
                ("search", tenant_id, None, principal_id, agent_id, task_id, correlation_id, request_id),
            )

    async def create_report(
        self,
        *,
        tenant_id: str,
        task_id: uuid.UUID,
        agent_id: str,
        on_behalf_of_id: str,
        source_document_ids: list[str],
        summary_text: str,
        correlation_id: uuid.UUID,
        request_id: uuid.UUID,
        consume_approval: tuple[uuid.UUID, str] | None = None,
    ) -> uuid.UUID:
        """Write a report. ``consume_approval`` = (approval id, args digest): the approval is consumed in the
        SAME transaction, so a report is never written without using up its single-use approval."""
        self.calls["create_report"] += 1
        report_id = uuid.uuid4()
        async with tenant_transaction(self._pool, tenant_id) as conn:
            if consume_approval is not None:
                await consume(
                    conn, approval_id=consume_approval[0], tenant_id=tenant_id, digest=consume_approval[1]
                )
            await conn.execute(
                "INSERT INTO reports (id, tenant_id, task_id, created_by_agent_id, on_behalf_of_id, "
                "source_document_ids, summary_text) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (report_id, tenant_id, task_id, agent_id, on_behalf_of_id, source_document_ids, summary_text),
            )
            await conn.execute(
                _SIDE_EFFECT,
                (
                    "report_write",
                    tenant_id,
                    f"report-{report_id}"[:64],
                    on_behalf_of_id,
                    agent_id,
                    task_id,
                    correlation_id,
                    request_id,
                ),
            )
        return report_id

    async def simulate_export(
        self,
        *,
        tenant_id: str,
        resource_id: str,
        principal_id: str,
        agent_id: str | None,
        task_id: uuid.UUID | None,
        correlation_id: uuid.UUID,
        request_id: uuid.UUID,
    ) -> None:
        """Test-only stand-in for exfiltration. Performs NO network I/O; only records that it ran."""
        self.calls["simulate_export"] += 1
        async with tenant_transaction(self._pool, tenant_id) as conn:
            await conn.execute(
                _SIDE_EFFECT,
                (
                    "export_simulated",
                    tenant_id,
                    resource_id,
                    principal_id,
                    agent_id,
                    task_id,
                    correlation_id,
                    request_id,
                ),
            )
