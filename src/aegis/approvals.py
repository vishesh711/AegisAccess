"""Human approval of sensitive agent writes (MCP_SPEC approval rule).

An approval is:
  * server-stored (table ``approvals``), never a tool argument: ``approved=true`` is rejected upstream;
  * bound to the EXACT action and arguments by a sha256 digest of their canonical JSON form;
  * granted only by the delegating human, through the authenticated API (an agent has no way to approve);
  * short-lived: a pending request expires after 10 minutes, a granted approval 5 minutes after the decision;
  * single-use: consumed in the same database transaction as the write it authorizes.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg_pool import AsyncConnectionPool

from aegis.db import Conn, tenant_transaction
from aegis.identity import Principal

PENDING_TTL = "10 minutes"
APPROVED_TTL = "5 minutes"


class ApprovalNotUsableError(Exception):
    """The approval was consumed, expired or withdrawn between lookup and use."""


@dataclass(frozen=True, slots=True)
class ApprovalView:
    id: uuid.UUID
    task_id: uuid.UUID
    agent_id: str
    action: str
    args_digest: str
    description: str
    status: str
    created_at: datetime
    expires_at: datetime
    consumed: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "approval_id": str(self.id),
            "task_id": str(self.task_id),
            "agent_id": self.agent_id,
            "action": self.action,
            "args_digest": self.args_digest,
            "description": self.description,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "consumed": self.consumed,
        }


def args_digest(action: str, arguments: dict[str, Any]) -> str:
    """Digest of the canonical JSON form of the action and its arguments (keys sorted, no whitespace)."""
    canonical = json.dumps({"action": action, "arguments": arguments}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def find_usable(
    pool: AsyncConnectionPool[Conn], *, tenant_id: str, task_id: uuid.UUID, digest: str, approver_id: str
) -> uuid.UUID | None:
    async with tenant_transaction(pool, tenant_id) as conn:
        row = await (
            await conn.execute(
                "SELECT id FROM approvals WHERE tenant_id = %s AND task_id = %s AND args_digest = %s"
                " AND approver_principal_id = %s AND status = 'approved' AND consumed_at IS NULL"
                " AND expires_at > now() ORDER BY created_at LIMIT 1",
                (tenant_id, task_id, digest, approver_id),
            )
        ).fetchone()
    return row["id"] if row else None


async def request_approval(
    pool: AsyncConnectionPool[Conn],
    *,
    tenant_id: str,
    task_id: uuid.UUID,
    approver_id: str,
    agent_id: str,
    action: str,
    digest: str,
    description: str,
) -> uuid.UUID:
    """Create (or reuse an open) pending request for exactly these arguments."""
    async with tenant_transaction(pool, tenant_id) as conn:
        existing = await (
            await conn.execute(
                "SELECT id FROM approvals WHERE tenant_id = %s AND task_id = %s AND args_digest = %s"
                " AND status = 'pending' AND expires_at > now() LIMIT 1",
                (tenant_id, task_id, digest),
            )
        ).fetchone()
        if existing:
            approval_id: uuid.UUID = existing["id"]
            return approval_id
        approval_id = uuid.uuid4()
        await conn.execute(
            "INSERT INTO approvals (id, tenant_id, task_id, approver_principal_id, agent_principal_id,"
            " action, args_digest, description, status, expires_at)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending', now() + %s::interval)",
            (
                approval_id,
                tenant_id,
                task_id,
                approver_id,
                agent_id,
                action,
                digest,
                description[:300],
                PENDING_TTL,
            ),
        )
    return approval_id


async def consume(conn: Conn, *, approval_id: uuid.UUID, tenant_id: str, digest: str) -> None:
    """Atomically mark an approval used. Must run in the SAME transaction as the write it authorizes."""
    cur = await conn.execute(
        "UPDATE approvals SET consumed_at = now() WHERE id = %s AND tenant_id = %s AND args_digest = %s"
        " AND status = 'approved' AND consumed_at IS NULL AND expires_at > now()",
        (approval_id, tenant_id, digest),
    )
    if cur.rowcount != 1:
        raise ApprovalNotUsableError()


async def decide(
    pool: AsyncConnectionPool[Conn], *, approver: Principal, approval_id: uuid.UUID, approve: bool
) -> ApprovalView | None:
    """Record the delegating human's decision. Returns None if the request is not theirs or not pending."""
    async with tenant_transaction(pool, approver.tenant_id) as conn:
        status = "approved" if approve else "rejected"
        cur = await conn.execute(
            "UPDATE approvals SET status = %s, decided_at = now(), decided_by = %s,"
            " expires_at = LEAST(expires_at, now() + %s::interval)"
            " WHERE id = %s AND tenant_id = %s AND approver_principal_id = %s AND status = 'pending'"
            " AND expires_at > now()",
            (status, approver.id, APPROVED_TTL, approval_id, approver.tenant_id, approver.id),
        )
        if cur.rowcount != 1:
            return None
        row = await (await conn.execute(_SELECT + " WHERE id = %s", (approval_id,))).fetchone()
    return _view(row) if row else None


async def list_for_approver(pool: AsyncConnectionPool[Conn], *, approver: Principal) -> list[ApprovalView]:
    async with tenant_transaction(pool, approver.tenant_id) as conn:
        rows = await (
            await conn.execute(
                _SELECT + " WHERE approver_principal_id = %s ORDER BY created_at DESC LIMIT 50",
                (approver.id,),
            )
        ).fetchall()
    return [_view(r) for r in rows]


_SELECT = (
    "SELECT id, task_id, agent_principal_id, action, args_digest, description, status, created_at,"
    " expires_at, consumed_at FROM approvals"
)


def _view(row: dict[str, Any]) -> ApprovalView:
    return ApprovalView(
        id=row["id"],
        task_id=row["task_id"],
        agent_id=row["agent_principal_id"],
        action=row["action"],
        args_digest=row["args_digest"],
        description=row["description"],
        status=row["status"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        consumed=row["consumed_at"] is not None,
    )
