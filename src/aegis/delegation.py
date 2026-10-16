"""Server-side tasks and delegations (user -> agent, scoped to actions and resources, time-bound).

A task id presented by a caller is only a *selector*. It confers nothing unless the stored
delegation is bound to the authenticated agent, in the agent's tenant, active, unexpired and
unrevoked. The delegating user's roles are re-read on every call, so revoking a user's role
also revokes what their agent can do.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from psycopg_pool import AsyncConnectionPool

from aegis.db import Conn, tenant_transaction
from aegis.identity import Principal
from aegis.pep import DelegationInput

AGENT_DELEGABLE_ACTIONS = frozenset({"documents:read", "documents:search", "reports:create"})


@dataclass(frozen=True, slots=True)
class TaskDelegation:
    task_id: uuid.UUID
    tenant_id: str
    owner_id: str
    agent_id: str
    status: str
    actions: tuple[str, ...]
    resource_ids: tuple[str, ...]
    expires_at: datetime
    revoked_at: datetime | None

    def problems(self, *, agent: Principal, now: datetime | None = None) -> list[str]:
        now = now or datetime.now(UTC)
        out: list[str] = []
        if self.agent_id != agent.id or self.tenant_id != agent.tenant_id:
            out.append("DELEGATION_AGENT_MISMATCH")
        if self.status != "active":
            out.append("TASK_NOT_ACTIVE")
        if self.revoked_at is not None:
            out.append("DELEGATION_REVOKED")
        if self.expires_at <= now:
            out.append("DELEGATION_EXPIRED")
        return out

    def to_input(self, *, agent: Principal) -> DelegationInput:
        return DelegationInput(
            task_id=self.task_id,
            valid=not self.problems(agent=agent),
            user_id=self.owner_id,
            agent_id=self.agent_id,
            actions=self.actions,
            resource_ids=self.resource_ids,
        )


def parse_task_id(raw: str | None) -> uuid.UUID | None:
    if not raw or len(raw) > 64:
        return None
    try:
        return uuid.UUID(raw)
    except ValueError:
        return None


_LOAD = """
SELECT t.id AS task_id, t.tenant_id, t.owner_principal_id, t.agent_principal_id, t.status,
       d.allowed_actions, d.allowed_resources, d.expires_at, d.revoked_at
FROM tasks t JOIN delegations d ON d.task_id = t.id AND d.tenant_id = t.tenant_id
WHERE t.id = %s AND t.tenant_id = %s
"""


async def load_delegation(
    pool: AsyncConnectionPool[Conn], *, tenant_id: str, task_id: uuid.UUID
) -> TaskDelegation | None:
    async with tenant_transaction(pool, tenant_id) as conn:
        row = await (await conn.execute(_LOAD, (task_id, tenant_id))).fetchone()
    if row is None:
        return None
    return TaskDelegation(
        task_id=row["task_id"],
        tenant_id=row["tenant_id"],
        owner_id=row["owner_principal_id"],
        agent_id=row["agent_principal_id"],
        status=row["status"],
        actions=tuple(row["allowed_actions"]),
        resource_ids=tuple(row["allowed_resources"]),
        expires_at=row["expires_at"],
        revoked_at=row["revoked_at"],
    )


async def create_task(
    pool: AsyncConnectionPool[Conn],
    *,
    owner: Principal,
    agent: Principal,
    actions: list[str],
    resource_ids: list[str],
    ttl_seconds: int,
    purpose: str,
) -> TaskDelegation:
    """Persist a task + delegation. Callers MUST have authorized every (action, resource) for ``owner``."""
    task_id = uuid.uuid4()
    now = datetime.now(UTC)
    expires = now + timedelta(seconds=ttl_seconds)
    async with tenant_transaction(pool, owner.tenant_id) as conn:
        await conn.execute(
            "INSERT INTO tasks (id, tenant_id, owner_principal_id, agent_principal_id, purpose, status) "
            "VALUES (%s, %s, %s, %s, %s, 'active')",
            (task_id, owner.tenant_id, owner.id, agent.id, purpose),
        )
        await conn.execute(
            "INSERT INTO delegations (id, task_id, tenant_id, user_principal_id, agent_principal_id, "
            "allowed_actions, allowed_resources, expires_at, created_at)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (uuid.uuid4(), task_id, owner.tenant_id, owner.id, agent.id, actions, resource_ids, expires, now),
        )
    return TaskDelegation(
        task_id=task_id,
        tenant_id=owner.tenant_id,
        owner_id=owner.id,
        agent_id=agent.id,
        status="active",
        actions=tuple(actions),
        resource_ids=tuple(resource_ids),
        expires_at=expires,
        revoked_at=None,
    )


async def revoke_task(pool: AsyncConnectionPool[Conn], *, owner: Principal, task_id: uuid.UUID) -> bool:
    async with tenant_transaction(pool, owner.tenant_id) as conn:
        cur = await conn.execute(
            "UPDATE tasks SET status = 'revoked'"
            " WHERE id = %s AND tenant_id = %s AND owner_principal_id = %s",
            (task_id, owner.tenant_id, owner.id),
        )
        if cur.rowcount != 1:
            return False
        await conn.execute(
            "UPDATE delegations SET revoked_at = now()"
            " WHERE task_id = %s AND tenant_id = %s AND revoked_at IS NULL",
            (task_id, owner.tenant_id),
        )
    return True
