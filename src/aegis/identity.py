"""Resolve a verified token to a server-side principal (tenant, roles, active) from PostgreSQL.

Tenant, roles and agent status come ONLY from the database. Headers, request bodies, tool
arguments and even token claims other than (iss, sub, azp) are never consulted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from psycopg_pool import AsyncConnectionPool

from aegis.authn import VerifiedToken
from aegis.db import Conn, transaction

_PRINCIPAL_SQL = """
SELECT p.id, p.type, p.tenant_id, p.active, p.client_id,
       COALESCE(array_agg(pr.role_id ORDER BY pr.role_id)
                FILTER (WHERE pr.role_id IS NOT NULL), ARRAY[]::text[]) AS roles,
       ai.active AS agent_active
FROM principals p
LEFT JOIN principal_roles pr ON pr.principal_id = p.id AND pr.tenant_id = p.tenant_id
LEFT JOIN agent_identities ai ON ai.principal_id = p.id AND ai.tenant_id = p.tenant_id
WHERE {where}
GROUP BY p.id, ai.active
"""


class IdentityError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class Principal:
    id: str
    type: str  # human | workload | agent
    tenant_id: str
    roles: tuple[str, ...]
    active: bool
    client_id: str | None

    def to_policy(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "tenant_id": self.tenant_id,
            "roles": list(self.roles),
            "active": self.active,
        }


def _from_row(row: dict[str, Any]) -> Principal:
    active = bool(row["active"])
    if row["type"] == "agent":
        # An agent must also have an active agent_identities registration.
        active = active and bool(row["agent_active"])
    return Principal(
        id=row["id"],
        type=row["type"],
        tenant_id=row["tenant_id"],
        roles=tuple(row["roles"]),
        active=active,
        client_id=row["client_id"],
    )


async def resolve_principal(
    pool: AsyncConnectionPool[Conn], token: VerifiedToken, *, human_login_clients: frozenset[str]
) -> Principal:
    async with transaction(pool) as conn:
        cur = await conn.execute(
            _PRINCIPAL_SQL.format(where="p.oidc_issuer = %s AND p.oidc_sub = %s"),
            (token.issuer, token.subject),
        )
        row = await cur.fetchone()
    if row is None:
        raise IdentityError("UNKNOWN_PRINCIPAL")
    principal = _from_row(row)
    # Bind the principal to the OAuth client that obtained the token.
    if principal.type == "human":
        if token.client_id not in human_login_clients:
            raise IdentityError("CLIENT_PRINCIPAL_MISMATCH")
    elif principal.client_id != token.client_id:
        raise IdentityError("CLIENT_PRINCIPAL_MISMATCH")
    return principal


async def load_principal(conn: Conn, principal_id: str, tenant_id: str) -> Principal | None:
    cur = await conn.execute(
        _PRINCIPAL_SQL.format(where="p.id = %s AND p.tenant_id = %s"), (principal_id, tenant_id)
    )
    row = await cur.fetchone()
    return _from_row(row) if row else None


async def resolve_delegated(
    pool: AsyncConnectionPool[Conn], token: VerifiedToken
) -> tuple[Principal, Principal]:
    """Resolve an exchanged token (``sub`` = the delegating human, ``azp`` = the acting agent).

    Returns (user, agent). A token whose subject is not a human — e.g. an agent's own
    client-credentials token — is refused: an agent may only act for a person who consented.
    """
    async with transaction(pool) as conn:
        user_row = await (
            await conn.execute(
                _PRINCIPAL_SQL.format(where="p.oidc_issuer = %s AND p.oidc_sub = %s"),
                (token.issuer, token.subject),
            )
        ).fetchone()
        agent_row = await (
            await conn.execute(
                _PRINCIPAL_SQL.format(where="p.client_id = %s AND p.type = 'agent'"), (token.client_id,)
            )
        ).fetchone()
    if agent_row is None:
        raise IdentityError("UNKNOWN_AGENT")
    if user_row is None:
        raise IdentityError("UNKNOWN_PRINCIPAL")
    user, agent = _from_row(user_row), _from_row(agent_row)
    if user.type != "human":
        raise IdentityError("DELEGATED_TOKEN_REQUIRED")
    if user.tenant_id != agent.tenant_id:
        raise IdentityError("CROSS_TENANT_DELEGATION")
    return user, agent
