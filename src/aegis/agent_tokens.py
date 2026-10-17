"""Agent-host side of delegation: obtain a per-task, user-bound token for the agent.

Flow (Keycloak 26.2 standard token exchange, RFC 8693):
  1. The user's API token must carry the consent scope ``delegate-<agent client>``. That scope puts the
     agent client in the token's audience; without it Keycloak refuses the exchange.
  2. The agent client exchanges that token. Keycloak returns a token with ``sub`` = the user,
     ``azp`` = the agent, ``aud`` = aegis-mcp. The agent's secret alone cannot mint such a token
     (agent clients have no service account).
  3. The returned token is verified like any other (signature, issuer, audience, expiry), its user and
     agent are checked against the stored delegation, and its ``jti`` (hashed) is bound to exactly one task.
The MCP server accepts the token only for that task, for that user and agent, until it expires.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
from psycopg_pool import AsyncConnectionPool

from aegis.authn import JwtVerifier, TokenValidationError
from aegis.db import Conn, tenant_transaction
from aegis.delegation import TaskDelegation
from aegis.identity import Principal, resolve_delegated

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105 - RFC 8693 identifier
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 - RFC 8693 identifier


class AgentTokenError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class TokenBinding:
    task_id: uuid.UUID
    tenant_id: str
    user_id: str
    agent_id: str
    expires_at: datetime


def token_id_digest(token_id: str) -> str:
    return hashlib.sha256(token_id.encode("utf-8")).hexdigest()


def consent_scope(agent_client_id: str) -> str:
    return f"delegate-{agent_client_id}"


async def exchange_user_token(
    http: httpx.AsyncClient, *, token_endpoint: str, client_id: str, client_secret: str, subject_token: str
) -> str:
    resp = await http.post(
        token_endpoint,
        data={
            "grant_type": TOKEN_EXCHANGE,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "requested_token_type": ACCESS_TOKEN_TYPE,
        },
        auth=(client_id, client_secret),
    )
    if resp.status_code != 200:
        # Keycloak answers 403 when the user token lacks the consent audience.
        raise AgentTokenError("CONSENT_REQUIRED" if resp.status_code == 403 else "TOKEN_EXCHANGE_FAILED")
    token = resp.json().get("access_token")
    if not isinstance(token, str):
        raise AgentTokenError("TOKEN_EXCHANGE_FAILED")
    return token


async def issue_task_token(
    *,
    http: httpx.AsyncClient,
    pool: AsyncConnectionPool[Conn],
    mcp_verifier: JwtVerifier,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    user_token: str,
    delegation: TaskDelegation,
) -> str:
    """Exchange the consenting user's token and bind the result to ``delegation``'s task."""
    token = await exchange_user_token(
        http,
        token_endpoint=token_endpoint,
        client_id=client_id,
        client_secret=client_secret,
        subject_token=user_token,
    )
    try:
        verified = await mcp_verifier.verify(token)
    except TokenValidationError as exc:
        raise AgentTokenError("EXCHANGED_TOKEN_INVALID") from exc
    if verified.token_id is None:
        raise AgentTokenError("EXCHANGED_TOKEN_INVALID")
    user, agent = await resolve_delegated(pool, verified)
    if (
        user.id != delegation.owner_id
        or agent.id != delegation.agent_id
        or user.tenant_id != delegation.tenant_id
    ):
        raise AgentTokenError("DELEGATION_MISMATCH")
    await bind_token(
        pool,
        token_id=verified.token_id,
        user=user,
        agent=agent,
        task_id=delegation.task_id,
        expires_at=datetime.fromtimestamp(verified.expires_at, UTC),
    )
    return token


async def bind_token(
    pool: AsyncConnectionPool[Conn],
    *,
    token_id: str,
    user: Principal,
    agent: Principal,
    task_id: uuid.UUID,
    expires_at: datetime,
) -> None:
    async with tenant_transaction(pool, user.tenant_id) as conn:
        await conn.execute(
            "INSERT INTO agent_token_bindings (token_id_sha256, tenant_id, task_id, user_principal_id,"
            " agent_principal_id, expires_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (token_id_digest(token_id), user.tenant_id, task_id, user.id, agent.id, expires_at),
        )


async def load_binding(
    pool: AsyncConnectionPool[Conn], *, tenant_id: str, token_id: str
) -> TokenBinding | None:
    async with tenant_transaction(pool, tenant_id) as conn:
        row = await (
            await conn.execute(
                "SELECT task_id, tenant_id, user_principal_id, agent_principal_id, expires_at"
                " FROM agent_token_bindings WHERE token_id_sha256 = %s AND tenant_id = %s",
                (token_id_digest(token_id), tenant_id),
            )
        ).fetchone()
    if row is None:
        return None
    return TokenBinding(
        task_id=row["task_id"],
        tenant_id=row["tenant_id"],
        user_id=row["user_principal_id"],
        agent_id=row["agent_principal_id"],
        expires_at=row["expires_at"],
    )
