"""Append-only, sanitized security audit events.

Never stored: tokens, secrets, prompts, document titles or bodies, raw tool arguments. Fields
that can carry attacker-chosen text (resource ids, tool names) are reduced to a strict charset;
anything else is replaced by a short digest so the attempt is still correlatable.
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Protocol

from psycopg_pool import AsyncConnectionPool

from aegis.db import Conn, transaction

log = logging.getLogger("aegis.audit")

_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9:._-]{0,79}$")
_SAFE_CODE = re.compile(r"^[A-Z0-9_,]{1,200}$")


def safe_identifier(value: str | None) -> str | None:
    if value is None:
        return None
    if _SAFE_ID.fullmatch(value):
        return value
    return "unsafe:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def safe_code(value: str) -> str:
    return value if _SAFE_CODE.fullmatch(value) else "INVALID_CODE"


class AuditUnavailableError(Exception):
    pass


@dataclass(slots=True)
class AuditEvent:
    event_kind: str  # decision | execution | incident | authn
    correlation_id: uuid.UUID
    request_id: uuid.UUID
    decision: str  # allow | deny | n/a
    reason_code: str
    evaluator_status: str
    principal_type: str | None = None
    principal_id: str | None = None
    tenant_id: str | None = None
    agent_id: str | None = None
    task_id: uuid.UUID | None = None
    tool_name: str | None = None
    action: str | None = None
    resource_id: str | None = None
    policy_version: str | None = None
    outcome: str | None = None
    duration_ms: float | None = None
    request_origin: str | None = None
    test_case_id: str | None = None
    id: uuid.UUID = field(default_factory=uuid.uuid4)


class AuditSink(Protocol):
    async def record(self, event: AuditEvent) -> None: ...


_INSERT = """
INSERT INTO audit_events (id, event_kind, correlation_id, request_id, principal_type, principal_id,
    tenant_id, agent_id, task_id, tool_name, action, resource_id, policy_version, decision,
    reason_code, evaluator_status, outcome, duration_ms, request_origin, test_case_id)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


class PgAuditSink:
    def __init__(self, pool: AsyncConnectionPool[Conn]) -> None:
        self._pool = pool

    async def record(self, event: AuditEvent) -> None:
        params = (
            event.id,
            event.event_kind,
            event.correlation_id,
            event.request_id,
            event.principal_type,
            safe_identifier(event.principal_id),
            safe_identifier(event.tenant_id),
            safe_identifier(event.agent_id),
            event.task_id,
            safe_identifier(event.tool_name),
            safe_identifier(event.action),
            safe_identifier(event.resource_id),
            safe_identifier(event.policy_version),
            event.decision,
            safe_code(event.reason_code),
            safe_identifier(event.evaluator_status) or "unknown",
            safe_identifier(event.outcome),
            event.duration_ms,
            event.request_origin,
            safe_identifier(event.test_case_id),
        )
        try:
            async with transaction(self._pool) as conn:
                await conn.execute(_INSERT, params)
        except Exception as exc:
            # Type only: exception text could echo parameters.
            log.error("audit write failed", extra={"fields": {"exc_type": type(exc).__name__}})
            raise AuditUnavailableError() from exc
