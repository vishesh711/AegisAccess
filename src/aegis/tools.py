"""Agent tool gateway: enforcement for every tool invocation (MCP_SPEC steps A-G).

The MCP server is only a transport. Every tool call reaches this gateway with an already
*authenticated* agent principal; the gateway then:
  B. loads the server-side task/delegation bound to that agent (task id = selector only),
  C/D. asks OPA with user ∩ agent ∩ task in the canonical input,
  E. relies on the enforcer to persist the decision before any side effect,
  F. calls only the typed adapter for the selected tool,
  G. records a separate execution event with the same correlation id.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, replace

from psycopg_pool import AsyncConnectionPool
from pydantic import BaseModel

from aegis.agent_tokens import load_binding
from aegis.db import Conn
from aegis.delegation import TaskDelegation, load_delegation, parse_task_id
from aegis.identity import Principal
from aegis.pep import Decision, Enforcer, PolicyResource, RequestMeta
from aegis.resources import DocumentStore, ResourceMeta, get_metadata, valid_resource_id

log = logging.getLogger("aegis.tools")

MAX_QUERY_CHARS = 100
MAX_RESULTS = 10
MAX_SUMMARY_DOCS = 10


# ------------------------------------------------------------------ output schemas


class DocumentOut(BaseModel):
    document_id: str
    title: str
    body: str
    classification: str


class SearchItem(BaseModel):
    document_id: str
    title: str


class SearchOut(BaseModel):
    items: list[SearchItem]


class ReportOut(BaseModel):
    report_id: str
    status: str


class ExportOut(BaseModel):
    status: str


class ToolDeniedError(Exception):
    """Sanitized denial: carries only a public reason and the request id."""

    def __init__(self, public_reason: str, request_id: uuid.UUID) -> None:
        super().__init__(f"{public_reason} (request_id={request_id})")
        self.public_reason = public_reason
        self.request_id = request_id


@dataclass(frozen=True, slots=True)
class ToolCaller:
    """Who is calling, as established from the verified bearer token (never from tool arguments)."""

    agent: Principal
    meta: RequestMeta
    user: Principal | None = None  # the delegating human (token ``sub``); None = not a delegated token
    token_id: str | None = None  # the token's ``jti``; must be bound to the task being acted on


@dataclass(frozen=True, slots=True)
class _Ctx:
    caller: ToolCaller
    meta: RequestMeta
    delegation: TaskDelegation
    user: Principal


class SlidingWindowLimiter:
    def __init__(self, per_minute: int) -> None:
        self._limit = per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self._hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self._limit:
            return False
        q.append(now)
        return True


class ToolGateway:
    def __init__(
        self,
        *,
        pool: AsyncConnectionPool[Conn],
        enforcer: Enforcer,
        store: DocumentStore,
        rate_limit_per_minute: int,
        max_summary_chars: int,
    ) -> None:
        self._pool = pool
        self._enforcer = enforcer
        self._store = store
        self._limiter = SlidingWindowLimiter(rate_limit_per_minute)
        self._max_summary = max_summary_chars

    # -------------------------------------------------------------- helpers

    async def _deny(
        self,
        caller: ToolCaller,
        meta: RequestMeta,
        reason: str,
        *,
        action: str | None,
        resource_id: str | None = None,
        task_id: uuid.UUID | None = None,
        subject: Principal | None = None,
    ) -> ToolDeniedError:
        decision = await self._enforcer.deny_without_evaluation(
            meta,
            subject=subject or caller.agent,
            action=action,
            resource_id=resource_id,
            reason=reason,
            agent=caller.agent,
            task_id=task_id,
        )
        return ToolDeniedError(decision.public_reason, meta.request_id)

    async def reject_call(self, caller: ToolCaller, tool_name: str, reason: str) -> None:
        """Audit a call rejected before dispatch (unknown tool, bad arguments, oversized payload)."""
        await self._enforcer.deny_without_evaluation(
            caller.meta,
            subject=caller.agent,
            action=None,
            resource_id=None,
            reason=reason,
            agent=caller.agent,
        )

    async def _context(self, caller: ToolCaller, raw_task_id: str | None, action: str) -> _Ctx:
        meta = caller.meta
        agent = caller.agent
        # A. caller must be an active, registered agent identity acting for a human (exchanged token).
        if agent.type != "agent" or not agent.active:
            raise await self._deny(caller, meta, "AGENT_INACTIVE_OR_NOT_AGENT", action=action)
        user = caller.user
        if user is None or user.type != "human" or caller.token_id is None:
            raise await self._deny(caller, meta, "DELEGATED_TOKEN_REQUIRED", action=action)
        if not self._limiter.allow(agent.id):
            raise await self._deny(caller, meta, "RATE_LIMITED", action=action)
        # B. server-side delegation, looked up inside the AGENT's tenant only.
        task_id = parse_task_id(raw_task_id)
        if task_id is None:
            raise await self._deny(caller, meta, "DELEGATION_MISSING", action=action)
        # The token itself must have been bound to THIS task by the agent host at exchange time.
        binding = await load_binding(self._pool, tenant_id=agent.tenant_id, token_id=caller.token_id)
        if binding is None:
            raise await self._deny(caller, meta, "TOKEN_NOT_BOUND", action=action, task_id=task_id)
        if binding.task_id != task_id:
            raise await self._deny(caller, meta, "TOKEN_NOT_BOUND_TO_TASK", action=action, task_id=task_id)
        if binding.user_id != user.id or binding.agent_id != agent.id:
            raise await self._deny(caller, meta, "TOKEN_BINDING_MISMATCH", action=action, task_id=task_id)
        delegation = await load_delegation(self._pool, tenant_id=agent.tenant_id, task_id=task_id)
        if delegation is None:
            raise await self._deny(caller, meta, "DELEGATION_NOT_FOUND", action=action, task_id=task_id)
        problems = delegation.problems(agent=agent)
        if delegation.owner_id != user.id:
            problems.append("DELEGATION_USER_MISMATCH")
        if problems:
            raise await self._deny(caller, meta, ",".join(problems), action=action, task_id=task_id)
        return _Ctx(caller=caller, meta=meta, delegation=delegation, user=user)

    async def _authorize(
        self, ctx: _Ctx, action: str, resource: ResourceMeta | PolicyResource | None
    ) -> Decision:
        return await self._enforcer.authorize(
            ctx.meta,
            subject=ctx.user,
            action=action,
            resource=resource,
            agent=ctx.caller.agent,
            delegation=ctx.delegation.to_input(agent=ctx.caller.agent),
        )

    async def _executed(self, ctx: _Ctx, action: str, resource_id: str | None, outcome: str) -> None:
        await self._enforcer.record_execution(
            ctx.meta,
            subject=ctx.user,
            action=action,
            resource_id=resource_id,
            outcome=outcome,
            agent=ctx.caller.agent,
            task_id=ctx.delegation.task_id,
        )

    # -------------------------------------------------------------- tools

    async def read_document(
        self, caller: ToolCaller, *, task_id: str | None, resource_id: str
    ) -> DocumentOut:
        action = "documents:read"
        ctx = await self._context(caller, task_id, action)
        meta_res = await get_metadata(self._pool, resource_id) if valid_resource_id(resource_id) else None
        decision = await self._authorize(ctx, action, meta_res)
        if not decision.allow or meta_res is None:
            raise ToolDeniedError(decision.public_reason, decision.request_id)
        doc = await self._store.read(
            tenant_id=ctx.delegation.tenant_id,
            resource_id=meta_res.id,
            principal_id=ctx.user.id,
            agent_id=ctx.caller.agent.id,
            task_id=ctx.delegation.task_id,
            correlation_id=ctx.meta.correlation_id,
        )
        await self._executed(ctx, action, meta_res.id, "success" if doc else "not_found")
        if doc is None:
            raise ToolDeniedError("ACCESS_DENIED", decision.request_id)
        return DocumentOut(
            document_id=doc.id, title=doc.title, body=doc.body, classification=doc.classification
        )

    async def search_documents(
        self, caller: ToolCaller, *, task_id: str | None, query: str, max_results: int
    ) -> SearchOut:
        action = "documents:search"
        if not (1 <= max_results <= MAX_RESULTS) or not (1 <= len(query) <= MAX_QUERY_CHARS):
            raise await self._deny(caller, caller.meta, "INVALID_ARGUMENTS", action=action)
        ctx = await self._context(caller, task_id, action)
        # Candidates come from the agent's tenant only; each is authorized BEFORE inclusion.
        candidates = await self._store.search_candidates(
            tenant_id=ctx.delegation.tenant_id, query=query, limit=MAX_RESULTS * 5
        )
        items: list[SearchItem] = []
        for hit in candidates:
            if len(items) >= max_results:
                break
            per_item_meta = replace(ctx.meta, request_id=uuid.uuid4())
            decision = await self._enforcer.authorize(
                per_item_meta,
                subject=ctx.user,
                action=action,
                resource=hit.meta,
                agent=ctx.caller.agent,
                delegation=ctx.delegation.to_input(agent=ctx.caller.agent),
            )
            if decision.dependency_failure:
                raise ToolDeniedError(decision.public_reason, decision.request_id)
            if decision.allow:
                items.append(SearchItem(document_id=hit.meta.id, title=hit.title))
        await self._store.record_search(
            tenant_id=ctx.delegation.tenant_id,
            principal_id=ctx.user.id,
            agent_id=ctx.caller.agent.id,
            task_id=ctx.delegation.task_id,
            correlation_id=ctx.meta.correlation_id,
        )
        await self._executed(ctx, action, None, "success")
        return SearchOut(items=items)

    async def create_summary(
        self,
        caller: ToolCaller,
        *,
        header_task_id: str | None,
        task_id: str,
        document_ids: list[str],
        summary_text: str,
    ) -> ReportOut:
        action = "reports:create"
        if header_task_id is not None and header_task_id != task_id:
            raise await self._deny(caller, caller.meta, "TASK_MISMATCH", action=action)
        if not (1 <= len(document_ids) <= MAX_SUMMARY_DOCS) or len(set(document_ids)) != len(document_ids):
            raise await self._deny(caller, caller.meta, "INVALID_ARGUMENTS", action=action)
        if not (1 <= len(summary_text) <= self._max_summary):
            raise await self._deny(caller, caller.meta, "INVALID_ARGUMENTS", action=action)
        ctx = await self._context(caller, task_id, action)
        # Every source document must itself be readable under the same intersection.
        for doc_id in document_ids:
            res = await get_metadata(self._pool, doc_id) if valid_resource_id(doc_id) else None
            d = await self._authorize(ctx, "documents:read", res)
            if not d.allow:
                raise ToolDeniedError(d.public_reason, d.request_id)
        report_res = PolicyResource(
            id=f"report:{ctx.delegation.task_id}"[:80],
            tenant_id=ctx.delegation.tenant_id,
            kind="report",
            classification="internal",
            department="*",
        )
        decision = await self._authorize(ctx, action, report_res)
        if not decision.allow:
            raise ToolDeniedError(decision.public_reason, decision.request_id)
        clean = "".join(ch for ch in summary_text if ch.isprintable() or ch in "\n\t")
        report_id = await self._store.create_report(
            tenant_id=ctx.delegation.tenant_id,
            task_id=ctx.delegation.task_id,
            agent_id=ctx.caller.agent.id,
            on_behalf_of_id=ctx.user.id,
            source_document_ids=document_ids,
            summary_text=clean,
            correlation_id=ctx.meta.correlation_id,
        )
        await self._executed(ctx, action, report_res.id, "success")
        return ReportOut(report_id=str(report_id), status="created")

    async def simulate_export(
        self, caller: ToolCaller, *, task_id: str | None, resource_id: str, destination: str
    ) -> ExportOut:
        """Test-only exfiltration stand-in. No role grants exports:simulate; no network I/O exists."""
        del destination  # never used: there is no network path
        action = "exports:simulate"
        ctx = await self._context(caller, task_id, action)
        res = await get_metadata(self._pool, resource_id) if valid_resource_id(resource_id) else None
        decision = await self._authorize(ctx, action, res)
        if not decision.allow or res is None:
            raise ToolDeniedError(decision.public_reason, decision.request_id)
        await self._store.simulate_export(
            tenant_id=ctx.delegation.tenant_id,
            resource_id=res.id,
            principal_id=ctx.user.id,
            agent_id=ctx.caller.agent.id,
            task_id=ctx.delegation.task_id,
            correlation_id=ctx.meta.correlation_id,
        )
        await self._executed(ctx, action, res.id, "success")
        return ExportOut(status="simulated")
