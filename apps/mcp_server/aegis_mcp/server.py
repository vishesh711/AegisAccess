"""AegisAccess MCP server (official MCP Python SDK, streamable HTTP, stateless).

Security layering per request:
  1. SDK ``BearerAuthBackend`` + ``RequireAuthMiddleware`` call ``AegisTokenVerifier`` on EVERY HTTP
     request (stateless mode: no session/connection identity is ever reused).
  2. ``ToolCallGuard`` (SDK server middleware) runs before SDK argument validation: unknown tool
     names, unexpected argument keys (e.g. ``user_id``/``tenant_id``), schema violations and
     oversized payloads are rejected and audited WITHOUT executing any tool code.
  3. Each tool resolves the agent principal from the database and hands off to ``ToolGateway``
     (delegation lookup, user ∩ agent ∩ task decision in OPA, audit, typed adapter).
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

import anyio
from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import CallToolResult, TextContent, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from aegis.agent_client import CORRELATION_HEADER, TASK_HEADER
from aegis.authn import TokenValidationError, VerifiedToken
from aegis.config import Settings, get_settings
from aegis.identity import IdentityError, resolve_principal
from aegis.logging import configure_logging, install_redaction_on_all_handlers
from aegis.pep import RequestMeta
from aegis.services import Services, open_services
from aegis.tools import (
    MAX_QUERY_CHARS,
    MAX_RESULTS,
    MAX_SUMMARY_DOCS,
    DocumentOut,
    ExportOut,
    ReportOut,
    SearchOut,
    ToolCaller,
    ToolDeniedError,
)

log = logging.getLogger("aegis.mcp")

MAX_ARGUMENT_BYTES = 16 * 1024
DocId = Annotated[str, Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9-]{1,63}$")]
TaskIdStr = Annotated[str, Field(min_length=36, max_length=36)]


# --------------------------------------------------------------------------- argument schemas
# Strict models (extra="forbid") used by the guard; tool signatures mirror the same constraints so
# the advertised input schemas match what is enforced.


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ReadArgs(_Args):
    resource_id: DocId


class SearchArgs(_Args):
    query: Annotated[str, Field(min_length=1, max_length=MAX_QUERY_CHARS)]
    max_results: Annotated[int, Field(ge=1, le=MAX_RESULTS)] = 5


class SummaryArgs(_Args):
    task_id: TaskIdStr
    document_ids: Annotated[list[DocId], Field(min_length=1, max_length=MAX_SUMMARY_DOCS)]
    summary_text: Annotated[str, Field(min_length=1, max_length=2000)]


class ExportArgs(_Args):
    resource_id: DocId
    destination: Annotated[str, Field(min_length=1, max_length=200)]


MVP_TOOLS: dict[str, type[_Args]] = {
    "documents.read": ReadArgs,
    "documents.search": SearchArgs,
    "reports.create_summary": SummaryArgs,
}
TEST_TOOLS: dict[str, type[_Args]] = {"exports.simulate": ExportArgs}


class _Holder:
    services: Services | None = None

    def get(self) -> Services:
        if self.services is None:
            raise ToolError("SERVICE_UNAVAILABLE")
        return self.services


# --------------------------------------------------------------------------- authentication


class AegisTokenVerifier:
    """SDK TokenVerifier backed by AegisAccess JWT validation (aud=aegis-mcp, RS256, agent clients only)."""

    def __init__(self, holder: _Holder) -> None:
        self._holder = holder

    async def verify_token(self, token: str) -> AccessToken | None:
        services = self._holder.services
        if services is None:
            return None
        try:
            vt = await services.mcp_verifier.verify(token)
        except TokenValidationError as exc:
            await services.enforcer.record_authn_failure(RequestMeta(origin="mcp"), exc.reason)
            return None
        # The raw token is NOT kept in request context: it is never forwarded anywhere.
        return AccessToken(
            token="[not-retained]",  # noqa: S106 - placeholder, not a credential
            client_id=vt.client_id,
            scopes=list(vt.scopes),
            expires_at=vt.expires_at,
            subject=vt.subject,
            resource=services.settings.mcp_resource_url,
            claims={"iss": vt.issuer, "aud": list(vt.audience)},
        )


def _verified_from_context() -> VerifiedToken | None:
    at = get_access_token()
    if at is None or at.subject is None or at.claims is None:
        return None
    return VerifiedToken(
        issuer=str(at.claims["iss"]),
        subject=at.subject,
        client_id=at.client_id,
        audience=tuple(at.claims.get("aud", ())),
        expires_at=at.expires_at or 0,
        token_id=None,
        scopes=tuple(at.scopes),
    )


def _correlation(headers: Any) -> uuid.UUID:
    raw = headers.get(CORRELATION_HEADER.lower()) if headers else None
    try:
        return uuid.UUID(raw) if raw and len(raw) <= 64 else uuid.uuid4()
    except ValueError:
        return uuid.uuid4()


async def _resolve_caller(services: Services, tool_name: str, headers: Any) -> ToolCaller:
    vt = _verified_from_context()
    meta = RequestMeta(origin="mcp", tool_name=tool_name, correlation_id=_correlation(headers))
    if vt is None:
        raise ToolError(f"UNAUTHENTICATED (request_id={meta.request_id})")
    try:
        # human_login_clients is empty: a human login token can never act as an MCP caller.
        principal = await resolve_principal(services.pool, vt, human_login_clients=frozenset())
    except IdentityError as exc:
        await services.enforcer.record_authn_failure(meta, exc.reason)
        raise ToolError(f"ACCESS_DENIED (request_id={meta.request_id})") from exc
    return ToolCaller(agent=principal, meta=meta)


# --------------------------------------------------------------------------- pre-dispatch guard


class ToolCallGuard:
    def __init__(self, holder: _Holder, registry: dict[str, type[_Args]]) -> None:
        self._holder = holder
        self._registry = registry

    async def __call__(self, ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
        if ctx.method != "tools/call":
            return await call_next(ctx)
        params = ctx.params or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        reason: str | None = None
        if not isinstance(name, str) or name not in self._registry:
            reason = "UNKNOWN_TOOL"
        elif not isinstance(arguments, dict):
            reason = "INVALID_ARGUMENTS"
        elif len(json.dumps(arguments, default=str)) > MAX_ARGUMENT_BYTES:
            reason = "PAYLOAD_TOO_LARGE"
        else:
            try:
                self._registry[name].model_validate(arguments)
            except ValidationError:
                reason = "INVALID_ARGUMENTS"  # covers unexpected keys such as user_id / tenant_id / role
        if reason is None:
            return await call_next(ctx)

        services = self._holder.get()
        safe_name = name if isinstance(name, str) else "invalid"
        headers = getattr(ctx, "headers", None)
        try:
            caller = await _resolve_caller(services, safe_name, headers)
            await services.gateway.reject_call(caller, safe_name, reason)
            rid = caller.meta.request_id
        except ToolError:
            rid = uuid.uuid4()
        # Sanitized: the submitted values are never echoed back.
        return CallToolResult(
            content=[TextContent(type="text", text=f"ACCESS_DENIED: {reason} (request_id={rid})")],
            is_error=True,
        )


# --------------------------------------------------------------------------- server


def build_mcp(holder: _Holder, settings: Settings) -> MCPServer:
    registry = dict(MVP_TOOLS)
    if settings.enable_test_tools:
        registry.update(TEST_TOOLS)

    mcp = MCPServer(
        "aegis-mcp",
        version="0.1.0",
        instructions="Allow-listed document tools. Every call is authorized server-side.",
        token_verifier=AegisTokenVerifier(holder),
        auth=AuthSettings(
            issuer_url=settings.oidc_issuer,
            resource_server_url=settings.mcp_resource_url,
            validate_token_resource=False,  # AegisTokenVerifier enforces the audience itself
        ),
        middleware=[ToolCallGuard(holder, registry)],
    )
    timeout = settings.tool_timeout_seconds

    async def run_tool(coro_factory: Any) -> Any:
        try:
            with anyio.fail_after(timeout):
                return await coro_factory()
        except ToolDeniedError as exc:
            raise ToolError(str(exc)) from exc
        except TimeoutError as exc:
            raise ToolError("TOOL_TIMEOUT") from exc

    read_only = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)

    @mcp.tool(
        name="documents.read",
        description="Read one document the delegated task permits.",
        annotations=read_only,
    )
    async def documents_read(resource_id: DocId, ctx: Context) -> DocumentOut:
        services = holder.get()
        caller = await _resolve_caller(services, "documents.read", ctx.headers)
        task = (ctx.headers or {}).get(TASK_HEADER.lower())
        result: DocumentOut = await run_tool(
            lambda: services.gateway.read_document(caller, task_id=task, resource_id=resource_id)
        )
        return result

    @mcp.tool(
        name="documents.search",
        description="Search document titles within the task scope.",
        annotations=read_only,
    )
    async def documents_search(
        query: Annotated[str, Field(min_length=1, max_length=MAX_QUERY_CHARS)],
        ctx: Context,
        max_results: Annotated[int, Field(ge=1, le=MAX_RESULTS)] = 5,
    ) -> SearchOut:
        services = holder.get()
        caller = await _resolve_caller(services, "documents.search", ctx.headers)
        task = (ctx.headers or {}).get(TASK_HEADER.lower())
        result: SearchOut = await run_tool(
            lambda: services.gateway.search_documents(
                caller, task_id=task, query=query, max_results=max_results
            )
        )
        return result

    @mcp.tool(
        name="reports.create_summary",
        description="Store a synthetic summary report for a delegated task (local write only, no network).",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False),
    )
    async def reports_create_summary(
        task_id: TaskIdStr,
        document_ids: Annotated[list[DocId], Field(min_length=1, max_length=MAX_SUMMARY_DOCS)],
        summary_text: Annotated[str, Field(min_length=1, max_length=2000)],
        ctx: Context,
    ) -> ReportOut:
        services = holder.get()
        caller = await _resolve_caller(services, "reports.create_summary", ctx.headers)
        header_task = (ctx.headers or {}).get(TASK_HEADER.lower())
        result: ReportOut = await run_tool(
            lambda: services.gateway.create_summary(
                caller,
                header_task_id=header_task,
                task_id=task_id,
                document_ids=document_ids,
                summary_text=summary_text,
            )
        )
        return result

    if settings.enable_test_tools:

        @mcp.tool(
            name="exports.simulate",
            description="TEST ONLY: models data exfiltration. Performs no network I/O; denied by policy.",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False),
        )
        async def exports_simulate(
            resource_id: DocId, destination: Annotated[str, Field(min_length=1, max_length=200)], ctx: Context
        ) -> ExportOut:
            services = holder.get()
            caller = await _resolve_caller(services, "exports.simulate", ctx.headers)
            task = (ctx.headers or {}).get(TASK_HEADER.lower())
            result: ExportOut = await run_tool(
                lambda: services.gateway.simulate_export(
                    caller, task_id=task, resource_id=resource_id, destination=destination
                )
            )
            return result

    return mcp


def create_app(settings: Settings | None = None) -> Starlette:
    settings = settings or get_settings()
    holder = _Holder()
    mcp = build_mcp(holder, settings)
    inner = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,  # no server-side session => no identity carried across requests
        json_response=True,
        max_request_body_size=64 * 1024,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=settings.mcp_allowed_hosts, allowed_origins=[]
        ),
    )

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        install_redaction_on_all_handlers()
        async with open_services(settings) as services:
            holder.services = services
            async with inner.router.lifespan_context(inner):
                yield
            holder.services = None

    async def live(_: Request) -> JSONResponse:
        return JSONResponse({"status": "live"})

    async def ready(_: Request) -> JSONResponse:
        checks = await holder.get().readiness()
        ok = all(checks.values())
        return JSONResponse({"ready": ok, "checks": checks}, status_code=200 if ok else 503)

    return Starlette(
        routes=[Route("/health/live", live), Route("/health/ready", ready), Mount("/", app=inner)],
        lifespan=lifespan,
    )


def app_factory() -> Starlette:
    configure_logging()
    return create_app()
