"""AegisAccess identity-aware API gateway (FastAPI). Every protected route goes through the PEP."""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from aegis.agent_client import McpToolClient
from aegis.agent_tokens import AgentTokenError, consent_scope, issue_task_token
from aegis.authn import JwksUnavailableError, TokenValidationError, VerifiedToken, bearer_from_header
from aegis.config import Settings, get_settings
from aegis.db import tenant_transaction, transaction
from aegis.delegation import AGENT_DELEGABLE_ACTIONS, create_task, load_delegation, parse_task_id, revoke_task
from aegis.identity import IdentityError, Principal, load_principal, resolve_principal
from aegis.logging import configure_logging, install_redaction_on_all_handlers
from aegis.pep import Decision, PolicyResource, RequestMeta
from aegis.planner import DeterministicPlanner
from aegis.resources import get_metadata, valid_resource_id
from aegis.services import Services, open_services

log = logging.getLogger("aegis.api")

_TEST_CASE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
ResourceId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")]


class ApiError(Exception):
    def __init__(self, status: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> None:
        super().__init__(body.get("reason_code", "error"))
        self.status = status
        self.body = body
        self.headers = headers or {}


@dataclass(frozen=True, slots=True)
class Caller:
    principal: Principal
    meta: RequestMeta
    verified: VerifiedToken
    # The raw bearer token is kept only so the agent host can EXCHANGE it at Keycloak (RFC 8693) for a
    # user-bound agent token. It is never logged, stored, or sent to any resource server.
    raw_token: str = field(repr=False, default="")


def _services(request: Request) -> Services:
    services: Services = request.app.state.services
    return services


def _decision_body(d: Decision) -> dict[str, Any]:
    return {
        "request_id": str(d.request_id),
        "decision": "allow" if d.allow else "deny",
        "reason_code": d.public_reason,
        "policy_version": d.policy_version,
    }


def _deny(d: Decision) -> ApiError:
    return ApiError(d.http_status, _decision_body(d))


def _new_meta(request: Request, settings: Settings) -> RequestMeta:
    test_case = request.headers.get("x-aegis-test-case")
    if settings.env not in {"local", "test", "ci"} or not test_case or not _TEST_CASE_RE.fullmatch(test_case):
        test_case = None
    meta = RequestMeta(origin="api", test_case_id=test_case)
    request.state.request_id = meta.request_id
    return meta


async def authenticated(request: Request) -> Caller:
    """Authentication + identity resolution. Headers such as X-Tenant-Id / X-User-Id / X-Roles are
    deliberately never read: identity comes from the verified token and the database only."""
    services = _services(request)
    meta = _new_meta(request, services.settings)
    unauth = {"WWW-Authenticate": 'Bearer error="invalid_token"'}
    token = bearer_from_header(request.headers.get("authorization"))
    if token is None:
        await services.enforcer.record_authn_failure(meta, "MISSING_TOKEN")
        raise ApiError(401, {"request_id": str(meta.request_id), "reason_code": "UNAUTHENTICATED"}, unauth)
    try:
        verified = await services.api_verifier.verify(token)
    except JwksUnavailableError as exc:
        await services.enforcer.record_authn_failure(meta, "JWKS_UNAVAILABLE")
        body = {"request_id": str(meta.request_id), "reason_code": "DEPENDENCY_UNAVAILABLE"}
        raise ApiError(503, body) from exc
    except TokenValidationError as exc:
        await services.enforcer.record_authn_failure(meta, exc.reason)
        raise ApiError(
            401, {"request_id": str(meta.request_id), "reason_code": "UNAUTHENTICATED"}, unauth
        ) from exc
    try:
        principal = await resolve_principal(
            services.pool, verified, human_login_clients=frozenset(services.settings.human_login_clients)
        )
    except IdentityError as exc:
        await services.enforcer.record_authn_failure(meta, exc.reason)
        raise ApiError(403, {"request_id": str(meta.request_id), "reason_code": "ACCESS_DENIED"}) from exc
    return Caller(principal=principal, meta=meta, verified=verified, raw_token=token)


CallerDep = Annotated[Caller, Depends(authenticated)]


# ----------------------------------------------------------------------------- request models


class TaskCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")  # e.g. owner_id / tenant_id in the body -> 422

    agent_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")]
    actions: Annotated[
        list[Literal["documents:read", "documents:search", "reports:create"]],
        Field(min_length=1, max_length=3),
    ]
    resource_ids: Annotated[list[ResourceId], Field(min_length=1, max_length=10)]
    ttl_seconds: Annotated[int, Field(ge=30, le=3600)] = 900
    purpose: Annotated[str, Field(min_length=1, max_length=200)] = "document summary"


class SimulateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")]
    action: Annotated[str, Field(max_length=40)]
    resource_id: ResourceId


# ----------------------------------------------------------------------------- app


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        install_redaction_on_all_handlers()
        async with open_services(settings) as services:
            app.state.services = services
            yield

    app = FastAPI(title="AegisAccess API", version="0.1.0", lifespan=lifespan)

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(status_code=exc.status, content=exc.body, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo submitted values (they could contain secrets or injected text).
        errors = [{"loc": list(e.get("loc", ())), "type": e.get("type")} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"reason_code": "INVALID_REQUEST", "errors": errors})

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.error(
            "unhandled error", extra={"fields": {"exc_type": type(exc).__name__, "path": request.url.path}}
        )
        rid = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=500, content={"reason_code": "INTERNAL_ERROR", "request_id": str(rid)}
        )

    @app.middleware("http")
    async def _headers(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        rid = getattr(request.state, "request_id", None)
        if rid is not None:
            response.headers["X-Request-Id"] = str(rid)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    # ------------------------------------------------------------------ health

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/health/ready")
    async def ready(request: Request) -> JSONResponse:
        checks = await _services(request).readiness()
        ok = all(checks.values())
        return JSONResponse(status_code=200 if ok else 503, content={"ready": ok, "checks": checks})

    # ------------------------------------------------------------------ resources

    @app.get("/api/v1/resources/{resource_id}")
    async def read_resource(resource_id: str, caller: CallerDep, request: Request) -> dict[str, Any]:
        services = _services(request)
        res = await get_metadata(services.pool, resource_id) if valid_resource_id(resource_id) else None
        decision = await services.enforcer.authorize(
            caller.meta, subject=caller.principal, action="documents:read", resource=res
        )
        if not decision.allow or res is None:
            raise _deny(decision)
        doc = await services.store.read(
            tenant_id=caller.principal.tenant_id,
            resource_id=res.id,
            principal_id=caller.principal.id,
            correlation_id=caller.meta.correlation_id,
        )
        await services.enforcer.record_execution(
            caller.meta,
            subject=caller.principal,
            action="documents:read",
            resource_id=res.id,
            outcome="success" if doc else "not_found",
        )
        if doc is None:  # adapter-level tenant guard refused (should be unreachable after policy allow)
            raise ApiError(
                403, {**_decision_body(decision), "decision": "deny", "reason_code": "ACCESS_DENIED"}
            )
        return {
            **_decision_body(decision),
            "document": {
                "id": doc.id,
                "title": doc.title,
                "body": doc.body,
                "classification": doc.classification,
            },
        }

    # ------------------------------------------------------------------ tasks / delegation

    @app.post("/api/v1/tasks", status_code=201)
    async def create_task_route(body: TaskCreate, caller: CallerDep, request: Request) -> dict[str, Any]:
        services = _services(request)
        user = caller.principal
        if user.type != "human":
            d = await services.enforcer.deny_without_evaluation(
                caller.meta,
                subject=user,
                action="tasks:create",
                resource_id=None,
                reason="ONLY_HUMANS_DELEGATE",
            )
            raise _deny(d)
        async with tenant_transaction(services.pool, user.tenant_id) as conn:
            agent = await load_principal(conn, body.agent_id, user.tenant_id)
        if agent is None or agent.type != "agent" or not agent.active:
            d = await services.enforcer.deny_without_evaluation(
                caller.meta,
                subject=user,
                action="tasks:create",
                resource_id=None,
                reason="AGENT_NOT_AVAILABLE",
            )
            raise _deny(d)
        actions: list[str] = sorted(set(body.actions))
        resource_ids = sorted(set(body.resource_ids))
        if not set(actions) <= AGENT_DELEGABLE_ACTIONS:
            raise ApiError(422, {"reason_code": "INVALID_REQUEST"})
        # Cap: the user may only delegate what they could do themselves (checked by the PDP now,
        # and re-checked on every tool call later).
        for action in actions:
            if action == "reports:create":
                targets: list[Any] = [
                    PolicyResource(
                        id="report:new",
                        tenant_id=user.tenant_id,
                        kind="report",
                        classification="internal",
                        department="*",
                    )
                ]
            else:
                targets = [await get_metadata(services.pool, rid) for rid in resource_ids]
            for target in targets:
                d = await services.enforcer.authorize(
                    caller.meta, subject=user, action=action, resource=target
                )
                if not d.allow:
                    raise _deny(d)
        task = await create_task(
            services.pool,
            owner=user,
            agent=agent,
            actions=actions,
            resource_ids=resource_ids,
            ttl_seconds=min(body.ttl_seconds, services.settings.max_task_ttl_seconds),
            purpose=body.purpose,
        )
        return {
            "request_id": str(caller.meta.request_id),
            "task_id": str(task.task_id),
            "agent_id": task.agent_id,
            "actions": list(task.actions),
            "resource_ids": list(task.resource_ids),
            "expires_at": task.expires_at.isoformat(),
        }

    @app.post("/api/v1/tasks/{task_id}/revoke")
    async def revoke_task_route(task_id: str, caller: CallerDep, request: Request) -> dict[str, Any]:
        services = _services(request)
        tid = parse_task_id(task_id)
        if tid is None or not await revoke_task(services.pool, owner=caller.principal, task_id=tid):
            d = await services.enforcer.deny_without_evaluation(
                caller.meta,
                subject=caller.principal,
                action="tasks:revoke",
                resource_id=None,
                reason="TASK_NOT_OWNED",
            )
            raise _deny(d)
        return {"request_id": str(caller.meta.request_id), "task_id": str(tid), "status": "revoked"}

    @app.post("/api/v1/tasks/{task_id}/invoke")
    async def invoke_task(task_id: str, caller: CallerDep, request: Request) -> dict[str, Any]:
        """Run the deterministic agent for a task the caller owns. Every tool call it makes is
        authorized independently by the MCP server using the AGENT's token + stored delegation."""
        services = _services(request)
        settings = services.settings
        tid = parse_task_id(task_id)
        delegation = (
            await load_delegation(services.pool, tenant_id=caller.principal.tenant_id, task_id=tid)
            if tid
            else None
        )
        if delegation is None or delegation.owner_id != caller.principal.id:
            d = await services.enforcer.deny_without_evaluation(
                caller.meta,
                subject=caller.principal,
                action="tasks:invoke",
                resource_id=None,
                reason="TASK_NOT_OWNED",
                task_id=tid,
            )
            raise _deny(d)
        async with tenant_transaction(services.pool, caller.principal.tenant_id) as conn:
            agent = await load_principal(conn, delegation.agent_id, delegation.tenant_id)
        if agent is None or agent.client_id != settings.agent_client_id:
            d = await services.enforcer.deny_without_evaluation(
                caller.meta,
                subject=caller.principal,
                action="tasks:invoke",
                resource_id=None,
                reason="AGENT_HOST_MISMATCH",
                task_id=tid,
            )
            raise _deny(d)
        # Consent: the user's token must name this agent in its audience (scope delegate-<agent>).
        if settings.agent_client_id not in caller.verified.audience:
            d = await services.enforcer.deny_without_evaluation(
                caller.meta,
                subject=caller.principal,
                action="tasks:invoke",
                resource_id=None,
                reason="CONSENT_REQUIRED",
                task_id=tid,
            )
            raise ApiError(
                403, {**_decision_body(d), "consent_scope": consent_scope(settings.agent_client_id)}
            )
        try:
            agent_token = await issue_task_token(
                http=services.http,
                pool=services.pool,
                mcp_verifier=services.mcp_verifier,
                token_endpoint=settings.token_endpoint,
                client_id=settings.agent_client_id,
                client_secret=settings.agent_client_secret.get_secret_value(),
                user_token=caller.raw_token,
                delegation=delegation,
            )
        except AgentTokenError as exc:
            d = await services.enforcer.deny_without_evaluation(
                caller.meta,
                subject=caller.principal,
                action="tasks:invoke",
                resource_id=None,
                reason=exc.reason,
                task_id=tid,
            )
            raise _deny(d) from exc
        planner = DeterministicPlanner()
        async with McpToolClient(
            url=settings.mcp_url,
            access_token=agent_token,
            task_id=str(delegation.task_id),
            correlation_id=caller.meta.correlation_id,
        ) as client:
            run = await planner.run(
                task_id=str(delegation.task_id), resource_ids=list(delegation.resource_ids), client=client
            )
        return {
            "request_id": str(caller.meta.request_id),
            "correlation_id": str(caller.meta.correlation_id),
            "task_id": str(delegation.task_id),
            "report_id": run.report_id,
            "trace": [t.as_dict() for t in run.trace],
        }

    # ------------------------------------------------------------------ audit (security admin)

    @app.get("/api/v1/audit")
    async def read_audit(
        caller: CallerDep,
        request: Request,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        before: datetime | None = None,
        correlation_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        services = _services(request)
        tenant = caller.principal.tenant_id
        target = PolicyResource(
            id=f"audit-log:{tenant}",
            tenant_id=tenant,
            kind="audit_log",
            classification="confidential",
            department="security",
        )
        decision = await services.enforcer.authorize(
            caller.meta, subject=caller.principal, action="audit:read", resource=target
        )
        if not decision.allow:
            raise _deny(decision)
        sql = (
            "SELECT id, event_time, event_kind, correlation_id, request_id, principal_type, principal_id,"
            " tenant_id,"
            " agent_id, task_id, tool_name, action, resource_id, policy_version, decision, reason_code,"
            " evaluator_status, outcome, duration_ms, request_origin, test_case_id FROM audit_events"
            " WHERE tenant_id = %s"
        )
        params: list[Any] = [tenant]
        if before is not None:
            sql += " AND event_time < %s"
            params.append(before)
        if correlation_id is not None:
            sql += " AND correlation_id = %s"
            params.append(correlation_id)
        sql += " ORDER BY event_time DESC LIMIT %s"
        params.append(limit)
        async with transaction(services.pool) as conn:
            rows = await (await conn.execute(sql, params)).fetchall()
        await services.enforcer.record_execution(
            caller.meta,
            subject=caller.principal,
            action="audit:read",
            resource_id=target.id,
            outcome="success",
        )
        events = [
            {k: (str(v) if isinstance(v, uuid.UUID | datetime) else v) for k, v in r.items()} for r in rows
        ]
        return {**_decision_body(decision), "events": events, "count": len(events)}

    # ------------------------------------------------------------------ policy simulation (dry run)

    @app.post("/api/v1/policy/simulate")
    async def simulate(body: SimulateRequest, caller: CallerDep, request: Request) -> dict[str, Any]:
        """Evaluates a hypothetical request in the caller's tenant. Never executes anything and
        cannot change any grant; the result is advisory only."""
        services = _services(request)
        tenant = caller.principal.tenant_id
        target = PolicyResource(
            id=f"policy:{tenant}",
            tenant_id=tenant,
            kind="policy",
            classification="confidential",
            department="security",
        )
        decision = await services.enforcer.authorize(
            caller.meta, subject=caller.principal, action="policy:simulate", resource=target
        )
        if not decision.allow:
            raise _deny(decision)
        async with tenant_transaction(services.pool, tenant) as conn:
            subject = await load_principal(conn, body.subject_id, tenant)
        res = await get_metadata(services.pool, body.resource_id)
        if subject is None or res is None or res.tenant_id != tenant:
            return {
                **_decision_body(decision),
                "simulation": {"decision": "deny", "reasons": ["UNKNOWN_SUBJECT_OR_RESOURCE"]},
            }
        policy_input = services.enforcer.build_input(
            subject=subject, action=body.action, resource=res, origin="api"
        )
        result = await services.pdp.decide(policy_input)
        reasons = (
            []
            if result.allow
            else (
                await services.pdp.explain(policy_input) if result.status == "ok" else ["POLICY_UNAVAILABLE"]
            )
        )
        await services.enforcer.record_execution(
            caller.meta,
            subject=caller.principal,
            action="policy:simulate",
            resource_id=target.id,
            outcome="simulated",
        )
        return {
            **_decision_body(decision),
            "simulation": {
                "decision": "allow" if result.allow else "deny",
                "reasons": reasons,
                "evaluator_status": result.status,
            },
        }

    return app


def app_factory() -> FastAPI:
    configure_logging()
    return create_app()
