"""Policy Enforcement Point.

Sequence for every protected operation:
  1. pre-checks that need no policy (unknown resource / action)        -> deny, audited
  2. canonical input built from SERVER-SIDE state only                  -> OPA
  3. any evaluator failure                                              -> deny (503), incident event
  4. decision event persisted BEFORE the caller may run the side effect;
     if that write fails on an allow, the allow is converted to a deny (503).
The caller runs the adapter only when ``Decision.allow`` is true, then records an execution event.
"""

from __future__ import annotations

import logging
import uuid
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from aegis.audit import AuditEvent, AuditSink, AuditUnavailableError
from aegis.identity import Principal
from aegis.pdp import PdpResult

log = logging.getLogger("aegis.pep")

KNOWN_ACTIONS = frozenset(
    {
        "documents:read",
        "documents:search",
        "reports:create",
        "audit:read",
        "policy:simulate",
        "exports:simulate",
    }
)
Origin = Literal["api", "mcp"]
EVALUATOR_FAILURES = frozenset({"timeout", "error", "malformed", "undefined"})


class PolicyDecisionPoint(Protocol):
    async def decide(self, policy_input: dict[str, Any]) -> PdpResult: ...

    async def explain(self, policy_input: dict[str, Any]) -> list[str]: ...


@dataclass(frozen=True, slots=True)
class RequestMeta:
    origin: Origin
    request_id: uuid.UUID = field(default_factory=uuid.uuid4)
    correlation_id: uuid.UUID = field(default_factory=uuid.uuid4)
    tool_name: str | None = None
    test_case_id: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyResource:
    """Policy view of a resource (documents come from ``ResourceMeta.to_policy``)."""

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


class SupportsPolicy(Protocol):
    @property
    def id(self) -> str: ...

    def to_policy(self) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class DelegationInput:
    task_id: uuid.UUID
    valid: bool
    user_id: str
    agent_id: str
    actions: tuple[str, ...]
    resource_ids: tuple[str, ...]

    def to_policy(self) -> dict[str, Any]:
        return {
            "task_id": str(self.task_id),
            "valid": self.valid,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "actions": list(self.actions),
            "resource_ids": list(self.resource_ids),
        }


@dataclass(frozen=True, slots=True)
class Decision:
    allow: bool
    reason_codes: tuple[str, ...]
    evaluator_status: str
    policy_version: str
    duration_ms: float
    request_id: uuid.UUID
    correlation_id: uuid.UUID

    @property
    def dependency_failure(self) -> bool:
        return self.evaluator_status in EVALUATOR_FAILURES or self.evaluator_status == "audit_unavailable"

    @property
    def http_status(self) -> int:
        if self.allow:
            return 200
        return 503 if self.dependency_failure else 403

    @property
    def public_reason(self) -> str:
        if self.allow:
            return "ALLOWED"
        return "DEPENDENCY_UNAVAILABLE" if self.dependency_failure else "ACCESS_DENIED"


class Enforcer:
    def __init__(
        self, *, pdp: PolicyDecisionPoint, audit: AuditSink, policy_version: str, environment: str
    ) -> None:
        self._pdp = pdp
        self._audit = audit
        self.policy_version = policy_version
        self._environment = environment

    def build_input(
        self,
        *,
        subject: Principal,
        action: str,
        resource: SupportsPolicy,
        origin: Origin,
        agent: Principal | None = None,
        delegation: DelegationInput | None = None,
    ) -> dict[str, Any]:
        policy_input: dict[str, Any] = {
            "subject": subject.to_policy(),
            "action": action,
            "resource": resource.to_policy(),
            "context": {"environment": self._environment, "request_origin": origin},
            "policy_version": self.policy_version,
        }
        if agent is not None:
            policy_input["agent"] = agent.to_policy()
        if delegation is not None:
            policy_input["delegation"] = delegation.to_policy()
        return policy_input

    def _event(
        self,
        meta: RequestMeta,
        *,
        kind: str,
        subject: Principal | None,
        action: str | None,
        resource_id: str | None,
        decision: str,
        reason: str,
        status: str,
        agent: Principal | None = None,
        task_id: uuid.UUID | None = None,
        outcome: str | None = None,
        duration_ms: float | None = None,
    ) -> AuditEvent:
        return AuditEvent(
            event_kind=kind,
            correlation_id=meta.correlation_id,
            request_id=meta.request_id,
            decision=decision,
            reason_code=reason,
            evaluator_status=status,
            principal_type=subject.type if subject else None,
            principal_id=subject.id if subject else None,
            tenant_id=subject.tenant_id if subject else None,
            agent_id=agent.id if agent else None,
            task_id=task_id,
            tool_name=meta.tool_name,
            action=action,
            resource_id=resource_id,
            policy_version=self.policy_version,
            outcome=outcome,
            duration_ms=duration_ms,
            request_origin=meta.origin,
            test_case_id=meta.test_case_id,
        )

    async def deny_without_evaluation(
        self,
        meta: RequestMeta,
        *,
        subject: Principal | None,
        action: str | None,
        resource_id: str | None,
        reason: str,
        agent: Principal | None = None,
        task_id: uuid.UUID | None = None,
        kind: str = "decision",
        status: str = "not_evaluated",
    ) -> Decision:
        """Deny decided by the PEP itself (e.g. unknown resource, invalid delegation). Audited best-effort."""
        with suppress(AuditUnavailableError):  # a deny stays a deny
            await self._audit.record(
                self._event(
                    meta,
                    kind=kind,
                    subject=subject,
                    action=action,
                    resource_id=resource_id,
                    decision="deny",
                    reason=reason,
                    status=status,
                    agent=agent,
                    task_id=task_id,
                )
            )
        return Decision(
            allow=False,
            reason_codes=(reason,),
            evaluator_status=status,
            policy_version=self.policy_version,
            duration_ms=0.0,
            request_id=meta.request_id,
            correlation_id=meta.correlation_id,
        )

    async def authorize(
        self,
        meta: RequestMeta,
        *,
        subject: Principal,
        action: str,
        resource: SupportsPolicy | None,
        agent: Principal | None = None,
        delegation: DelegationInput | None = None,
    ) -> Decision:
        task_id = delegation.task_id if delegation else None
        if resource is None:
            return await self.deny_without_evaluation(
                meta,
                subject=subject,
                action=action,
                resource_id=None,
                reason="RESOURCE_NOT_FOUND",
                agent=agent,
                task_id=task_id,
            )
        if action not in KNOWN_ACTIONS:
            return await self.deny_without_evaluation(
                meta,
                subject=subject,
                action=action,
                resource_id=resource.id,
                reason="UNKNOWN_ACTION",
                agent=agent,
                task_id=task_id,
            )

        policy_input = self.build_input(
            subject=subject,
            action=action,
            resource=resource,
            origin=meta.origin,
            agent=agent,
            delegation=delegation,
        )
        try:
            result = await self._pdp.decide(policy_input)
        except Exception as exc:  # defensive: an unexpected PDP client bug must still deny
            log.error("pdp client failure", extra={"fields": {"exc_type": type(exc).__name__}})
            result = PdpResult(allow=False, status="error", duration_ms=0.0)

        kind = "decision"
        if result.status != "ok":
            reasons: tuple[str, ...] = ("POLICY_UNAVAILABLE",)
            kind = "incident"
            allow = False
        elif result.allow:
            reasons = ("ALLOW",)
            allow = True
        else:
            reasons = tuple(await self._pdp.explain(policy_input))
            allow = False

        status: str = result.status
        try:
            await self._audit.record(
                self._event(
                    meta,
                    kind=kind,
                    subject=subject,
                    action=action,
                    resource_id=resource.id,
                    decision="allow" if allow else "deny",
                    reason=",".join(reasons),
                    status=status,
                    agent=agent,
                    task_id=task_id,
                    duration_ms=result.duration_ms,
                )
            )
        except AuditUnavailableError:
            if allow:
                # Fail closed: no side effect without a durable decision record.
                allow, reasons, status = False, ("AUDIT_UNAVAILABLE",), "audit_unavailable"

        return Decision(
            allow=allow,
            reason_codes=reasons,
            evaluator_status=status,
            policy_version=self.policy_version,
            duration_ms=result.duration_ms,
            request_id=meta.request_id,
            correlation_id=meta.correlation_id,
        )

    async def record_execution(
        self,
        meta: RequestMeta,
        *,
        subject: Principal,
        action: str,
        resource_id: str | None,
        outcome: str,
        agent: Principal | None = None,
        task_id: uuid.UUID | None = None,
    ) -> None:
        try:
            await self._audit.record(
                self._event(
                    meta,
                    kind="execution",
                    subject=subject,
                    action=action,
                    resource_id=resource_id,
                    decision="n/a",
                    reason="EXECUTED" if outcome == "success" else "EXECUTION_FAILED",
                    status="ok",
                    agent=agent,
                    task_id=task_id,
                    outcome=outcome,
                )
            )
        except AuditUnavailableError:
            log.error("execution audit write failed", extra={"fields": {"request_id": str(meta.request_id)}})

    async def record_authn_failure(self, meta: RequestMeta, reason: str) -> None:
        """Sanitized authentication failure (no token material)."""
        with suppress(AuditUnavailableError):
            await self._audit.record(
                AuditEvent(
                    event_kind="authn",
                    correlation_id=meta.correlation_id,
                    request_id=meta.request_id,
                    decision="deny",
                    reason_code=reason,
                    evaluator_status="not_evaluated",
                    request_origin=meta.origin,
                    tool_name=meta.tool_name,
                    test_case_id=meta.test_case_id,
                    policy_version=self.policy_version,
                )
            )
