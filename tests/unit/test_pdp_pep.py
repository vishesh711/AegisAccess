"""OPA client strictness and PEP fail-closed behaviour (fake PDP / fake audit)."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from aegis.audit import AuditEvent, AuditUnavailableError
from aegis.identity import Principal
from aegis.pdp import OpaClient, PdpResult
from aegis.pep import Enforcer, RequestMeta
from aegis.resources import ResourceMeta

ALICE = Principal(
    id="alice", type="human", tenant_id="alpha", roles=("engineer",), active=True, client_id=None
)
DOC = ResourceMeta(
    id="doc-alpha-eng",
    tenant_id="alpha",
    kind="document",
    classification="internal",
    department="engineering",
)


def run(coro: Any) -> Any:
    return asyncio.run(coro)


# ------------------------------------------------------------------------ OPA client


def opa_with(handler: Any) -> OpaClient:
    return OpaClient(
        base_url="http://opa.test",
        token="t" * 20,
        timeout_seconds=0.5,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


@pytest.mark.parametrize(
    ("response", "allow", "status"),
    [
        (httpx.Response(200, json={"result": True}), True, "ok"),
        (httpx.Response(200, json={"result": False}), False, "ok"),
        (httpx.Response(200, json={}), False, "undefined"),
        (httpx.Response(200, json={"result": "true"}), False, "malformed"),
        (httpx.Response(200, json={"result": 1}), False, "malformed"),
        (httpx.Response(200, json={"result": {"allow": True}}), False, "malformed"),
        (httpx.Response(200, json=[True]), False, "malformed"),
        (httpx.Response(200, content=b"<html>ok</html>"), False, "malformed"),
        (httpx.Response(500, json={"result": True}), False, "error"),
        (httpx.Response(401, json={"code": "unauthorized"}), False, "error"),
    ],
)
def test_opa_result_parsing(response: httpx.Response, allow: bool, status: str) -> None:
    res = run(opa_with(lambda _req: response).decide({"x": 1}))
    assert (res.allow, res.status) == (allow, status)


def test_opa_timeout_denies() -> None:
    def slow(_: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    res = run(opa_with(slow).decide({}))
    assert (res.allow, res.status) == (False, "timeout")


def test_opa_connection_error_denies() -> None:
    def down(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    res = run(opa_with(down).decide({}))
    assert (res.allow, res.status) == (False, "error")


def test_opa_sends_bearer_and_input_envelope() -> None:
    seen: dict[str, Any] = {}

    def h(req: httpx.Request) -> httpx.Response:
        seen["auth"] = req.headers.get("authorization")
        seen["path"] = req.url.path
        seen["body"] = req.content
        return httpx.Response(200, json={"result": True})

    run(opa_with(h).decide({"a": 1}))
    assert seen["auth"] == "Bearer " + "t" * 20
    assert seen["path"] == "/v1/data/aegis/authz/allow"
    assert seen["body"] == b'{"input":{"a":1}}'


# ------------------------------------------------------------------------ PEP


class FakePdp:
    def __init__(self, result: PdpResult | Exception) -> None:
        self.result = result
        self.calls: list[dict[str, Any]] = []

    async def decide(self, policy_input: dict[str, Any]) -> PdpResult:
        self.calls.append(policy_input)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    async def explain(self, policy_input: dict[str, Any]) -> list[str]:
        return ["SUBJECT_NOT_GRANTED"]


class FakeAudit:
    def __init__(self, fail: bool = False) -> None:
        self.events: list[AuditEvent] = []
        self.fail = fail

    async def record(self, event: AuditEvent) -> None:
        if self.fail:
            raise AuditUnavailableError()
        self.events.append(event)


def enforcer(pdp: FakePdp, audit: FakeAudit) -> Enforcer:
    return Enforcer(pdp=pdp, audit=audit, policy_version="policy-v1", environment="test")


def test_allow_is_audited() -> None:
    pdp, audit = FakePdp(PdpResult(True, "ok", 1.0)), FakeAudit()
    d = run(
        enforcer(pdp, audit).authorize(
            RequestMeta(origin="api"), subject=ALICE, action="documents:read", resource=DOC
        )
    )
    assert d.allow and d.http_status == 200
    assert [e.decision for e in audit.events] == ["allow"]


def test_audit_failure_converts_allow_to_deny() -> None:
    """Fail closed: without a durable decision record there must be no side effect."""
    pdp, audit = FakePdp(PdpResult(True, "ok", 1.0)), FakeAudit(fail=True)
    d = run(
        enforcer(pdp, audit).authorize(
            RequestMeta(origin="api"), subject=ALICE, action="documents:read", resource=DOC
        )
    )
    assert not d.allow
    assert d.http_status == 503
    assert d.reason_codes == ("AUDIT_UNAVAILABLE",)


@pytest.mark.parametrize("status", ["timeout", "error", "malformed", "undefined"])
def test_evaluator_failures_deny_with_incident(status: str) -> None:
    pdp, audit = FakePdp(PdpResult(False, status, 1.0)), FakeAudit()  # type: ignore[arg-type]
    d = run(
        enforcer(pdp, audit).authorize(
            RequestMeta(origin="api"), subject=ALICE, action="documents:read", resource=DOC
        )
    )
    assert not d.allow and d.http_status == 503
    assert audit.events[0].event_kind == "incident"
    assert audit.events[0].reason_code == "POLICY_UNAVAILABLE"


def test_pdp_client_exception_denies() -> None:
    pdp, audit = FakePdp(RuntimeError("bug")), FakeAudit()
    d = run(
        enforcer(pdp, audit).authorize(
            RequestMeta(origin="api"), subject=ALICE, action="documents:read", resource=DOC
        )
    )
    assert not d.allow and d.http_status == 503


def test_policy_deny_is_403_with_reasons() -> None:
    pdp, audit = FakePdp(PdpResult(False, "ok", 1.0)), FakeAudit()
    d = run(
        enforcer(pdp, audit).authorize(
            RequestMeta(origin="api"), subject=ALICE, action="documents:read", resource=DOC
        )
    )
    assert not d.allow and d.http_status == 403
    assert d.public_reason == "ACCESS_DENIED"
    assert audit.events[0].reason_code == "SUBJECT_NOT_GRANTED"


def test_unknown_resource_and_action_never_reach_pdp() -> None:
    pdp, audit = FakePdp(PdpResult(True, "ok", 1.0)), FakeAudit()
    e = enforcer(pdp, audit)
    d1 = run(e.authorize(RequestMeta(origin="api"), subject=ALICE, action="documents:read", resource=None))
    d2 = run(e.authorize(RequestMeta(origin="api"), subject=ALICE, action="documents:delete", resource=DOC))
    assert not d1.allow and not d2.allow
    assert pdp.calls == []
    assert [ev.reason_code for ev in audit.events] == ["RESOURCE_NOT_FOUND", "UNKNOWN_ACTION"]


def test_canonical_input_built_from_server_state() -> None:
    pdp, audit = FakePdp(PdpResult(False, "ok", 1.0)), FakeAudit()
    run(
        enforcer(pdp, audit).authorize(
            RequestMeta(origin="api"), subject=ALICE, action="documents:read", resource=DOC
        )
    )
    i = pdp.calls[0]
    assert i == {
        "subject": {
            "id": "alice",
            "type": "human",
            "tenant_id": "alpha",
            "roles": ["engineer"],
            "active": True,
        },
        "action": "documents:read",
        "resource": {
            "id": "doc-alpha-eng",
            "tenant_id": "alpha",
            "kind": "document",
            "classification": "internal",
            "department": "engineering",
        },
        "context": {"environment": "test", "request_origin": "api"},
        "policy_version": "policy-v1",
    }
