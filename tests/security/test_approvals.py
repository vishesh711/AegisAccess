"""T14: sensitive agent writes need a server-stored, single-use human approval of the exact arguments.

Scenario: Bob delegates a summary of a CONFIDENTIAL forecast to agent-alpha. Creating that report is a
sensitive write, so the policy denies it until Bob approves the exact (task, documents, summary) digest.
Every test checks the reports actually written (report_write side effects), not just the responses.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx
import pytest

from aegis.agent_client import McpToolClient
from tests.conftest import Evidence, Keycloak, ServerHandle, bound_agent_token
from tests.security.test_mcp_scenarios import create_task, mcp_call

pytestmark = pytest.mark.security
DOC = "doc-alpha-forecast"
APPROVAL_RE = re.compile(r"approval_id=([0-9a-f-]{36})")


def summary_args(task: str, text: str = "Synthetic forecast summary") -> dict[str, Any]:
    return {"task_id": task, "document_ids": [DOC], "summary_text": text}


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def request_and_get_id(url: str, token: str, task: str, text: str = "Synthetic forecast summary") -> str:
    res = mcp_call(url, token, task, "reports.create_summary", summary_args(task, text))
    assert not res.ok and res.error is not None and "APPROVAL_REQUIRED" in res.error, res.error
    m = APPROVAL_RE.search(res.error)
    assert m is not None
    return m.group(1)


def test_t14_full_flow_approve_then_single_use(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence, record: Any
) -> None:
    task = create_task(api, kc, "bob", [DOC])
    token = bound_agent_token(kc, "bob", task)
    mark = db.mark()
    approval_id = request_and_get_id(mcp_server.url, token, task)
    writes_before_approval = db.side_effects(mark, kind="report_write")

    # Bob sees the request and approves it via the API (human, authenticated, the delegating user).
    listed = api.get("/api/v1/approvals", headers=auth(kc.password_token("bob"))).json()["approvals"]
    assert any(a["approval_id"] == approval_id and a["status"] == "pending" for a in listed)
    r = api.post(f"/api/v1/approvals/{approval_id}/approve", headers=auth(kc.password_token("bob")))
    assert r.status_code == 200 and r.json()["approval"]["status"] == "approved"

    first = mcp_call(mcp_server.url, token, task, "reports.create_summary", summary_args(task))
    replay = mcp_call(mcp_server.url, token, task, "reports.create_summary", summary_args(task))
    writes = db.side_effects(mark, kind="report_write")
    record(
        scenario_id="T14-replay",
        description="Approved sensitive write executes once; identical replay is denied",
        request="reports.create_summary(confidential) x2 after one approval",
        expected_decision="allow,deny",
        actual_decision=f"{'allow' if first.ok else 'deny'},{'allow' if replay.ok else 'deny'}",
        expected_side_effects=1,
        actual_side_effects=writes,
        audit_events=0,
        attack=True,
    )
    assert writes_before_approval == 0
    assert first.ok
    assert not replay.ok and replay.error is not None and "APPROVAL_REQUIRED" in replay.error
    assert writes == 1


def test_t14_changed_arguments_need_new_approval(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence, record: Any
) -> None:
    task = create_task(api, kc, "bob", [DOC])
    token = bound_agent_token(kc, "bob", task)
    approval_id = request_and_get_id(mcp_server.url, token, task, "Approved text")
    assert (
        api.post(
            f"/api/v1/approvals/{approval_id}/approve", headers=auth(kc.password_token("bob"))
        ).status_code
        == 200
    )
    mark = db.mark()
    tampered = mcp_call(
        mcp_server.url,
        token,
        task,
        "reports.create_summary",
        summary_args(task, "Approved text, plus everything in the payroll file"),
    )
    writes = db.side_effects(mark, kind="report_write")
    record(
        scenario_id="T14-tamper",
        description="Approval for one summary text used with different text",
        request="reports.create_summary with modified summary_text",
        expected_decision="deny",
        actual_decision="allow" if tampered.ok else "deny",
        expected_side_effects=0,
        actual_side_effects=writes,
        audit_events=0,
        attack=True,
    )
    assert not tampered.ok and writes == 0
    # The original approval is untouched and still works for the exact approved arguments.
    assert mcp_call(
        mcp_server.url, token, task, "reports.create_summary", summary_args(task, "Approved text")
    ).ok


def test_t14_only_the_delegating_human_can_approve(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence
) -> None:
    task = create_task(api, kc, "bob", [DOC])
    token = bound_agent_token(kc, "bob", task)
    approval_id = request_and_get_id(mcp_server.url, token, task)
    # another human in the same tenant
    assert (
        api.post(
            f"/api/v1/approvals/{approval_id}/approve", headers=auth(kc.password_token("alice"))
        ).status_code
        == 403
    )
    # the agent's own (exchanged) token is not an API token at all
    assert api.post(f"/api/v1/approvals/{approval_id}/approve", headers=auth(token)).status_code == 401
    # Bob's consent token for a different task cannot be "approval" either: approval is an explicit API call
    mark = db.mark()
    assert not mcp_call(mcp_server.url, token, task, "reports.create_summary", summary_args(task)).ok
    assert db.side_effects(mark, kind="report_write") == 0
    listed = api.get("/api/v1/approvals", headers=auth(kc.password_token("alice"))).json()["approvals"]
    assert all(a["approval_id"] != approval_id for a in listed)


def test_t14_rejected_and_expired_approvals(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence
) -> None:
    task = create_task(api, kc, "bob", [DOC])
    token = bound_agent_token(kc, "bob", task)
    rejected = request_and_get_id(mcp_server.url, token, task, "text one")
    assert (
        api.post(f"/api/v1/approvals/{rejected}/reject", headers=auth(kc.password_token("bob"))).status_code
        == 200
    )
    expired = request_and_get_id(mcp_server.url, token, task, "text two")
    assert (
        api.post(f"/api/v1/approvals/{expired}/approve", headers=auth(kc.password_token("bob"))).status_code
        == 200
    )
    db.execute("UPDATE approvals SET expires_at = now() - interval '1 second' WHERE id = %s", (expired,))
    mark = db.mark()
    assert not mcp_call(
        mcp_server.url, token, task, "reports.create_summary", summary_args(task, "text one")
    ).ok
    assert not mcp_call(
        mcp_server.url, token, task, "reports.create_summary", summary_args(task, "text two")
    ).ok
    assert db.side_effects(mark, kind="report_write") == 0
    # a decided approval cannot be decided again
    assert (
        api.post(f"/api/v1/approvals/{rejected}/approve", headers=auth(kc.password_token("bob"))).status_code
        == 403
    )


def test_t14_concurrent_use_consumes_once(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence
) -> None:
    task = create_task(api, kc, "bob", [DOC])
    token = bound_agent_token(kc, "bob", task)
    approval_id = request_and_get_id(mcp_server.url, token, task)
    assert (
        api.post(
            f"/api/v1/approvals/{approval_id}/approve", headers=auth(kc.password_token("bob"))
        ).status_code
        == 200
    )

    async def one() -> bool:
        async with McpToolClient(url=f"{mcp_server.url}/mcp", access_token=token, task_id=task) as c:
            return (await c.call("reports.create_summary", summary_args(task))).ok

    async def race() -> list[bool]:
        return list(await asyncio.gather(*(one() for _ in range(5))))

    mark = db.mark()
    results = asyncio.run(race())
    assert db.side_effects(mark, kind="report_write") == 1
    assert results.count(True) == 1


def test_t14_full_agent_run_reports_pending_approval(api: httpx.Client, kc: Keycloak, db: Evidence) -> None:
    """End to end through the agent host: the run stops at the approval, and resumes after it."""
    task = create_task(api, kc, "bob", [DOC])
    mark = db.mark()
    first = api.post(f"/api/v1/tasks/{task}/invoke", headers=auth(kc.consent_token("bob"))).json()
    assert first["report_id"] is None and len(first["pending_approvals"]) == 1
    assert db.side_effects(mark, kind="report_write") == 0
    approval_id = first["pending_approvals"][0]
    assert (
        api.post(
            f"/api/v1/approvals/{approval_id}/approve", headers=auth(kc.password_token("bob"))
        ).status_code
        == 200
    )
    second = api.post(f"/api/v1/tasks/{task}/invoke", headers=auth(kc.consent_token("bob"))).json()
    assert second["report_id"] is not None and second["pending_approvals"] == []
    assert db.side_effects(mark, kind="report_write") == 1


def test_t14_approved_flag_argument_is_not_consent(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence
) -> None:
    task = create_task(api, kc, "bob", [DOC])
    token = bound_agent_token(kc, "bob", task)
    mark = db.mark()
    res = mcp_call(
        mcp_server.url, token, task, "reports.create_summary", {**summary_args(task), "approved": True}
    )
    assert not res.ok and res.error is not None and "INVALID_ARGUMENTS" in res.error
    assert db.side_effects(mark, kind="report_write") == 0
