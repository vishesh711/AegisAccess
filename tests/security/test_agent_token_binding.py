"""T13: agent tokens are bound to one consenting user and one task (Keycloak standard token exchange).

Threat closed: before this, anyone holding an agent's client secret could mint an agent token and use
ANY task delegated to that agent. Now an agent token exists only by exchanging a user's consent token,
carries that user as ``sub`` and the agent as ``azp``, and is bound server-side to exactly one task.
Every test checks the observed side effects in PostgreSQL, not only the response.
"""

from __future__ import annotations

from typing import Any

import httpx
import psycopg
import pytest

from tests.conftest import (
    APP_DSN,
    CLIENT_SECRETS,
    TOKEN_URL,
    Evidence,
    Keycloak,
    ServerHandle,
    bound_agent_token,
)
from tests.security.test_mcp_scenarios import create_task, denied, mcp_call

pytestmark = pytest.mark.security
READ = ("documents.read", {"resource_id": "doc-alpha-eng"})
EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS = "urn:ietf:params:oauth:token-type:access_token"


def _exchange(kc: Keycloak, subject: str, agent: str) -> httpx.Response:
    return kc.http.post(
        TOKEN_URL,
        data={
            "grant_type": EXCHANGE,
            "subject_token": subject,
            "subject_token_type": ACCESS,
            "requested_token_type": ACCESS,
        },
        auth=(agent, CLIENT_SECRETS[agent]),
    )


def test_t13_stolen_agent_secret_cannot_mint_tokens(kc: Keycloak, record: Any) -> None:
    """An attacker with agent-alpha's secret gets nothing: no service account, and a leaked ordinary user
    token cannot be exchanged because it does not name the agent in its audience (no consent)."""
    cc = kc.http.post(
        TOKEN_URL,
        data={"grant_type": "client_credentials"},
        auth=("agent-alpha", CLIENT_SECRETS["agent-alpha"]),
    )
    leaked_plain = _exchange(kc, kc.password_token("alice"), "agent-alpha")
    consent_for_alpha_used_by_beta = _exchange(kc, kc.consent_token("alice", "agent-alpha"), "agent-beta")
    record(
        scenario_id="T13-secret",
        description="Stolen agent secret: client credentials, exchange of a "
        "non-consent user token, exchange of another agent's consent token",
        request="Keycloak token endpoint x3",
        expected_decision="refused",
        actual_decision="refused"
        if {cc.status_code, leaked_plain.status_code, consent_for_alpha_used_by_beta.status_code}
        <= {400, 401, 403}
        else "issued",
        expected_side_effects=0,
        actual_side_effects=0,
        audit_events=0,
        attack=True,
    )
    assert cc.status_code in (400, 401) and "access_token" not in cc.text
    assert leaked_plain.status_code == 403 and "access_token" not in leaked_plain.text
    assert consent_for_alpha_used_by_beta.status_code == 403


def test_t13_agent_own_token_rejected_by_mcp(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence, record: Any
) -> None:
    """agent-beta is deliberately misconfigured with a service account. Its own token (sub = the agent) is
    refused by the MCP server: an agent may act only for a consenting human."""
    task = create_task(api, kc, "carol", ["doc-beta-eng"], agent="agent-beta")
    own = kc.client_token("agent-beta")
    mark, since = db.mark(), db.now()
    res = mcp_call(mcp_server.url, own, task, "documents.read", {"resource_id": "doc-beta-eng"})
    effects = db.side_effects(mark)
    authn = [e for e in db.audit_since(since) if e["event_kind"] == "authn"]
    record(
        scenario_id="T13-own-token",
        description="Agent's own client-credentials token at the MCP server",
        request="documents.read(doc-beta-eng) with agent-beta's own token",
        expected_decision="deny",
        actual_decision="allow" if res.ok else "deny",
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=len(authn),
        attack=True,
    )
    assert denied(res) and effects == 0
    assert any(e["reason_code"] == "DELEGATED_TOKEN_REQUIRED" for e in authn)


def test_t13_unbound_and_cross_task_tokens(
    mcp_server: ServerHandle, api: httpx.Client, kc: Keycloak, db: Evidence, record: Any
) -> None:
    task_a = create_task(api, kc, "alice", ["doc-alpha-eng"])
    task_b = create_task(api, kc, "alice", ["doc-alpha-eng"])
    bob_task = create_task(api, kc, "bob", ["doc-alpha-finance-notes"])
    unbound = kc.exchanged_token("alice")  # valid exchange, never bound by the agent host
    bound_a = bound_agent_token(kc, "alice", task_a)
    bob_bound = bound_agent_token(kc, "bob", bob_task)
    mark, since = db.mark(), db.now()
    results = {
        "unbound": mcp_call(mcp_server.url, unbound, task_a, *READ),
        "bound_to_other_task": mcp_call(mcp_server.url, bound_a, task_b, *READ),
        "other_users_token": mcp_call(mcp_server.url, bob_bound, task_a, *READ),
    }
    effects = db.side_effects(mark)
    reasons = {e["reason_code"] for e in db.audit_since(since) if e["decision"] == "deny"}
    record(
        scenario_id="T13-binding",
        description="Unbound token; token bound to another task; another user's bound token",
        request="documents.read(doc-alpha-eng) x3",
        expected_decision="deny",
        actual_decision="deny" if all(denied(r) for r in results.values()) else "allow",
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=len(reasons),
        attack=True,
    )
    for name, res in results.items():
        assert denied(res), name
    assert effects == 0
    assert {"TOKEN_NOT_BOUND", "TOKEN_NOT_BOUND_TO_TASK"} <= reasons
    # sanity: the same bound token works for the task it was bound to
    assert mcp_call(mcp_server.url, bound_a, task_a, *READ).ok


def test_t13_invoke_requires_consent(api: httpx.Client, kc: Keycloak, db: Evidence) -> None:
    task = create_task(api, kc, "alice", ["doc-alpha-eng"])
    mark = db.mark()
    r = api.post(
        f"/api/v1/tasks/{task}/invoke", headers={"Authorization": f"Bearer {kc.password_token('alice')}"}
    )
    assert r.status_code == 403
    assert r.json()["consent_scope"] == "delegate-agent-alpha"
    assert db.side_effects(mark) == 0
    assert db.audit_for_request(r.json()["request_id"])[0]["reason_code"] == "CONSENT_REQUIRED"


def test_t13_exchanged_token_is_not_an_api_token(api: httpx.Client, kc: Keycloak, db: Evidence) -> None:
    mark = db.mark()
    r = api.get(
        "/api/v1/resources/doc-alpha-eng", headers={"Authorization": f"Bearer {kc.exchanged_token('alice')}"}
    )
    assert r.status_code == 401 and db.side_effects(mark) == 0


def test_t13_bindings_cannot_be_repointed() -> None:
    with psycopg.connect(APP_DSN, autocommit=True) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE agent_token_bindings SET task_id = task_id")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM agent_token_bindings")
