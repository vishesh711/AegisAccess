"""T12: caller-supplied identity/tenant/role claims (headers, query, body) are ignored or rejected."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from tests.conftest import Evidence, Keycloak

pytestmark = pytest.mark.security

SPOOF_HEADERS = {
    "X-Tenant-Id": "beta",
    "X-User-Id": "bob",
    "X-Roles": "finance-analyst,security-admin",
    "X-Forwarded-User": "bob",
    "X-Remote-User": "bob",
    "X-Auth-Request-User": "bob",
    "X-Principal": '{"id":"bob","tenant_id":"alpha","roles":["finance-analyst"]}',
}


def test_t12_spoofed_headers_and_query(api: httpx.Client, kc: Keycloak, db: Evidence, record: Any) -> None:
    tok = kc.password_token("alice")
    mark = db.mark()
    payroll = api.get(
        "/api/v1/resources/doc-alpha-payroll?tenant_id=alpha&user_id=bob&role=finance-analyst",
        headers={"Authorization": f"Bearer {tok}", **SPOOF_HEADERS},
    )
    beta = api.get(
        "/api/v1/resources/doc-beta-eng?tenant_id=beta",
        headers={"Authorization": f"Bearer {tok}", **SPOOF_HEADERS},
    )
    audit_ = api.get("/api/v1/audit", headers={"Authorization": f"Bearer {tok}", **SPOOF_HEADERS})
    effects = db.side_effects(mark)
    payroll_audit = db.audit_for_request(payroll.json()["request_id"])
    record(
        scenario_id="T12",
        description="Spoofed tenant/user/role headers + query params",
        request="GET payroll / beta doc / audit with X-Tenant-Id, X-User-Id, X-Roles, ?tenant_id=...",
        expected_decision="deny",
        actual_decision="deny"
        if {payroll.status_code, beta.status_code, audit_.status_code} == {403}
        else "allow",
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=len(payroll_audit),
        attack=True,
    )
    assert payroll.status_code == beta.status_code == audit_.status_code == 403
    assert effects == 0
    # The decision was made for the REAL identity from the token.
    assert payroll_audit[0]["principal_id"] == "alice" and payroll_audit[0]["tenant_id"] == "alpha"


def test_t12_body_identity_fields_rejected(api: httpx.Client, kc: Keycloak, db: Evidence) -> None:
    tok = kc.password_token("alice")
    base = {"agent_id": "agent-alpha", "actions": ["documents:read"], "resource_ids": ["doc-alpha-eng"]}
    for extra in (
        {"owner_id": "bob"},
        {"tenant_id": "beta"},
        {"roles": ["finance-analyst"]},
        {"user_id": "bob"},
        {"approved": True},
    ):
        r = api.post("/api/v1/tasks", json={**base, **extra}, headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 422, extra
        assert "bob" not in r.text and "beta" not in r.text  # values never echoed


def test_t12_cannot_delegate_beyond_own_permissions(api: httpx.Client, kc: Keycloak, db: Evidence) -> None:
    """Alice cannot create a task covering payroll or another tenant's document."""
    tok = kc.password_token("alice")
    for rids in (["doc-alpha-payroll"], ["doc-beta-eng"], ["doc-alpha-eng", "doc-alpha-payroll"]):
        r = api.post(
            "/api/v1/tasks",
            json={"agent_id": "agent-alpha", "actions": ["documents:read"], "resource_ids": rids},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r.status_code == 403, rids
    # nor delegate to an agent of another tenant
    r = api.post(
        "/api/v1/tasks",
        json={"agent_id": "agent-beta", "actions": ["documents:read"], "resource_ids": ["doc-alpha-eng"]},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 403
    # nor delegate actions outside the agent-delegable set
    r = api.post(
        "/api/v1/tasks",
        json={"agent_id": "agent-alpha", "actions": ["exports:simulate"], "resource_ids": ["doc-alpha-eng"]},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 422


def test_validation_errors_do_not_echo_input(api: httpx.Client, kc: Keycloak) -> None:
    tok = kc.password_token("alice")
    secret_like = "eyJhbGciOiJIUzI1NiJ9.eyJzZWNyZXQiOiJ4In0.c2lnbmF0dXJlLXNlY3JldA"
    r = api.post(
        "/api/v1/tasks",
        json={"agent_id": secret_like, "actions": ["documents:read"], "resource_ids": ["doc-alpha-eng"]},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 422
    assert secret_like not in r.text
