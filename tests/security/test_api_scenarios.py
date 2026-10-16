"""T01-T03 and related identity/tenancy scenarios against real Keycloak + OPA + PostgreSQL.

Every test asserts the HTTP outcome AND the observed side effects in PostgreSQL AND the audit trail.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from tests.conftest import CANARIES, Evidence, Keycloak

pytestmark = pytest.mark.security


def get(api: httpx.Client, token: str, rid: str, **headers: str) -> httpx.Response:
    return api.get(f"/api/v1/resources/{rid}", headers={"Authorization": f"Bearer {token}", **headers})


def test_t01_alice_reads_alpha_engineering(
    api: httpx.Client, kc: Keycloak, db: Evidence, record: Any
) -> None:
    mark = db.mark()
    r = get(api, kc.password_token("alice"), "doc-alpha-eng")
    reads = db.side_effects(mark, kind="document_read", resource_id="doc-alpha-eng")
    audit = db.audit_for_request(r.json()["request_id"])
    record(
        scenario_id="T01",
        description="Alice reads alpha engineering document",
        request="GET /api/v1/resources/doc-alpha-eng (alice token)",
        expected_decision="allow",
        actual_decision=r.json()["decision"],
        expected_side_effects=1,
        actual_side_effects=reads,
        audit_events=len(audit),
        attack=False,
    )
    assert r.status_code == 200
    assert r.json()["document"]["id"] == "doc-alpha-eng"
    assert reads == 1
    assert db.side_effects(mark) == 1  # nothing else happened
    assert [(e["event_kind"], e["decision"]) for e in audit] == [("decision", "allow"), ("execution", "n/a")]
    assert audit[0]["principal_id"] == "alice" and audit[0]["tenant_id"] == "alpha"
    assert audit[0]["evaluator_status"] == "ok" and audit[0]["policy_version"] == "policy-v1"


def test_t02_alice_denied_payroll(api: httpx.Client, kc: Keycloak, db: Evidence, record: Any) -> None:
    mark = db.mark()
    r = get(api, kc.password_token("alice"), "doc-alpha-payroll")
    effects = db.side_effects(mark)
    audit = db.audit_for_request(r.json()["request_id"])
    record(
        scenario_id="T02",
        description="Alice (engineer) reads restricted payroll",
        request="GET /api/v1/resources/doc-alpha-payroll (alice token)",
        expected_decision="deny",
        actual_decision=r.json()["decision"],
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=len(audit),
        attack=True,
    )
    assert r.status_code == 403
    assert r.json() == {
        "request_id": r.json()["request_id"],
        "decision": "deny",
        "reason_code": "ACCESS_DENIED",
        "policy_version": "policy-v1",
    }
    assert "AEGIS-CANARY-PAYROLL-7731" not in r.text
    assert effects == 0
    assert len(audit) == 1 and audit[0]["decision"] == "deny"
    assert audit[0]["reason_code"] == "SUBJECT_NOT_GRANTED"


def test_t03_cross_tenant_idor(api: httpx.Client, kc: Keycloak, db: Evidence, record: Any) -> None:
    mark = db.mark()
    r = get(api, kc.password_token("alice"), "doc-beta-eng")
    effects = db.side_effects(mark)
    audit = db.audit_for_request(r.json()["request_id"])
    record(
        scenario_id="T03",
        description="Alice guesses beta tenant document id (IDOR)",
        request="GET /api/v1/resources/doc-beta-eng (alice token)",
        expected_decision="deny",
        actual_decision=r.json()["decision"],
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=len(audit),
        attack=True,
    )
    assert r.status_code == 403
    assert "AEGIS-CANARY-BETA-8814" not in r.text and "Beta" not in r.text
    assert effects == 0
    assert audit[0]["reason_code"] == "TENANT_MISMATCH"


def test_cross_tenant_response_indistinguishable_from_missing(api: httpx.Client, kc: Keycloak) -> None:
    """No existence oracle: another tenant's id and a nonexistent id look identical to the caller."""
    tok = kc.password_token("alice")
    a, b = get(api, tok, "doc-beta-eng"), get(api, tok, "doc-does-not-exist")
    assert a.status_code == b.status_code == 403
    assert {k: v for k, v in a.json().items() if k != "request_id"} == {
        k: v for k, v in b.json().items() if k != "request_id"
    }


def test_carol_reads_own_tenant_but_not_alpha(api: httpx.Client, kc: Keycloak, db: Evidence) -> None:
    tok = kc.password_token("carol")
    mark = db.mark()
    assert get(api, tok, "doc-beta-eng").status_code == 200
    assert get(api, tok, "doc-alpha-eng").status_code == 403
    assert db.side_effects(mark, kind="document_read") == 1


def test_bob_finance_reads_payroll(api: httpx.Client, kc: Keycloak, db: Evidence) -> None:
    mark = db.mark()
    r = get(api, kc.password_token("bob"), "doc-alpha-payroll")
    assert r.status_code == 200
    assert db.side_effects(mark, resource_id="doc-alpha-payroll") == 1


def test_workload_uses_its_own_credential(api: httpx.Client, kc: Keycloak, db: Evidence) -> None:
    tok = kc.client_token("svc-reporter")
    mark = db.mark()
    assert get(api, tok, "doc-alpha-eng").status_code == 200
    assert get(api, tok, "doc-alpha-payroll").status_code == 403
    assert db.side_effects(mark, kind="document_read") == 1


def test_deactivated_user_denied(api: httpx.Client, kc: Keycloak, db: Evidence, record: Any) -> None:
    """dave still has a valid Keycloak login, but is inactive in the authorization store."""
    mark = db.mark()
    r = get(api, kc.password_token("dave"), "doc-alpha-eng")
    effects = db.side_effects(mark)
    record(
        scenario_id="X-INACTIVE",
        description="Deactivated employee with valid IdP session",
        request="GET doc-alpha-eng (dave token)",
        expected_decision="deny",
        actual_decision=r.json()["decision"],
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=len(db.audit_for_request(r.json()["request_id"])),
        attack=True,
    )
    assert r.status_code == 403 and effects == 0
    assert db.audit_for_request(r.json()["request_id"])[0]["reason_code"] == "SUBJECT_INACTIVE"


def test_unprovisioned_user_denied(api: httpx.Client, kc: Keycloak, db: Evidence) -> None:
    mark = db.mark()
    r = get(api, kc.password_token("eve"), "doc-alpha-eng")
    assert r.status_code == 403
    assert db.side_effects(mark) == 0
    events = db.audit_for_request(r.json()["request_id"])
    assert events[0]["event_kind"] == "authn" and events[0]["reason_code"] == "UNKNOWN_PRINCIPAL"


def test_secadmin_requires_mfa(kc: Keycloak) -> None:
    import time

    assert kc.password_token("secadmin")  # correct password + TOTP (cached for the session)
    # Keycloak's brute-force "quick login check" locks an account for 60 s when two failures land
    # within 1 s of each other, so the deliberate failures are spaced out.
    no_otp = kc.raw_password_grant("secadmin")
    assert no_otp.status_code in (400, 401)
    time.sleep(1.5)
    wrong_otp = kc.raw_password_grant("secadmin", totp="000000")
    assert wrong_otp.status_code in (400, 401)


def test_audit_api_restricted_to_security_admin(api: httpx.Client, kc: Keycloak) -> None:
    alice = api.get("/api/v1/audit", headers={"Authorization": f"Bearer {kc.password_token('alice')}"})
    assert alice.status_code == 403
    r = api.get(
        "/api/v1/audit?limit=200", headers={"Authorization": f"Bearer {kc.password_token('secadmin')}"}
    )
    assert r.status_code == 200
    events = r.json()["events"]
    assert events and all(e["tenant_id"] == "alpha" for e in events)  # never beta's events
    assert not any(c in r.text for c in CANARIES)


def test_policy_simulation_is_advisory_and_admin_only(api: httpx.Client, kc: Keycloak, db: Evidence) -> None:
    body = {"subject_id": "alice", "action": "documents:read", "resource_id": "doc-alpha-payroll"}
    denied = api.post(
        "/api/v1/policy/simulate",
        json=body,
        headers={"Authorization": f"Bearer {kc.password_token('alice')}"},
    )
    assert denied.status_code == 403
    mark = db.mark()
    r = api.post(
        "/api/v1/policy/simulate",
        json=body,
        headers={"Authorization": f"Bearer {kc.password_token('secadmin')}"},
    )
    assert r.status_code == 200
    assert r.json()["simulation"]["decision"] == "deny"
    assert "SUBJECT_NOT_GRANTED" in r.json()["simulation"]["reasons"]
    assert db.side_effects(mark) == 0  # dry run never executes
    # cannot simulate across tenants
    cross = api.post(
        "/api/v1/policy/simulate",
        json={**body, "resource_id": "doc-beta-eng"},
        headers={"Authorization": f"Bearer {kc.password_token('secadmin')}"},
    )
    assert cross.json()["simulation"]["reasons"] == ["UNKNOWN_SUBJECT_OR_RESOURCE"]
