"""Runs last (file name): scans everything the suite produced for leaked secrets or protected content.

* audit_events rows: no tokens, signatures, passwords, client secrets or document canaries
* application logs (raw messages, BEFORE the redaction filter): no tokens, secrets or canaries
* stored reports: no restricted (payroll) content
"""

from __future__ import annotations

from typing import Any

import psycopg
import pytest

from tests.conftest import CANARIES, CLIENT_SECRETS, OWNER_DSN, PASSWORDS, Keycloak, LogCapture

pytestmark = pytest.mark.security


def _needles(kc: Keycloak) -> list[str]:
    needles = (
        list(CANARIES) + list(PASSWORDS.values()) + list(CLIENT_SECRETS.values()) + ["dummy-opa-pep-token"]
    )
    for tok in kc.issued:
        needles.append(tok)
        needles.append(tok.split(".")[2][:24])  # signature fragment
    return needles


def test_audit_trail_contains_no_secrets_or_content(kc: Keycloak, record: Any) -> None:
    assert kc.issued, "suite must have issued tokens before this check"
    with psycopg.connect(OWNER_DSN) as conn:
        rows = conn.execute("SELECT * FROM audit_events").fetchall()
    blob = "\n".join("|".join("" if v is None else str(v) for v in row) for row in rows)
    leaks = [n[:12] + "..." for n in _needles(kc) if n and n in blob]
    record(
        scenario_id="AUDIT-SECRECY",
        description=f"Scan of {len(rows)} audit rows for tokens/secrets/canaries",
        request="SELECT * FROM audit_events",
        expected_decision="clean",
        actual_decision="clean" if not leaks else "leak",
        expected_side_effects=0,
        actual_side_effects=len(leaks),
        audit_events=len(rows),
        attack=False,
    )
    assert len(rows) > 50
    assert leaks == []
    assert "eyJ" not in blob and "Bearer" not in blob


def test_logs_contain_no_secrets_or_content(captured_logs: LogCapture, kc: Keycloak, record: Any) -> None:
    assert captured_logs.records, "log capture saw nothing"
    blob = "\n".join(captured_logs.records)
    leaks = [n[:12] + "..." for n in _needles(kc) if n and n in blob]
    record(
        scenario_id="LOG-SECRECY",
        description=f"Scan of {len(captured_logs.records)} raw log records",
        request="captured application/library logs",
        expected_decision="clean",
        actual_decision="clean" if not leaks else "leak",
        expected_side_effects=0,
        actual_side_effects=len(leaks),
        audit_events=0,
        attack=False,
    )
    assert leaks == []


def test_reports_contain_no_restricted_content() -> None:
    with psycopg.connect(OWNER_DSN) as conn:
        rows = conn.execute("SELECT summary_text, source_document_ids FROM reports").fetchall()
    assert rows
    for summary, sources in rows:
        assert "doc-alpha-payroll" not in sources
        assert "AEGIS-CANARY-PAYROLL-7731" not in summary


def test_runtime_role_cannot_tamper_with_audit(record: Any) -> None:
    from tests.conftest import APP_DSN

    outcomes = []
    with psycopg.connect(APP_DSN, autocommit=True) as conn:
        for sql in (
            "UPDATE audit_events SET decision = 'allow'",
            "DELETE FROM audit_events",
            "TRUNCATE audit_events",
        ):
            try:
                conn.execute(sql)  # type: ignore[arg-type]
                outcomes.append("allowed")
            except psycopg.errors.InsufficientPrivilege:
                outcomes.append("denied")
    record(
        scenario_id="AUDIT-IMMUTABLE",
        description="Runtime DB role attempts UPDATE/DELETE/TRUNCATE on audit",
        request="aegis_app: UPDATE/DELETE/TRUNCATE audit_events",
        expected_decision="deny",
        actual_decision="deny" if set(outcomes) == {"denied"} else "allow",
        expected_side_effects=0,
        actual_side_effects=outcomes.count("allowed"),
        audit_events=0,
        attack=True,
    )
    assert outcomes == ["denied"] * 3
