"""Database-level and PDP-hardening guarantees, tested directly (defence in depth below the PEP)."""

from __future__ import annotations

import asyncio
import uuid

import httpx
import psycopg
import pytest

from aegis.db import create_pool
from aegis.resources import DocumentStore
from tests.conftest import APP_DSN, OPA_TOKEN, OPA_URL, OWNER_DSN

pytestmark = pytest.mark.integration


@pytest.fixture
def app_conn() -> psycopg.Connection:
    conn = psycopg.connect(APP_DSN, autocommit=True)
    yield conn  # type: ignore[misc]
    conn.close()


# ----------------------------------------------------------------------------- audit immutability


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE audit_events SET decision = 'allow' WHERE decision = 'deny'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ],
)
def test_runtime_role_cannot_mutate_audit(app_conn: psycopg.Connection, sql: str) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app_conn.execute(sql)  # type: ignore[arg-type]


def test_even_owner_cannot_mutate_audit_rows() -> None:
    # Self-contained: write an event as the runtime role first (works on a fresh database too).
    event_id = uuid.uuid4()
    with psycopg.connect(APP_DSN, autocommit=True) as app:
        app.execute(
            "INSERT INTO audit_events (id, event_kind, correlation_id, request_id, decision, reason_code,"
            " evaluator_status) VALUES (%s, 'authn', %s, %s, 'deny', 'TEST_EVENT', 'not_evaluated')",
            (event_id, uuid.uuid4(), uuid.uuid4()),
        )
    with psycopg.connect(OWNER_DSN, autocommit=True) as conn:
        assert conn.execute("SELECT count(*) FROM audit_events WHERE id = %s", (event_id,)).fetchone()[0] == 1  # type: ignore[index]
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            conn.execute("UPDATE audit_events SET reason_code = 'X'")
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            conn.execute("DELETE FROM audit_events")


def test_runtime_role_has_no_ddl_or_side_effect_tampering(app_conn: psycopg.Connection) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app_conn.execute("CREATE TABLE evil (x int)")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app_conn.execute("DELETE FROM resource_side_effects")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app_conn.execute("SELECT count(*) FROM resource_side_effects")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app_conn.execute("UPDATE principal_roles SET role_id = 'finance-analyst'")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app_conn.execute("UPDATE resources SET tenant_id = 'alpha'")


# ----------------------------------------------------------------------------- row-level security


def test_rls_no_tenant_means_no_rows(app_conn: psycopg.Connection) -> None:
    assert app_conn.execute("SELECT count(*) FROM resources").fetchone()[0] == 0  # type: ignore[index]
    assert app_conn.execute("SELECT count(*) FROM tasks").fetchone()[0] == 0  # type: ignore[index]


def test_rls_tenant_scoped_rows(app_conn: psycopg.Connection) -> None:
    with app_conn.transaction():
        app_conn.execute("SELECT set_config('aegis.tenant_id', 'alpha', true)")
        tenants = {r[0] for r in app_conn.execute("SELECT tenant_id FROM resources")}
        body = app_conn.execute("SELECT body FROM resources WHERE id = 'doc-beta-eng'").fetchone()
    assert tenants == {"alpha"}
    assert body is None


def test_metadata_function_never_exposes_body(app_conn: psycopg.Connection) -> None:
    cur = app_conn.execute("SELECT * FROM resource_metadata('doc-beta-eng')")
    cols = [d.name for d in cur.description or []]
    assert cols == ["id", "tenant_id", "kind", "classification", "department"]


def test_adapter_refuses_cross_tenant_read_even_if_called_directly() -> None:
    """Simulates a PEP bug: the adapter is called for a beta document with alpha's tenant scope."""

    async def go() -> tuple[object, object]:
        pool = create_pool(APP_DSN)
        await pool.open()
        try:
            store = DocumentStore(pool)
            corr = uuid.uuid4()
            cross = await store.read(
                tenant_id="alpha", resource_id="doc-beta-eng", principal_id="alice", correlation_id=corr
            )
            own = await store.read(
                tenant_id="beta", resource_id="doc-beta-eng", principal_id="carol", correlation_id=corr
            )
            return cross, own
        finally:
            await pool.close()

    cross, own = asyncio.run(go())
    assert cross is None
    assert own is not None


# ----------------------------------------------------------------------------- OPA hardening


def test_opa_rejects_unauthenticated_decision_queries() -> None:
    r = httpx.post(f"{OPA_URL}/v1/data/aegis/authz/allow", json={"input": {}})
    assert r.status_code == 401


def test_opa_rejects_policy_replacement_even_with_pep_token() -> None:
    evil = "package aegis.authz\nallow := true\n"
    headers = {"Authorization": f"Bearer {OPA_TOKEN}"}
    r = httpx.put(f"{OPA_URL}/v1/policies/authz.rego", content=evil, headers=headers)
    assert r.status_code in (401, 403)
    r = httpx.put(
        f"{OPA_URL}/v1/data/aegis/roles/engineer",
        json={"principal_types": ["human"], "grants": []},
        headers=headers,
    )
    assert r.status_code in (401, 403)
    r = httpx.get(f"{OPA_URL}/v1/data/aegis/roles", headers=headers)
    assert r.status_code in (401, 403)
    # and the real policy is unchanged
    ok = httpx.get(f"{OPA_URL}/v1/data/aegis/authz/policy_version", headers=headers)
    assert ok.json()["result"] == "policy-v2"
    deny = httpx.post(f"{OPA_URL}/v1/data/aegis/authz/allow", json={"input": {}}, headers=headers)
    assert deny.json() == {"result": False}
