"""T15: the external append-only audit store, and reconciliation against the database (ADR-8).

Real VersityGW (S3 API, versioning + COMPLIANCE object lock) and real PostgreSQL. Tamper cases on the
store use their own key prefix so the real ``batches/`` chain stays clean; database tampering is done
as the table owner (who can disable the immutability trigger, residual risk #3) and is restored after.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import psycopg
import pytest
from botocore.exceptions import ClientError
from psycopg.rows import dict_row

from aegis.audit import AuditEvent, PgAuditSink
from aegis.audit_reconcile import (
    compare_with_db,
    read_sink,
    reconcile_activity,
)
from aegis.audit_sink import (
    BATCH_PREFIX,
    EVENT_COLUMNS,
    GENESIS_SHA256,
    SELECT_EVENTS,
    Shipper,
    SinkSettings,
    batch_key,
    body_sha256,
    canonical_event,
    encode_batch,
    s3_client,
)
from aegis.db import create_pool
from aegis.resources import DocumentStore
from tests.conftest import APP_DSN, OWNER_DSN, Evidence, Keycloak

pytestmark = pytest.mark.security

SINK_URL = "http://127.0.0.1:7070"
BUCKET = "aegis-audit"
RETENTION_DAYS = 7
SHIPPER_DSN = "postgresql://aegis_audit_shipper:dummy-aegis-shipper-pw@127.0.0.1:5432/aegis"
AUDITOR_DSN = "postgresql://aegis_auditor:dummy-aegis-auditor-pw@127.0.0.1:5432/aegis"
# DUMMY local sink credentials (infra/compose.yaml defaults).
ROOT = ("dummy-sink-root", "dummy-sink-root-secret")
SHIPPER = ("aegis-shipper", "dummy-sink-shipper-secret")
AUDITOR = ("aegis-auditor", "dummy-sink-auditor-secret")


def client(creds: tuple[str, str]) -> Any:
    return s3_client(SinkSettings(endpoint=SINK_URL, access_key=creds[0], secret_key=creds[1], bucket=BUCKET))


def ship_all() -> int:
    cfg = SinkSettings(endpoint=SINK_URL, access_key=SHIPPER[0], secret_key=SHIPPER[1], bucket=BUCKET)
    return Shipper(SHIPPER_DSN, s3_client(cfg), cfg).ship_all()


def snapshot(prefix: str = BATCH_PREFIX, retention_days: int = RETENTION_DAYS) -> Any:
    return read_sink(client(AUDITOR), BUCKET, retention_days=retention_days, prefix=prefix)


def denied(fn: Any) -> bool:
    try:
        fn()
    except ClientError:
        return True
    return False


@pytest.fixture
def auditor_conn() -> Iterator[psycopg.Connection[Any]]:
    with psycopg.connect(AUDITOR_DSN) as conn:
        yield conn


def alice_read(api: httpx.Client, kc: Keycloak, rid: str) -> str:
    r = api.get(f"/api/v1/resources/{rid}", headers={"Authorization": f"Bearer {kc.password_token('alice')}"})
    request_id: str = r.json()["request_id"]
    return request_id


# ------------------------------------------------------------------ shipping


def test_t15_audit_events_reach_the_worm_store(
    api: httpx.Client, kc: Keycloak, db: Evidence, auditor_conn: psycopg.Connection[Any], record: Any
) -> None:
    rid = alice_read(api, kc, "doc-alpha-eng")
    event_ids = {str(e["id"]) for e in db.audit_for_request(rid)}
    ship_all()
    snap, sink_findings = snapshot()
    _, db_findings = compare_with_db(
        auditor_conn, snap, max_lag_seconds=3600, snapshot_started=datetime.now(UTC) - timedelta(seconds=5)
    )
    record(
        scenario_id="T15-ship",
        description="Allowed read: decision + execution events land in the WORM store and match the DB",
        request="GET doc-alpha-eng (alice), then ship + verify",
        expected_decision="allow",
        actual_decision="allow" if event_ids <= snap.digests.keys() else "deny",
        expected_side_effects=0,
        actual_side_effects=0,
        audit_events=len(event_ids),
        attack=False,
    )
    assert len(event_ids) == 2 and event_ids <= snap.digests.keys()
    assert sink_findings == []  # whole store: chain, versions, retention, digests
    assert db_findings == []  # whole database vs store


def test_t15_store_refuses_deletion_and_retention_changes(
    api: httpx.Client, kc: Keycloak, record: Any
) -> None:
    alice_read(api, kc, "doc-alpha-eng")
    ship_all()
    root, shipper, auditor = client(ROOT), client(SHIPPER), client(AUDITOR)
    first = root.list_object_versions(Bucket=BUCKET, Prefix=BATCH_PREFIX)["Versions"][0]
    key, version = first["Key"], first["VersionId"]
    short = datetime.now(UTC) + timedelta(seconds=2)
    attempts = {
        "shipper delete": denied(lambda: shipper.delete_object(Bucket=BUCKET, Key=key)),
        "shipper delete version": denied(
            lambda: shipper.delete_object(Bucket=BUCKET, Key=key, VersionId=version)
        ),
        "shipper change policy": denied(lambda: shipper.delete_bucket_policy(Bucket=BUCKET)),
        "auditor write": denied(lambda: auditor.put_object(Bucket=BUCKET, Key=key, Body=b"x")),
        "root delete version": denied(lambda: root.delete_object(Bucket=BUCKET, Key=key, VersionId=version)),
        "root delete version with governance bypass": denied(
            lambda: root.delete_object(
                Bucket=BUCKET, Key=key, VersionId=version, BypassGovernanceRetention=True
            )
        ),
        "root shorten retention": denied(
            lambda: root.put_object_retention(
                Bucket=BUCKET,
                Key=key,
                VersionId=version,
                Retention={"Mode": "COMPLIANCE", "RetainUntilDate": short},
            )
        ),
        "root suspend versioning": denied(
            lambda: root.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Suspended"})
        ),
        "root delete bucket": denied(lambda: root.delete_bucket(Bucket=BUCKET)),
    }
    still_there = root.get_object(Bucket=BUCKET, Key=key, VersionId=version)["Body"].read()
    _, findings = snapshot()
    record(
        scenario_id="T15-worm",
        description="Delete / shorten-retention / unversion attempts on a shipped audit batch (incl. root)",
        request=f"{len(attempts)} destructive S3 calls on {key}",
        expected_decision="deny",
        actual_decision="deny" if all(attempts.values()) else "allow",
        expected_side_effects=0,
        actual_side_effects=sum(not v for v in attempts.values()),
        audit_events=0,
        attack=True,
    )
    assert all(attempts.values()), {k: v for k, v in attempts.items() if not v}
    assert still_there and findings == []


# ------------------------------------------------------------------ store tampering is visible


def _synthetic_event(**over: Any) -> dict[str, Any]:
    event: dict[str, Any] = {col: None for col in EVENT_COLUMNS}
    event.update(
        id=str(uuid.uuid4()),
        event_time=datetime.now(UTC).isoformat(),
        event_kind="decision",
        correlation_id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
        decision="deny",
        reason_code="SUBJECT_NOT_GRANTED",
        evaluator_status="ok",
        test_case_id="t15-synthetic",
    )
    event.update(over)
    return event


def _put(s3: Any, key: str, body: bytes, *, lock: bool = True, exclusive: bool = True) -> None:
    extra: dict[str, Any] = {}
    if lock:
        extra |= {
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": datetime.now(UTC) + timedelta(days=1),
        }
    if exclusive:
        extra["IfNoneMatch"] = "*"
    s3.put_object(Bucket=BUCKET, Key=key, Body=body, **extra)


def test_t15_tampered_store_is_detected(record: Any) -> None:
    shipper, root = client(SHIPPER), client(ROOT)
    base = f"t15-tamper/{uuid.uuid4()}/"
    b1 = encode_batch(1, GENESIS_SHA256, [_synthetic_event()])
    b2 = encode_batch(2, body_sha256(b1), [_synthetic_event()])

    def prefix(case: str) -> str:
        return f"{base}{case}/"

    # clean chain: no findings
    _put(shipper, batch_key(1, prefix("clean")), b1)
    _put(shipper, batch_key(2, prefix("clean")), b2)
    # a compromised shipper overwrites batch 1 (a new version; the locked original stays)
    _put(shipper, batch_key(1, prefix("overwrite")), b1)
    _put(shipper, batch_key(1, prefix("overwrite")), encode_batch(1, GENESIS_SHA256, []), exclusive=False)
    # batch 2 missing
    _put(shipper, batch_key(1, prefix("gap")), b1)
    _put(shipper, batch_key(3, prefix("gap")), encode_batch(3, GENESIS_SHA256, []))
    # batch 2 does not chain to batch 1
    _put(shipper, batch_key(1, prefix("chain")), b1)
    _put(shipper, batch_key(2, prefix("chain")), encode_batch(2, "f" * 64, [_synthetic_event()]))
    # event content edited after its digest was computed
    _put(shipper, batch_key(1, prefix("corrupt")), b1.replace(b"SUBJECT_NOT_GRANTED", b"ALLOW"))
    # written without COMPLIANCE retention
    _put(root, batch_key(1, prefix("unlocked")), b1, lock=False)
    # root hides the latest version behind a delete marker (allowed by S3 object lock semantics)
    _put(shipper, batch_key(1, prefix("marker")), b1)
    marker_refused = denied(lambda: root.delete_object(Bucket=BUCKET, Key=batch_key(1, prefix("marker"))))

    results = {
        case: {f.code for f in snapshot(prefix(case), retention_days=1)[1]}
        for case in ("clean", "overwrite", "gap", "chain", "corrupt", "unlocked", "marker")
    }
    expected = {
        "clean": set(),
        "overwrite": {"SINK_OBJECT_OVERWRITTEN"},
        "gap": {"SINK_BATCH_MISSING"},
        "chain": {"SINK_CHAIN_BROKEN"},
        "corrupt": {"SINK_EVENT_CORRUPT"},
        "unlocked": {"SINK_RETENTION_WEAK"},
        "marker": set() if marker_refused else {"SINK_DELETE_MARKER"},
    }
    record(
        scenario_id="T15-sink-tamper",
        description="Overwrite, gap, broken chain, edited event, unlocked object, delete marker in the store",
        request="6 tampered batch sequences + 1 clean, verified with the read-only auditor",
        expected_decision="deny",
        actual_decision="deny" if results == expected else "allow",
        expected_side_effects=0,
        actual_side_effects=sum(results[c] != expected[c] for c in expected),
        audit_events=0,
        attack=True,
    )
    assert results == expected
    # the original of an overwritten batch is still readable and still the one that is verified
    versions = root.list_object_versions(Bucket=BUCKET, Prefix=prefix("overwrite"))["Versions"]
    assert len(versions) == 2


# ------------------------------------------------------------------ database tampering is visible


def _owner_tamper(statements: list[tuple[str, tuple[Any, ...]]]) -> None:
    """Run statements as the table owner with the immutability trigger disabled for this transaction only."""
    with psycopg.connect(OWNER_DSN) as conn, conn.transaction():
        conn.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update")
        for sql, params in statements:
            conn.execute(sql, params)  # type: ignore[arg-type]
        conn.execute("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update")


def test_t15_database_tampering_after_shipping_is_detected(
    api: httpx.Client, kc: Keycloak, db: Evidence, auditor_conn: psycopg.Connection[Any], record: Any
) -> None:
    allowed = db.audit_for_request(alice_read(api, kc, "doc-alpha-eng"))
    denied_events = db.audit_for_request(alice_read(api, kc, "doc-alpha-payroll"))
    execution = next(e for e in allowed if e["event_kind"] == "execution")
    denial = next(e for e in denied_events if e["decision"] == "deny")
    ship_all()
    snap, _ = snapshot()
    assert {str(execution["id"]), str(denial["id"])} <= snap.digests.keys()

    original = {k: execution[k] for k in EVENT_COLUMNS}
    insert = (
        "INSERT INTO audit_events ("  # noqa: S608 - constant column list, values bound
        + ", ".join(EVENT_COLUMNS)
        + ") VALUES ("
        + ", ".join(["%s"] * len(EVENT_COLUMNS))
        + ")"
    )
    # Attacker with owner rights: turn the denial into an allow and erase the execution record.
    _owner_tamper(
        [
            (
                "UPDATE audit_events SET decision = 'allow', reason_code = 'ALLOW' WHERE id = %s",
                (denial["id"],),
            ),
            ("DELETE FROM audit_events WHERE id = %s", (execution["id"],)),
        ]
    )
    try:
        _, findings = compare_with_db(auditor_conn, snap, max_lag_seconds=3600)
        auditor_conn.commit()
        modified = {f.ref for f in findings if f.code == "DB_EVENT_MODIFIED"}
        missing = {f.ref for f in findings if f.code == "DB_EVENT_MISSING"}
    finally:
        _owner_tamper(
            [
                (
                    "UPDATE audit_events SET decision = %s, reason_code = %s WHERE id = %s",
                    (denial["decision"], denial["reason_code"], denial["id"]),
                ),
                (insert, tuple(original[c] for c in EVENT_COLUMNS)),
            ]
        )
    _, after = compare_with_db(auditor_conn, snap, max_lag_seconds=3600)
    record(
        scenario_id="T15-db-tamper",
        description="Owner disables the audit trigger, rewrites a denial as allow and deletes an execution row",
        request="UPDATE + DELETE on shipped audit_events as table owner",
        expected_decision="deny",
        actual_decision="deny"
        if str(denial["id"]) in modified and str(execution["id"]) in missing
        else "allow",
        expected_side_effects=0,
        actual_side_effects=0,
        audit_events=2,
        attack=True,
    )
    assert str(denial["id"]) in modified
    assert str(execution["id"]) in missing
    # restored rows match the store again
    assert not {f.ref for f in after} & {str(denial["id"]), str(execution["id"])}


def test_t15_unshipped_events_and_fake_shipment_records_are_detected(
    db: Evidence, auditor_conn: psycopg.Connection[Any]
) -> None:
    snap, _ = snapshot()  # taken BEFORE the event exists, so no concurrent shipper can race this test
    started = db.now()
    event_id = uuid.uuid4()
    with psycopg.connect(OWNER_DSN) as conn:
        conn.execute(
            "INSERT INTO audit_events (id, event_time, event_kind, correlation_id, request_id, decision,"
            " reason_code, evaluator_status, test_case_id)"
            " VALUES (%s, now() - interval '1 hour', 'decision', %s, %s, 'deny', 'SUBJECT_NOT_GRANTED', 'ok',"
            " 't15-unshipped')",
            (event_id, uuid.uuid4(), uuid.uuid4()),
        )
        # an attacker claims it was shipped, so the shipper skips it
        conn.execute(
            "INSERT INTO audit_shipments (event_id, batch_seq, event_sha256, shipped_at)"
            " VALUES (%s, 999999, %s, now() - interval '1 hour')",
            (event_id, "0" * 64),
        )
    try:
        _, findings = compare_with_db(auditor_conn, snap, max_lag_seconds=120, snapshot_started=started)
        auditor_conn.commit()
    finally:
        with psycopg.connect(OWNER_DSN) as conn:
            conn.execute("DELETE FROM audit_shipments WHERE event_id = %s", (event_id,))
    assert str(event_id) in {f.ref for f in findings if f.code == "EVENT_NOT_SHIPPED"}
    assert str(event_id) in {f.ref for f in findings if f.code == "SHIPMENT_RECORD_UNBACKED"}
    ship_all()  # once the fake record is gone, the event is shipped like any other
    assert str(event_id) in snapshot()[0].digests


# ------------------------------------------------------------------ allow / execution reconciliation


def test_t15_reconciliation_flags_policy_bypass_but_not_normal_traffic(
    api: httpx.Client, kc: Keycloak, db: Evidence, auditor_conn: psycopg.Connection[Any], record: Any
) -> None:
    since = db.now()
    normal_rid = alice_read(api, kc, "doc-alpha-eng")
    bypass_rid, forged_rid, unknown_rid = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

    async def simulate_bugs() -> tuple[Any, list[uuid.UUID]]:
        pool = create_pool(APP_DSN)
        await pool.open()
        try:
            # 1. a code path that calls the resource adapter without asking the policy engine
            doc = await DocumentStore(pool).read(
                tenant_id="alpha",
                resource_id="doc-alpha-payroll",
                principal_id="alice",
                correlation_id=uuid.uuid4(),
                request_id=bypass_rid,
            )
            # 2. an execution recorded with no allow decision, 3. an execution of an unknown action
            sink = PgAuditSink(pool)
            ids = []
            for rid, action, resource in (
                (forged_rid, "documents:read", "doc-alpha-payroll"),
                (unknown_rid, "files:delete", "doc-alpha-eng"),
            ):
                ev = AuditEvent(
                    event_kind="execution",
                    correlation_id=uuid.uuid4(),
                    request_id=rid,
                    decision="n/a",
                    reason_code="EXECUTED",
                    evaluator_status="ok",
                    principal_type="human",
                    principal_id="alice",
                    tenant_id="alpha",
                    action=action,
                    resource_id=resource,
                    outcome="success",
                    request_origin="api",
                    test_case_id="t15-bypass",
                )
                await sink.record(ev)
                ids.append(ev.id)
            return doc, ids
        finally:
            await pool.close()

    doc, (forged_id, unknown_id) = asyncio.run(simulate_bugs())
    assert doc is not None  # the adapter really ran: this is the side effect to be caught
    findings = reconcile_activity(auditor_conn, since=since, settle_seconds=0)
    critical = {(f.code, f.ref) for f in findings if f.severity == "critical"}
    side_effect_refs = {f.detail for f in findings if f.code == "SIDE_EFFECT_WITHOUT_EXECUTION"}
    normal_ids = {str(e["id"]) for e in db.audit_for_request(normal_rid)}
    record(
        scenario_id="T15-reconcile",
        description="Adapter call without PEP, execution without allow, unknown action; plus one normal read",
        request="direct DocumentStore.read(payroll) + 2 forged execution events + GET doc-alpha-eng",
        expected_decision="deny",
        actual_decision="deny" if len(critical) == 3 else "allow",
        expected_side_effects=1,
        actual_side_effects=len(side_effect_refs),
        audit_events=2,
        attack=True,
    )
    assert ("EXECUTION_WITHOUT_ALLOW", str(forged_id)) in critical
    assert ("EXECUTION_UNKNOWN_ACTION", str(unknown_id)) in critical
    assert len(side_effect_refs) == 1 and str(bypass_rid) in next(iter(side_effect_refs))
    # exactly these three, and nothing about the normal, policy-checked read
    assert len(critical) == 3
    assert not {ref for _, ref in critical} & normal_ids


def test_audit_sink_roles_are_least_privilege() -> None:
    """The shipper cannot change audit rows; the auditor cannot write anything."""
    with psycopg.connect(SHIPPER_DSN) as conn:
        for sql in (
            "UPDATE audit_events SET reason_code = 'X' WHERE false",
            "DELETE FROM audit_shipments WHERE false",
            "SELECT 1 FROM resources LIMIT 1",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(sql)
            conn.rollback()
    with psycopg.connect(AUDITOR_DSN) as conn:
        for sql in (
            "INSERT INTO audit_shipments (event_id, batch_seq, event_sha256) VALUES"
            " (gen_random_uuid(), 1, repeat('0', 64))",
            "DELETE FROM resource_side_effects WHERE false",
            "SELECT 1 FROM resources LIMIT 1",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(sql)
            conn.rollback()
    with psycopg.connect(AUDITOR_DSN, row_factory=dict_row) as conn:
        assert conn.execute(SELECT_EVENTS + " LIMIT 1").fetchall() is not None
        row = conn.execute(SELECT_EVENTS + " LIMIT 1").fetchone()
        if row:
            assert set(canonical_event(row)) == set(EVENT_COLUMNS)
