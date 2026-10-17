"""Verify the external audit store and reconcile it with the database (ADR-8).

Three groups of checks; every finding names a stable code, a severity and the ids involved
(never event content):

1. Store integrity (read with the read-only auditor user):
   SINK_DELETE_MARKER, SINK_OBJECT_OVERWRITTEN, SINK_UNEXPECTED_OBJECT, SINK_BATCH_MISSING,
   SINK_CHAIN_BROKEN, SINK_EVENT_CORRUPT, SINK_EVENT_CONFLICT, SINK_RETENTION_WEAK.
2. Store vs database (who changed what after the fact):
   DB_EVENT_MISSING   - shipped event no longer in the database (deleted)
   DB_EVENT_MODIFIED  - database row differs from the shipped copy
   EVENT_NOT_SHIPPED  - database row older than the allowed lag is not in the store
   SHIPMENT_RECORD_UNBACKED - audit_shipments claims an event the store does not hold
3. Activity reconciliation (database only):
   EXECUTION_WITHOUT_ALLOW      - an execution event for a policy-governed action with no matching
                                  allow decision in the same request
   EXECUTION_UNKNOWN_ACTION     - an execution event for an action this checker does not know
   SIDE_EFFECT_WITHOUT_EXECUTION - a resource side effect with no matching execution event
   ALLOWED_NOT_EXECUTED (warning) - an MCP tool call was allowed but nothing executed
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

import psycopg
from botocore.exceptions import ClientError
from psycopg.rows import dict_row

from aegis.audit_sink import (
    BATCH_PREFIX,
    FORMAT,
    GENESIS_SHA256,
    SELECT_EVENTS,
    body_sha256,
    canonical_event,
    event_digest,
)

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

CRITICAL = "critical"
WARNING = "warning"

# Actions whose execution must follow an OPA allow decision for the same request and resource.
PDP_GOVERNED_ACTIONS = (
    "documents:read",
    "reports:create",
    "exports:simulate",
    "audit:read",
    "policy:simulate",
)
# Actions that execute without a single matching decision, by design:
#  documents:search - each result is authorized under its own request id; the search itself returns
#                     only allowed items (tests: test_search_filters_before_returning)
#  approvals:*      - authorized by the approver-ownership predicate inside the UPDATE (ADR-7)
NON_PDP_ACTIONS = ("documents:search", "approvals:approve", "approvals:reject")
SIDE_EFFECT_ACTION = {
    "document_read": "documents:read",
    "report_write": "reports:create",
    "search": "documents:search",
    "export_simulated": "exports:simulate",
}


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    severity: str
    ref: str
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "severity": self.severity, "ref": self.ref, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class StoredObject:
    key: str
    version_id: str
    body: bytes
    last_modified: datetime
    lock_mode: str | None
    retain_until: datetime | None


@dataclass(slots=True)
class SinkSnapshot:
    batches: int = 0
    # event id -> digest, and the event time (for the "since" window)
    digests: dict[str, str] = field(default_factory=dict)
    event_times: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class Report:
    findings: list[Finding] = field(default_factory=list)
    batches: int = 0
    events_in_sink: int = 0
    events_in_db: int = 0

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == CRITICAL]

    def codes(self) -> set[str]:
        return {f.code for f in self.findings}

    def refs(self, code: str) -> set[str]:
        return {f.ref for f in self.findings if f.code == code}

    def as_dict(self) -> dict[str, Any]:
        return {
            "batches": self.batches,
            "events_in_sink": self.events_in_sink,
            "events_in_db": self.events_in_db,
            "critical": len(self.critical),
            "warnings": len(self.findings) - len(self.critical),
            "findings": [f.as_dict() for f in self.findings],
        }


# ------------------------------------------------------------------ 1. store integrity


def verify_objects(
    objects: Sequence[StoredObject],
    delete_markers: Iterable[str],
    *,
    retention_days: int,
    prefix: str = BATCH_PREFIX,
) -> tuple[SinkSnapshot, list[Finding]]:
    """Pure check over everything listed under ``prefix`` (all versions)."""
    findings = [Finding("SINK_DELETE_MARKER", CRITICAL, key) for key in sorted(set(delete_markers))]
    by_key: dict[str, list[StoredObject]] = {}
    for obj in objects:
        by_key.setdefault(obj.key, []).append(obj)

    seqs: dict[int, StoredObject] = {}
    for key, versions in sorted(by_key.items()):
        versions.sort(key=lambda o: o.last_modified)
        if len(versions) > 1:
            findings.append(Finding("SINK_OBJECT_OVERWRITTEN", CRITICAL, key, f"{len(versions)} versions"))
        name = key.removeprefix(prefix)
        stem = name.removesuffix(".jsonl")
        if not (name.endswith(".jsonl") and stem.isdigit() and len(stem) == 12 and int(stem) > 0):
            findings.append(Finding("SINK_UNEXPECTED_OBJECT", CRITICAL, key))
            continue
        seqs[int(stem)] = versions[0]  # the first write is the original; later versions are tampering

    snapshot = SinkSnapshot(batches=len(seqs))
    min_retention = timedelta(days=retention_days) - timedelta(minutes=5)
    prev_sha = GENESIS_SHA256
    for expected in range(1, (max(seqs) if seqs else 0) + 1):
        batch = seqs.get(expected)
        if batch is None:
            findings.append(Finding("SINK_BATCH_MISSING", CRITICAL, f"{prefix}{expected:012d}.jsonl"))
            prev_sha = ""  # chain cannot be continued across a gap
            continue
        if (
            batch.lock_mode != "COMPLIANCE"
            or batch.retain_until is None
            or batch.retain_until - batch.last_modified < min_retention
        ):
            findings.append(Finding("SINK_RETENTION_WEAK", CRITICAL, batch.key, f"mode={batch.lock_mode}"))
        findings += _verify_batch(batch, expected, prev_sha, snapshot)
        prev_sha = body_sha256(batch.body)
    return snapshot, findings


def _verify_batch(obj: StoredObject, seq: int, prev_sha: str, snapshot: SinkSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = obj.body.decode("ascii").splitlines()
        header = json.loads(lines[0])
        entries = [json.loads(line) for line in lines[1:]]
    except (UnicodeDecodeError, json.JSONDecodeError, IndexError):
        return [Finding("SINK_CHAIN_BROKEN", CRITICAL, obj.key, "unreadable batch")]
    if (
        not isinstance(header, dict)
        or header.get("format") != FORMAT
        or header.get("seq") != seq
        or header.get("count") != len(entries)
        or (prev_sha and header.get("prev_sha256") != prev_sha)
    ):
        findings.append(Finding("SINK_CHAIN_BROKEN", CRITICAL, obj.key))
    for entry in entries:
        event = entry.get("event") if isinstance(entry, dict) else None
        if not isinstance(event, dict) or entry.get("event_id") != event.get("id"):
            findings.append(Finding("SINK_EVENT_CORRUPT", CRITICAL, obj.key, "malformed entry"))
            continue
        event_id = str(event["id"])
        digest = event_digest(event)
        if entry.get("sha256") != digest:
            findings.append(Finding("SINK_EVENT_CORRUPT", CRITICAL, event_id, obj.key))
            continue
        known = snapshot.digests.get(event_id)
        if known is not None and known != digest:
            findings.append(Finding("SINK_EVENT_CONFLICT", CRITICAL, event_id, obj.key))
            continue
        snapshot.digests[event_id] = digest
        snapshot.event_times[event_id] = str(event.get("event_time"))
    return findings


def read_sink(
    s3: S3Client, bucket: str, *, retention_days: int, prefix: str = BATCH_PREFIX
) -> tuple[SinkSnapshot, list[Finding]]:
    objects: list[StoredObject] = []
    markers: list[str] = []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=prefix):
        markers += [m.get("Key", "") for m in page.get("DeleteMarkers", [])]
        for v in page.get("Versions", []):
            key, version = v.get("Key", ""), v.get("VersionId", "")
            got = s3.get_object(Bucket=bucket, Key=key, VersionId=version)
            # The dedicated retention API is authoritative (some servers omit lock headers on GET).
            try:
                retention = s3.get_object_retention(Bucket=bucket, Key=key, VersionId=version)["Retention"]
            except ClientError:
                retention = {}
            objects.append(
                StoredObject(
                    key=key,
                    version_id=version,
                    body=got["Body"].read(),
                    last_modified=got["LastModified"],
                    lock_mode=retention.get("Mode"),
                    retain_until=retention.get("RetainUntilDate"),
                )
            )
    return verify_objects(objects, markers, retention_days=retention_days, prefix=prefix)


# ------------------------------------------------------------------ 2. store vs database


def compare_with_db(
    conn: psycopg.Connection[Any],
    snapshot: SinkSnapshot,
    *,
    max_lag_seconds: int,
    snapshot_started: datetime | None = None,
) -> tuple[int, list[Finding]]:
    """``snapshot_started``: database time taken just before the store was read. Shipment records are
    written after their upload, so only records older than it are compared (no race with a shipper
    running concurrently). Records dated in the future are always compared. Missing events are caught
    by EVENT_NOT_SHIPPED regardless, which never trusts audit_shipments."""
    findings: list[Finding] = []
    with conn.cursor(row_factory=dict_row) as cur:
        rows = cur.execute(SELECT_EVENTS + " ORDER BY event_time, id").fetchall()
        lag_cutoff = cur.execute(
            "SELECT now() - make_interval(secs => %s) AS t", (max_lag_seconds,)
        ).fetchone()
        shipments = cur.execute(
            "SELECT event_id, event_sha256 FROM audit_shipments"
            " WHERE %(t)s::timestamptz IS NULL OR shipped_at < %(t)s"
            " OR shipped_at > now() + interval '1 minute'",
            {"t": snapshot_started},
        ).fetchall()
    cutoff: datetime = lag_cutoff["t"] if lag_cutoff else datetime.max
    db_digests: dict[str, str] = {}
    for row in rows:
        event_id = str(row["id"])
        digest = event_digest(canonical_event(row))
        db_digests[event_id] = digest
        shipped = snapshot.digests.get(event_id)
        if shipped is None:
            if row["event_time"] < cutoff:
                findings.append(Finding("EVENT_NOT_SHIPPED", CRITICAL, event_id))
        elif shipped != digest:
            findings.append(Finding("DB_EVENT_MODIFIED", CRITICAL, event_id))
    for event_id in snapshot.digests.keys() - db_digests.keys():
        findings.append(Finding("DB_EVENT_MISSING", CRITICAL, event_id, snapshot.event_times[event_id]))
    for s in shipments:
        event_id = str(s["event_id"])
        if snapshot.digests.get(event_id) != s["event_sha256"]:
            findings.append(Finding("SHIPMENT_RECORD_UNBACKED", CRITICAL, event_id))
    return len(rows), findings


# ------------------------------------------------------------------ 3. activity reconciliation

_EXECUTION_WITHOUT_ALLOW = """
SELECT e.id, e.request_id, e.action, e.resource_id
FROM audit_events e
WHERE e.event_kind = 'execution' AND e.event_time >= %(since)s AND e.event_time < %(settled)s
  AND e.action = ANY(%(governed)s)
  AND NOT EXISTS (
      SELECT 1 FROM audit_events d
      WHERE d.request_id = e.request_id AND d.event_kind = 'decision' AND d.decision = 'allow'
        AND d.action = e.action AND d.resource_id IS NOT DISTINCT FROM e.resource_id)
ORDER BY e.event_time
"""

_EXECUTION_UNKNOWN_ACTION = """
SELECT e.id, e.action FROM audit_events e
WHERE e.event_kind = 'execution' AND e.event_time >= %(since)s AND e.event_time < %(settled)s
  AND (e.action IS NULL OR NOT (e.action = ANY(%(known)s)))
"""

_SIDE_EFFECT_WITHOUT_EXECUTION = """
SELECT s.id, s.kind, s.resource_id, s.request_id
FROM resource_side_effects s
WHERE s.event_time >= %(since)s AND s.event_time < %(settled)s
  AND NOT EXISTS (
      SELECT 1 FROM audit_events e
      WHERE e.request_id = s.request_id AND e.event_kind = 'execution'
        AND e.action = (%(kind_map)s::jsonb ->> s.kind)
        AND e.tenant_id = s.tenant_id AND e.principal_id = s.principal_id
        AND (s.kind <> 'document_read' OR e.resource_id = s.resource_id))
ORDER BY s.id
"""

_ALLOWED_NOT_EXECUTED = """
SELECT d.id, d.request_id, d.tool_name, d.action
FROM audit_events d
WHERE d.event_kind = 'decision' AND d.decision = 'allow' AND d.request_origin = 'mcp'
  AND d.event_time >= %(since)s AND d.event_time < %(settled)s
  AND ((d.tool_name = 'documents.read' AND d.action = 'documents:read')
       OR (d.tool_name = 'reports.create_summary' AND d.action = 'reports:create'))
  AND NOT EXISTS (
      SELECT 1 FROM audit_events e
      WHERE e.request_id = d.request_id AND e.event_kind = 'execution' AND e.action = d.action)
"""


def reconcile_activity(
    conn: psycopg.Connection[Any], *, since: datetime, settle_seconds: int
) -> list[Finding]:
    findings: list[Finding] = []
    with conn.cursor(row_factory=dict_row) as cur:
        settled_row = cur.execute(
            "SELECT now() - make_interval(secs => %s) AS t", (settle_seconds,)
        ).fetchone()
        params: Mapping[str, Any] = {
            "since": since,
            "settled": settled_row["t"] if settled_row else since,
            "governed": list(PDP_GOVERNED_ACTIONS),
            "known": list(PDP_GOVERNED_ACTIONS + NON_PDP_ACTIONS),
            "kind_map": json.dumps(SIDE_EFFECT_ACTION),
        }
        for r in cur.execute(_EXECUTION_WITHOUT_ALLOW, params).fetchall():
            findings.append(
                Finding(
                    "EXECUTION_WITHOUT_ALLOW", CRITICAL, str(r["id"]), f"{r['action']} {r['resource_id']}"
                )
            )
        for r in cur.execute(_EXECUTION_UNKNOWN_ACTION, params).fetchall():
            findings.append(Finding("EXECUTION_UNKNOWN_ACTION", CRITICAL, str(r["id"]), str(r["action"])))
        for r in cur.execute(_SIDE_EFFECT_WITHOUT_EXECUTION, params).fetchall():
            findings.append(
                Finding(
                    "SIDE_EFFECT_WITHOUT_EXECUTION",
                    CRITICAL,
                    f"side_effect:{r['id']}",
                    f"{r['kind']} {r['resource_id']} request={r['request_id']}",
                )
            )
        for r in cur.execute(_ALLOWED_NOT_EXECUTED, params).fetchall():
            findings.append(Finding("ALLOWED_NOT_EXECUTED", WARNING, str(r["id"]), str(r["tool_name"])))
    return findings


def run_all(
    conn: psycopg.Connection[Any],
    s3: S3Client,
    bucket: str,
    *,
    retention_days: int,
    activity_since: datetime,
    max_lag_seconds: int = 120,
    settle_seconds: int = 10,
) -> Report:
    started = conn.execute("SELECT now()").fetchone()
    conn.commit()  # end the transaction so the comparison below sees rows committed meanwhile
    snapshot, findings = read_sink(s3, bucket, retention_days=retention_days)
    db_count, db_findings = compare_with_db(
        conn, snapshot, max_lag_seconds=max_lag_seconds, snapshot_started=started[0] if started else None
    )
    report = Report(
        findings=findings + db_findings,
        batches=snapshot.batches,
        events_in_sink=len(snapshot.digests),
        events_in_db=db_count,
    )
    report.findings += reconcile_activity(conn, since=activity_since, settle_seconds=settle_seconds)
    return report
