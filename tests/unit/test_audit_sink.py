"""Pure checks of the audit batch format and the store verifier (no services needed)."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aegis.audit_reconcile import StoredObject, verify_objects
from aegis.audit_sink import (
    EVENT_COLUMNS,
    GENESIS_SHA256,
    batch_key,
    body_sha256,
    canonical_event,
    encode_batch,
    event_digest,
)

NOW = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)


def test_event_columns_cover_every_audit_column() -> None:
    """A column added to audit_events must be shipped and verified too."""
    sql = Path("migrations/0001_init.up.sql").read_text()
    block = re.search(r"CREATE TABLE audit_events \((.*?)\n\);", sql, re.S)
    assert block is not None
    columns = [line.split()[0] for line in block.group(1).strip().splitlines()]
    later = "".join(p.read_text() for p in sorted(Path("migrations").glob("*.up.sql")))
    assert "ALTER TABLE audit_events ADD" not in later
    assert tuple(columns) == EVENT_COLUMNS


def event(**over: Any) -> dict[str, Any]:
    row: dict[str, Any] = {c: None for c in EVENT_COLUMNS}
    row.update(id=uuid.uuid4(), event_time=NOW, decision="deny", reason_code="X", duration_ms=1.25)
    row.update(over)
    return canonical_event(row)


def test_canonical_form_is_stable_and_complete() -> None:
    e = event()
    assert set(e) == set(EVENT_COLUMNS)
    assert e["event_time"] == "2026-10-17T12:00:00+00:00" and isinstance(e["id"], str)
    assert event_digest(e) == event_digest(dict(reversed(list(e.items()))))  # key order irrelevant
    assert event_digest(e) != event_digest({**e, "decision": "allow"})


def obj(
    seq: int, body: bytes, *, key: str | None = None, minutes: int = 0, lock: str | None = "COMPLIANCE"
) -> StoredObject:
    t = NOW + timedelta(minutes=minutes)
    return StoredObject(
        key=key or batch_key(seq),
        version_id=f"v{seq}-{minutes}",
        body=body,
        last_modified=t,
        lock_mode=lock,
        retain_until=t + timedelta(days=7) if lock else None,
    )


def chain(n: int) -> list[bytes]:
    bodies, prev = [], GENESIS_SHA256
    for seq in range(1, n + 1):
        b = encode_batch(seq, prev, [event(), event()])
        bodies.append(b)
        prev = body_sha256(b)
    return bodies


def codes(objects: list[StoredObject], markers: tuple[str, ...] = ()) -> set[str]:
    return {f.code for f in verify_objects(objects, markers, retention_days=7)[1]}


def test_clean_chain_verifies_and_collects_events() -> None:
    bodies = chain(3)
    snap, findings = verify_objects([obj(i + 1, b) for i, b in enumerate(bodies)], (), retention_days=7)
    assert findings == [] and snap.batches == 3 and len(snap.digests) == 6


def test_duplicate_event_with_same_digest_is_fine_but_conflict_is_not() -> None:
    e = event()
    b1 = encode_batch(1, GENESIS_SHA256, [e])
    b2 = encode_batch(2, body_sha256(b1), [e])  # re-shipped after a crash: accepted
    assert codes([obj(1, b1), obj(2, b2)]) == set()
    b2x = encode_batch(2, body_sha256(b1), [{**e, "reason_code": "Y"}])
    assert codes([obj(1, b1), obj(2, b2x)]) == {"SINK_EVENT_CONFLICT"}


def test_each_kind_of_tampering_is_reported() -> None:
    b1, b2, b3 = chain(3)
    assert codes([obj(1, b1), obj(3, b3)]) == {"SINK_BATCH_MISSING"}
    assert codes([obj(1, b1), obj(2, b2), obj(2, b1, minutes=5), obj(3, b3)]) == {"SINK_OBJECT_OVERWRITTEN"}
    assert codes([obj(1, b1), obj(2, b3)]) == {"SINK_CHAIN_BROKEN"}
    assert codes([obj(1, b1.replace(b'"X"', b'"Z"'))]) == {"SINK_EVENT_CORRUPT"}
    assert codes([obj(1, b1, lock=None)]) == {"SINK_RETENTION_WEAK"}
    assert codes([obj(1, b1, lock="GOVERNANCE")]) == {"SINK_RETENTION_WEAK"}
    assert codes([obj(1, b1), obj(0, b"x", key="batches/notes.txt")]) == {"SINK_UNEXPECTED_OBJECT"}
    assert codes([obj(1, b1)], markers=(batch_key(1),)) == {"SINK_DELETE_MARKER"}
    assert codes([obj(1, b"not json")]) == {"SINK_CHAIN_BROKEN"}


def test_overwrite_keeps_verifying_the_original_version() -> None:
    b1, b2 = chain(2)
    forged = encode_batch(1, GENESIS_SHA256, [])
    snap, findings = verify_objects([obj(1, b1), obj(1, forged, minutes=9), obj(2, b2)], (), retention_days=7)
    assert {f.code for f in findings} == {"SINK_OBJECT_OVERWRITTEN"}
    assert len(snap.digests) == 4  # events from the ORIGINAL batch 1, not the empty forgery
