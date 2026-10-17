"""Ship audit events to an external append-only (WORM) object store (ADR-8).

Each batch is one S3 object ``batches/<seq>.jsonl``:

    line 1   {"format": "aegis-audit-batch/1", "seq": n, "prev_sha256": <sha256 of batch n-1>, "count": k}
    line 2.. {"event_id": ..., "sha256": <sha256 of the canonical event>, "event": {...all columns...}}

Every object is written with ``If-None-Match: *`` (never overwrites a key) and an explicit
COMPLIANCE retention date (nobody, including the store's root user, can delete it or shorten the
date through the S3 API). The batches form a hash chain, so a missing or altered batch is visible
even to someone who only holds a later one.

The shipper runs as its own database role (SELECT on audit rows, INSERT on ``audit_shipments``) and
its own sink user (bucket policy: add and read objects only). It never deletes anything anywhere.

Run: ``python -m aegis.audit_sink --once`` or ``--loop`` (the compose ``audit-shipper`` service).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import boto3
import psycopg
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from psycopg.rows import dict_row

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

log = logging.getLogger("aegis.audit_sink")

FORMAT = "aegis-audit-batch/1"
BATCH_PREFIX = "batches/"
GENESIS_SHA256 = "0" * 64
DEFAULT_BUCKET = "aegis-audit"
DEFAULT_RETENTION_DAYS = 7
MAX_BATCH = 500

# Every audit_events column, in a fixed order. A new column must be added here, or the verifier
# would silently stop covering it (tests/unit/test_audit_sink.py checks this against the schema).
EVENT_COLUMNS: tuple[str, ...] = (
    "id",
    "event_time",
    "event_kind",
    "correlation_id",
    "request_id",
    "principal_type",
    "principal_id",
    "tenant_id",
    "agent_id",
    "task_id",
    "tool_name",
    "action",
    "resource_id",
    "policy_version",
    "decision",
    "reason_code",
    "evaluator_status",
    "outcome",
    "duration_ms",
    "request_origin",
    "test_case_id",
)
SELECT_EVENTS = "SELECT " + ", ".join(EVENT_COLUMNS) + " FROM audit_events"  # noqa: S608 - constant columns


@dataclass(frozen=True, slots=True)
class SinkSettings:
    endpoint: str
    access_key: str
    secret_key: str = field(repr=False)
    bucket: str = DEFAULT_BUCKET
    retention_days: int = DEFAULT_RETENTION_DAYS
    region: str = "us-east-1"

    @classmethod
    def from_env(cls, *, access_default: str, secret_default: str) -> SinkSettings:
        return cls(
            endpoint=os.environ.get("AEGIS_AUDIT_SINK_URL", "http://127.0.0.1:7070"),
            access_key=os.environ.get("AEGIS_AUDIT_SINK_ACCESS_KEY", access_default),
            secret_key=os.environ.get("AEGIS_AUDIT_SINK_SECRET_KEY", secret_default),
            bucket=os.environ.get("AEGIS_AUDIT_SINK_BUCKET", DEFAULT_BUCKET),
            retention_days=int(os.environ.get("AEGIS_AUDIT_SINK_RETENTION_DAYS", DEFAULT_RETENTION_DAYS)),
        )


def s3_client(cfg: SinkSettings) -> S3Client:
    client: S3Client = boto3.client(
        "s3",
        endpoint_url=cfg.endpoint,
        aws_access_key_id=cfg.access_key,
        aws_secret_access_key=cfg.secret_key,
        region_name=cfg.region,
        config=Config(
            s3={"addressing_style": "path"},
            connect_timeout=3,
            read_timeout=10,
            retries={"max_attempts": 2, "mode": "standard"},
        ),
    )
    return client


# ------------------------------------------------------------------ canonical form


def _canonical_value(value: Any) -> Any:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    return value


def canonical_event(row: Mapping[str, Any]) -> dict[str, Any]:
    """The exact, column-complete form of one audit row that is shipped and later compared."""
    return {col: _canonical_value(row[col]) for col in EVENT_COLUMNS}


def _dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def event_digest(event: Mapping[str, Any]) -> str:
    return hashlib.sha256(_dumps(event).encode("ascii")).hexdigest()


def batch_key(seq: int, prefix: str = BATCH_PREFIX) -> str:
    return f"{prefix}{seq:012d}.jsonl"


def encode_batch(seq: int, prev_sha256: str, events: Sequence[Mapping[str, Any]]) -> bytes:
    header = {"format": FORMAT, "seq": seq, "prev_sha256": prev_sha256, "count": len(events)}
    lines = [_dumps(header)]
    lines += [_dumps({"event_id": e["id"], "sha256": event_digest(e), "event": dict(e)}) for e in events]
    return ("\n".join(lines) + "\n").encode("ascii")


def body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


# ------------------------------------------------------------------ shipper


class ShipConflictError(Exception):
    """Another writer created the next batch key first; retry on the next tick."""


def _error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))


class Shipper:
    def __init__(self, dsn: str, s3: S3Client, cfg: SinkSettings, *, prefix: str = BATCH_PREFIX) -> None:
        self._dsn = dsn
        self._s3 = s3
        self._cfg = cfg
        self._prefix = prefix

    def last_batch(self) -> tuple[int, str]:
        """(seq, sha256) of the newest batch in the store, or (0, genesis) when empty."""
        last_key: str | None = None
        for page in self._s3.get_paginator("list_objects_v2").paginate(
            Bucket=self._cfg.bucket, Prefix=self._prefix
        ):
            for obj in page.get("Contents", []):
                key = obj.get("Key", "")
                if last_key is None or key > last_key:
                    last_key = key
        if last_key is None:
            return 0, GENESIS_SHA256
        seq = int(last_key.removeprefix(self._prefix).removesuffix(".jsonl"))
        body = self._s3.get_object(Bucket=self._cfg.bucket, Key=last_key)["Body"].read()
        return seq, body_sha256(body)

    def ship_once(self, limit: int = MAX_BATCH) -> int:
        """Ship up to ``limit`` not-yet-shipped events as one batch. Returns the number shipped."""
        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            rows = conn.execute(
                SELECT_EVENTS  # noqa: S608 - constant SQL, values are bound parameters
                + " a WHERE NOT EXISTS"
                " (SELECT 1 FROM audit_shipments s WHERE s.event_id = a.id)"
                " ORDER BY event_time, id LIMIT %s",
                (limit,),
            ).fetchall()
            if not rows:
                return 0
            events = [canonical_event(r) for r in rows]
            seq, prev = self.last_batch()
            body = encode_batch(seq + 1, prev, events)
            retain_until = datetime.now(UTC) + timedelta(days=self._cfg.retention_days)
            try:
                self._s3.put_object(
                    Bucket=self._cfg.bucket,
                    Key=batch_key(seq + 1, self._prefix),
                    Body=body,
                    ContentType="application/x-ndjson",
                    IfNoneMatch="*",
                    ObjectLockMode="COMPLIANCE",
                    ObjectLockRetainUntilDate=retain_until,
                )
            except ClientError as exc:
                if _error_code(exc) in {"PreconditionFailed", "ConditionalRequestConflict"}:
                    raise ShipConflictError() from exc
                raise
            # Bookkeeping only. If this fails after the upload, the events are shipped again in a
            # later batch; the verifier accepts duplicates whose digests agree.
            with conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO audit_shipments (event_id, batch_seq, event_sha256) VALUES (%s, %s, %s)"
                    " ON CONFLICT (event_id) DO NOTHING",
                    [(e["id"], seq + 1, event_digest(e)) for e in events],
                )
            conn.commit()
        return len(events)

    def ship_all(self, max_batches: int = 1000) -> int:
        total = 0
        for _ in range(max_batches):
            try:
                n = self.ship_once()
            except ShipConflictError:
                continue
            if n == 0:
                break
            total += n
        return total

    def run_forever(self, interval: float) -> None:
        while True:
            try:
                shipped = self.ship_all()
                if shipped:
                    log.info("shipped audit events", extra={"fields": {"count": shipped}})
            except (psycopg.Error, BotoCoreError, ClientError) as exc:
                # Type only: messages can contain endpoint details. The verifier reports the lag.
                log.error("audit shipping failed", extra={"fields": {"exc_type": type(exc).__name__}})
            time.sleep(interval)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true", help="ship everything pending, then exit")
    mode.add_argument("--loop", action="store_true", help="ship continuously")
    parser.add_argument(
        "--interval", type=float, default=float(os.environ.get("AEGIS_AUDIT_SHIP_INTERVAL", 3))
    )
    args = parser.parse_args(argv)

    from aegis.logging import configure_logging

    configure_logging()
    dsn = os.environ.get(
        "AEGIS_AUDIT_SHIPPER_DATABASE_URL",
        # DUMMY local default.
        "postgresql://aegis_audit_shipper:dummy-aegis-shipper-pw@127.0.0.1:5432/aegis",
    )
    cfg = SinkSettings.from_env(
        access_default="aegis-shipper",
        secret_default="dummy-sink-shipper-secret",  # noqa: S106 - DUMMY local default
    )
    shipper = Shipper(dsn, s3_client(cfg), cfg)
    if args.once:
        print(f"shipped {shipper.ship_all()} audit events")
        return 0
    shipper.run_forever(args.interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())
