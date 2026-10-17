"""Verify the external audit store and reconcile it with PostgreSQL (ADR-8).

Runs as the read-only DB role `aegis_auditor` and the read-only sink user. Exits 1 on any critical
finding. Store integrity and store-vs-database checks always cover the whole history; activity checks
(execution without allow, side effect without execution) cover events since --activity-since.

    python scripts/audit_verify.py [--activity-since 2026-10-17T10:00:00Z | 15m] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg

from aegis.audit_reconcile import run_all
from aegis.audit_sink import SinkSettings, s3_client

AUDITOR_DSN = os.environ.get(
    "AEGIS_AUDITOR_DATABASE_URL",
    "postgresql://aegis_auditor:dummy-aegis-auditor-pw@127.0.0.1:5432/aegis",  # DUMMY local default
)


def parse_since(value: str) -> datetime:
    m = re.fullmatch(r"(\d+)([smhd])", value)
    if m:
        unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[m.group(2)]
        return datetime.now(UTC) - timedelta(**{unit: int(m.group(1))})
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--activity-since", default="24h")
    ap.add_argument("--max-lag", type=int, default=120, help="seconds an event may wait to be shipped")
    ap.add_argument("--settle", type=int, default=10, help="ignore activity newer than this (seconds)")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    cfg = SinkSettings.from_env(
        access_default=os.environ.get("AUDIT_SINK_AUDITOR_ACCESS_KEY", "aegis-auditor"),
        secret_default=os.environ.get("AUDIT_SINK_AUDITOR_SECRET_KEY", "dummy-sink-auditor-secret"),
    )
    with psycopg.connect(AUDITOR_DSN) as conn:
        report = run_all(
            conn,
            s3_client(cfg),
            cfg.bucket,
            retention_days=cfg.retention_days,
            activity_since=parse_since(args.activity_since),
            max_lag_seconds=args.max_lag,
            settle_seconds=args.settle,
        )
    summary = report.as_dict()
    print(
        f"audit sink: {summary['batches']} batches, {summary['events_in_sink']} events "
        f"(database: {summary['events_in_db']}); critical findings: {summary['critical']}, "
        f"warnings: {summary['warnings']}"
    )
    counts: dict[tuple[str, str], int] = {}
    for f in report.findings:
        counts[(f.severity, f.code)] = counts.get((f.severity, f.code), 0) + 1
    for (severity, code), n in sorted(counts.items()):
        print(f"  {severity:8} {code:32} {n}")
    for f in report.critical[:20]:
        print(f"  - {f.code} {f.ref} {f.detail}")
    if args.json:
        args.json.write_text(json.dumps(summary, indent=2) + "\n")
    return 1 if report.critical else 0


if __name__ == "__main__":
    sys.exit(main())
