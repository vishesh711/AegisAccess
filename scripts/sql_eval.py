"""Run the detection SQL over the labelled fixture and write artifacts/verification/sql-eval.md.

Uses the read-only runtime role. Numbers describe the synthetic fixture only.
"""

from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parent.parent
DSN = os.environ.get("AEGIS_DATABASE_URL", "postgresql://aegis_app:dummy-aegis-app-pw@127.0.0.1:5432/aegis")
QUERIES = ["confusion_matrix.sql", "by_rule.sql", "by_policy_version.sql"]


def table(cur: psycopg.Cursor) -> str:
    cols = [d.name for d in cur.description or []]
    rows = cur.fetchall()
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    out += ["| " + " | ".join("NULL" if v is None else str(v) for v in r) + " |" for r in rows]
    return "\n".join(out)


def main() -> None:
    rev = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=ROOT
    ).stdout.strip()
    parts = [
        "# SQL detection evaluation (synthetic fixture)",
        "",
        f"Generated {datetime.now(UTC).isoformat(timespec='seconds')} at git `{rev}` by `make sql-eval`.",
        "Dataset: `analytics/detection_fixture.csv` (hand-labelled, synthetic). These metrics describe this",
        "fixture only and are not a claim about real-world detection performance.",
    ]
    with psycopg.connect(DSN) as conn:
        n = conn.execute(
            "SELECT count(*), count(*) FILTER (WHERE ground_truth_is_attack) FROM detection_events"
        ).fetchone()
        assert n is not None
        parts.append(f"\nRows: {n[0]} (attacks: {n[1]}, benign: {n[0] - n[1]})")
        for q in QUERIES:
            sql = (ROOT / "analytics" / "queries" / q).read_text()
            cur = conn.execute(sql)  # type: ignore[call-overload]
            parts += ["", f"## {q}", "", table(cur)]
    out = ROOT / "artifacts" / "verification" / "sql-eval.md"
    out.write_text("\n".join(parts) + "\n")
    print("\n".join(parts))


if __name__ == "__main__":
    main()
