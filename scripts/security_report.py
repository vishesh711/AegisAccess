"""Render artifacts/security-test-report.md from the recorded scenario outcomes of `pytest tests/security`
and store them in the scenario_results table. Every number comes from the test run / database."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "artifacts" / "tmp" / "scenarios.json"
OUT = ROOT / "artifacts" / "security-test-report.md"
OWNER_DSN = os.environ.get(
    "AEGIS_OWNER_DATABASE_URL", "postgresql://aegis_owner:dummy-aegis-owner-pw@127.0.0.1:5432/aegis"
)
MANDATORY = [f"T{i:02d}" for i in range(1, 13)]


def esc(text: str) -> str:
    return text.replace("|", "\\|")


def main() -> int:
    if not SRC.exists():
        print("no recorded scenarios; run `pytest tests/security` first")
        return 1
    data = json.loads(SRC.read_text())
    scenarios = data["scenarios"]
    run_id = uuid.uuid4()
    rev = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=ROOT
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "status", "--porcelain"], capture_output=True, text=True, cwd=ROOT
    ).stdout.strip()

    with psycopg.connect(OWNER_DSN) as conn:
        for s in scenarios:
            conn.execute(
                "INSERT INTO scenario_results (run_id, scenario_id, description, expected_decision, actual_decision,"
                " expected_side_effects, actual_side_effects, audit_events_observed, ground_truth_is_attack, passed)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    run_id,
                    s["scenario_id"],
                    s["description"],
                    s["expected_decision"],
                    s["actual_decision"],
                    s["expected_side_effects"],
                    s["actual_side_effects"],
                    s["audit_events"],
                    s["attack"],
                    s["passed"],
                ),
            )
        lat = conn.execute(
            "SELECT count(*), percentile_cont(0.5) WITHIN GROUP (ORDER BY duration_ms),"
            " percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms), max(duration_ms)"
            " FROM audit_events WHERE event_kind = 'decision' AND evaluator_status = 'ok' AND duration_ms IS NOT NULL"
        ).fetchone()
        conn.commit()

    seen = {s["scenario_id"].split("-")[0] for s in scenarios}
    missing = [m for m in MANDATORY if m not in seen]
    failed = [s for s in scenarios if not s["passed"]]
    lines = [
        "# AegisAccess security test report",
        "",
        f"* Generated: {datetime.now(UTC).isoformat(timespec='seconds')}",
        f"* Git revision: `{rev}`{' (working tree has uncommitted changes)' if dirty else ''}",
        f"* Run id (scenario_results.run_id): `{run_id}`",
        f"* pytest exit status for `tests/security`: **{data['exitstatus']}** (0 = all tests passed)",
        f"* Scenarios recorded: {len(scenarios)}; outcome mismatches: {len(failed)}; "
        f"mandatory T01-T12 missing: {', '.join(missing) or 'none'}",
        "",
        "Side-effect counts are **observed** rows in `resource_side_effects` (written by the resource adapter in",
        "the same transaction as the protected operation), read back from PostgreSQL after each request — not",
        "inferred from HTTP status codes. Audit counts are rows in the append-only `audit_events` table.",
        "",
        "| Scenario | Description | Request | Expected | Actual | Side effects (exp/obs) | Audit rows | Result |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for s in sorted(scenarios, key=lambda x: x["scenario_id"]):
        lines.append(
            f"| {s['scenario_id']} | {esc(s['description'])} | `{esc(s['request'])}` | {s['expected_decision']} | "
            f"{s['actual_decision']} | {s['expected_side_effects']}/{s['actual_side_effects']} | "
            f"{s['audit_events']} | {'PASS' if s['passed'] else '**FAIL**'} |"
        )
    n, p50, p95, mx = lat or (0, None, None, None)
    lines += [
        "",
        "## Policy decision latency (measured, not a guarantee)",
        "",
        f"From `audit_events.duration_ms` of successful OPA evaluations accumulated in this database (n={n}).",
        f"p50 = {p50:.2f} ms, p95 = {p95:.2f} ms, max = {mx:.2f} ms." if n else "No samples.",
        f"Environment: {platform.platform()}, Python {sys.version.split()[0]}, OPA in Docker on the same host,",
        "PEP->OPA over the local Docker bridge/loopback. Includes HTTP round trip; excludes JWT validation and DB.",
        "The PRD target (p95 < 100 ms) is aspirational for local runs; this sample is not a load test.",
        "",
    ]
    OUT.write_text("\n".join(lines))
    print("\n".join(lines[:9]))
    return 0 if data["exitstatus"] == 0 and not failed and not missing else 2


if __name__ == "__main__":
    sys.exit(main())
