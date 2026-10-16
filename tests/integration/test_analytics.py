"""SQL detection metrics are exact and reproducible on the labelled fixture.

Expected values were computed by hand from analytics/detection_fixture.csv (33 rows, 13 attacks):
  baseline (any deny):  21 flagged -> TP 11, FP 10, FN 2 (e29, e30 were allowed), TN 10
  candidate (R1|R2|R3|R4): flags e15 e19 e20 e21 e22 e23 e24 e25 e26 e27 e31 e33
                        -> TP 10, FP 2 (e15 outage burst, e33 inactive-user retries), FN 3 (e28 e29 e30), TN 18
and they are ALSO recomputed below by an independent Python implementation of the same rules.
"""

from __future__ import annotations

import csv
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import psycopg
import pytest

from tests.conftest import APP_DSN

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[2]


def q(name: str) -> list[tuple[Any, ...]]:
    with psycopg.connect(APP_DSN) as conn:
        return conn.execute((ROOT / "analytics" / "queries" / name).read_text()).fetchall()  # type: ignore[call-overload]


def test_fixture_loaded() -> None:
    with psycopg.connect(APP_DSN) as conn:
        row = conn.execute(
            "SELECT count(*), count(*) FILTER (WHERE ground_truth_is_attack) FROM detection_events"
        ).fetchone()
    assert row == (33, 13)


def test_confusion_matrix_exact() -> None:
    rows = {r[0]: r[1:] for r in q("confusion_matrix.sql")}
    assert rows["baseline_any_deny"] == (11, 10, 2, 10, Decimal("0.5238"), Decimal("0.8462"))
    assert rows["candidate_rules"] == (10, 2, 3, 18, Decimal("0.8333"), Decimal("0.7692"))


def test_by_rule_exact() -> None:
    rows = {r[0]: r[1:] for r in q("by_rule.sql")}
    assert rows == {
        "r1_cross_tenant": (4, 0, Decimal("1.0000")),
        "r2_agent_out_of_scope": (3, 0, Decimal("1.0000")),
        "r3_token_forgery": (3, 0, Decimal("1.0000")),
        "r4_deny_burst": (4, 2, Decimal("0.6667")),
    }


def test_by_policy_version_exact() -> None:
    rows = {r[0]: r[1:] for r in q("by_policy_version.sql")}
    assert rows == {"policy-v0": (1, 0, 1, 3, 1), "policy-v1": (9, 2, 2, 15, 1)}


def test_division_by_zero_protected() -> None:
    with psycopg.connect(APP_DSN) as conn:
        row = conn.execute("SELECT round(0::numeric / NULLIF(0, 0), 4)").fetchone()
    assert row == (None,)


def _python_oracle() -> dict[str, tuple[int, int, int, int]]:
    rows = list(csv.DictReader((ROOT / "analytics" / "detection_fixture.csv").open()))
    for r in rows:
        r["t"] = datetime.fromisoformat(r["event_time"].replace("Z", "+00:00"))
    flags: dict[str, tuple[bool, bool]] = {}
    for r in rows:
        deny = r["decision"] == "deny"
        r1 = bool(r["resource_tenant"]) and r["resource_tenant"] != r["subject_tenant"]
        r2 = (
            r["principal_type"] == "agent"
            and deny
            and any(
                k in r["reason_code"] for k in ("TASK_SCOPE_EXCEEDED", "UNKNOWN_TOOL", "RESTRICTED_VIA_AGENT")
            )
        )
        r3 = r["action"] == "authn" and r["reason_code"] in (
            "INVALID_SIGNATURE",
            "DISALLOWED_ALGORITHM",
            "UNKNOWN_SIGNING_KEY",
            "WRONG_AUDIENCE",
            "MALFORMED_TOKEN",
        )
        window = [
            o
            for o in rows
            if o["principal_id"] == r["principal_id"]
            and o["decision"] == "deny"
            and r["t"] - timedelta(minutes=5) <= o["t"] <= r["t"]
        ]
        r4 = deny and len(window) >= 3
        flags[r["event_id"]] = (deny, r1 or r2 or r3 or r4)
    out = {}
    for i, name in enumerate(("baseline_any_deny", "candidate_rules")):
        tp = fp = fn = tn = 0
        for r in rows:
            gt, f = r["ground_truth_is_attack"] == "true", flags[r["event_id"]][i]
            tp += gt and f
            fp += (not gt) and f
            fn += gt and not f
            tn += (not gt) and not f
        out[name] = (tp, fp, fn, tn)
    return out


def test_sql_matches_independent_python_oracle() -> None:
    sql = {r[0]: tuple(r[1:5]) for r in q("confusion_matrix.sql")}
    assert sql == _python_oracle()
