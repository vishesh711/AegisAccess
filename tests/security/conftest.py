"""Scenario recorder: every mandatory scenario records request, expected vs. actual decision and
OBSERVED side-effect counts (from PostgreSQL). `make security-test` renders the report."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import pytest

OUT = Path(__file__).resolve().parents[2] / "artifacts" / "tmp" / "scenarios.json"
_RESULTS: list[dict[str, Any]] = []


@dataclass
class Scenario:
    scenario_id: str
    description: str
    request: str
    expected_decision: str
    actual_decision: str
    expected_side_effects: int
    actual_side_effects: int
    audit_events: int
    attack: bool
    test: str = ""

    @property
    def passed(self) -> bool:
        return (
            self.expected_decision == self.actual_decision
            and self.expected_side_effects == self.actual_side_effects
        )


@pytest.fixture
def record(request: pytest.FixtureRequest) -> Callable[..., Scenario]:
    def _record(**kw: Any) -> Scenario:
        sc = Scenario(test=request.node.nodeid, **kw)
        _RESULTS.append({**asdict(sc), "passed": sc.passed})
        return sc

    return _record


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not _RESULTS:
        return
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"exitstatus": int(exitstatus), "scenarios": _RESULTS}, indent=2))
