"""The large labelled dataset is reproducible: regenerating it yields the committed file byte for byte."""

from __future__ import annotations

import csv
import importlib.util
import io
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_generator():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("gen", ROOT / "scripts" / "gen_detection_dataset.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_committed_dataset_matches_generator() -> None:
    gen = _load_generator()
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=gen.FIELDS, lineterminator="\n")
    w.writeheader()
    w.writerows(gen.generate())
    assert buf.getvalue() == (ROOT / "analytics" / "detection_large.csv").read_text()


def test_labels_come_from_scenarios_not_rules() -> None:
    rows = _load_generator().generate()
    attacks = [r for r in rows if r["ground_truth_is_attack"] == "true"]
    # Attacks the policy itself allowed exist (detection must not equal "denied"), and benign denies exist.
    assert any(r["decision"] == "allow" for r in attacks)
    assert any(r["decision"] == "deny" and r["ground_truth_is_attack"] == "false" for r in rows)
    assert len({r["event_id"] for r in rows}) == len(rows)
