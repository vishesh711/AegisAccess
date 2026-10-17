"""Generate analytics/detection_large.csv: a deterministic, labelled synthetic day of access events.

The generator owns the ground truth: every row's `ground_truth_is_attack` comes from the scenario
that produced it, never from the detection rules being evaluated. Re-running with the same seed
produces byte-identical output (checked by tests/unit/test_dataset_generator.py).

Scenario mix (all synthetic):
  benign  - normal reads/searches; expired tokens; one-off mis-clicks; a 5-minute OPA outage;
            a deactivated user retrying; agent search filtering
  attack  - cross-tenant ID-guessing bursts; slow cross-tenant probes; forged-token sprays;
            prompt-injected agent calls; insider single probes (look like mis-clicks);
            a stolen workload credential reading allowed documents (looks like normal traffic);
            agent reads allowed under the older policy-v0
"""

from __future__ import annotations

import csv
import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

SEED = 20261017
START = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)
OUT = Path(__file__).resolve().parent.parent / "analytics" / "detection_large.csv"
FIELDS = [
    "event_id",
    "event_time",
    "principal_id",
    "principal_type",
    "subject_tenant",
    "resource_tenant",
    "action",
    "tool_name",
    "decision",
    "reason_code",
    "policy_version",
    "ground_truth_is_attack",
]
V1_FROM = START + timedelta(hours=6)  # policy-v1 rolled out at 06:00


def generate(seed: int = SEED) -> list[dict[str, str]]:
    rnd = random.Random(seed)  # noqa: S311 - reproducible synthetic data, not security-relevant
    rows: list[dict[str, object]] = []

    def ev(
        t: datetime,
        pid: str,
        ptype: str,
        st: str,
        rt: str,
        action: str,
        tool: str,
        decision: str,
        reason: str,
        attack: bool,
    ) -> None:
        rows.append(
            {
                "t": t,
                "principal_id": pid,
                "principal_type": ptype,
                "subject_tenant": st,
                "resource_tenant": rt,
                "action": action,
                "tool_name": tool,
                "decision": decision,
                "reason_code": reason,
                "policy_version": "policy-v1" if t >= V1_FROM else "policy-v0",
                "ground_truth_is_attack": attack,
            }
        )

    def at(minute: float) -> datetime:
        return START + timedelta(seconds=round(minute * 60))

    users = [(f"u{i:03d}", "alpha" if i % 3 else "beta") for i in range(1, 41)]

    # --- benign: normal allowed traffic, spread over working hours (07:00-19:00)
    for _ in range(1300):
        uid, ten = rnd.choice(users)
        ev(
            at(rnd.uniform(420, 1140)),
            uid,
            "human",
            ten,
            ten,
            rnd.choice(["documents:read", "documents:search"]),
            "",
            "allow",
            "ALLOW",
            False,
        )
    for _ in range(150):
        ev(
            at(rnd.uniform(0, 1440)),
            "svc-reporter",
            "workload",
            "alpha",
            "alpha",
            "documents:read",
            "",
            "allow",
            "ALLOW",
            False,
        )
    for _ in range(120):
        agent, ten = rnd.choice([("agent-alpha", "alpha"), ("agent-beta", "beta")])
        ev(
            at(rnd.uniform(420, 1140)),
            agent,
            "agent",
            ten,
            ten,
            rnd.choice(["documents:read", "reports:create"]),
            rnd.choice(["documents.read", "reports.create_summary"]),
            "allow",
            "ALLOW",
            False,
        )

    # --- benign denies
    for _ in range(60):  # expired tokens
        uid, ten = rnd.choice(users)
        ev(at(rnd.uniform(420, 1140)), uid, "human", ten, "", "authn", "", "deny", "TOKEN_EXPIRED", False)
    for _ in range(40):  # one-off mis-clicks on a document outside the user's role
        uid, ten = rnd.choice(users)
        ev(
            at(rnd.uniform(420, 1140)),
            uid,
            "human",
            ten,
            ten,
            "documents:read",
            "",
            "deny",
            "SUBJECT_NOT_GRANTED",
            False,
        )
    outage = rnd.sample(users, 12)  # 5-minute OPA outage at 13:00: 3 requests each
    for uid, ten in outage:
        for k in range(3):
            ev(
                at(780 + rnd.uniform(0, 5) + k * 0.01),
                uid,
                "human",
                ten,
                ten,
                "documents:read",
                "",
                "deny",
                "POLICY_UNAVAILABLE",
                False,
            )
    for uid, ten in (("dave", "alpha"), ("u099", "beta")):  # deactivated users retrying
        base = rnd.uniform(500, 900)
        for k in range(rnd.randint(3, 5)):
            ev(
                at(base + k * 0.7),
                uid,
                "human",
                ten,
                ten,
                "documents:read",
                "",
                "deny",
                "SUBJECT_INACTIVE",
                False,
            )
    for _ in range(30):  # agent search filtering hides out-of-scope titles (expected behaviour)
        ev(
            at(rnd.uniform(420, 1140)),
            "agent-alpha",
            "agent",
            "alpha",
            "alpha",
            "documents:search",
            "documents.search",
            "deny",
            "TASK_SCOPE_EXCEEDED,SUBJECT_NOT_GRANTED",
            False,
        )

    # --- attacks
    for b in range(6):  # cross-tenant ID-guessing bursts
        uid = f"x{b:02d}"
        base = rnd.uniform(300, 1300)
        for k in range(rnd.randint(4, 8)):
            ev(
                at(base + k * rnd.uniform(0.2, 0.6)),
                uid,
                "human",
                "beta",
                "alpha",
                "documents:read",
                "",
                "deny",
                "TENANT_MISMATCH",
                True,
            )
    for h in range(10):  # slow cross-tenant probe: one guess an hour
        ev(
            at(60 * (h + 8) + rnd.uniform(0, 10)),
            "u031",
            "human",
            "alpha",
            "beta",
            "documents:read",
            "",
            "deny",
            "TENANT_MISMATCH",
            True,
        )
    for _ in range(35):  # forged-token sprays
        ev(
            at(rnd.uniform(0, 1440)),
            "anonymous",
            "unknown",
            "unknown",
            "",
            "authn",
            "",
            "deny",
            rnd.choice(
                ["INVALID_SIGNATURE", "DISALLOWED_ALGORITHM", "UNKNOWN_SIGNING_KEY", "WRONG_AUDIENCE"]
            ),
            True,
        )
    for _ in range(20):  # prompt-injected agent calls
        reason, tool, action = rnd.choice(
            [
                ("TASK_SCOPE_EXCEEDED", "documents.read", "documents:read"),
                ("RESTRICTED_VIA_AGENT,TASK_SCOPE_EXCEEDED", "documents.read", "documents:read"),
                ("UNKNOWN_TOOL", "admin.grant_role", "tools:call"),
                ("SUBJECT_NOT_GRANTED,TASK_SCOPE_EXCEEDED", "exports.simulate", "exports:simulate"),
            ]
        )
        ev(
            at(rnd.uniform(420, 1140)),
            "agent-alpha",
            "agent",
            "alpha",
            "alpha" if action != "tools:call" else "",
            action,
            tool,
            "deny",
            reason,
            True,
        )
    for _ in range(15):  # insider single probes: indistinguishable from mis-clicks by these rules
        uid, ten = rnd.choice(users)
        ev(
            at(rnd.uniform(420, 1140)),
            uid,
            "human",
            ten,
            ten,
            rnd.choice(["documents:read", "audit:read"]),
            "",
            "deny",
            "SUBJECT_NOT_GRANTED",
            True,
        )
    for _ in range(25):  # stolen workload credential, overnight, reading what it is allowed to read
        ev(
            at(rnd.uniform(60, 240)),
            "svc-reporter",
            "workload",
            "alpha",
            "alpha",
            "documents:read",
            "",
            "allow",
            "ALLOW",
            True,
        )
    for _ in range(8):  # agent reads that policy-v0 allowed (before the restricted-via-agent rule)
        ev(
            at(rnd.uniform(0, 300)),
            "agent-alpha",
            "agent",
            "alpha",
            "alpha",
            "documents:read",
            "documents.read",
            "allow",
            "ALLOW",
            True,
        )

    rows.sort(key=lambda r: (r["t"], r["principal_id"], r["action"], r["reason_code"]))  # type: ignore[arg-type,return-value]
    out: list[dict[str, str]] = []
    for i, r in enumerate(rows, 1):
        t = r["t"]
        assert isinstance(t, datetime)
        out.append(
            {
                "event_id": f"L{i:05d}",
                "event_time": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
                **{k: str(r[k]).lower() if k == "ground_truth_is_attack" else str(r[k]) for k in FIELDS[2:]},
            }
        )
    return out


def main() -> int:
    rows = generate()
    with OUT.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    attacks = sum(r["ground_truth_is_attack"] == "true" for r in rows)
    print(f"wrote {OUT.name}: {len(rows)} rows, {attacks} attacks, {len(rows) - attacks} benign")
    return 0


if __name__ == "__main__":
    sys.exit(main())
