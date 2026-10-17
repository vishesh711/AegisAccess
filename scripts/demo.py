"""Narrated demo against the running compose stack (`make up migrate seed` first).

Shows: an allowed employee read, a denied cross-tenant read, a denied AI exfiltration attempt
(prompt injection), a sensitive agent write held for human approval, the audit trail (as the
MFA-protected security admin), side-effect evidence from PostgreSQL, and the detection metrics. Tokens are never printed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import sys
import time

import httpx
import psycopg

API = os.environ.get("AEGIS_DEMO_API", "http://127.0.0.1:8000")
TOKEN_URL = "http://localhost:8080/realms/aegis/protocol/openid-connect/token"
OWNER_DSN = os.environ.get(
    "AEGIS_OWNER_DATABASE_URL", "postgresql://aegis_owner:dummy-aegis-owner-pw@127.0.0.1:5432/aegis"
)
# Synthetic demo credentials (also in infra/keycloak/aegis-realm.json). Not secrets.
PW = {"alice": "alice-demo-pw", "bob": "bob-demo-pw", "secadmin": "secadmin-demo-pw"}
OTP_KEY = b"aegis-demo-otp-secret-dummy01"


def totp(key: bytes) -> str:
    digest = hmac.new(key, struct.pack(">Q", int(time.time() // 30)), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[o : o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def login(user: str, scope: str | None = None) -> str:
    data = {"grant_type": "password", "client_id": "aegis-cli", "username": user, "password": PW[user]}
    if scope:
        data["scope"] = scope
    if user == "secadmin":
        data["totp"] = totp(OTP_KEY)
    r = httpx.post(TOKEN_URL, data=data, timeout=10)
    if r.status_code != 200 and user == "secadmin":  # TOTP code already used this window: wait for the next
        time.sleep(31 - time.time() % 30)
        data["totp"] = totp(OTP_KEY)
        r = httpx.post(TOKEN_URL, data=data, timeout=10)
    r.raise_for_status()
    token: str = r.json()["access_token"]
    return token


def h(title: str) -> None:
    print(f"\n=== {title} " + "=" * max(0, 70 - len(title)))


def effects_since(conn: psycopg.Connection, mark: int) -> list[tuple[str, str]]:
    return [
        (r[0], r[1])
        for r in conn.execute(
            "SELECT kind, coalesce(resource_id, '-') FROM resource_side_effects WHERE id > %s ORDER BY id",
            (mark,),
        )
    ]


def mark(conn: psycopg.Connection) -> int:
    row = conn.execute("SELECT coalesce(max(id), 0) FROM resource_side_effects").fetchone()
    return int(row[0]) if row else 0


def main() -> int:
    conn = psycopg.connect(OWNER_DSN, autocommit=True)
    alice = {"Authorization": f"Bearer {login('alice')}"}

    h("1. Alice (alpha engineer) reads the alpha engineering spec")
    m = mark(conn)
    r = httpx.get(f"{API}/api/v1/resources/doc-alpha-eng", headers=alice)
    print(
        f"HTTP {r.status_code} decision={r.json()['decision']} title={r.json().get('document', {}).get('title')!r}"
    )
    print(f"observed side effects: {effects_since(conn, m)}")

    h("2. Alice guesses a beta-tenant document id (IDOR) and sends spoofed headers")
    m = mark(conn)
    r = httpx.get(
        f"{API}/api/v1/resources/doc-beta-eng", headers={**alice, "X-Tenant-Id": "beta", "X-Roles": "admin"}
    )
    print(f"HTTP {r.status_code} {r.json()}")
    print(f"observed side effects: {effects_since(conn, m)}  (expected: none)")

    h("3. Alice delegates a summary task to agent-alpha (one document contains a prompt injection)")
    r = httpx.post(
        f"{API}/api/v1/tasks",
        headers=alice,
        json={
            "agent_id": "agent-alpha",
            "actions": ["documents:read", "reports:create"],
            "resource_ids": ["doc-alpha-eng", "doc-alpha-eng-notes"],
            "ttl_seconds": 300,
        },
    )
    task = r.json()
    print(f"task {task['task_id']} actions={task['actions']} resources={task['resource_ids']}")
    m = mark(conn)
    # Starting the agent needs Alice's consent: a token carrying scope delegate-agent-alpha. The agent host
    # exchanges it at Keycloak for a token bound to Alice + agent-alpha, then binds that token to this task.
    consent = {"Authorization": f"Bearer {login('alice', scope='delegate-agent-alpha')}"}
    no_consent = httpx.post(f"{API}/api/v1/tasks/{task['task_id']}/invoke", headers=alice, timeout=60)
    print(
        f"invoke without consent scope: HTTP {no_consent.status_code}, needs scope {no_consent.json().get('consent_scope')}"
    )
    r = httpx.post(f"{API}/api/v1/tasks/{task['task_id']}/invoke", headers=consent, timeout=60)
    run = r.json()
    for t in run["trace"]:
        status = "ALLOWED" if t["ok"] else "DENIED "
        print(f"  step {t['step']}: [{t['origin']:8}] {status} {t['tool']}({json.dumps(t['arguments'])})")
    print(f"observed side effects: {effects_since(conn, m)}")
    print("-> the planner OBEYED the injected text; the MCP tool boundary denied payroll + export.")

    h("3b. Bob delegates a CONFIDENTIAL forecast summary: the report write waits for his approval")
    bob = {"Authorization": f"Bearer {login('bob')}"}
    bob_task = httpx.post(
        f"{API}/api/v1/tasks",
        headers=bob,
        json={
            "agent_id": "agent-alpha",
            "actions": ["documents:read", "reports:create"],
            "resource_ids": ["doc-alpha-forecast"],
            "ttl_seconds": 300,
        },
    ).json()["task_id"]
    bob_consent = {"Authorization": f"Bearer {login('bob', scope='delegate-agent-alpha')}"}
    m = mark(conn)
    first = httpx.post(f"{API}/api/v1/tasks/{bob_task}/invoke", headers=bob_consent, timeout=60).json()
    print(f"first run: report_id={first['report_id']} pending_approvals={first['pending_approvals']}")
    print(f"observed side effects: {effects_since(conn, m)}  (read only, no report_write)")
    for approval_id in first["pending_approvals"]:
        r = httpx.post(f"{API}/api/v1/approvals/{approval_id}/approve", headers=bob)
        print(f"Bob approves {approval_id}: HTTP {r.status_code} status={r.json()['approval']['status']}")
    m = mark(conn)
    second = httpx.post(f"{API}/api/v1/tasks/{bob_task}/invoke", headers=bob_consent, timeout=60).json()
    print(f"second run: report_id={second['report_id']} pending_approvals={second['pending_approvals']}")
    print(f"observed side effects: {effects_since(conn, m)}")
    print("-> the approval covered exactly those arguments and was used up by that one write.")

    h("4. Security admin (password + TOTP MFA) inspects the audit trail for that agent run")
    sec = {"Authorization": f"Bearer {login('secadmin')}"}
    r = httpx.get(
        f"{API}/api/v1/audit", headers=sec, params={"correlation_id": run["correlation_id"], "limit": 50}
    )
    for e in reversed(r.json()["events"]):
        print(
            f"  {e['event_kind']:9} {e['decision']:5} {e['tool_name'] or '-':24} {e['resource_id'] or '-':22} "
            f"{e['reason_code']}"
        )

    h("5. Detection metrics on the labelled synthetic datasets (make sql-eval for details)")
    for row in conn.execute(open("analytics/queries/confusion_matrix.sql").read()):  # noqa: SIM115
        dataset, detector, tp, fp, fn, tn, precision, recall = row[:8]
        print(
            f"  {dataset:8} {detector:18} TP={tp} FP={fp} FN={fn} TN={tn}"
            f" precision={precision} recall={recall}"
        )
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
