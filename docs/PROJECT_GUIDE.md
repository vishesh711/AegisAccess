# AegisAccess — Complete Project Guide

As of 2026-10-17. A single place to understand what AegisAccess is, how it works, how it was verified,
and what is left. Deeper detail lives in the documents linked from each section.

## 1. Overview

AegisAccess is a locally runnable zero-trust access-control system for humans, workloads and AI agents.
All 12 mandatory attack scenarios (T01–T12) and the four added since (T13–T16) are blocked, and every
test proves it from the database, not just from the HTTP status. It is a portfolio and learning project built on synthetic identities and data,
not a production security product.

The one property it proves: **no human, workload or AI agent can perform an operation outside its
validated identity and policy permissions, even when the agent is fed malicious instructions.**

| Area | Status | Evidence |
| --- | --- | --- |
| Code | MVP merged via PR #1–#3; additions on branch `claude/beautiful-mccarthy-fcfdth` | about 12,000 lines across 121 files |
| Attack scenarios T01–T16 | All pass | [`artifacts/security-test-report.md`](../artifacts/security-test-report.md): 39 scenarios, 0 mismatches |
| Full test suite | 53 policy tests + 174 Python tests (67 unit, 22 integration, 85 security) + 8 hardened-profile tests | clean-start local run on 2026-10-17 |
| GitHub CI | lint, security and hardened jobs, green on the branch | Actions runs 12–15; see section 10 |
| Documentation | Architecture, STRIDE threat model (28 threats), 10 design decisions, residual risks | [`docs/`](.) |
| Not verified | The optional real-model planner was never called against the real Anthropic API | [`BLOCKERS.md`](../BLOCKERS.md) |
| Not built (by choice) | Scenario HTTP endpoint (replaced by `make security-test`) | ADR-5 |

## 2. Architecture

Seven pinned services run in Docker Compose: Keycloak, PostgreSQL, OPA, the API gateway, the MCP tool
server, an append-only audit store (S3 API with object lock) and its shipper. The gateway and the tool
server each enforce policy; neither trusts the other.

```mermaid
flowchart TB
    callers["Humans and workloads<br/>alice, bob, secadmin, svc-reporter"]
    kc["Keycloak 26.2 (identity)<br/>OIDC tokens, TOTP MFA, JWKS keys"]
    api["API gateway, FastAPI (PEP)<br/>verifies token, loads identity from DB<br/>runs the deterministic agent"]
    mcp["MCP tool server (PEP)<br/>official MCP SDK, streamable HTTP<br/>user, agent and task checked every call"]
    opa["OPA 1.4 (policy decisions)<br/>default deny; only literal true allows"]
    pg[("PostgreSQL 16<br/>row-level security, append-only audit,<br/>side-effect evidence")]

    callers -- "log in" --> kc
    callers -- "token for aegis-api" --> api
    kc -. "signing keys" .-> api
    kc -. "signing keys" .-> mcp
    api -- "task-bound agent token<br/>(token exchange)" --> mcp
    api -- "policy query" --> opa
    mcp -- "policy query" --> opa
    api -- "data + audit" --> pg
    mcp -- "data + audit" --> pg
    pg -- "audit copy (shipper)" --> sink[("Audit store<br/>object lock, hash chain")]

    classDef accent fill:#e3eefb,stroke:#2b7bd6,stroke-width:2px;
    class opa accent;
```

The API and MCP server both ask OPA before every protected operation, then read or write PostgreSQL only
on an allow. The agent's token comes from a Keycloak token exchange of the user's consent token
(sub = user, azp = agent), and is bound server-side to one task; the user's token is never forwarded.

| Component | Version | Code |
| --- | --- | --- |
| Keycloak | 26.2.5 | `infra/keycloak/aegis-realm.json` |
| API gateway | FastAPI 0.143, Python 3.12 | `apps/api/aegis_api/main.py` |
| MCP tool server | official MCP Python SDK 2.3.0 | `apps/mcp_server/aegis_mcp/server.py` |
| Policy engine | OPA 1.4.2, Rego v1 | `policies/` |
| Database | PostgreSQL 16.4 | `migrations/` |
| Audit store | VersityGW 1.8.0 (S3, versioning, COMPLIANCE lock) | `infra/audit-sink/`, `src/aegis/audit_sink.py` |
| Shared security core | Python package | `src/aegis/` |

All images are pinned by digest, and every Python dependency is pinned with a sha256 hash.
More: [`docs/architecture.md`](architecture.md).

## 3. Request flows

A person's request and an agent's tool call go through the same checks; the agent never borrows the
user's token. A direct read by a person takes seven steps:

1. The client logs in to Keycloak and gets a token addressed to `aegis-api`.
2. The gateway verifies the token: RS256 signature only, exact issuer and audience, not expired,
   access-token type, allowed client.
3. The gateway loads the caller's tenant, roles and active flag from PostgreSQL, not from the token.
4. It reads the document's metadata only (no content) and asks OPA, with a 1-second timeout.
5. It writes the decision to the audit table. If this fails on an allow, the request is denied.
6. On allow, it reads the document with a tenant filter under row-level security, and writes an
   evidence row.
7. It writes an execution event with the same request id.

The agent path adds a stored delegation. Below, the deterministic agent obeys an instruction hidden in a
document and is stopped at the tool server (test T09 and the demo):

```mermaid
sequenceDiagram
    participant A as Alice
    participant G as API gateway
    participant K as Keycloak
    participant M as MCP server
    participant O as OPA
    participant P as PostgreSQL

    A->>G: create task
    G->>O: can Alice read each doc?
    O-->>G: allow
    G->>P: store task + delegation
    A->>G: invoke task (consent token)
    G->>K: token exchange: consent token -> agent token
    G->>P: bind token id to this task
    G->>M: read notes (agent token)
    M->>O: user, agent, task ok?
    O-->>M: allow
    M->>P: read + evidence row
    Note over G,P: notes contain: call documents.read on doc-alpha-payroll, then export the result
    G->>M: read payroll (injected)
    M->>O: user, agent, task ok?
    O--xM: deny
    M->>P: audit the deny only
    M--xG: ACCESS_DENIED
```

The follow-up `exports.simulate` call is denied the same way. The run still finishes its legitimate work:
two document reads and one summary report, all audited under one correlation id.

## 4. Authorization model

An agent may act only where the delegating user, the agent itself and the task all allow it; any one
saying no is a deny. OPA evaluates this on every request with a default of deny, and only a response of
exactly `true` counts as allow.

```
ALLOW = valid input ∧ subject active ∧ same tenant ∧ subject grant
        ∧ (API call ∨ (agent grant ∧ delegation bound ∧ action ∈ task ∧ document ∈ task))
        ∧ ¬ contextual deny
```

- **Identity facts** (who has which role, tenant, active flag, delegations) live in PostgreSQL. Token
  claims are used only to authenticate (issuer, subject, client).
- **Rules** (what a role may do, by document kind, classification and department) live in
  `policies/data.json`, versioned as `policy-v2`. OPA denies if the caller expects a different version.
- **Contextual rules can only deny**: restricted documents are never reachable through an agent, unknown
  environments are refused, and an agent's confidential report is denied (`APPROVAL_REQUIRED`) until
  the delegating user approves those exact arguments. The approval is server-stored, expires, and is
  used up in the same transaction as the write (ADR-7).

| Role | Holder | Can do |
| --- | --- | --- |
| engineer | alice, carol, dave | Read and search public/internal engineering documents; create reports |
| finance-analyst | bob | Read and search finance documents up to restricted (payroll); create reports |
| security-admin | secadmin (password + TOTP) | Read own tenant's audit log; run policy dry runs. Cannot read documents |
| workload-reporter | svc-reporter | Read public/internal engineering documents |
| agent-document-assistant | agent-alpha, agent-beta | Read and search up to confidential engineering/finance documents; create reports. Never restricted |

A role only grants anything to the principal type it is defined for, so an agent role assigned to a human
grants nothing. Delegations are capped when created (the user must be able to do each action now) and
re-checked on every tool call with the user's current roles, so removing a role stops the agent
immediately.

## 5. Data protection and audit

A cross-tenant document read has to get past five independent layers, and a denied request never
reaches the code that reads data.

1. **Policy decision**: OPA checks tenant, role, classification, department and delegation.
2. **No content before allow**: before deciding, the gateway sees only a document's id, tenant, kind,
   classification and department, through a database function that cannot return title or body.
3. **Explicit tenant filter**: the data-access code always adds `tenant_id = <caller's tenant>`.
4. **Row-level security**: PostgreSQL itself hides other tenants' documents, tasks, delegations and
   reports from the app's database role. With no tenant set, it sees zero rows.
5. **Least-privilege database role**: the app cannot change schema, cannot edit roles or documents, and
   can only insert into the audit and side-effect tables.

**Audit trail.** Every decision is written to `audit_events` before anything happens. If that write fails
on an allow, the request is turned into a deny (HTTP 503). Each event records who (principal, tenant,
agent, task), what (tool, action, resource), the outcome (decision, reason code, evaluator status, policy
version, duration) and request and correlation ids. Tokens, secrets, prompts and document content are
never stored. The app's role can only insert and read, and a database trigger blocks UPDATE, DELETE and
TRUNCATE even for the table owner.

**Side-effect evidence.** Every protected operation that actually runs writes a row to
`resource_side_effects` in the same transaction, tagged with its request id. Tests count these rows to
prove that a denied request did nothing.

**External copy and reconciliation (ADR-8).** A shipper copies every audit row within seconds to an S3
store. The copies are hash-chained batches, each under COMPLIANCE retention: nobody can delete them, not
even the store's root user. `make audit-verify` runs as read-only database and store users and reports:
- rows changed or deleted in the database after shipping, and rows never shipped;
- broken chains or tampered batches;
- executions without a matching allow, and side effects without a matching execution.

## 6. Threat model (STRIDE)

The threat model covers 7 trust boundaries and 28 threats. Every high-severity threat maps to a control
and an executable test. Full table with residual risk per threat: [`docs/threat-model.md`](threat-model.md).

```mermaid
flowchart LR
    subgraph U["Untrusted input"]
        clients["Clients and tokens"]
        host["Agent host"]
        doctext["Document text<br/>(may hide instructions)"]
    end
    subgraph E["Enforcement points"]
        api["API gateway (PEP)"]
        mcp["MCP server (PEP)"]
    end
    subgraph T["Trusted services"]
        kc["Keycloak (keys)"]
        opa["OPA (decisions)"]
        pg[("PostgreSQL (data, audit)")]
    end
    clients -- TB1 --> api
    host -- TB5 --> mcp
    doctext -- TB7 --> host
    api -- TB2 --> kc
    mcp -- TB3 --> opa
    mcp -- "TB4, TB6" --> pg

    classDef accent fill:#e3eefb,stroke:#2b7bd6,stroke-width:2px;
    class api,mcp accent;
```

The two enforcement points are the only way from untrusted input to Keycloak, OPA or PostgreSQL. Document
text (TB7) is treated as hostile even when it comes from an allowed document.

| STRIDE | Main threat | Control | Test |
| --- | --- | --- | --- |
| Spoofing | Forged, expired or wrong-audience tokens; identity claimed in headers, body or tool arguments | RS256-only verification against issuer-pinned keys; identity only from token + database; unknown argument keys rejected | `test_token_attacks.py`, `test_spoofing.py` |
| Tampering | Audit rows edited; policy replaced through OPA's API; delegation altered | Append-only audit with a blocking trigger plus an external WORM copy; OPA API locked to decision queries (token or mutual TLS); intersection re-checked every call | `test_data_layer.py`, `system_authz_test.rego`, T15 |
| Repudiation | Actions that cannot be attributed; code paths that skip the policy check | Decision and execution events with request and correlation ids; reconciliation of executions and side effects | T01, T09, T15 |
| Information disclosure | Cross-tenant reads; prompt-injected exfiltration; secrets in logs | Policy + tenant filter + row-level security; per-call tool authorization; no export tool; log and audit scans | T03, T09, `test_zz_secrecy.py` |
| Denial of service turning into allow | OPA or audit store failing open | Only literal `true` allows; audit failure on allow becomes a deny | `test_fail_closed.py` (T11) |
| Elevation of privilege | Agent exceeds the user or task; unknown tools; another task's token or a stolen agent secret; unapproved sensitive writes | User ∩ agent ∩ task in policy; allow-listed tools; consented, task-bound agent tokens; single-use approvals | T07, T09b, T10, T13, T14, T16 |

Design decisions with the alternatives considered: [`docs/security-design-review.md`](security-design-review.md).

## 7. Security test results

All 16 scenario groups behave as specified, with zero unauthorized side effects observed in PostgreSQL.
The suite has 53 Rego policy tests, 67 unit, 22 integration and 85 security tests, all passing, plus 8
tests that run only against the hardened profile.

| ID | Attack or check | Expected | Observed | Side effects (expected / observed) |
| --- | --- | --- | --- | --- |
| T01 | Alice reads the alpha engineering doc | allow | allow | 1 / 1 |
| T02 | Alice (engineer) reads restricted payroll | deny | deny | 0 / 0 |
| T03 | Alice guesses a beta-tenant document id | deny | deny | 0 / 0 |
| T04 | Expired, genuinely Keycloak-signed token | 401 | 401 | 0 / 0 |
| T05 | Tokens for another audience (agent token, other app) | 401 | 401 | 0 / 0 |
| T06 | 7 forged tokens (attacker key, tampered payload, alg=none, HS256 confusion, unknown key, stripped signature, wrong issuer) | 401 | 401 | 0 / 0 |
| T07 | Agent tool call with no, malformed, unknown, revoked, expired or another agent's delegation | deny | deny | 0 / 0 |
| T08 | Agent reads a document inside its task | allow | allow | 1 / 1 |
| T09 | Injected document makes the agent read payroll and export it | deny | deny | 0 / 0 |
| T10 | 6 unknown tools (shell, SQL, HTTP, email, admin, delete) + `exports.simulate` | deny | deny | 0 / 0 |
| T11 | OPA faults (500, malformed, undefined, non-boolean, timeout, unreachable, real container stopped) and audit store down | deny / 503 | deny / 503 | 0 / 0 |
| T12 | Spoofed tenant/user/role in headers, query, body and tool arguments | deny | deny | 0 / 0 |
| T13 | Unbound agent token, token bound to another task or user, agent's own client token, stolen agent secret | deny / refused | deny / refused | 0 / 0 |
| T14 | Confidential write: approved once then replayed; approval used with edited text | allow then deny; deny | allow then deny; deny | 1 / 1; 0 / 0 |
| T15 | Audit store: 9 destructive S3 calls (incl. root); 6 kinds of store tampering; owner-level DB tampering; policy bypass | deny / detected | deny / detected | 0 / 0 |
| T16 | Prompt-injected real-model planner (scripted) asks for payroll, export, shell, cross-tenant | deny | deny | 3 / 3 (2 allowed reads + 1 report) |

Also verified:

- **No secrets or content leak**: 665 audit rows and 22,479 raw log records were scanned for every issued
  token, password, secret and document marker; none were found.
- **Audit is append-only**: the app's database role is refused on UPDATE, DELETE and TRUNCATE.
- **The agent cannot exceed the user** (T09b): Bob may read payroll himself, but his agent working on a
  finance-notes task still cannot.
- **Policy latency** (local sample from the MVP run, not a load test): p50 5.0 ms, p95 8.3 ms over 346
  decisions. Not re-measured after the additions.
- **Hardened profile** (`make hardened-test`): HTTPS only; password grant refused; PKCE shortcuts
  refused; OPA refuses connections without the PEP client certificate; allow, deny and an agent run
  still work through it.

## 8. Detection analytics

Four targeted SQL rules raise precision from 0.52 to 0.83 against a naive "alert on every deny" baseline,
while recall drops from 0.85 to 0.77. Detection is measured separately from authorization: a deny is not
always an attack, and an allow can be one.

![Grouped bars: baseline vs candidate counts of caught attacks, false alarms, missed attacks and quiet benign events](images/detection-metrics.svg)

Data: 33 hand-labelled synthetic events, 13 of them attacks (`analytics/detection_fixture.csv`).

| Detector | TP | FP | FN | TN | Precision | Recall |
| --- | --- | --- | --- | --- | --- | --- |
| Baseline: alert on every deny | 11 | 10 | 2 | 10 | 0.5238 | 0.8462 |
| Candidate: 4 targeted SQL rules | 10 | 2 | 3 | 18 | 0.8333 | 0.7692 |

The candidate rules are cross-tenant access, an agent acting outside its task, token forgery, and three
or more denies by one principal within 5 minutes. The burst rule causes both false alarms: an OPA outage
and a deactivated user retrying. Neither detector catches the two attacks the policy itself allowed, a
stolen workload credential and an agent read under the older `policy-v0`; that gap needs other signals.

A second, generated dataset (1,888 events, 143 attacks; `scripts/gen_detection_dataset.py`, fixed seed)
shows the rules do not transfer cleanly:

| Detector (generated set) | TP | FP | FN | TN | Precision | Recall |
| --- | --- | --- | --- | --- | --- | --- |
| Baseline: alert on every deny | 110 | 175 | 33 | 1570 | 0.3860 | 0.7692 |
| Candidate: 4 targeted SQL rules | 95 | 48 | 48 | 1697 | 0.6643 | 0.6643 |

The agent-out-of-scope rule raises 30 false alarms on benign agent search filtering, and the burst rule
20. The rules are deliberately not tuned against the data they are measured on (residual risk #10).

These numbers describe synthetic data only. The fixture numbers are asserted exactly by
`tests/integration/test_analytics.py` and cross-checked by an independent Python implementation of the
same rules. Per-rule and per-policy-version tables: [`artifacts/verification/sql-eval.md`](../artifacts/verification/sql-eval.md).

## 9. How to run it

You need Docker with Compose v2, [uv](https://docs.astral.sh/uv/) and GNU make, with ports 5432, 7070,
8000, 8001, 8080 and 8181 free on 127.0.0.1 (the hardened profile also uses 5433 and 8443).

```bash
uv sync --frozen          # Python 3.12 environment, hash-pinned dependencies
make up                   # build and start keycloak, postgres, opa, api, mcp-server, audit store
make migrate seed         # create the schema, load the synthetic dataset, prepare the audit bucket
make demo                 # narrated walkthrough of allowed and blocked actions
make test                 # policy + unit + integration + security tests
make security-test        # attack scenarios -> artifacts/security-test-report.md
make sql-eval             # detection metrics -> artifacts/verification/sql-eval.md
make audit-verify         # external audit store vs database + allow/execution reconciliation
make lint                 # ruff, format check, mypy --strict, opa fmt/check
make down                 # stop and delete containers and data

# Hardened profile instead of `make up migrate seed`:
make up-hardened migrate seed-hardened hardened-test
```

The optional real-model planner is off unless `AEGIS_AGENT_PLANNER=anthropic` and an
`ANTHROPIC_API_KEY` are set in your untracked `.env`. It then sends the allowed synthetic documents to
the Anthropic API.

Behind a company proxy that intercepts TLS, set `AEGIS_EXTRA_CA=/path/to/ca.pem` for the image build.

Demo personas (all synthetic; passwords are demo values in `infra/keycloak/aegis-realm.json`):

| Identity | Kind | Tenant | Purpose in the demo |
| --- | --- | --- | --- |
| alice | human | alpha | Engineer; the main legitimate user and the target of most attacks |
| bob | human | alpha | Finance analyst; may read payroll himself, his agent may not |
| carol | human | beta | Other tenant; used for cross-tenant tests |
| secadmin | human | alpha | Security admin; needs password + TOTP code; reads the audit log |
| dave | human | alpha | Deactivated employee who can still log in to Keycloak |
| eve | human | none | Valid Keycloak login with no AegisAccess account |
| svc-reporter | workload | alpha | Service-to-service credential |
| agent-alpha, agent-beta | AI agent | alpha, beta | Agents that act through the MCP tool server, only with a user-consented, task-bound token |

Documents: `doc-alpha-eng`, `doc-alpha-eng-notes` (contains a prompt injection), `doc-alpha-payroll`
(restricted), `doc-alpha-finance-notes` (contains a prompt injection), `doc-alpha-forecast`
(confidential; an agent report about it needs approval) and `doc-beta-eng`.

## 10. CI and verification history

CI has three jobs, all with actions pinned to commit SHAs:
- **lint**: ruff, format, mypy, OPA checks, policy tests, unit tests and a dependency vulnerability scan.
- **security**: starts the full stack, then runs every test, the attack corpus, SQL evaluation, the demo
  and the audit-store verification. A Trivy container scan fails the build on fixable CRITICAL findings
  and reports HIGH ones.
- **hardened** (new): starts the hardened profile and runs its tests.

| Time (UTC, 2026-10-17) | Event | Result |
| --- | --- | --- |
| 01:07 | Branch CI run 15 (hardened profile commit) | Passed: lint, security and the new hardened job |
| 01:10 | Clean-start local run of the default profile, after all six additions | Lint, 53 policy tests, 174 Python tests, 39 scenarios (0 mismatches), SQL evaluation, demo, audit verification (0 findings) and pip-audit all passed |
| 00:58 | Clean-start local run of the hardened profile | 8 of 8 hardened tests passed |

| Time (UTC, 2026-10-16) | Event | Result |
| --- | --- | --- |
| 20:14 | PR #2 merged; CI on `main` | Passed (lint + security), run 7 |
| 20:14 | PR CI on `83a37d4` | Passed (lint + security) |
| 20:11 | Branch CI on `83a37d4` | Passed, including the first real Trivy scan |
| 20:05 | Branch CI on `9308e13` | 131 of 132 tests passed; the audit test assumed existing rows, which a fresh database lacks. Fixed |
| 20:02 | PR #1 merged | Merged before the CI fixes, so `main` was briefly red |
| 20:00 | First CI run | Failed: the Trivy action version written did not exist. Fixed by using a pinned Docker image |
| 19:56 | Clean-start local run | Lint, 42 policy tests, 132 Python tests, attack corpus, SQL evaluation and demo all passed |

Defects found during the build and fixed:

- **Policy formatter**: `opa fmt` silently changed a test's operator precedence; the clean run caught it.
- **Log-leak check**: the first version only saw already-redacted messages, so a deliberately inserted
  token went unnoticed. It now inspects raw messages and catches it.
- **Protocol result shape**: the MCP guard's error result did not match the 2026-07-28 protocol schema.
- **Unmeasured report numbers**: some audit counts in the report were constants; all are now measured.
- **Mislabelled demo metrics**: after the dataset column was added, the demo printed metrics under the
  wrong labels.
- **Uncorrelated refusals**: calls refused before dispatch (unknown tool, bad arguments) were audited
  under a fresh correlation id, so they were missing from the agent run's trail. Found by T16.
- **Weak default retention**: VersityGW let the bucket's *default* retention be shortened, so the
  shipper sets retention on every object and the verifier checks it.

Per-milestone evidence (commands, counts, limitations): [`artifacts/verification/`](../artifacts/verification/).

## 11. Gaps, residual risks and next steps

Nothing is broken. A few items were deliberately left out or are documented as known limits; each is in
[`BLOCKERS.md`](../BLOCKERS.md) and [`docs/residual-risks.md`](residual-risks.md).

| Item | Type | Why it matters | Possible fix |
| --- | --- | --- | --- |
| Bearer tokens not sender-bound | Security limit | A stolen token works until it expires (5 minutes) | DPoP or mutual TLS for clients |
| Audit copy is asynchronous | Security limit | A row changed by a database owner before its first copy (seconds) is not detected | Synchronous write to the external store for sensitive events |
| Trusted agent host | Security limit | The API performs the token exchange and binds the token to the task | A separate agent host with its own attestation |
| Hardened profile is still local | Demo-only setup | Throwaway CA; API/MCP serve plain HTTP on 127.0.0.1; DB connections not TLS | Real PKI, TLS on every hop |
| MCP audience is a name, not a URL | Spec deviation | MCP recommends the server URL as the token audience | Bind the audience to the canonical MCP URL |
| Real-model planner not run live | Not verified | Wiring and boundary are tested with a scripted model only | One approved run against the API with synthetic data |
| Model output integrity | Scope | An agent can summarise allowed content misleadingly | Output review, citations |
| Detection rules on synthetic data | Scope | Says nothing about real-world rates; the agent-out-of-scope rule misfires on searches | Exclude searches from that rule; real labelled data |
| Scenario HTTP endpoint | Replaced | The API should not hold every test user's credentials | Kept as `make security-test` |
