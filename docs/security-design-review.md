# Security design review (ADRs)

Status: accepted for the MVP. Each ADR states the decision, alternatives, and what would change it.

## ADR-1: OPA as a separate local service (vs embedded library vs central PDP)

**Decision.** One OPA container per deployment, queried over HTTP by both PEPs (API and MCP server)
with a 1 s timeout; OPA's own REST API locked down with token authentication and a `system.authz`
policy that permits only decision queries and health.

**Alternatives.** (a) Embedded evaluation (e.g. WASM/Python Rego) — no network hop, but a second
evaluator implementation to keep in sync with `opa test`. (b) Central shared PDP — single place to
govern, but a cross-service availability dependency and larger blast radius.

**Consequences.** Every decision is an HTTP call; an outage denies everything (by design — see
`test_fail_closed.py`). Measured latency is reported with sample size in the security report; it is
not a guarantee. A production setup would add mTLS between PEP and OPA, signed bundles, and decision
logs shipped off-host. Revisit if p95 latency or availability requirements tighten.

## ADR-2: Delegation mechanism (server-stored task + user-bound agent token via token exchange)

**Decision.** A user creates a task through the authenticated API; the server stores the delegation
(user, agent, actions, resource ids, expiry). The PDP caps it: each requested (action, resource) must
be allowed for the user at creation time, and the full intersection user ∩ agent ∩ task is re-evaluated
on **every** tool call with freshly loaded roles.

The agent never holds a token of its own. To start a run, the user's API token must carry the consent
scope `delegate-<agent>`, which puts the agent client in the token's audience. The agent host exchanges
that token at Keycloak (standard token exchange, RFC 8693, Keycloak 26.2) for a token with `sub` = the
user, `azp` = the agent and `aud` = `aegis-mcp`. It verifies the result and records, server-side, that
this token's `jti` (hashed) belongs to exactly one task (`agent_token_bindings`, insert-only, RLS). The
MCP server accepts a tool call only if the token's user and agent match the stored delegation and its
`jti` is bound to the task named in `Aegis-Task-Id`. Agent clients have no service account.

**Alternatives.** (a) Forward the user's token to the MCP server — rejected: token passthrough, the
user token's audience is the API. (b) Agent client-credentials token + task id header (the original
design) — replaced: anyone holding the agent secret could use any of the agent's tasks. (c) Task id in
the token through Keycloak dynamic scopes (`aegis-task:<id>`) — rejected after testing: the feature is
experimental in 26.2, and the agent could request a task scope the user's token did not contain, so the
scope proved nothing beyond the server-side check. (d) Boolean "user approved" tool argument —
rejected outright (MCP_SPEC approval rule).

**Consequences.** A stolen agent secret alone yields no token, and cannot exchange an ordinary user token
(no consent audience). A leaked agent token works only for its one task, for its one user, for at most
300 s. Remaining gap: the agent host that performs the exchange is trusted to bind honestly, and
Keycloak 26.2 does not add an `act` claim, so the agent appears only as `azp` (tested in
`tests/security/test_agent_token_binding.py`).

## ADR-3: Audit durability and fail-closed semantics

**Decision.** Audit events live in PostgreSQL `audit_events`: the runtime role can only INSERT/SELECT;
a trigger blocks UPDATE/DELETE/TRUNCATE for everyone. The decision event is written **before** any side
effect; if that write fails for an allow, the allow becomes a 503 deny. Execution events are written
after the operation (failure is logged, not fatal, because the operation already happened).
Side effects are instrumented in `resource_side_effects` inside the same transaction as the operation.

**Alternatives.** External append-only sink (WORM bucket, SIEM) — stronger against DB superuser
tampering, out of scope for a local demo. Async queue — better availability, but weakens
"no side effect without a durable decision record".

**Consequences.** Audit availability is coupled to DB availability (acceptable: data is in the same
DB). A DB superuser can disable triggers; ADR-8 adds the external immutable copy and the gap checks.

## ADR-4: MCP transport (streamable HTTP, stateless, bearer per request)

**Decision.** Official MCP Python SDK 2.3.0 `MCPServer.streamable_http_app(stateless_http=True,
json_response=True)` with the SDK's `BearerAuthBackend` calling AegisAccess's `TokenVerifier`
(RS256, issuer, audience `aegis-mcp`, azp limited to registered agent clients) on every request. The
raw token is not retained in request context. A `ServerMiddleware` guard rejects unknown tools,
unexpected argument keys, schema violations and oversized arguments before SDK dispatch, because the
SDK silently drops unknown argument keys. DNS-rebinding protection uses an explicit host allow-list.
Protected-resource metadata is advertised by the SDK.

**Alternatives.** stdio transport (identity inherited from the launcher — not a remote authenticated
server); stateful sessions (session id would be tempting to treat as identity).

**Consequences / deviations.** The audience is the logical identifier `aegis-mcp` rather than the
canonical MCP server URI recommended by RFC 8707 / the MCP authorization spec, because Keycloak's
audience mapper issues a static string and the server is reached under different hostnames inside and
outside compose; `validate_token_resource=False` because the verifier enforces the audience itself.

## ADR-5: Scenario runner instead of `POST /api/v1/scenarios/{id}/run`

**Decision.** The MVP lists a test-only scenario endpoint. It is **not** implemented: running the
attack corpus requires credentials for many personas (and forging tokens), which an API server must
not hold. The corpus runs as `make security-test` (pytest + recorder) and writes `scenario_results` and
`artifacts/security-test-report.md`.

## ADR-6: Policy facts vs policy rules

**Decision.** Identity facts (principals, roles, delegations, active flags) in PostgreSQL; rules (what
a role may do per kind/classification/department) in Rego data under a version id (now `policy-v2`). Token
claims are used only for authentication. The PEP sends its expected policy version; OPA denies on
mismatch, and readiness fails if OPA serves a different version.

**Consequences.** Role changes take effect on the next request without token refresh; policy changes
are code-reviewed and tested with `opa test`.

## ADR-7: Human approval for sensitive agent writes

**Context.** MCP_SPEC asks for approval of sensitive tool calls and PRD scenario P1 asks that an approval
cannot be replayed. An approval flag in tool arguments, or a prompt asking the model to "confirm", would be
controlled by the agent and is no control at all.

**Decision.**
- The policy denies `reports:create` from MCP with `APPROVAL_REQUIRED` when the report is confidential or
  restricted (a report takes the highest classification of its source documents) unless the PEP passes
  `approval.valid = true`. This is a deny-only contextual rule: approval never adds a grant the
  user ∩ agent ∩ task intersection lacks.
- On that deny, the tool server stores a pending row in `approvals` bound to tenant, task, delegating user,
  agent, action and the sha256 of the canonical JSON of the arguments (task id, sorted document ids, summary
  text). The agent gets only the approval id.
- Only the delegating human approves, through `POST /api/v1/approvals/{id}/approve` with their own API
  token. Pending requests expire after 10 minutes, granted approvals 5 minutes after the decision.
- The approval is consumed with a conditional `UPDATE ... WHERE consumed_at IS NULL` in the **same
  transaction** as the report insert. A replay, a concurrent duplicate or changed arguments find no usable
  approval and are denied with no write.
- The runtime role may only update the decision and consumption columns; it cannot change the digest,
  approver or task of an approval.

**Alternatives rejected.** Approval as a token claim or scope (the agent host holds the user's consent token,
and a claim is not single-use); approval inside OPA data (OPA should stay stateless; consumption must be
atomic with the write, which only the database can do).

**Evidence.** `tests/security/test_approvals.py` (T14: single use + replay, tampered arguments, wrong
approver, rejected and expired, five concurrent uses -> one write, full agent run, `approved` argument),
approval tests in `policies/authz_test.rego`. Mutation checks: removing consumption, consuming outside the write
transaction, or ignoring the digest each make T14 fail.

## ADR-8: External append-only audit store and reconciliation

**Context.** ADR-3 keeps audit rows in PostgreSQL, where the table owner or a superuser can disable the
immutability trigger and rewrite history. A check that "every allowed action was executed and every
execution was allowed" was also missing.

**Decision.**
- A local S3-compatible store (VersityGW 1.8.0, POSIX backend, versioning + object lock) runs in compose.
  MinIO images are no longer published on Docker Hub, so VersityGW was chosen; it was tested here before
  use (results below).
- `audit-shipper` (its own DB role: SELECT on `audit_events`, INSERT on `audit_shipments`; its own S3 user)
  ships unshipped rows every 3 s as `batches/<seq>.jsonl`:
  - a header with the previous batch's sha256 (hash chain), then one line per event with its digest;
  - each object written with `If-None-Match: *` and an explicit per-object COMPLIANCE retention (7 days).
  "Unshipped" means "no `audit_shipments` row", not "after the last id", so rows that commit late are
  never skipped.
- The bucket policy gives the shipper only put/get/list and the auditor only get/list/versions/retention.
  Nobody has delete, policy, lock or versioning rights; COMPLIANCE retention blocks deletion even for root.
- `make audit-verify` (DB role `aegis_auditor`, read-only S3 user) reports:
  - store integrity: delete markers, extra versions, gaps, broken chain, edited events, weak retention;
  - store vs database: rows deleted or modified after shipping, rows not shipped within 120 s, shipment
    records with no stored copy;
  - activity: executions of policy-governed actions without an allow decision in the same request,
    executions of unknown actions, side effects without an execution event (now matched by
    `request_id`, migration 0007), and a warning for allowed MCP calls that never executed.

**Measured VersityGW behaviour (v1.8.0, this environment).** With explicit COMPLIANCE retention:
- deleting a version is refused, including with the governance bypass header;
- shortening the retention is refused, as is suspending versioning;
- a second write with `If-None-Match` is refused, and an overwrite without it adds a version while keeping
  the original;
- root can still add a delete marker (standard S3 semantics): the locked version stays readable, and the
  verifier reports `SINK_DELETE_MARKER`.

With only the bucket's *default* retention, the retention could be shortened and the version then
deleted. That is why the shipper sets retention per object and the verifier checks it on every object
via `GetObjectRetention` (GET does not return the lock headers on this server).

**Alternatives rejected.** A second PostgreSQL database (same administrators, no WORM property); a local
append-only file (deletable by anyone with the volume); syslog/SIEM (out of scope for a local demo).

**Consequences.** Events are copied within seconds, not synchronously: an attacker with owner rights who
acts within the shipping interval can alter a row before its first copy (residual risk #3). Anyone with
access to the storage volume or host bypasses the S3 API entirely; the hash chain and the database copy
make that visible, but cannot prevent it. Production should use a managed store with compliance-mode
object lock (for example S3 Object Lock) in a separate account.

**Evidence.**
- `tests/security/test_audit_sink.py` (T15): shipping; nine destructive calls refused, including as root;
  six kinds of store tampering detected; owner-level DB tampering detected; fake shipment records and
  unshipped rows detected; reconciliation flags an adapter call that skipped the PEP, a forged execution
  and an unknown action, with zero findings for normal traffic.
- `tests/unit/test_audit_sink.py`.
- Mutation checks: disabling any one of eight verifier or shipper controls makes T15 fail.
- On a full test run, the activity checks reported only the deliberate cases above, plus the existing
  test that calls the adapter directly, plus four warnings from the T14 concurrency test (allowed, then
  denied because another request had already used the approval).

## ADR-9: Hardened profile (TLS, PKCE, mutual TLS to OPA)

**Context.** The default profile favours a scriptable demo: plain-HTTP Keycloak on a file store,
password-grant logins, and a static bearer token protecting OPA (residual risks #4 and #6).

**Decision.** An overlay, `infra/compose.hardened.yaml`, changes only transport and login, never the
authorization logic:
- `scripts/gen_pki.py` creates a throwaway local CA (ECDSA P-256, 30 days, via the `cryptography` X.509
  builder) with server certificates for Keycloak and OPA and a client certificate `CN=aegis-pep`.
- Keycloak runs `start` (production mode): HTTPS only on 8443, its own PostgreSQL (`keycloak-db`).
  `scripts/harden_realm.py` derives the realm with `sslRequired=all` and the password grant disabled
  on every client.
- Humans log in through the public client `aegis-web` with authorization code + PKCE (S256 enforced)
  and a loopback redirect (RFC 8252). The client is also in the default realm, so both profiles
  support it. `src/aegis/pkce_client.py` performs the browser steps for the demo personas.
- OPA runs `--authentication=tls --authorization=basic`. `system.authz` chooses its identity check
  from `AEGIS_OPA_AUTH_MODE`, never from the request. In `tls` mode the verified certificate subject
  must equal `AEGIS_OPA_PEP_IDENTITY`; in `token` mode, a bearer string that looks like a subject is
  just a wrong token (Rego test). Any other mode authenticates nobody.
- The PEPs use a dedicated OPA HTTP client that presents the client certificate and sends no bearer
  token. `opa_auth=mtls` without an https URL, CA, certificate or key fails at startup.
  `tls_ca_file` replaces the system trust store, so only the demo CA is trusted.
- Principals are bound to (issuer, subject), so the hardened stack is seeded with its https issuer
  (`make seed-hardened`).

**Measured (this environment, `make hardened-test`, 8 tests).**
- Discovery works over HTTPS with the demo CA, fails against the system trust store, and nothing
  answers on plain HTTP.
- The realm is in PostgreSQL with `ssl_required=ALL`.
- The password grant returns `unauthorized_client`.
- Missing PKCE and `plain` PKCE are refused at the authorization endpoint; a missing or wrong
  `code_verifier` is refused at the token endpoint.
- OPA:
  - refuses the TLS handshake with no client certificate, or one from another CA;
  - answers 401/403 for a certificate from the right CA with another subject;
  - serves decisions to the PEP certificate, but refuses it policy writes and raw data reads.
- Through all this, a PKCE login still gets allow (with one side effect), deny (with none, OPA status
  `ok`) and a full agent run from a PKCE consent login (injected payroll read denied, one report
  written).
- Mutation check: letting `system.authz` accept any certificate subject fails both the live test and
  a Rego test.

**Alternatives rejected.** Keycloak client-certificate auth for users (not what PKCE demonstrates);
a service mesh for mTLS (new infrastructure, out of scope); keeping the password grant in the hardened
realm (it is what the profile removes).

**Consequences / not covered.** The CA and keys are local throwaway files, readable by the containers
(and anyone on the host). API and MCP still serve plain HTTP on 127.0.0.1, and the API→MCP hop is plain
HTTP on the compose network. Database connections are not TLS, OPA bundles are unsigned, and the
Keycloak health check is a TCP probe (the image has no TLS client). The full attack suite runs on the
default profile; the hardened suite covers transport and login, plus representative allow, deny and
agent paths.

## ADR-10: Optional real-model planner

**Context.** Every test uses a deterministic planner that obeys injected instructions on purpose. That
proves the tool boundary holds against a worst-case agent, but not that a real model is wired the same
way.

**Decision.**
- `src/aegis/llm_planner.py` implements the same `run(task_id, resource_ids, client)` interface with a
  manual tool loop on the official Anthropic Python SDK (`anthropic==1.15.0`, the `llm` extra):
  - model `claude-opus-5-5`, effort `medium`, adaptive thinking (the model default), `tool_choice: auto`;
  - three strict tool schemas mirroring the MCP tools (API names can't contain dots: `documents_read` is
    sent as `documents.read`);
  - server-side refusal fallback (`fallbacks: "default"`), step and turn budgets.
- The model only proposes calls. Every proposal, including tools that don't exist, goes unchanged through
  the agent's task-bound token to the MCP server. There, the normal checks apply: authentication,
  user ∩ agent ∩ task, approval, audit. The planner filters and decides nothing, and its system prompt
  is not a control.
- It is selected only by `AEGIS_AGENT_PLANNER=anthropic`, at startup (a missing SDK fails the boot).
  The default stays `deterministic`. Credentials come from the SDK's own environment resolution; the
  planner never reads, stores or logs them.
- What leaves the process: task id, document ids, tool schemas, and the content of documents the
  boundary allowed (synthetic data only). Never tokens, identities, or denied content (asserted in T16).
- Tool results longer than 8,000 characters are cut, and the cut is marked in the text.

**Found while building it.** Calls refused before dispatch (unknown tool, bad arguments, oversized
payload) were audited under a fresh correlation id. The guard read headers from a context object that
has none, so these refusals did not show up in the agent run's trail. Fixed: the guard now reads them
from the transport's HTTP request. T16 asserts the `UNKNOWN_TOOL` refusal is in the run's trail.

**Evidence.**
- `tests/unit/test_llm_planner.py` (5 tests): forwarding without filtering, request shape, strict-schema
  keywords, budgets and refusal.
- `tests/security/test_llm_planner_boundary.py` (T16, 2 tests): a scripted, prompt-injected model goes
  through the real API, token exchange, MCP, OPA and PostgreSQL:
  - payroll, export, shell and cross-tenant calls are all denied;
  - exactly 3 side effects: two allowed reads and one report;
  - four correlated denials;
  - no payroll or beta canary and no token in anything the model was sent;
  - a confidential report still waits for the human approval.

**Not verified.** No request was sent to the real Anthropic API from this environment: that needs a key
and the user's approval to send (synthetic) data to an external service. The tests prove the wiring and
the boundary, not a real model's behaviour. Output integrity (a misleading summary of allowed content)
is unchanged: residual risk #9.

