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
DB). A DB superuser can disable triggers; production should stream to an external immutable store and
alert on gaps (missing execution events for allow decisions are detectable by correlation id).

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
a role may do per kind/classification/department) in Rego data under version `policy-v1`. Token
claims are used only for authentication. The PEP sends its expected policy version; OPA denies on
mismatch, and readiness fails if OPA serves a different version.

**Consequences.** Role changes take effect on the next request without token refresh; policy changes
are code-reviewed and tested with `opa test`.
