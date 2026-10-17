# AegisAccess — Implementation Plan

Source of truth: `PRD.md`, `MVP.md`, `MCP_SPEC.md`, `CLAUDE.md` (kept in `docs/spec/`).
This plan records what was actually verified in the build environment; checkboxes are
updated only after the corresponding command has been run and has passed.

## 0. Environment inspection (done before writing code)

| Item | Finding |
|---|---|
| Docker | Engine 29.8.2 + Compose v5.6.0. Daemon had to be started manually (`dockerd`). |
| Images | `postgres:16.4-alpine`, `openpolicyagent/opa:1.4.2-static`, `python:3.12-slim` pull from Docker Hub. `quay.io` is **blocked** by the egress proxy, so Keycloak uses the Docker Hub mirror `keycloak/keycloak:26.2.5` (same upstream project). All pinned by digest in `infra/compose.yaml`. |
| Python | Host 3.13; project targets **3.12** (uv-managed venv, same as container image). |
| MCP SDK | `mcp==2.3.0` (official, supports protocol 2026-07-28). Verified by spike: `MCPServer(token_verifier=..., auth=AuthSettings(...))` + `streamable_http_app(stateless_http=True, json_response=True)`; bearer token verified on **every HTTP request** by `BearerAuthBackend`; tool handlers read the verified token with `mcp.server.auth.middleware.auth_context.get_access_token()`; `Context.headers` exposes request headers; `ServerMiddleware` sees raw `tools/call` params before validation; dotted tool names (`documents.read`) are valid (SEP-986 regex). Unknown tools return `is_error=True`. Extra tool arguments are *silently dropped* by the SDK, so AegisAccess adds middleware that rejects them. |
| Container builds | Builds need `--network host` + proxy CA in this sandbox only. Handled by optional build args/secret; a normal workstation needs nothing extra. |

## 1. Architecture

```
 human (aegis-cli, password grant – demo only)      workload (svc-reporter, client_credentials)
          │ access token aud=aegis-api                       │ aud=aegis-api
          ▼                                                  ▼
 ┌──────────────────────────── API gateway (FastAPI, PEP) ─────────────────────────────┐
 │ JWT validation (RS256, iss, aud, exp, nbf, typ, JWKS cache w/ rotation)            │
 │ identity resolution: (iss, sub) -> principals row (tenant, roles, active) from DB  │
 │ PEP: canonical input -> OPA -> audit(decision) -> adapter -> audit(execution)      │
 │ /tasks: server-side delegation (scope capped by OPA "could the user do this")      │
 │ /tasks/{id}/invoke: runs deterministic agent; agent uses ITS OWN token (no         │
 │   passthrough of the user's token)                                                 │
 └───────────────┬──────────────────────────────────────┬───────────────────────────────┘
                 │                                      │ agent token aud=aegis-mcp
                 ▼                                      ▼
        OPA (aegis.authz, default deny)     MCP server (official SDK, streamable HTTP)
                 ▲                           bearer verified per request; tool gateway =
                 │                           same PEP with user ∩ agent ∩ task intersection
                 └──────────────┬────────────┘
                                ▼
                 PostgreSQL (RLS on tenant tables; append-only audit; side-effect log)
```

Trust boundaries (STRIDE in `docs/threat-model.md`): client→gateway, gateway→Keycloak/JWKS,
gateway→OPA, gateway→DB, agent→MCP, MCP→resources.

### Key design decisions (ADRs in `docs/security-design-review.md`)
1. **Authorization facts vs policy.** Who-has-which-role / delegations live in Postgres;
   what-a-role-may-do lives in Rego data (`policies/data.json`, versioned as `policy_version`).
   Token claims are used only for authentication (iss/sub/azp/aud), never for tenant/roles.
2. **Agent identity** = its own Keycloak confidential client (`agent-alpha`) with audience
   `aegis-mcp`. User intent = server-stored delegation (task) created by the user through the
   authenticated API. The task id travels in the `Aegis-Task-Id` header as a *selector only*;
   it is honoured only if the server-side delegation is bound to the authenticated agent,
   same tenant, unexpired and unrevoked.
3. **Intersection in the PDP.** Rego allows an agent action only if the delegating user's
   roles permit it AND the agent's roles permit it AND the task lists the action AND (for
   documents) the resource id. Contextual rules (e.g. restricted data never via MCP) can only deny.
4. **Fail closed everywhere.** OPA query `POST /v1/data/aegis/authz/allow`; only a JSON body
   whose `result` is literally `true` allows. Timeout / HTTP error / malformed / undefined → deny
   (HTTP 503 at API). Decision audit must be persisted *before* any side effect.
5. **Defence in depth on data.** Resource body reads go through an adapter that applies an
   explicit tenant predicate *and* Postgres RLS (`aegis.tenant_id` GUC). PEP reads only
   non-sensitive metadata via a `SECURITY DEFINER` function, so the PDP can make the tenant
   decision without the PEP ever touching another tenant's body.
6. **OPA hardening.** OPA runs with `--authentication=token --authorization=basic` and a
   `system.authz` policy: only decision queries and health are allowed; policy PUT/DELETE denied.
7. **Scenario endpoint deviation.** `POST /api/v1/scenarios/{id}/run` is *not* implemented as
   an HTTP endpoint: running the attack corpus needs credentials for many personas, which an API
   server must not hold. The corpus runs as `make security-test` (pytest + recorder). Recorded
   in ADR-5.

## 2. Repository layout

```
apps/api/aegis_api/        FastAPI app (routes, deps)
apps/mcp_server/aegis_mcp/ MCP server (official SDK), middleware, tool registration
src/aegis/                 config, authn (JWT/JWKS), identity, db, pdp (OPA client), pep,
                           audit, resources adapter, delegation, tool gateway, planner, agent client
policies/                  authz.rego, data.json, system_authz.rego + *_test.rego
infra/compose.yaml         keycloak, postgres, opa, api, mcp-server
infra/keycloak/            aegis-realm.json (synthetic users, fixed ids, dummy secrets)
infra/postgres/init/       role bootstrap (owner + runtime role)
migrations/                NNNN_*.up.sql / .down.sql + scripts/migrate.py runner
scripts/                   migrate, seed, demo, sql_eval, security report, wait_for
analytics/                 labelled fixture CSV + detection / metric SQL
tests/unit|integration|security (+ fixtures)
docs/                      architecture, threat model, design review, residual risks, sql eval
artifacts/verification/    M0..M4 evidence; artifacts/security-test-report.md
```

## 3. Data model (migration 0001/0002)

`tenants`, `principals(id, tenant_id, type∈{human,workload,agent}, oidc_issuer, oidc_sub, client_id, active)`
UNIQUE(oidc_issuer, oidc_sub); `roles`; `principal_roles(principal_id, tenant_id, role_id)` with
composite FK to principals(id, tenant_id); `agent_identities(id, principal_id, tenant_id, active)`;
`resources(id, tenant_id, kind, classification, department, owner_id, title, body)` (RLS);
`tasks(id, tenant_id, owner_principal_id, agent_principal_id, purpose, status)` (RLS);
`delegations(id, task_id, tenant_id, user_principal_id, agent_principal_id, allowed_actions[],
allowed_resources[], expires_at, revoked_at)` (RLS); `reports` (RLS); `policy_versions`;
`audit_events` (append-only: app role has INSERT/SELECT only + trigger blocks UPDATE/DELETE/TRUNCATE);
`resource_side_effects` (instrumentation: one row per *actual* protected operation);
`scenario_results`; `detection_events` (analytics fixture).

Runtime role `aegis_app`: no DDL, no UPDATE/DELETE on audit; owner role `aegis_owner` runs migrations.

## 4. API contract

| Method/Path | AuthN | AuthZ (PEP→OPA action) | Notes |
|---|---|---|---|
| GET /health/live | none | – | process only |
| GET /health/ready | none | – | db, opa (+policy_version), jwks; booleans only |
| GET /api/v1/resources/{id} | Bearer aud=aegis-api | documents:read | 401/403/503; body only on allow |
| POST /api/v1/tasks | Bearer (human) | each requested (action,resource) must be allowed for the user | body `extra=forbid`; agent must be same-tenant & active |
| POST /api/v1/tasks/{id}/revoke | Bearer (owner) | owner check | sets revoked_at |
| POST /api/v1/tasks/{id}/invoke | Bearer (owner) | owner check, then every tool call enforced at MCP | runs deterministic agent |
| GET /api/v1/audit | Bearer | audit:read (security-admin, own tenant) | sanitized, paginated |
| POST /api/v1/policy/simulate | Bearer | policy:simulate | evaluates hypothetical input, never executes |

Response model for decisions: `{request_id, decision, reason_code, policy_version}`; reason codes to
clients are coarse (`ACCESS_DENIED`, `UNAUTHENTICATED`, `DEPENDENCY_UNAVAILABLE`); detailed codes in audit.

## 5. MCP tools and enforcement (MCP_SPEC A–G)

Tools: `documents.read(resource_id)`, `documents.search(query, max_results)`,
`reports.create_summary(task_id, document_ids, summary_text)`; `exports.simulate(...)` only when
`AEGIS_ENABLE_TEST_TOOLS=true` (no network; policy grants it to nobody).

Per call: (A) bearer verified by SDK middleware with AegisAccess verifier (aud=aegis-mcp, azp must be a
registered agent client) → principal from DB; (B) task/delegation loaded from DB under agent tenant RLS,
bound to agent, unexpired, unrevoked, owner active; (C/D) canonical input built server-side → OPA
(intersection in Rego); (E) decision audit persisted (failure → deny); (F) typed adapter with tenant
predicate + RLS; (G) execution audit with same correlation id. Middleware rejects unknown tools, unknown
argument keys and oversized payloads *before* any tool code runs, and audits the attempt.

## 6. Milestones

### M0 — Foundation
- [x] pyproject + uv.lock + hashed requirements.lock; ruff, mypy strict on src
- [x] Dockerfile (non-root, hash-pinned install), compose with digest-pinned images, 127.0.0.1-only ports
- [x] Makefile: up, down, migrate, seed, lint, test, security-test, demo
- [x] migration runner + 0001 schema; `make lint` and unit tests green
- [x] artifacts/verification/M0.md

### M1 — Identity & tenancy
- [x] Keycloak realm import (fixed ids, audience mappers, short-lived client, OTP for secadmin)
- [x] JWT verifier: RS256 only, iss, aud, exp, nbf, typ=Bearer, azp allowlist, JWKS cache + refresh on unknown kid (rate-limited)
- [x] identity resolution from DB; RLS + tenant predicate; seed data
- [x] T01–T06, T12 pass against real Keycloak/Postgres; artifacts/verification/M1.md

### M2 — Authorization
- [x] Rego policy + data + system.authz; `opa test`, `opa check --strict`, `opa fmt` clean
- [x] OPA client strict result parsing; PEP; decision/execution/incident audit; audit immutability
- [x] T01–T03, T11 end-to-end through real OPA; failure injection (down/timeout/500/malformed/undefined)
- [x] artifacts/verification/M2.md

### M3 — Secure MCP
- [x] MCP server with official SDK, verifier, middleware, tool gateway, rate limit, timeouts
- [x] tasks/delegation API; deterministic planner (follows injected instructions naively); agent client
- [x] T07–T10 + MCP integration tests (list, impersonation, wrong audience, connection reuse, revoked/expired, schema) 
- [x] artifacts/verification/M3.md

### M4 — Security validation
- [x] analytics fixture + SQL confusion matrix (baseline vs candidate, by rule, by policy version) + tests
- [x] security suite recorder → scenario_results + artifacts/security-test-report.md
- [x] docs: architecture, STRIDE, design review ADRs, residual risks, sql evaluation
- [x] clean-start run (`make down && make up migrate seed lint test security-test sql-eval demo`)
- [x] CI workflow executed on GitHub (green on `main`; see BLOCKERS.md)
- [x] artifacts/verification/M4.md

### Post-MVP additions (user request: items 1–6)
- [x] 6 Hygiene: actions pinned to commit SHAs, Trivy fails on fixable CRITICAL, 1,888-row generated labelled dataset
- [x] 1 Agent tokens via Keycloak standard token exchange, bound server-side to one task (T13)
- [x] 2 Human approval for confidential agent writes: server-stored, digest-bound, single-use (T14, ADR-7)
- [ ] 5 External append-only audit sink + allow/execution reconciliation
- [ ] 4 Hardened profile: Keycloak TLS + PostgreSQL, auth code + PKCE, mTLS to OPA
- [ ] 3 Optional real LLM planner behind the same tool boundary (off by default)

## 7. Test mapping

| ID | Scenario | Test location | Side-effect evidence |
|---|---|---|---|
| T01 | Alice reads doc-alpha-eng → ALLOW | tests/security/test_api_scenarios.py | +1 `document_read` row, 1 decision + 1 execution audit |
| T02 | Alice reads doc-alpha-payroll → DENY | same | 0 reads, deny audit |
| T03 | Alice reads doc-beta-eng (IDOR) → DENY | same | 0 reads; adapter direct call also returns nothing (RLS) |
| T04 | expired token → 401 | tests/security/test_token_attacks.py | 0 reads, no decision audit |
| T05 | wrong audience (agent token, other-app token) → 401 | same | 0 reads |
| T06 | forged sig / alg=none / HS256 confusion / unknown kid / tampered payload → 401 | same | 0 reads |
| T07 | agent tool call with no / foreign / revoked / expired delegation → DENY | tests/security/test_mcp_scenarios.py | 0 tool side effects |
| T08 | agent reads in-scope doc → ALLOW | same | exactly +1 read |
| T09 | injected document makes planner request payroll + export → DENY | same | 0 payroll reads, 0 exports, audit of attempts |
| T10 | unknown tool / exports.simulate → DENY | same | 0 side effects, audited |
| T11 | OPA down/timeout/500/malformed/undefined → DENY/503 | tests/security/test_fail_closed.py | 0 reads, incident audit |
| T12 | spoofed tenant/user/role headers, body fields, tool args → ignored/rejected | tests/security/test_spoofing.py | access unchanged, 0 extra reads |
| T13 | agent token not bound to the task / bound to another task / other agent / other user → DENY | tests/security/test_agent_token_binding.py | 0 tool side effects |
| T14 | confidential agent write without approval, replayed, tampered, wrong approver, expired, concurrent → DENY (one write only) | tests/security/test_approvals.py | `report_write` rows counted per attempt |
| + | audit secrecy (no tokens/canaries), audit UPDATE/DELETE denied, SQL metrics exact, MCP schema | tests/security, tests/integration | DB assertions |

## 8. Commands

```
make up            # build + start keycloak, postgres, opa, api, mcp-server (127.0.0.1 only)
make migrate seed  # apply migrations, load synthetic dataset
make lint          # ruff check, ruff format --check, mypy, opa fmt/check
make test          # unit + policy + integration + security tests (needs `make up`)
make security-test # attack corpus with side-effect checks -> artifacts/security-test-report.md
make sql-eval      # detection confusion matrix -> artifacts/verification/sql-eval.md
make demo          # narrated demo
make down          # stop and remove containers + volumes
```
