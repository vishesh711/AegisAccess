# AegisAccess — MVP scope and delivery contract

## Scope lock
Build the smallest end-to-end security system proving a single invariant: **a human, workload, or AI agent cannot perform an operation outside validated identity and policy permissions, including when the agent receives malicious content.** Prioritize secure functionality over dashboards, microservices, and Go optimizations.

## MVP topology
Docker Compose services: `keycloak`, `postgres`, `opa`, `api` (Python/FastAPI), `mcp-server` (official MCP Python SDK), optional `demo-client`. The MCP server exposes allowlisted tools and has its own authorization checks; do not create a generic remote executor. Keycloak+OPA are explicit runtime dependencies. Use a fake deterministic agent/planner by default; optional LLM adapter is disabled unless configured via env.

## MVP endpoints and tools
API: `/health/live`, `/health/ready`, `/api/v1/resources/{id}`, `/api/v1/tasks`, `/api/v1/tasks/{id}/invoke`, `/api/v1/audit` and test-only `/api/v1/scenarios/{scenario_id}/run`.
MCP tools: `documents.read(resource_id)`, `documents.search(query, max_results)`, `reports.create_summary(task_id, document_ids, summary_text)`; all request-time identity and scope checked. For MVP, fake agent's `summary_text` is synthetic. Tool metadata is untrusted for authorization. There is no broad SQL tool or shell tool.

## Sample personas/resources
Tenants: `alpha`, `beta`. Identities: `alice` (alpha engineering), `bob` (alpha finance), `carol` (beta engineering), `secadmin` (alpha security), `agent-alpha` (alpha AI tool client), `svc-reporter` (alpha workload). Resources: alpha engineering spec, alpha payroll, beta engineering spec; seeded labels/roles; clear expected accesses documented in fixtures.

## 12 mandatory security acceptance tests
T01 valid Alice reads alpha engineering document -> ALLOW; one read side effect; one audit event.
T02 Alice reads alpha payroll -> DENY; zero read side effects; audit event.
T03 Alice reads beta engineering document by guessing ID -> DENY; zero side effects.
T04 expired token -> 401; zero resource access.
T05 wrong-audience token -> 401; zero resource access.
T06 forged / invalid-signature token -> 401; zero resource access.
T07 absent delegation for agent tool -> DENY; zero tool side effects.
T08 agent tries authorized document read in permitted task -> ALLOW; exactly one read side effect.
T09 embedded prompt injection instructs agent to read alpha payroll -> tool DENY; zero prohibited reads.
T10 agent requests nonexistent/unknown tool or exports.simulate -> DENY; zero prohibited side effects.
T11 OPA down, timeout or invalid response -> DENY/503; zero side effects; sanitized incident event (if DB available).
T12 caller sends spoofed tenant_id/user_id/role JSON or headers -> ignored or rejected; access unchanged.
Additional mandatory: audit does not include tokens, secrets, or document content; database audit role cannot UPDATE/DELETE rows; test datasets produce exact TP/FP/FN/TN; real resource method is not called for denied operations.

## Work breakdown with immutable completion criteria
M0: Scaffold project; pinned deps; compose starts; README quickstart; `make lint`, `make test`; all pass. No fake green tests.
M1: Keycloak seeded realm; OIDC/JWKS verification; tenant/resource schema; migrate and seed; T01-T06/T12 pass.
M2: OPA Rego PDP and enforcement; fail-closed; audit events; T01-T03/T11 pass end-to-end through real OPA.
M3: Official MCP SDK tool server; identity/delegation intersection; deterministic agent; prompt injection fixture; T07-T10 pass with side-effect counters.
M4: Security evaluation SQL, STRIDE, policy ADR, CI and demo reproducibility; all mandatory tests pass on clean environment.

## Required commands
- `make up`: start local dependencies/services
- `make migrate`: apply DB migrations
- `make seed`: create deterministic demo dataset
- `make test`: run unit, integration, security and policy tests
- `make security-test`: run attack fixture corpus and side-effect checks
- `make demo`: show allowed employee read, denied cross-tenant read, denied AI exfiltration attempt, audit and metrics
- `make lint`: ruff + mypy (+ policy format/check where applicable)
- `make down`: cleanly stop containers
Document any manual Keycloak flow; never print real secret/token values into logs.

## Launch gate
Before declaring an MVP milestone done, produce `artifacts/verification/<milestone>.md` with exact commands run, pass counts, meaningful logs, known limitations, git revision. If failing, document failures and remain unfinished. At the end, produce `artifacts/security-test-report.md` with outcomes of every T01-T12 and explicit observed side-effect counts.
