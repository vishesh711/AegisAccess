# AegisAccess — Product Requirements Document (PRD)
Version: 1.0 | Date: 2026-10-16 | Status: Approved build specification

## 1. Executive summary
Build a locally runnable, security-first demonstration of enterprise zero-trust access across human users, workloads, and AI agents. An identity-aware gateway authenticates incoming requests; a policy decision point (OPA) authorizes each requested operation; protected services enforce those decisions at every resource boundary; all decisions are auditable; adversarial tests prove unauthorized actions do not occur. This is a demonstrable security engineering portfolio project, NOT a production-certified enterprise security product.

## 2. Why / target audience
Primary user: security engineer interviewing for Google Security Engineer II, Core / Enterprise Access Security Engineering. Secondary: reviewers who clone the repository and run tests and demos. The project should demonstrate IAM, authentication, authorization, cyber/security engineering, network security, automation, AI agent/LLM workflow security, threat modeling, design reviews, and SQL-based effectiveness measurement. Do not inflate metrics or use these keywords without implementation evidence.

## 3. Goals
G1. Authenticated users can request protected resources; access is allow/deny according to explicit role, tenant, resource classification, action, and contextual attributes.
G2. A tool-using AI agent cannot exceed the *intersection* of delegated user permission, agent identity permission, and per-task permission, even if it follows prompt injection.
G3. Each allow/deny and attempted tool action generates a traceable structured event without raw credentials or confidential payloads.
G4. Automated tests reproduce credential misuse, tenant bypass, policy failures, agent injection, and unauthorized export, proving fail-closed enforcement.
G5. SQL analytics produces a labeled confusion matrix and reproducible precision/recall for attack detection; separate detection from access policy authorization.
G6. Entire core stack starts locally with documented commands and seeded sample identities; CI gates changes on security tests.

## 4. Non-goals for MVP
No public-cloud production deployment; no custom cryptography or IdP; no custom OAuth authorization server; no unrestricted SQL agent tool; no live internet exfiltration; no access to real company data; no multi-region HA; no ML-based anomaly detection required; no privileged shell access exposed to model; no implementing a new general-purpose MCP spec or bespoke JSON-RPC transport. No Go gateway before the Python reference enforcement path is working. No real phishing, live adversary infrastructure, or real employee credentials.

## 5. Personas and stories
- Employee: logs in and reads own tenant's permitted engineering document.
- Finance user: reads finance document only with suitable grant and contextual policy.
- Security administrator: can inspect sanitized decision history and run policy dry runs; cannot silently bypass production enforcement.
- Workload: accesses a bounded service resource using a service-specific credential and audience, not an arbitrary human token.
- AI agent: receives task-scoped authority and invokes only registered, allowlisted tools.
- Reviewer: reproduces attacks and sees requested operation, policy result, actual resource side effect, and event trace.

## 6. Major requirements (priority / acceptance)
### FR-01 OIDC authentication (P0)
Integrate Keycloak as an OIDC provider. Discover issuer metadata and JWKS; validate signature with approved algorithms, exact issuer, audience, expiry, not-before when present, and identity type. Reject missing, expired, forged, wrong-audience, or wrong-issuer tokens. MFA is configured in Keycloak for an admin/test persona; do not invent or write an MFA implementation. Document local-demo vs production TLS boundaries. Accept: positive user flow and negative token tests.

### FR-02 IAM data and tenant boundary (P0)
Store subject-to-tenant, roles, resources with tenant and classification, agent identities, scoped grants, tool allowlists, audit events in PostgreSQL. Never trust tenant_id, user_id, role, scopes, or agent_id from a caller-supplied JSON body; derive or verify against authenticated server-side data. Enforce object-level authorization at protected read/write operations. Accept: cross-tenant requests denied even if client changes resource ID or headers.

### FR-03 Central PDP and explicit PEP (P0)
Policy Enforcement Point (PEP) is gateway/service middleware; Policy Decision Point (PDP) is OPA/Rego. Use canonical input JSON including authenticated subject, validated context, action, resource, delegation, and policy_version. Rego default deny. Unknown action/resource/subject denies. OPA timeout, HTTP error, empty/malformed or undefined result denies, with structured reason. PEP MUST run directly on every protected side-effect boundary, not only on initial UI or agent planning. Denied requests must not call the underlying resource service. Accept: all paths tested; fail-closed when OPA unavailable.

### FR-04 AI delegation and MCP tool boundary (P0)
Agent permissions = user grant ∩ agent grant ∩ task grant. Every tool call authorizes using server-validated user, agent, task, resource, and requested action. No auth based only on LLM prompt, tool descriptions or `user_confirmed: true` flags. Agent has exactly three MVP tools: `documents.read`, `documents.search`, `reports.create_summary` (writes a local synthetic summary, requires task scope). Avoid any email sending and outbound web tools. Permit test-only `exports.simulate` to model exfiltration as a forbidden action; it must have no network access. Model is optional; deterministic fake planner is required for offline tests. Accept: injected document text cannot read payroll or simulate export; attempted calls recorded, underlying side effects zero.

### FR-05 Audit telemetry (P0)
Append-only audit table from application role (no UPDATE/DELETE grants), containing event_id, timestamp UTC, correlation_id, request_id, principal_type, principal_id (pseudonym where needed), tenant_id, agent_id, task_id, tool_name, action, resource_id, policy_version, decision, reason_code, evaluator_status, duration_ms, test_case_id. No JWTs, secrets, raw prompt, raw document body, or PII in audit. Keep security event creation resilient; if audit storage unavailable for sensitive writes, deny (fail closed) and expose sanitized error. Design checks for missed events. Accept: correlation from request through decision and eventual side-effect; no secrets in logs.

### FR-06 Security scenarios and incident view (P0/P1)
Automated attack corpus: expired token, wrong audience, forged token, cross-tenant IDOR, user-without-grant, overprivileged agent, prompt injection in document, unauthorized export attempt, OPA outage, missing delegation, replay of single-use approval (P1), unknown tool. Each scenario has fixtures, expected decision, side_effect_count, observed audit events. CI must assert outcomes. A basic CLI or HTML report suffices for MVP; dashboard is P1.

### FR-07 Security analytics (P0)
Seed reproducible, labeled synthetic events, preserving separate `ground_truth_is_attack`, `rule_flagged`, and `authz_allowed` fields. SQL aggregates TP, FP, FN, TN and computes precision and recall with division-by-zero protection. Add by-rule and by-policy-version reporting. Include a baseline vs candidate comparison using the SAME fixture dataset and labeled classifications. Never fabricate achieved percentages. Accept: deterministic test expected counts and SQL tested against database.

### FR-08 Secure automation (P0)
CI: lint, format check, static type checking, unit+integration+security tests, OPA policy tests, dependency scanning and container scan where available. Pin top-level and transitive dependencies with lockfiles; use pinned container versions/digests in deployment. Test service unavailability and strict schema validation. CI fails on unauthorized side effects even when API response misleadingly says denied.

### FR-09 Threat model and security design review (P0)
STRIDE threat model with trust boundaries: browser/CLI→gateway, gateway→IdP/JWKS, gateway→OPA, gateway→protected API/DB, agent→MCP server, MCP server→resource. Document threats, risk severity, mitigation, control test, residual risk. At least one security design review (ADR) weighing local OPA vs central service, user delegation mechanism, audit durability, and MCP transport choice. Accept: diagrams and evidence links to executable test cases.

### FR-10 Usability (P1)
Single `make up`, `make seed`, `make demo`, `make test`, `make down` equivalent, explicit documented prerequisites, zero-cost synthetic demonstration. Simple reviewer UI showing principals, requests, decisions and attack replay is optional; prioritize reliable security behavior over polish.

## 7. End-to-end flow
1. Client authenticates via Keycloak and receives OIDC access token for intended audience.
2. Client requests protected object via gateway.
3. Gateway validates token and resolves subject/tenant/identity context against trusted server-side data.
4. PEP assembles canonical policy input, calls OPA with a bounded timeout, rejects unexpected response shapes.
5. Decision and reason are recorded with correlation IDs.
6. If allow, protected service rechecks appropriate authorization (or verifies trustworthy, short-lived, cryptographically bound authorization context), and performs action; if deny, NO action occurs.
7. For an agent tool call, the MCP resource server validates bearer token audience and the *user∩agent∩task* grant before any tool implementation runs. A connection/session ID is never security identity.
8. Logs and synthetic fixtures support incident triage and correctness measurement.

## 8. Conceptual data model
- `principals(id, type, oidc_sub, tenant_id, active)`
- `roles(id, name)` and `principal_roles(principal_id, role_id, tenant_id)`
- `resources(id, tenant_id, kind, classification, owner_id)`
- `policy_versions(id, digest, status, created_at)`
- `agent_identities(id, principal_id, tenant_id, active)`
- `delegations(id, user_principal_id, agent_id, tenant_id, task_id, allowed_actions, allowed_resources, expires_at, revoked_at)`
- `tasks(id, tenant_id, owner_principal_id, status, created_at)`
- `audit_events(id, event_time, correlation_id, principal_id, tenant_id, agent_id, task_id, action, resource_id, tool_name, decision, reason_code, policy_version, evaluator_status, duration_ms, test_case_id)`
- `scenario_results(id, scenario_id, expected_decision, actual_decision, expected_side_effects, actual_side_effects, ground_truth_is_attack, rule_flagged)`
Use real PK/FK constraints, indexes, and explicit tenant constraints; validate data model with migration tests. Use no automatic DB admin privileges for runtime API.

## 9. API surface (illustrative; implement OpenAPI)
- `GET /health/live` and `GET /health/ready` (avoid disclosing secrets)
- `GET /api/v1/resources/{id}` — authenticated read, object-level PEP
- `POST /api/v1/tasks` — create task with validated requested scopes; server caps scopes to user permissions
- `POST /api/v1/tasks/{id}/invoke` — deterministic model-independent tool invocation, identity from token, not body
- `GET /api/v1/audit` — restricted security-admin scope, sanitized and paginated
- `POST /api/v1/policy/simulate` — security-admin only, cannot grant real access
- `POST /api/v1/scenarios/{scenario_id}/run` — LOCAL TEST ENVIRONMENT ONLY, disabled in non-test environments
Response model: `request_id`, `decision` (`allow|deny`), `reason_code`, `policy_version`; HTTP statuses 401 authn, 403 authz, 503 policy/audit dependency failure when appropriate; never divulge policy internals to general users.

## 10. SLO / constraints (targets, NOT measured results)
- Zero unauthorized side effects in the committed attack corpus (mandatory).
- 100% of exercised protected paths must invoke PEP, established by tests/instrumentation.
- p95 local policy decision < 100 ms as an aspirational local benchmark, measure and report with sample size/hardware; no guarantee.
- All seeded attack evidence repeatable locally without real credentials or paid LLM API.
- Health/readiness checks distinguish backend and auth/PDP dependencies.

## 11. Exit criteria / definition of done
MVP accepted only when: fresh clone and documented setup work; test identity login works; positive legitimate access works; at least 10 negative security scenarios pass; OPA unavailable denies with zero side effects; agent injection cannot invoke prohibited action; all events queryable with no raw secrets; SQL confusion-matrix results deterministic; threat model and security review current; CI green. If any condition fails, mark milestone BLOCKED and do not claim completion.

## 12. Phase 2 (not MVP)
Go gateway, risk-adaptive access, device posture, mTLS workload auth, full OIDC token exchange if supported/configured correctly, human approval workflow with nonce and operation binding, security dashboard, Kubernetes admission policies, structured rule experiments, high-cardinality load test.

## 13. JD alignment and truthful portfolio reporting
Trace each keyword to code, executable test, and documentation. Do not claim Google match score, measured security improvement, breach prevention, external certification, production deployment, or scalability metrics without evidence.
