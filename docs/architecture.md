# AegisAccess architecture

AegisAccess is a **local, synthetic-data** demonstration of zero-trust access control for humans,
workloads and AI agents. It is a portfolio/education project, not a production product.

## Components

| Component | Tech (pinned) | Role | Code |
|---|---|---|---|
| Identity provider | Keycloak 26.2.5 (`start-dev`, realm import) | OIDC tokens; MFA (TOTP) for `secadmin`; brute-force protection | `infra/keycloak/aegis-realm.json` |
| API gateway / PEP | FastAPI 0.143 on Python 3.12 | JWT validation, identity resolution, PEP for every route, task delegation, agent runner | `apps/api/aegis_api/main.py` |
| MCP server / PEP | official MCP Python SDK 2.3.0, streamable HTTP, stateless | per-request bearer auth, pre-dispatch guard, tool gateway | `apps/mcp_server/aegis_mcp/server.py` |
| PDP | OPA 1.4.2, Rego v1 | default-deny decisions; user ∩ agent ∩ task; deny-only context rules | `policies/` |
| Data + audit | PostgreSQL 16.4 | identities/roles/delegations, RLS-protected documents, append-only audit, side-effect log | `migrations/` |
| External audit store | VersityGW 1.8.0 (S3 API, versioning, COMPLIANCE object lock) + `audit-shipper` | append-only, hash-chained copy of every audit event; read-only verifier reconciles it with the DB (ADR-8) | `src/aegis/audit_sink.py`, `src/aegis/audit_reconcile.py` |
| Shared library | `src/aegis` | authn, identity, pdp client, pep, audit, resources adapter, delegation, tools, planner | `src/aegis/` |

All container images are pinned by digest; Python dependencies (including transitive) are pinned with
sha256 hashes in `requirements.lock` and installed with `pip --require-hashes`. All ports bind to `127.0.0.1`.

## Request flows

### Human or workload reads a document

```
client --(Bearer, aud=aegis-api)--> API
  1. authn.JwtVerifier: RS256 only, kid -> JWKS (issuer-pinned discovery), iss, aud, exp, nbf, typ=Bearer,
     azp in allow-list, no token also valid for aegis-mcp                       -> 401 on failure
  2. identity.resolve_principal: (iss, sub) -> principals row; tenant/roles/active from DB;
     principal bound to OAuth client (azp)                                       -> 403 if unknown
  3. resources.get_metadata: SECURITY DEFINER fn returns id/tenant/kind/classification/department only
  4. pep.Enforcer.authorize -> OPA POST /v1/data/aegis/authz/allow  (result must be literally true)
  5. decision written to audit_events (allow is revoked if this write fails -> 503)
  6. resources.DocumentStore.read: tenant predicate + RLS (aegis.tenant_id GUC); writes a
     resource_side_effects row in the same transaction
  7. execution event (same request/correlation id)
```

### AI agent acting for a user

```
user --(aud=aegis-api)--> POST /api/v1/tasks         server-side task + delegation; every requested
                                                     (action, resource) must be allowed for the user NOW
user --(aud=aegis-api)--> POST /api/v1/tasks/{id}/invoke
    API (agent runner) --client_credentials--> Keycloak : token for agent-alpha, aud=aegis-mcp
    API --(agent token, Aegis-Task-Id)--> MCP server      (user's token is NEVER forwarded)
        SDK BearerAuthBackend -> AegisTokenVerifier (aud=aegis-mcp, agent clients only), every request
        ToolCallGuard: unknown tool / extra args / schema / size -> deny + audit, no tool code runs
        tool -> ToolGateway:
           A agent principal from DB (active, registered)          B delegation for (agent tenant, task id)
             bound to this agent, active, unexpired, unrevoked      delegating user re-read with current roles
           C/D OPA with subject=user, agent=agent, delegation=task  E decision audited before side effects
           F typed adapter (tenant predicate + RLS)                 G execution event, same correlation id
```

The deterministic planner (`src/aegis/planner.py`) deliberately **obeys** instructions found in
document text, simulating a successfully prompt-injected model. Security therefore never depends on
the model refusing; it depends on the tool boundary.

## Authorization model

`ALLOW = valid input ∧ active subject ∧ same tenant ∧ subject role grant
        ∧ (origin=api ∨ (agent active ∧ agent same tenant ∧ subject is human ∧ agent role grant
                         ∧ delegation bound to (agent,user) ∧ action ∈ task ∧ document ∈ task))
        ∧ no contextual deny (restricted data via agent; environment not allowed)`

* Facts (who has which role, delegations, agent status) live in PostgreSQL.
* Rules (what a role may do) live in Rego data (`policies/data.json`), versioned as `policy-v1`; the
  PEP sends its expected `policy_version` and OPA denies on mismatch.
* Role grants only apply to the principal types the role is defined for.
* `deny_reasons` explains denials for audit; it is never consulted to grant access, and a Rego test
  asserts `allow ⇔ count(deny_reasons) = 0` over representative inputs.

## Data protection layers for a document read

1. PDP decision (tenant, role, classification, department, delegation).
2. PEP never reads title/body before allow (metadata function exposes no content).
3. Adapter query has an explicit `tenant_id` predicate.
4. PostgreSQL RLS on `resources`, `tasks`, `delegations`, `reports` for the runtime role; with no tenant
   set, zero rows are visible.
5. Runtime DB role: no DDL, no UPDATE/DELETE/TRUNCATE on audit, insert-only on side-effect log.

## Audit copy outside the database (ADR-8)

```
 audit_events ──(aegis_audit_shipper: SELECT)──► audit-shipper ──(put-only S3 user)──► audit-sink
      ▲                                                                                 │ batches/<seq>.jsonl
      │                                                                                 │ hash chain + COMPLIANCE lock
  make audit-verify (aegis_auditor + read-only S3 user): store integrity, store vs DB, allow/execution
```

Each side-effect row carries the `request_id` of the call that caused it, so the verifier can match it
to that request's execution event, and each execution to an allow decision.

## Health

`/health/live` (process) and `/health/ready` (database, OPA reachable, OPA `policy_version` matches,
JWKS loadable) on both API and MCP server. Readiness exposes booleans only.

## Local-demo vs production boundaries

* Keycloak runs `start-dev` over plain HTTP with an H2 store; users log in with the password grant
  (demo convenience). Production: TLS everywhere, authorization code + PKCE, a real Keycloak DB.
* OPA is a sidecar-style service on the compose network protected by a bearer token and
  `system.authz`; production would use mTLS and bundle signing.
* Secrets are dummy values in `.env.example` / realm JSON.
