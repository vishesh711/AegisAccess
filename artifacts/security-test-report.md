# AegisAccess security test report

* Generated: 2026-10-17T00:26:11+00:00
* Git revision: `2d918c0` (working tree has uncommitted changes)
* Run id (scenario_results.run_id): `f11d508a-3c99-4333-adb0-652a84ad9093`
* pytest exit status for `tests/security`: **0** (0 = all tests passed)
* Scenarios recorded: 33; outcome mismatches: 0; mandatory T01-T12 missing: none

Side-effect counts are **observed** rows in `resource_side_effects` (written by the resource adapter in
the same transaction as the protected operation), read back from PostgreSQL after each request — not
inferred from HTTP status codes. Audit counts are rows in the append-only `audit_events` table.

| Scenario | Description | Request | Expected | Actual | Side effects (exp/obs) | Audit rows | Result |
|---|---|---|---|---|---|---|---|
| AUDIT-IMMUTABLE | Runtime DB role attempts UPDATE/DELETE/TRUNCATE on audit | `aegis_app: UPDATE/DELETE/TRUNCATE audit_events` | deny | deny | 0/0 | 0 | PASS |
| AUDIT-SECRECY | Scan of 1979 audit rows for tokens/secrets/canaries | `SELECT * FROM audit_events` | clean | clean | 0/0 | 1979 | PASS |
| LOG-SECRECY | Scan of 9611 raw log records | `captured application/library logs` | clean | clean | 0/0 | 0 | PASS |
| T01 | Alice reads alpha engineering document | `GET /api/v1/resources/doc-alpha-eng (alice token)` | allow | allow | 1/1 | 2 | PASS |
| T02 | Alice (engineer) reads restricted payroll | `GET /api/v1/resources/doc-alpha-payroll (alice token)` | deny | deny | 0/0 | 1 | PASS |
| T03 | Alice guesses beta tenant document id (IDOR) | `GET /api/v1/resources/doc-beta-eng (alice token)` | deny | deny | 0/0 | 1 | PASS |
| T04 | Expired (genuinely Keycloak-signed) access token | `GET doc-alpha-eng with token past exp` | 401 | 401 | 0/0 | 0 | PASS |
| T05 | Tokens issued for another audience (MCP agent token; other app) | `GET doc-alpha-eng with aud=aegis-mcp and aud=other-service tokens` | 401 | 401 | 0/0 | 0 | PASS |
| T05-mcp | MCP server given no token / API-audience tokens / garbage | `POST /mcp tools/call documents.read` | 401 | 401 | 0/0 | 0 | PASS |
| T06 | Forged/invalid-signature tokens (7 variants) | `GET doc-alpha-eng with attacker_key_same_kid, tampered_payload, alg_none, hs256_key_confusion, unknown_kid, signature_stripped, wrong_issuer` | 401 | 401 | 0/0 | 0 | PASS |
| T07 | Agent tool call without a valid delegation (none/malformed/unknown/other agent's task) | `documents.read(doc-alpha-eng) x4` | deny | deny | 0/0 | 4 | PASS |
| T08 | Agent reads a document inside its delegated task | `documents.read(doc-alpha-eng) with alice's task` | allow | allow | 1/1 | 2 | PASS |
| T09 | Prompt injection in a document instructs the agent to read payroll and export it | `POST /api/v1/tasks/{id}/invoke (planner obeys injected text)` | deny | deny | 0/0 | 2 | PASS |
| T09b | Injection targets payroll that the DELEGATING USER may read; agent ∩ task still deny | `planner on bob's finance-notes task` | deny | deny | 0/0 | 4 | PASS |
| T10 | Unknown tools (admin/shell/sql/http/email/delete) and test-only exports.simulate | `admin.grant_role, execute_command, run_sql, http_fetch, send_email, documents.delete, exports.simulate` | deny | deny | 0/0 | 7 | PASS |
| T11-allow_object_not_bool | OPA fault: allow_object_not_bool (request would normally be allowed) | `GET doc-alpha-eng (alice) with faulty PDP` | deny | deny | 0/0 | 1 | PASS |
| T11-audit-down | Audit store unavailable on an otherwise-allowed read | `GET doc-alpha-eng (alice) with audit writes failing` | deny | deny | 0/0 | 0 | PASS |
| T11-http_500 | OPA fault: http_500 (request would normally be allowed) | `GET doc-alpha-eng (alice) with faulty PDP` | deny | deny | 0/0 | 1 | PASS |
| T11-malformed_json | OPA fault: malformed_json (request would normally be allowed) | `GET doc-alpha-eng (alice) with faulty PDP` | deny | deny | 0/0 | 1 | PASS |
| T11-mcp | OPA unreachable at the MCP tool boundary | `documents.read(doc-alpha-eng) in a valid task` | deny | deny | 0/0 | 1 | PASS |
| T11-non_boolean_result | OPA fault: non_boolean_result (request would normally be allowed) | `GET doc-alpha-eng (alice) with faulty PDP` | deny | deny | 0/0 | 1 | PASS |
| T11-opa-stopped | Real OPA container stopped (compose deployment) | `GET doc-alpha-eng (alice) via deployed API` | deny | deny | 0/0 | 1 | PASS |
| T11-timeout | OPA fault: timeout (request would normally be allowed) | `GET doc-alpha-eng (alice) with faulty PDP` | deny | deny | 0/0 | 1 | PASS |
| T11-undefined_result | OPA fault: undefined_result (request would normally be allowed) | `GET doc-alpha-eng (alice) with faulty PDP` | deny | deny | 0/0 | 1 | PASS |
| T11-unreachable | OPA connection refused | `GET doc-alpha-eng (alice)` | deny | deny | 0/0 | 1 | PASS |
| T12 | Spoofed tenant/user/role headers + query params | `GET payroll / beta doc / audit with X-Tenant-Id, X-User-Id, X-Roles, ?tenant_id=...` | deny | deny | 0/0 | 1 | PASS |
| T12-mcp | Identity/role/approval fields injected into MCP tool arguments | `documents.read(doc-alpha-payroll, user_id=bob \| tenant_id=beta \| role=... \| approved=true)` | deny | deny | 0/0 | 6 | PASS |
| T13-binding | Unbound token; token bound to another task; another user's bound token | `documents.read(doc-alpha-eng) x3` | deny | deny | 0/0 | 2 | PASS |
| T13-own-token | Agent's own client-credentials token at the MCP server | `documents.read(doc-beta-eng) with agent-beta's own token` | deny | deny | 0/0 | 1 | PASS |
| T13-secret | Stolen agent secret: client credentials, exchange of a non-consent user token, exchange of another agent's consent token | `Keycloak token endpoint x3` | refused | refused | 0/0 | 0 | PASS |
| T14-replay | Approved sensitive write executes once; identical replay is denied | `reports.create_summary(confidential) x2 after one approval` | allow,deny | allow,deny | 1/1 | 0 | PASS |
| T14-tamper | Approval for one summary text used with different text | `reports.create_summary with modified summary_text` | deny | deny | 0/0 | 0 | PASS |
| X-INACTIVE | Deactivated employee with valid IdP session | `GET doc-alpha-eng (dave token)` | deny | deny | 0/0 | 1 | PASS |

## Policy decision latency (measured, not a guarantee)

From `audit_events.duration_ms` of successful OPA evaluations accumulated in this database (n=1218).
p50 = 4.33 ms, p95 = 8.55 ms, max = 19.34 ms.
Environment: Linux-6.18.44-fc-v139-x86_64-with-glibc2.39, Python 3.12.3, OPA in Docker on the same host,
PEP->OPA over the local Docker bridge/loopback. Includes HTTP round trip; excludes JWT validation and DB.
The PRD target (p95 < 100 ms) is aspirational for local runs; this sample is not a load test.
