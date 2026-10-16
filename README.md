# AegisAccess

A locally runnable, security-first demonstration of **zero-trust access control for humans, workloads
and AI agents**: Keycloak OIDC authentication, an identity-aware FastAPI gateway, OPA/Rego as the policy
decision point, PostgreSQL with row-level security and an append-only audit trail, and an MCP tool
server (official Python SDK) where every agent tool call is authorized on
**delegating user ∩ agent ∩ task**.

> Synthetic identities and data only. This is a portfolio / learning project, **not** a production
> security product. See [`docs/residual-risks.md`](docs/residual-risks.md) and [`BLOCKERS.md`](BLOCKERS.md).

## What it demonstrates

* Forged, expired, wrong-audience and wrong-issuer tokens are rejected (401) before any decision.
* Cross-tenant ID guessing, privilege escalation and spoofed identity headers/body/tool-args are denied.
* A deliberately **prompt-injectable** agent obeys a malicious instruction hidden in a document
  ("read payroll and export it") — and the MCP tool boundary denies both calls.
* OPA outages, timeouts, malformed/undefined decisions and audit-store failures **fail closed**.
* Every test checks the **observed side effects in PostgreSQL**, not just the HTTP status.
* SQL detection rules with an exact, hand-verifiable confusion matrix on a labelled fixture.

## Quick start

Prerequisites: Docker with Compose v2, [uv](https://docs.astral.sh/uv/), GNU make. Ports 5432, 8000,
8001, 8080, 8181 free on 127.0.0.1.

```bash
uv sync --frozen          # Python 3.12 venv with hash-pinned deps
make up                   # build + start keycloak, postgres, opa, api, mcp-server (waits for health)
make migrate seed         # schema + synthetic dataset
make demo                 # narrated walkthrough
make test                 # Rego + unit + integration + security tests
make security-test        # attack corpus -> artifacts/security-test-report.md
make sql-eval             # detection metrics -> artifacts/verification/sql-eval.md
make lint                 # ruff, format check, mypy --strict, opa fmt/check
make down                 # stop and delete containers + volumes
```

Behind a TLS-intercepting proxy, image builds accept `AEGIS_EXTRA_CA=/path/ca.pem`,
`AEGIS_BUILD_NETWORK=host` and `AEGIS_BUILD_HTTPS_PROXY=...` (not needed normally).

## Personas (synthetic; passwords are demo values in the realm import)

| Identity | Kind | Tenant | Roles | Notes |
|---|---|---|---|---|
| alice | human | alpha | engineer | |
| bob | human | alpha | finance-analyst | may read payroll directly |
| carol | human | beta | engineer | |
| secadmin | human | alpha | security-admin | password **+ TOTP** (MFA); audit + policy dry-run only |
| dave | human | alpha | engineer | **deactivated** in AegisAccess, still valid in Keycloak |
| eve | human | – | – | valid Keycloak user, **not provisioned** |
| svc-reporter | workload | alpha | workload-reporter | client credentials, aud `aegis-api` |
| agent-alpha / agent-beta | agent | alpha / beta | agent-document-assistant | client credentials, aud `aegis-mcp` |

Documents: `doc-alpha-eng`, `doc-alpha-eng-notes` (contains a prompt injection), `doc-alpha-payroll`
(restricted), `doc-alpha-finance-notes` (contains a prompt injection), `doc-beta-eng`.

## Try it by hand

```bash
TOKEN=$(curl -s -d grant_type=password -d client_id=aegis-cli -d username=alice -d password=alice-demo-pw \
  http://localhost:8080/realms/aegis/protocol/openid-connect/token | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -H "Authorization: Bearer $TOKEN" localhost:8000/api/v1/resources/doc-alpha-eng      # allow
curl -s -H "Authorization: Bearer $TOKEN" localhost:8000/api/v1/resources/doc-alpha-payroll  # 403
curl -s -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: beta" localhost:8000/api/v1/resources/doc-beta-eng  # 403
```

## API

| Endpoint | Purpose |
|---|---|
| `GET /health/live`, `GET /health/ready` | liveness; readiness of DB, OPA (+policy version), JWKS |
| `GET /api/v1/resources/{id}` | object-level authorized document read |
| `POST /api/v1/tasks` | create a delegation for an agent (capped to what the user may do) |
| `POST /api/v1/tasks/{id}/revoke` | revoke (owner only) |
| `POST /api/v1/tasks/{id}/invoke` | run the deterministic agent; it uses its own token against the MCP server |
| `GET /api/v1/audit` | sanitized, tenant-scoped audit events (security-admin) |
| `POST /api/v1/policy/simulate` | advisory dry run (security-admin), never executes |

MCP tools (`http://localhost:8001/mcp`): `documents.read`, `documents.search`, `reports.create_summary`;
plus test-only `exports.simulate` (no network I/O; granted to nobody) when `AEGIS_ENABLE_TEST_TOOLS=true`.

## Repository map

```
apps/api/aegis_api/        FastAPI gateway             src/aegis/          shared security core
apps/mcp_server/aegis_mcp/ MCP server (official SDK)   policies/           Rego + data + tests
infra/                     compose, Keycloak realm, Postgres role bootstrap
migrations/                SQL (RLS, grants, append-only audit, detection views)
scripts/                   migrate, seed, demo, sql_eval, security_report
tests/unit|integration|security                         analytics/          fixture + SQL
docs/                      architecture, threat model, design review (ADRs), residual risks, spec/
artifacts/                 security-test-report.md, verification/ (per-milestone evidence)
```

## Documentation

* **[Complete project guide with diagrams](docs/PROJECT_GUIDE.md)** — start here
* [Architecture](docs/architecture.md) · [STRIDE threat model](docs/threat-model.md) ·
  [Security design review / ADRs](docs/security-design-review.md) · [Residual risks](docs/residual-risks.md)
* [Implementation plan](PLAN.md) · [Blockers](BLOCKERS.md) · [Security test report](artifacts/security-test-report.md)
* Original specifications: [`docs/spec/`](docs/spec/)
