# Residual risks and deferred work

What the MVP does **not** protect against, or only partially. Honest list, not a roadmap promise.

## Residual risks
1. **Bearer tokens are not sender-constrained.** A stolen token works until expiry (300 s). No DPoP/mTLS.
2. **Agent identity = client secret.** Holder of `agent-alpha`'s secret can act on any task delegated to
   that agent (ADR-2). Token exchange binding tokens to a task is Phase 2.
3. **Audit in the same database.** Superuser can disable the immutability trigger; no external WORM sink.
4. **Local-demo IdP settings.** Keycloak `start-dev` (HTTP, H2), password grant for the CLI client,
   `sslRequired=none`. Not acceptable in production.
5. **Logical MCP audience** (`aegis-mcp`) instead of an RFC 8707 resource URI (ADR-4).
6. **OPA channel** protected by a static bearer token, no mTLS; policy volume trusted, bundles unsigned.
7. **In-memory rate limiter** is per-process and resets on restart.
8. **Side channels** (timing of cross-tenant vs nonexistent ids, search timing) not evaluated.
9. **Model output integrity**: an agent can still produce a misleading summary from in-scope content;
   only *access* is controlled.
10. **Detection metrics** are computed on a 33-row hand-labelled synthetic fixture; they say nothing
    about real-world performance.
11. **GitHub Actions** are pinned by version tag, not commit SHA (SHAs were not verifiable offline here).
12. **Container scan** in CI is report-only; it was not run in the build environment (see `BLOCKERS.md`).
13. **Single-use approval workflow** (MCP_SPEC approval rule, PRD replay scenario P1) is not implemented,
    so no tool requires approval and no approval can be replayed.
14. **Caller-supplied correlation id.** The MCP server accepts `Aegis-Correlation-Id` (UUID-validated) so an
    agent run can be traced end to end. It never affects authorization, but a malicious agent could reuse
    another run's id to muddy correlation; `request_id` is always server-generated.

## Deferred (Phase 2, per PRD §12)
Go gateway; OAuth token exchange with `act` claims; human approval workflow with nonce and argument
digest binding; mTLS workload identity; risk-adaptive access / device posture; security dashboard;
external audit sink; load testing with high-cardinality data.
