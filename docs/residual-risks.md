# Residual risks and deferred work

What the MVP does **not** protect against, or only partially. Honest list, not a roadmap promise.

## Residual risks
1. **Bearer tokens are not sender-constrained.** A stolen token works until expiry (300 s). No DPoP/mTLS.
2. **Trusted agent host.** Agent tokens come from a user-consented token exchange and are bound to one
   task (ADR-2), so a stolen agent secret alone is useless. The process that performs the exchange and
   writes the binding (here, the API) is still trusted to bind the token to the task the user invoked.
3. **Audit copy is asynchronous.** The DB owner or a superuser can still disable the immutability trigger.
   Every row is copied within seconds to the external WORM store (ADR-8), and later changes are
   reported, but a row altered before its first copy is not. Anyone with access to the store's volume
   or host bypasses its S3 API (the hash chain makes that visible). VersityGW's bucket *default*
   retention could be shortened in testing, so safety relies on the per-object retention the shipper
   sets and the verifier checks. Reconciliation is detective: it runs on demand (`make audit-verify`,
   CI), with no alerting.
4. **Local-demo IdP settings.** Keycloak `start-dev` (HTTP, H2), password grant for the CLI client,
   `sslRequired=none`. Not acceptable in production.
5. **Logical MCP audience** (`aegis-mcp`) instead of an RFC 8707 resource URI (ADR-4).
6. **OPA channel** protected by a static bearer token, no mTLS; policy volume trusted, bundles unsigned.
7. **In-memory rate limiter** is per-process and resets on restart.
8. **Side channels** (timing of cross-tenant vs nonexistent ids, search timing) not evaluated.
9. **Model output integrity**: an agent can still produce a misleading summary from in-scope content;
   only *access* is controlled.
10. **Detection metrics** come from synthetic data: a 33-row hand-labelled fixture and a 1,888-row generated
    day (`scripts/gen_detection_dataset.py`). They say nothing about real-world performance. The larger set
    shows rule R2 misfiring on benign agent search filtering (30 false alarms): the rule needs to exclude
    `documents:search`, which is deliberately not tuned against the same data it is measured on.
11. **GitHub Actions** are pinned to commit SHAs; updating them is a manual step (no Dependabot configured).
12. **Container scan** fails the build only on fixable CRITICAL findings; HIGH findings (44 on the last
    scan, all in the Debian base image) are reported, not blocking.
13. **Approval scope.** Only agent report writes classified confidential or higher need human approval
    (ADR-7). The approver sees a server-written description and the argument digest, not a rendered diff
    of the summary text, and there is no approval UI: approvals go through the API. A user who approves
    without reading is not protected against.
14. **Caller-supplied correlation id.** The MCP server accepts `Aegis-Correlation-Id` (UUID-validated) so an
    agent run can be traced end to end. It never affects authorization, but a malicious agent could reuse
    another run's id to muddy correlation; `request_id` is always server-generated.

## Deferred (Phase 2, per PRD §12)
Go gateway; `act`-claim delegation chains; an approval UI; mTLS workload identity; risk-adaptive access / device posture; security dashboard;
alerting on audit-verify findings; load testing with high-cardinality data.
