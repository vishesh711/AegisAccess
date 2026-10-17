# Blockers and unverified items

Items that could not be verified in the build environment (a sandboxed cloud container). Nothing
here is claimed as working.

| Item | Status | Detail |
|---|---|---|
| GitHub Actions CI (`.github/workflows/ci.yml`) | **Verified** | Runs on GitHub-hosted runners and is green on `main` (lint + security jobs). The first runs failed on two defects that were fixed: a nonexistent Trivy action tag, and a test that assumed existing audit rows. |
| Container image vulnerability scan (Trivy) | **Verified in CI only** | Runs in CI from the digest-pinned `aquasec/trivy:0.58.1` image, failing the build on fixable CRITICAL findings and reporting HIGH ones (the last scan found 0 CRITICAL, 44 HIGH in the Debian base image). It cannot run in the build sandbox, whose proxy blocks the vulnerability DB download. `pip-audit` on the hashed lockfile passes: no known vulnerabilities. |
| Keycloak image source | Deviation | `quay.io` is blocked by the sandbox proxy, so the Docker Hub image `keycloak/keycloak:26.2.5` (published by the Keycloak project) is used, pinned by digest. |
| Image build in the sandbox | Environment-specific | Building needed `AEGIS_BUILD_NETWORK=host AEGIS_BUILD_HTTPS_PROXY=$HTTPS_PROXY AEGIS_EXTRA_CA=<proxy CA>`. On a normal workstation/CI none of these are needed (defaults). |
| Docker daemon | Environment-specific | The sandbox had no running daemon; it was started manually with `dockerd`. |
| Real LLM adapter | Not implemented (optional in spec) | Only the deterministic planner exists; no paid LLM was used. |
| Approval workflow / approval replay scenario (P1) | **Implemented and tested** | Confidential agent report writes need a server-stored, single-use approval from the delegating user, bound to an argument digest (ADR-7). Covered by T14 in `tests/security/test_approvals.py`. |
| External audit store | **Implemented and tested** with VersityGW 1.8.0 (Docker Hub, digest-pinned) | MinIO images are no longer on Docker Hub (`pull access denied`), Bitnami's is gone, and `cgr.dev` is blocked here. VersityGW's object-lock behaviour was measured before use (ADR-8); its bucket default retention can be shortened, so per-object retention is used and verified. |
| `POST /api/v1/scenarios/{id}/run` | Not implemented by design | See ADR-5; replaced by `make security-test`. |
