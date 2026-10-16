# Blockers and unverified items

Items that could not be verified in the build environment (a sandboxed cloud container). Nothing
here is claimed as working.

| Item | Status | Detail |
|---|---|---|
| GitHub Actions CI (`.github/workflows/ci.yml`) | **Not executed** | Written and every step was run locally with the same `make` targets, but the workflow itself has not run on GitHub-hosted runners from this environment. |
| Container image vulnerability scan (Trivy) | **Not executed** | Trivy needs its vulnerability DB from `ghcr.io`, which the sandbox egress proxy does not allow. CI step is report-only. `pip-audit` on the hashed lockfile **was** run: no known vulnerabilities. |
| Keycloak image source | Deviation | `quay.io` is blocked by the sandbox proxy, so the Docker Hub image `keycloak/keycloak:26.2.5` (published by the Keycloak project) is used, pinned by digest. |
| Image build in the sandbox | Environment-specific | Building needed `AEGIS_BUILD_NETWORK=host AEGIS_BUILD_HTTPS_PROXY=$HTTPS_PROXY AEGIS_EXTRA_CA=<proxy CA>`. On a normal workstation/CI none of these are needed (defaults). |
| Docker daemon | Environment-specific | The sandbox had no running daemon; it was started manually with `dockerd`. |
| Real LLM adapter | Not implemented (optional in spec) | Only the deterministic planner exists; no paid LLM was used. |
| Approval workflow / approval replay scenario (P1) | Not implemented | See `docs/residual-risks.md` #13. |
| `POST /api/v1/scenarios/{id}/run` | Not implemented by design | See ADR-5; replaced by `make security-test`. |
