# Instructions to paste into Claude Code

You are implementing **AegisAccess** from the four attached specification files in this repository: `PRD.md`, `MVP.md`, `MCP_SPEC.md`, and `CLAUDE.md`. Read ALL files in full before you create or modify code.

Your mission is to build a fully runnable, security-first, locally reproducible MVP, not just write a design or toy mock. Act as a security engineer and a backend engineer: implement real Keycloak OIDC/JWKS validation, real OPA/Rego authorization with default deny, protected resource enforcement, PostgreSQL audit trails, and an official Python MCP SDK server with tool-level delegated permissions. Include a deterministic fake agent so security tests do not depend on an LLM API.

First inspect the environment/repo and SDK compatibility, then write `PLAN.md` detailing exact milestone tasks M0-M4, repo tree, API contracts, threat boundaries, acceptance-test mapping T01-T12, and runnable commands. Then immediately execute M0, M1, M2, M3 and M4 sequentially in this run as far as the environment allows. Do not stop after planning or scaffolding. Make incremental commits if a git repository is available, but never push or deploy without my explicit approval.

Non-negotiable: enforce every sensitive operation outside LLM text at the server/tool boundary; never trust caller-declared identity; deny if OPA/JWKS/delegation is invalid; distinguish authentication vs authorization; never pass through wrong-audience OAuth tokens; prevent cross-tenant reads and unauthorized AI tool calls; no real network exfiltration or unrestricted tools. Validate prevention by checking ZERO unauthorized resource side effects, not just HTTP status or the agent's final message. Use synthetic demo data only.

Run tests at each milestone and produce verification reports with ACTUAL commands and test counts. Implement 12 required attack/authorization scenarios from `MVP.md`, audit secrecy checks, SQL precision/recall calculation, STRIDE threat model, security design reviews, and CI. If something cannot be verified, record it as unfinished in `BLOCKERS.md`. Never fabricate metrics, test outcomes, or production-readiness claims.

Final delivery: complete source, pinned dependencies/containers, Docker Compose, Makefile (`up`, `migrate`, `seed`, `test`, `security-test`, `demo`, `down`), README with fresh-clone instructions, architecture and threat-model docs, security test report, and concise list of deferred work. Start now by reading the four source files and inspecting the repository.
