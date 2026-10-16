"""Runtime configuration (environment variables prefixed with ``AEGIS_``).

Defaults target the local Docker Compose demo. Every secret default is a clearly
dummy value; production deployments must override them (and would not use this demo).
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", extra="ignore")

    env: str = "local"

    # PostgreSQL DSN for the *runtime* role (no DDL, append-only audit).
    database_url: SecretStr = SecretStr(
        "postgresql://aegis_app:dummy-aegis-app-pw@127.0.0.1:5432/aegis"  # pragma: allowlist secret
    )

    # OIDC. ``oidc_issuer`` is the exact ``iss`` value tokens must carry.
    # ``oidc_discovery_base`` is where *this process* reaches Keycloak (may differ inside compose).
    oidc_issuer: str = "http://localhost:8080/realms/aegis"
    oidc_discovery_base: str | None = None
    api_audience: str = "aegis-api"
    mcp_audience: str = "aegis-mcp"
    # Clients (``azp``) whose tokens the API accepts. Human logins + the workload client.
    api_allowed_clients: list[str] = Field(
        default_factory=lambda: ["aegis-cli", "aegis-cli-short", "svc-reporter"]
    )
    # Clients whose tokens represent humans (as opposed to workloads/agents).
    human_login_clients: list[str] = Field(default_factory=lambda: ["aegis-cli", "aegis-cli-short"])
    # Clients the MCP server accepts (registered agent identities only).
    mcp_allowed_clients: list[str] = Field(default_factory=lambda: ["agent-alpha", "agent-beta"])
    jwt_leeway_seconds: int = 0
    jwks_min_refresh_seconds: float = 30.0
    http_timeout_seconds: float = 3.0

    # OPA (policy decision point).
    opa_url: str = "http://127.0.0.1:8181"
    opa_token: SecretStr = SecretStr("dummy-opa-pep-token")  # pragma: allowlist secret
    opa_timeout_seconds: float = 1.0
    policy_version: str = "policy-v1"

    # MCP server identity (resource indicator advertised in protected-resource metadata).
    mcp_resource_url: str = "http://localhost:8001/mcp"
    mcp_allowed_hosts: list[str] = Field(
        default_factory=lambda: ["127.0.0.1:*", "localhost:*", "mcp-server:*"]
    )
    enable_test_tools: bool = False
    mcp_rate_limit_per_minute: int = 120
    tool_timeout_seconds: float = 5.0

    # Agent runner (used by POST /api/v1/tasks/{id}/invoke). The agent authenticates with its
    # OWN client credentials; the user's token is never forwarded (no token passthrough).
    mcp_url: str = "http://127.0.0.1:8001/mcp"
    agent_client_id: str = "agent-alpha"
    agent_client_secret: SecretStr = SecretStr("dummy-agent-alpha-secret")  # pragma: allowlist secret

    # Limits.
    max_task_ttl_seconds: int = 3600
    max_summary_chars: int = 2000

    @property
    def discovery_base(self) -> str:
        return (self.oidc_discovery_base or self.oidc_issuer).rstrip("/")

    @property
    def token_endpoint(self) -> str:
        return f"{self.discovery_base}/protocol/openid-connect/token"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
