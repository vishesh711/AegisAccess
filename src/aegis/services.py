"""Wiring of shared runtime services for the API and the MCP server."""

from __future__ import annotations

import ssl
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass

import httpx
from psycopg_pool import AsyncConnectionPool

from aegis.audit import PgAuditSink
from aegis.authn import JwksCache, JwtVerifier
from aegis.config import Settings
from aegis.db import Conn, create_pool, ping
from aegis.pdp import OpaClient
from aegis.pep import Enforcer
from aegis.resources import DocumentStore
from aegis.tools import ToolGateway


@dataclass
class Services:
    settings: Settings
    http: httpx.AsyncClient
    pool: AsyncConnectionPool[Conn]
    jwks: JwksCache
    api_verifier: JwtVerifier
    mcp_verifier: JwtVerifier
    pdp: OpaClient
    audit: PgAuditSink
    enforcer: Enforcer
    store: DocumentStore
    gateway: ToolGateway

    async def readiness(self) -> dict[str, bool]:
        db_ok = await ping(self.pool)
        version = await self.pdp.loaded_policy_version()
        jwks_ok = await self.jwks.ready()
        return {
            "database": db_ok,
            "policy_engine": version is not None,
            "policy_version_match": version == self.settings.policy_version,
            "jwks": jwks_ok,
        }


def tls_verify(settings: Settings) -> ssl.SSLContext | bool:
    """Outbound TLS trust: only the configured CA when set, otherwise the system store."""
    if settings.tls_ca_file:
        return ssl.create_default_context(cafile=settings.tls_ca_file)
    return True


def opa_http_client(settings: Settings) -> httpx.AsyncClient:
    """Dedicated client for OPA. In mtls mode it presents the PEP client certificate."""
    verify = tls_verify(settings)
    if settings.opa_auth == "mtls":
        cert, key = settings.opa_client_cert_file, settings.opa_client_key_file
        if not isinstance(verify, ssl.SSLContext) or not cert or not key:
            raise ValueError("opa_auth=mtls requires tls_ca_file and a client certificate and key")
        verify.load_cert_chain(cert, key)
    return httpx.AsyncClient(verify=verify, timeout=settings.opa_timeout_seconds, follow_redirects=False)


@asynccontextmanager
async def open_services(settings: Settings) -> AsyncIterator[Services]:
    async with AsyncExitStack() as stack:
        http = await stack.enter_async_context(
            httpx.AsyncClient(
                verify=tls_verify(settings), timeout=settings.http_timeout_seconds, follow_redirects=False
            )
        )
        opa_http = await stack.enter_async_context(opa_http_client(settings))
        pool = create_pool(settings.database_url.get_secret_value())
        await pool.open(wait=False)
        try:
            jwks = JwksCache(
                issuer=settings.oidc_issuer,
                discovery_base=settings.discovery_base,
                client=http,
                min_refresh_seconds=settings.jwks_min_refresh_seconds,
            )
            api_verifier = JwtVerifier(
                jwks=jwks,
                issuer=settings.oidc_issuer,
                audience=settings.api_audience,
                allowed_clients=frozenset(settings.api_allowed_clients),
                conflicting_audiences=frozenset({settings.mcp_audience}),
                leeway_seconds=settings.jwt_leeway_seconds,
            )
            mcp_verifier = JwtVerifier(
                jwks=jwks,
                issuer=settings.oidc_issuer,
                audience=settings.mcp_audience,
                allowed_clients=frozenset(settings.mcp_allowed_clients),
                conflicting_audiences=frozenset({settings.api_audience}),
                leeway_seconds=settings.jwt_leeway_seconds,
            )
            pdp = OpaClient(
                base_url=settings.opa_url,
                token=settings.opa_token.get_secret_value() if settings.opa_auth == "token" else None,
                timeout_seconds=settings.opa_timeout_seconds,
                client=opa_http,
            )
            audit = PgAuditSink(pool)
            enforcer = Enforcer(
                pdp=pdp, audit=audit, policy_version=settings.policy_version, environment=settings.env
            )
            store = DocumentStore(pool)
            gateway = ToolGateway(
                pool=pool,
                enforcer=enforcer,
                store=store,
                rate_limit_per_minute=settings.mcp_rate_limit_per_minute,
                max_summary_chars=settings.max_summary_chars,
            )
            yield Services(
                settings=settings,
                http=http,
                pool=pool,
                jwks=jwks,
                api_verifier=api_verifier,
                mcp_verifier=mcp_verifier,
                pdp=pdp,
                audit=audit,
                enforcer=enforcer,
                store=store,
                gateway=gateway,
            )
        finally:
            await pool.close()
