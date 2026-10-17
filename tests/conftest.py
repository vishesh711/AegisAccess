"""Shared fixtures for integration and security tests.

These tests need the compose stack (keycloak, postgres, opa) running and migrated+seeded
(`make up migrate seed`). They FAIL (not skip) when it is unavailable: no fake green.

The API and MCP servers under test run in-process (uvicorn threads) from the working tree, wired
to the REAL Keycloak, PostgreSQL and OPA. Fault-injection variants start extra server instances
with a different configuration (e.g. an OPA URL that times out).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import socket
import struct
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import httpx
import psycopg
import pytest
import uvicorn

from aegis.config import Settings

KC = "http://localhost:8080/realms/aegis"
TOKEN_URL = f"{KC}/protocol/openid-connect/token"
OWNER_DSN = "postgresql://aegis_owner:dummy-aegis-owner-pw@127.0.0.1:5432/aegis"  # pragma: allowlist secret
APP_DSN = "postgresql://aegis_app:dummy-aegis-app-pw@127.0.0.1:5432/aegis"  # pragma: allowlist secret
OPA_URL = "http://127.0.0.1:8181"
OPA_TOKEN = "dummy-opa-pep-token"  # pragma: allowlist secret

PASSWORDS = {
    "alice": "alice-demo-pw",
    "bob": "bob-demo-pw",
    "carol": "carol-demo-pw",
    "secadmin": "secadmin-demo-pw",
    "dave": "dave-demo-pw",
    "eve": "eve-demo-pw",
}
CLIENT_SECRETS = {
    "agent-alpha": "dummy-agent-alpha-secret",
    "agent-beta": "dummy-agent-beta-secret",  # agent-beta keeps a service account (misconfigured persona)
    "svc-reporter": "dummy-svc-reporter-secret",
}
SECADMIN_OTP_KEY = b"aegis-demo-otp-secret-dummy01"
CANARIES = [
    "AEGIS-CANARY-ENG-4471",
    "AEGIS-CANARY-NOTES-5582",
    "AEGIS-CANARY-PAYROLL-7731",
    "AEGIS-CANARY-FINNOTES-6693",
    "AEGIS-CANARY-BETA-8814",
]


def totp(key: bytes, at: float | None = None, step: int = 30) -> str:
    counter = int((at or time.time()) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


# ---------------------------------------------------------------------------- stack check


def _reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session", autouse=True)
def _require_stack(request: pytest.FixtureRequest) -> None:
    needs_stack = any(
        "integration" in str(item.fspath) or "security" in str(item.fspath) for item in request.session.items
    )
    if not needs_stack:
        return
    missing = [
        n
        for n, p in (("keycloak", 8080), ("postgres", 5432), ("opa", 8181))
        if not _reachable("127.0.0.1", p)
    ]
    if missing:
        pytest.fail(
            f"compose stack not running ({', '.join(missing)}); run `make up migrate seed`", pytrace=False
        )


# ---------------------------------------------------------------------------- identity helpers


class Keycloak:
    def __init__(self) -> None:
        self.http = httpx.Client(timeout=10)
        self._mfa_cache: tuple[str, float] | None = None
        self._last_otp_window = -1
        self.issued: list[str] = []  # every token handed out, for leak scanning

    def _secadmin_token(self) -> str:
        # Keycloak rejects re-use of a TOTP code, so cache the MFA session token (lifespan 300 s)
        # and never submit the same 30 s window twice.
        if self._mfa_cache and time.time() - self._mfa_cache[1] < 240:
            return self._mfa_cache[0]
        for _attempt in range(2):
            # A code already used (e.g. by a previous test process in the same window) is rejected
            # by Keycloak, so on failure wait for the next window and retry once.
            while int(time.time() // 30) == self._last_otp_window:
                time.sleep(0.5)
            self._last_otp_window = int(time.time() // 30)
            data = {
                "grant_type": "password",
                "client_id": "aegis-cli",
                "username": "secadmin",
                "password": PASSWORDS["secadmin"],
                "totp": totp(SECADMIN_OTP_KEY),
            }
            resp = self.http.post(TOKEN_URL, data=data)
            if resp.status_code == 200:
                break
        assert resp.status_code == 200, f"MFA login failed: {resp.status_code}"
        token: str = resp.json()["access_token"]
        self.issued.append(token)
        self._mfa_cache = (token, time.time())
        return token

    def password_token(self, user: str, client: str = "aegis-cli", **extra: str) -> str:
        if user == "secadmin" and not extra and client == "aegis-cli":
            return self._secadmin_token()
        data = {
            "grant_type": "password",
            "client_id": client,
            "username": user,
            "password": PASSWORDS[user],
            **extra,
        }
        resp = self.http.post(TOKEN_URL, data=data)
        assert resp.status_code == 200, f"login failed for {user}: {resp.status_code}"
        token: str = resp.json()["access_token"]
        self.issued.append(token)
        return token

    def raw_password_grant(self, user: str, **extra: str) -> httpx.Response:
        data = {
            "grant_type": "password",
            "client_id": "aegis-cli",
            "username": user,
            "password": PASSWORDS[user],
        }
        data.update(extra)
        return self.http.post(TOKEN_URL, data=data)

    def client_token(self, client: str) -> str:
        resp = self.http.post(
            TOKEN_URL, data={"grant_type": "client_credentials"}, auth=(client, CLIENT_SECRETS[client])
        )
        assert resp.status_code == 200, f"client credentials failed for {client}"
        token: str = resp.json()["access_token"]
        self.issued.append(token)
        return token

    def consent_token(self, user: str, agent: str = "agent-alpha") -> str:
        """User login that consents to delegation to ``agent`` (scope delegate-<agent>)."""
        return self.password_token(user, scope=f"delegate-{agent}")

    def exchanged_token(self, user: str, agent: str = "agent-alpha") -> str:
        """RFC 8693 exchange by the agent client of the user's consent token. NOT bound to any task."""
        resp = self.http.post(
            TOKEN_URL,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": self.consent_token(user, agent),
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            },
            auth=(agent, CLIENT_SECRETS[agent]),
        )
        assert resp.status_code == 200, f"token exchange failed for {user}/{agent}: {resp.status_code}"
        token: str = resp.json()["access_token"]
        self.issued.append(token)
        return token

    def jwks(self) -> dict[str, Any]:
        result: dict[str, Any] = self.http.get(f"{KC}/protocol/openid-connect/certs").json()
        return result


@pytest.fixture(scope="session")
def kc() -> Keycloak:
    return Keycloak()


# ---------------------------------------------------------------------------- database evidence


class Evidence:
    """Reads ground truth directly from PostgreSQL as the owner role."""

    def __init__(self) -> None:
        self.conn = psycopg.connect(OWNER_DSN, autocommit=True)

    def mark(self) -> int:
        row = self.conn.execute("SELECT COALESCE(max(id), 0) FROM resource_side_effects").fetchone()
        return int(row[0]) if row else 0

    def side_effects(self, since: int, *, kind: str | None = None, resource_id: str | None = None) -> int:
        sql = "SELECT count(*) FROM resource_side_effects WHERE id > %s"
        params: list[Any] = [since]
        if kind:
            sql += " AND kind = %s"
            params.append(kind)
        if resource_id:
            sql += " AND resource_id = %s"
            params.append(resource_id)
        row = self.conn.execute(sql, params).fetchone()  # type: ignore[call-overload]
        return int(row[0]) if row else 0

    def audit_for_request(self, request_id: str) -> list[dict[str, Any]]:
        cur = self.conn.cursor(row_factory=psycopg.rows.dict_row)
        return cur.execute(
            "SELECT * FROM audit_events WHERE request_id = %s ORDER BY event_time", (request_id,)
        ).fetchall()

    def audit_for_correlation(self, correlation_id: str) -> list[dict[str, Any]]:
        cur = self.conn.cursor(row_factory=psycopg.rows.dict_row)
        return cur.execute(
            "SELECT * FROM audit_events WHERE correlation_id = %s ORDER BY event_time", (correlation_id,)
        ).fetchall()

    def audit_since(self, ts: Any) -> list[dict[str, Any]]:
        cur = self.conn.cursor(row_factory=psycopg.rows.dict_row)
        return cur.execute(
            "SELECT * FROM audit_events WHERE event_time >= %s ORDER BY event_time", (ts,)
        ).fetchall()

    def now(self) -> Any:
        row = self.conn.execute("SELECT clock_timestamp()").fetchone()
        assert row is not None
        return row[0]

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self.conn.execute(sql, params)  # type: ignore[arg-type]


@pytest.fixture(scope="session")
def db() -> Iterator[Evidence]:
    ev = Evidence()
    yield ev
    ev.conn.close()


# ---------------------------------------------------------------------------- in-process servers


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


@dataclass
class ServerHandle:
    url: str
    server: uvicorn.Server
    thread: threading.Thread
    app: Any = None

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


def start_server(app: Any) -> ServerHandle:
    port = free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 20
    while not server.started:
        if time.time() > deadline or not thread.is_alive():
            raise RuntimeError("server failed to start")
        time.sleep(0.05)
    return ServerHandle(url=f"http://127.0.0.1:{port}", server=server, thread=thread, app=app)


def make_settings(**over: Any) -> Settings:
    base: dict[str, Any] = {
        "env": "test",
        "database_url": APP_DSN,
        "oidc_issuer": KC,
        "opa_url": OPA_URL,
        "opa_token": OPA_TOKEN,
        "enable_test_tools": True,
        "jwks_min_refresh_seconds": 5.0,
    }
    base.update(over)
    return Settings(**base)


@pytest.fixture(scope="session")
def mcp_server(captured_logs: LogCapture) -> Iterator[ServerHandle]:
    from aegis_mcp.server import create_app

    handle = start_server(create_app(make_settings()))
    yield handle
    handle.stop()


@pytest.fixture(scope="session")
def api_server(mcp_server: ServerHandle) -> Iterator[ServerHandle]:
    from aegis_api.main import create_app

    handle = start_server(create_app(make_settings(mcp_url=f"{mcp_server.url}/mcp")))
    yield handle
    handle.stop()


@pytest.fixture(scope="session")
def api(api_server: ServerHandle) -> Iterator[httpx.Client]:
    with httpx.Client(base_url=api_server.url, timeout=30) as client:
        yield client


# ---------------------------------------------------------------------------- log capture


@dataclass
class LogCapture(logging.Handler):
    records: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        logging.Handler.__init__(self, level=logging.DEBUG)

    def handle(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        # Bypass handler filters (the app installs a redacting filter on every root handler) and
        # run first among root handlers, so we see the record before anything mutates it.
        self.emit(record)
        return True

    def emit(self, record: logging.LogRecord) -> None:
        # Raw message BEFORE any redaction filter: proves the app does not try to log secrets.
        try:
            self.records.append(record.getMessage())
        except Exception:
            self.records.append(str(record.msg))

    __hash__ = logging.Handler.__hash__


@pytest.fixture(scope="session")
def captured_logs() -> Iterator[LogCapture]:
    cap = LogCapture()
    root = logging.getLogger()
    root.handlers.insert(0, cap)
    old = root.level
    root.setLevel(logging.DEBUG)
    yield cap
    root.removeHandler(cap)
    root.setLevel(old)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def bound_agent_token(kc: Keycloak, user: str, task_id: str, agent: str = "agent-alpha") -> str:
    """A per-task, user-bound agent token, produced by the PRODUCTION agent-host code path
    (consent login -> Keycloak token exchange -> verification -> binding to the task)."""
    import asyncio
    import uuid as _uuid

    from aegis.agent_tokens import issue_task_token
    from aegis.delegation import load_delegation
    from aegis.services import open_services

    consent = kc.consent_token(user, agent)

    async def go() -> str:
        async with open_services(make_settings()) as services:
            with psycopg.connect(OWNER_DSN) as conn:
                row = conn.execute("SELECT tenant_id FROM tasks WHERE id = %s", (task_id,)).fetchone()
            assert row is not None, "task not found"
            delegation = await load_delegation(services.pool, tenant_id=row[0], task_id=_uuid.UUID(task_id))
            assert delegation is not None
            return await issue_task_token(
                http=services.http,
                pool=services.pool,
                mcp_verifier=services.mcp_verifier,
                token_endpoint=services.settings.token_endpoint,
                client_id=agent,
                client_secret=CLIENT_SECRETS[agent],
                user_token=consent,
                delegation=delegation,
            )

    token = asyncio.run(go())
    kc.issued.append(token)
    return token
