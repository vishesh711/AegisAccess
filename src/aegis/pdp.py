"""OPA client (policy decision point). Strict, fail-closed parsing of decisions.

Only an HTTP 200 JSON object whose ``result`` is the boolean ``true`` allows. Anything else —
timeout, connection error, non-200, non-JSON, missing ``result`` (undefined decision), or a
non-boolean ``result`` — is a deny with a distinct ``status`` for audit.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Literal

import httpx

PdpStatus = Literal["ok", "timeout", "error", "malformed", "undefined"]

ALLOW_PATH = "/v1/data/aegis/authz/allow"
REASONS_PATH = "/v1/data/aegis/authz/deny_reasons"
VERSION_PATH = "/v1/data/aegis/authz/policy_version"


@dataclass(frozen=True, slots=True)
class PdpResult:
    allow: bool
    status: PdpStatus
    duration_ms: float


class OpaClient:
    def __init__(
        self, *, base_url: str, token: str, timeout_seconds: float, client: httpx.AsyncClient
    ) -> None:
        self._base = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"}
        self._timeout = httpx.Timeout(timeout_seconds)
        self._client = client

    async def decide(self, policy_input: dict[str, Any]) -> PdpResult:
        start = time.perf_counter()

        def done(allow: bool, status: PdpStatus) -> PdpResult:
            return PdpResult(allow=allow, status=status, duration_ms=(time.perf_counter() - start) * 1000)

        try:
            resp = await self._client.post(
                self._base + ALLOW_PATH,
                json={"input": policy_input},
                headers=self._headers,
                timeout=self._timeout,
            )
        except httpx.TimeoutException:
            return done(False, "timeout")
        except httpx.HTTPError:
            return done(False, "error")
        if resp.status_code != 200:
            return done(False, "error")
        try:
            body = resp.json()
        except ValueError:
            return done(False, "malformed")
        if not isinstance(body, dict):
            return done(False, "malformed")
        if "result" not in body:
            return done(False, "undefined")
        result = body["result"]
        if result is True:
            return done(True, "ok")
        if result is False:
            return done(False, "ok")
        return done(False, "malformed")

    async def explain(self, policy_input: dict[str, Any]) -> list[str]:
        """Best-effort deny reasons for audit. Never used to grant access."""
        try:
            resp = await self._client.post(
                self._base + REASONS_PATH,
                json={"input": policy_input},
                headers=self._headers,
                timeout=self._timeout,
            )
            body = resp.json() if resp.status_code == 200 else None
        except (httpx.HTTPError, ValueError):
            return ["EXPLANATION_UNAVAILABLE"]
        result = body.get("result") if isinstance(body, dict) else None
        if not isinstance(result, list) or not all(isinstance(r, str) for r in result):
            return ["EXPLANATION_UNAVAILABLE"]
        return sorted(result) or ["POLICY_DENY"]

    async def loaded_policy_version(self) -> str | None:
        try:
            resp = await self._client.get(
                self._base + VERSION_PATH, headers=self._headers, timeout=self._timeout
            )
            body = resp.json() if resp.status_code == 200 else None
        except (httpx.HTTPError, ValueError):
            return None
        result = body.get("result") if isinstance(body, dict) else None
        return result if isinstance(result, str) else None
