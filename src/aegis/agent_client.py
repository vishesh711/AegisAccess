"""The agent's MCP client: calls the MCP server over streamable HTTP with the official SDK client,
presenting the per-task, user-bound token from ``aegis.agent_tokens`` on every request.

The delegating user's API token is never sent to the MCP server (no token passthrough).
"""

from __future__ import annotations

import uuid
from types import TracebackType
from typing import Any

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from aegis.planner import ToolResult

TASK_HEADER = "Aegis-Task-Id"
CORRELATION_HEADER = "Aegis-Correlation-Id"


class McpToolClient:
    """One MCP client per agent run. Identity = the bearer token on every HTTP request."""

    def __init__(
        self,
        *,
        url: str,
        access_token: str,
        task_id: str | None,
        correlation_id: uuid.UUID | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        headers = {"Authorization": f"Bearer {access_token}"}
        if task_id is not None:
            headers[TASK_HEADER] = task_id
        if correlation_id is not None:
            headers[CORRELATION_HEADER] = str(correlation_id)
        self._http = httpx2.AsyncClient(headers=headers, timeout=timeout_seconds)
        self._client = Client(streamable_http_client(url, http_client=self._http))

    async def __aenter__(self) -> McpToolClient:
        await self._http.__aenter__()
        await self._client.__aenter__()
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        try:
            await self._client.__aexit__(exc_type, exc, tb)
        finally:
            await self._http.__aexit__(exc_type, exc, tb)

    async def list_tools(self) -> list[Any]:
        return list((await self._client.list_tools()).tools)

    async def call(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        result = await self._client.call_tool(name, arguments)
        if result.is_error:
            text = " ".join(getattr(c, "text", "") for c in result.content)[:300]
            return ToolResult(ok=False, error=text or "TOOL_ERROR")
        data = result.structured_content if isinstance(result.structured_content, dict) else None
        return ToolResult(ok=True, data=data)
