"""Scripted stand-in for ``AsyncAnthropic().beta.messages.create`` (no network, no API key).

Each script step is a list of tool calls ``(name, input)``; an empty list ends the turn. The fake
records every request it receives so tests can check exactly what would have left the process.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

Step = list[tuple[str, dict[str, Any]]] | Callable[[list[dict[str, Any]]], list[tuple[str, dict[str, Any]]]]


class ScriptedModel:
    def __init__(self, steps: list[Step], *, final_stop: str = "end_turn") -> None:
        self.steps = steps
        self.final_stop = final_stop
        self.requests: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> Any:
        self.requests.append(kwargs)
        turn = len(self.requests) - 1
        step = self.steps[turn] if turn < len(self.steps) else []
        calls = step(kwargs["messages"]) if callable(step) else step
        if not calls:
            return SimpleNamespace(
                content=[SimpleNamespace(type="text", text="Done.")], stop_reason=self.final_stop
            )
        blocks = [
            SimpleNamespace(type="tool_use", id=f"toolu_{turn}_{i}", name=name, input=args)
            for i, (name, args) in enumerate(calls)
        ]
        return SimpleNamespace(content=blocks, stop_reason="tool_use")

    def sent_text(self) -> str:
        """Everything the planner would have sent to the API, serialized."""
        return json.dumps(self.requests, default=lambda o: getattr(o, "__dict__", str(o)))

    def tool_results(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for msg in self.requests[-1]["messages"] if self.requests else []:
            if msg["role"] == "user" and isinstance(msg["content"], list):
                out += msg["content"]
        return out
