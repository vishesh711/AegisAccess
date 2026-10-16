"""Structured logging with credential redaction.

Logs must never contain bearer tokens, client secrets or document bodies. Application code
never logs those values deliberately; this filter is a second line of defence that scrubs
anything shaped like a JWT, a bearer header or a ``secret=``/``password=`` pair.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")
_KV_RE = re.compile(r"(?i)((?:client_)?secret|password|token|authorization)(\s*[=:]\s*)([^\s,&\"']+)")

REDACTED = "[REDACTED]"


def redact(text: str) -> str:
    text = _JWT_RE.sub(REDACTED, text)
    text = _BEARER_RE.sub(f"Bearer {REDACTED}", text)
    return _KV_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # Redact message template and each argument, keeping the args shape that formatters
        # (e.g. uvicorn's access formatter) rely on.
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(redact(a) if isinstance(a, str) else a for a in record.args)
        elif isinstance(record.args, dict):
            record.args = {k: redact(v) if isinstance(v, str) else v for k, v in record.args.items()}
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update({k: redact(str(v)) for k, v in fields.items()})
        if record.exc_info:
            # Exception *type* only: messages can embed request data.
            payload["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
        return json.dumps(payload, sort_keys=True)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    # httpx logs full URLs at INFO; keep it quiet (URLs never carry secrets here, but be strict).
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpx2").setLevel(logging.WARNING)


def install_redaction_on_all_handlers() -> None:
    """Attach the redacting filter to every existing handler (e.g. uvicorn's)."""
    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access"):
        for h in logging.getLogger(name).handlers:
            if not any(isinstance(f, RedactingFilter) for f in h.filters):
                h.addFilter(RedactingFilter())
