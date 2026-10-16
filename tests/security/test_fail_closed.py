"""T11: the policy engine (and audit store) failing must never produce an allow.

Fault injection: extra API/MCP instances are started whose OPA URL points at a stub that times
out, errors, returns malformed or undefined results, or at a closed port. One test also stops the
REAL OPA container used by the compose API service.
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx
import pytest

from tests.conftest import Evidence, Keycloak, ServerHandle, free_port, make_settings, start_server

pytestmark = pytest.mark.security

MODES: dict[str, tuple[int, bytes, float]] = {
    "http_500": (500, b'{"code":"internal_error"}', 0.0),
    "malformed_json": (200, b"{not json", 0.0),
    "undefined_result": (200, b"{}", 0.0),
    "non_boolean_result": (200, b'{"result": "true"}', 0.0),
    "allow_object_not_bool": (200, b'{"result": {"allow": true}}', 0.0),
    "timeout": (200, b'{"result": true}', 3.0),  # would allow, but arrives after the 1 s timeout
}


class _StubOpa(BaseHTTPRequestHandler):
    mode = "http_500"

    def do_POST(self) -> None:
        status, body, delay = MODES[self.server.mode]  # type: ignore[attr-defined]
        if delay:
            time.sleep(delay)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture(scope="module")
def stub_opa() -> Iterator[ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", free_port()), _StubOpa)
    srv.mode = "http_500"  # type: ignore[attr-defined]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()


@pytest.fixture(scope="module")
def broken_api(stub_opa: ThreadingHTTPServer) -> Iterator[ServerHandle]:
    from aegis_api.main import create_app

    url = f"http://127.0.0.1:{stub_opa.server_address[1]}"
    handle = start_server(create_app(make_settings(opa_url=url, opa_timeout_seconds=1.0)))
    yield handle
    handle.stop()


@pytest.fixture(scope="module")
def unreachable_api() -> Iterator[ServerHandle]:
    from aegis_api.main import create_app

    handle = start_server(create_app(make_settings(opa_url=f"http://127.0.0.1:{free_port()}")))
    yield handle
    handle.stop()


@pytest.fixture(scope="module")
def wrong_token_api() -> Iterator[ServerHandle]:
    """Real OPA, but the PEP presents the wrong token -> OPA's system.authz returns 401."""
    from aegis_api.main import create_app

    handle = start_server(create_app(make_settings(opa_token="wrong-token-0123456789")))
    yield handle
    handle.stop()


def _read(url: str, token: str, rid: str = "doc-alpha-eng") -> httpx.Response:
    return httpx.get(
        f"{url}/api/v1/resources/{rid}", headers={"Authorization": f"Bearer {token}"}, timeout=20
    )


@pytest.mark.parametrize("mode", list(MODES))
def test_t11_policy_engine_faults(
    mode: str,
    stub_opa: ThreadingHTTPServer,
    broken_api: ServerHandle,
    kc: Keycloak,
    db: Evidence,
    record: Any,
) -> None:
    stub_opa.mode = mode  # type: ignore[attr-defined]
    mark = db.mark()
    r = _read(broken_api.url, kc.password_token("alice"))  # alice WOULD be allowed if OPA worked
    effects = db.side_effects(mark)
    audit = db.audit_for_request(r.json()["request_id"])
    record(
        scenario_id=f"T11-{mode}",
        description=f"OPA fault: {mode} (request would normally be allowed)",
        request="GET doc-alpha-eng (alice) with faulty PDP",
        expected_decision="deny",
        actual_decision=r.json()["decision"],
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=len(audit),
        attack=False,
    )
    assert r.status_code == 503
    assert r.json()["decision"] == "deny" and r.json()["reason_code"] == "DEPENDENCY_UNAVAILABLE"
    assert effects == 0
    assert len(audit) == 1
    assert audit[0]["event_kind"] == "incident" and audit[0]["reason_code"] == "POLICY_UNAVAILABLE"
    expected_status = {
        "http_500": "error",
        "malformed_json": "malformed",
        "undefined_result": "undefined",
        "non_boolean_result": "malformed",
        "allow_object_not_bool": "malformed",
        "timeout": "timeout",
    }
    assert audit[0]["evaluator_status"] == expected_status[mode]


def test_t11_policy_engine_unreachable(
    unreachable_api: ServerHandle, kc: Keycloak, db: Evidence, record: Any
) -> None:
    mark = db.mark()
    r = _read(unreachable_api.url, kc.password_token("alice"))
    effects = db.side_effects(mark)
    record(
        scenario_id="T11-unreachable",
        description="OPA connection refused",
        request="GET doc-alpha-eng (alice)",
        expected_decision="deny",
        actual_decision=r.json()["decision"],
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=len(db.audit_for_request(r.json()["request_id"])),
        attack=False,
    )
    assert r.status_code == 503 and effects == 0
    ready = httpx.get(f"{unreachable_api.url}/health/ready", timeout=10)
    assert ready.status_code == 503 and ready.json()["checks"]["policy_engine"] is False


def test_t11_pep_not_authorized_at_opa(wrong_token_api: ServerHandle, kc: Keycloak, db: Evidence) -> None:
    mark = db.mark()
    r = _read(wrong_token_api.url, kc.password_token("alice"))
    assert r.status_code == 503 and db.side_effects(mark) == 0


def test_t11_audit_store_failure_blocks_allow(
    api_server: ServerHandle, kc: Keycloak, db: Evidence, record: Any
) -> None:
    """If the decision cannot be durably recorded, the allowed operation must not run."""
    from aegis.audit import AuditUnavailableError

    services = api_server.app.state.services
    original = services.audit.record

    async def failing(event: Any) -> None:
        raise AuditUnavailableError()

    services.audit.record = failing
    try:
        mark = db.mark()
        r = _read(api_server.url, kc.password_token("alice"))
        effects = db.side_effects(mark)
    finally:
        services.audit.record = original
    record(
        scenario_id="T11-audit-down",
        description="Audit store unavailable on an otherwise-allowed read",
        request="GET doc-alpha-eng (alice) with audit writes failing",
        expected_decision="deny",
        actual_decision=r.json()["decision"],
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=0,
        attack=False,
    )
    assert r.status_code == 503 and r.json()["decision"] == "deny"
    assert effects == 0


def _compose(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-f", "infra/compose.yaml", *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_t11_real_opa_container_stopped(kc: Keycloak, db: Evidence, record: Any) -> None:
    """End-to-end against the deployed compose API container with the real OPA container stopped."""
    deployed = "http://127.0.0.1:8000"
    if httpx.get(f"{deployed}/health/live", timeout=5).status_code != 200:
        pytest.fail("compose api container not running")
    token = kc.password_token("alice")
    assert _read(deployed, token).status_code == 200  # baseline: allowed while OPA is up
    stop = _compose("stop", "opa")
    assert stop.returncode == 0, stop.stderr
    try:
        mark = db.mark()
        r = _read(deployed, token)
        effects = db.side_effects(mark)
        audit = db.audit_for_request(r.json()["request_id"])
    finally:
        _compose("start", "opa")
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                if httpx.get("http://127.0.0.1:8181/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
    record(
        scenario_id="T11-opa-stopped",
        description="Real OPA container stopped (compose deployment)",
        request="GET doc-alpha-eng (alice) via deployed API",
        expected_decision="deny",
        actual_decision=r.json()["decision"],
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=len(audit),
        attack=False,
    )
    assert r.status_code == 503 and effects == 0
    assert audit[0]["event_kind"] == "incident"
    assert json.loads(httpx.get(f"{deployed}/health/ready", timeout=10).text)["ready"] is True
