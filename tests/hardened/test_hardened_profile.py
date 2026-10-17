"""Hardened profile (ADR-9) against the running `make up-hardened` stack.

Checks transport and login properties, and that authorization still works end to end through them:
  * Keycloak: HTTPS only, certificate from the local demo CA, realm stored in PostgreSQL;
  * logins: password grant disabled, authorization code + PKCE (S256) enforced;
  * OPA: reachable only with the PEP client certificate; other identities refused;
  * the API/MCP pair still allows, denies and audits correctly, with the agent run started from a
    PKCE login carrying the delegation consent scope.
"""

from __future__ import annotations

import importlib.util
import ssl
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest
from cryptography.hazmat.primitives import serialization

from aegis.pkce_client import LoginResult, login

pytestmark = pytest.mark.hardened

ROOT = Path(__file__).resolve().parents[2]
PKI = ROOT / ".build" / "pki"
CA_FILE = str(PKI / "ca.crt")
ISSUER = "https://localhost:8443/realms/aegis"
API = "http://127.0.0.1:8000"
OPA = "https://localhost:8181"
REDIRECT = "http://127.0.0.1:8765/callback"
OWNER_DSN = "postgresql://aegis_owner:dummy-aegis-owner-pw@127.0.0.1:5432/aegis"  # DUMMY
KEYCLOAK_DB_DSN = "postgresql://keycloak:dummy-keycloak-db-pw@127.0.0.1:5433/keycloak"  # DUMMY
PASSWORDS = {"alice": "alice-demo-pw", "bob": "bob-demo-pw"}  # synthetic personas
DECISION = "/v1/data/aegis/authz/allow"


def ca() -> ssl.SSLContext:
    """Trust only the local demo CA."""
    return ssl.create_default_context(cafile=CA_FILE)


def pkce(user: str, **kwargs: Any) -> LoginResult:
    with httpx.Client(verify=ca(), timeout=10) as http:
        return login(
            http,
            issuer=ISSUER,
            client_id="aegis-web",
            redirect_uri=REDIRECT,
            username=user,
            password=kwargs.pop("password", PASSWORDS[user]),
            **kwargs,
        )


def token(user: str, scope: str = "openid") -> str:
    result = pkce(user, scope=scope)
    assert result.status == "ok" and result.access_token, result
    return result.access_token


def side_effects_since(mark: int, kind: str | None = None) -> int:
    with psycopg.connect(OWNER_DSN) as conn:
        row = conn.execute(
            "SELECT count(*) FROM resource_side_effects WHERE id > %s AND (%s::text IS NULL OR kind = %s)",
            (mark, kind, kind),
        ).fetchone()
        return int(row[0]) if row else 0


def mark() -> int:
    with psycopg.connect(OWNER_DSN) as conn:
        row = conn.execute("SELECT coalesce(max(id), 0) FROM resource_side_effects").fetchone()
        return int(row[0]) if row else 0


# ------------------------------------------------------------------ Keycloak transport and storage


def test_keycloak_serves_https_only_with_the_demo_ca() -> None:
    meta = httpx.get(f"{ISSUER}/.well-known/openid-configuration", verify=ca()).json()
    assert meta["issuer"] == ISSUER and meta["token_endpoint"].startswith("https://")
    # the certificate is not trusted by the system store: it really is the local CA's
    with pytest.raises(httpx.ConnectError):
        httpx.get(f"{ISSUER}/.well-known/openid-configuration")
    # no plain-HTTP listener: the dev port is closed and the TLS port does not speak HTTP
    with pytest.raises(httpx.HTTPError):
        httpx.get("http://localhost:8080/realms/aegis", timeout=3)
    try:
        plain = httpx.get("http://localhost:8443/realms/aegis", timeout=3)
        assert plain.status_code != 200
    except httpx.HTTPError:
        pass


def test_keycloak_stores_the_realm_in_postgresql() -> None:
    with psycopg.connect(KEYCLOAK_DB_DSN) as conn:
        realm = conn.execute("SELECT id, ssl_required FROM realm WHERE name = 'aegis'").fetchone()
        assert realm is not None and realm[1] == "ALL"
        users = conn.execute("SELECT count(*) FROM user_entity WHERE realm_id = %s", (realm[0],)).fetchone()
        assert users is not None and users[0] >= 6


# ------------------------------------------------------------------ logins


def test_password_grant_is_disabled() -> None:
    for client in ("aegis-cli", "aegis-web"):
        r = httpx.post(
            f"{ISSUER}/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": client,
                "username": "alice",
                "password": "alice-demo-pw",
            },
            verify=ca(),
        )
        assert r.status_code in (400, 401) and r.json()["error"] == "unauthorized_client"


def test_pkce_s256_is_enforced() -> None:
    attempts = {
        "no code_challenge": pkce("alice", challenge_method=None),
        "plain method": pkce("alice", challenge_method="plain"),
        "no code_verifier": pkce("alice", send_verifier=False),
        "wrong code_verifier": pkce("alice", wrong_verifier=True),
        "wrong password": pkce("alice", password="not-the-password"),
    }
    assert {k: (r.status, r.access_token) for k, r in attempts.items()} == {
        "no code_challenge": ("authorize_error", None),
        "plain method": ("authorize_error", None),
        "no code_verifier": ("token_error", None),
        "wrong code_verifier": ("token_error", None),
        "wrong password": ("login_failed", None),
    }
    assert pkce("alice").status == "ok"


# ------------------------------------------------------------------ OPA mutual TLS


def _load_gen_pki() -> Any:
    spec = importlib.util.spec_from_file_location("gen_pki", ROOT / "scripts" / "gen_pki.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _client_with(cert: Any, key: Any, tmp: Path, name: str) -> httpx.Client:
    cert_path, key_path = tmp / f"{name}.crt", tmp / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    ctx = ssl.create_default_context(cafile=CA_FILE)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return httpx.Client(verify=ctx, timeout=5)


def _pep_client() -> httpx.Client:
    ctx = ssl.create_default_context(cafile=CA_FILE)
    ctx.load_cert_chain(str(PKI / "pep.crt"), str(PKI / "pep.key"))
    return httpx.Client(verify=ctx, timeout=5)


def test_opa_accepts_only_the_pep_client_certificate(tmp_path: Path) -> None:
    gen = _load_gen_pki()
    real_ca = gen.x509.load_pem_x509_certificate((PKI / "ca.crt").read_bytes())
    real_ca_key = serialization.load_pem_private_key((PKI / "ca.key").read_bytes(), password=None)
    rogue_ca, rogue_ca_key = gen.make_ca()
    body = {"input": {}}

    def refused_handshake(client: httpx.Client) -> bool:
        try:
            client.post(OPA + DECISION, json=body)
        except httpx.HTTPError:
            return True
        return False

    # no client certificate at all (also: the old bearer token is no longer a way in)
    no_cert = httpx.Client(verify=ca(), timeout=5, headers={"Authorization": "Bearer dummy-opa-pep-token"})
    assert refused_handshake(no_cert)
    # certificate named like the PEP, but from a CA OPA does not trust
    assert refused_handshake(
        _client_with(*gen.issue(rogue_ca, rogue_ca_key, "aegis-pep", client=True), tmp_path, "rogue")
    )
    # trusted CA, wrong identity: TLS succeeds, OPA's system.authz refuses
    with _client_with(*gen.issue(real_ca, real_ca_key, "intruder", client=True), tmp_path, "intruder") as c:
        assert c.post(OPA + DECISION, json=body).status_code in (401, 403)
    with _pep_client() as pep:
        assert pep.post(OPA + DECISION, json=body).status_code == 200
        # even the PEP cannot change policy or read raw data
        assert pep.put(OPA + "/v1/policies/authz", content=b"package x").status_code in (401, 403)
        assert pep.get(OPA + "/v1/data/aegis/roles").status_code in (401, 403)
    # and OPA's server certificate is not trusted by the system store
    with pytest.raises(httpx.ConnectError):
        httpx.get(OPA + "/health")


# ------------------------------------------------------------------ authorization still works end to end


def test_api_is_ready_over_tls_and_mtls() -> None:
    r = httpx.get(f"{API}/health/ready").json()
    assert r == {
        "ready": True,
        "checks": {"database": True, "policy_engine": True, "policy_version_match": True, "jwks": True},
    }


def test_pkce_login_drives_allow_and_deny_with_side_effects() -> None:
    headers = {"Authorization": f"Bearer {token('alice')}"}
    m = mark()
    allowed = httpx.get(f"{API}/api/v1/resources/doc-alpha-eng", headers=headers)
    reads_after_allow = side_effects_since(m, "document_read")
    denied = httpx.get(f"{API}/api/v1/resources/doc-alpha-payroll", headers=headers)
    assert allowed.status_code == 200 and reads_after_allow == 1
    assert denied.status_code == 403 and "AEGIS-CANARY" not in denied.text
    assert side_effects_since(m) == 1  # the denied read had no side effect
    with psycopg.connect(OWNER_DSN) as conn:
        rows = conn.execute(
            "SELECT decision, evaluator_status FROM audit_events WHERE request_id = %s AND event_kind = 'decision'",
            (denied.json()["request_id"],),
        ).fetchall()
    assert rows == [("deny", "ok")]  # a real OPA answer over mTLS, not an evaluator failure


def test_agent_run_from_a_pkce_consent_login() -> None:
    alice = {"Authorization": f"Bearer {token('alice')}"}
    task = httpx.post(
        f"{API}/api/v1/tasks",
        headers=alice,
        json={
            "agent_id": "agent-alpha",
            "actions": ["documents:read", "reports:create"],
            "resource_ids": ["doc-alpha-eng", "doc-alpha-eng-notes"],
            "ttl_seconds": 300,
        },
    ).json()["task_id"]
    no_consent = httpx.post(f"{API}/api/v1/tasks/{task}/invoke", headers=alice, timeout=60)
    assert no_consent.status_code == 403
    consent = {"Authorization": f"Bearer {token('alice', scope='openid delegate-agent-alpha')}"}
    m = mark()
    run = httpx.post(f"{API}/api/v1/tasks/{task}/invoke", headers=consent, timeout=60).json()
    outcome = {(t["tool"], t["arguments"].get("resource_id"), t["ok"]) for t in run["trace"]}
    assert ("documents.read", "doc-alpha-eng", True) in outcome
    assert ("documents.read", "doc-alpha-payroll", False) in outcome  # injected, denied at the tool boundary
    assert run["report_id"] is not None
    with psycopg.connect(OWNER_DSN) as conn:
        kinds = [
            (r[0], r[1])
            for r in conn.execute(
                "SELECT kind, resource_id FROM resource_side_effects WHERE id > %s ORDER BY id", (m,)
            )
        ]
    assert ("document_read", "doc-alpha-payroll") not in kinds
    assert [k for k, _ in kinds].count("report_write") == 1
