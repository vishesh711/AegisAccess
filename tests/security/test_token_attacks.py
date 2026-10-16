"""T04-T06: expired, wrong-audience and forged tokens are rejected with 401 and ZERO resource access."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from tests.conftest import Evidence, Keycloak, b64url

pytestmark = pytest.mark.security
TARGET = "doc-alpha-eng"


def attempt(api: httpx.Client, db: Evidence, token: str) -> tuple[httpx.Response, int, int]:
    """Returns (response, side effects, decision events). 401 must mean no decision was ever made."""
    mark = db.mark()
    since = db.now()
    r = api.get(f"/api/v1/resources/{TARGET}", headers={"Authorization": f"Bearer {token}"})
    decisions = [e for e in db.audit_since(since) if e["event_kind"] in ("decision", "execution")]
    return r, db.side_effects(mark), len(decisions)


def _parts(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    return jwt.get_unverified_header(token), jwt.decode(token, options={"verify_signature": False})


def test_t04_expired_token(api: httpx.Client, kc: Keycloak, db: Evidence, record: Any) -> None:
    token = kc.password_token("alice", client="aegis-cli-short")  # real Keycloak token, 2 s lifespan
    _, claims = _parts(token)
    assert claims["exp"] - claims["iat"] <= 2
    time.sleep(3.2)
    r, effects, decisions = attempt(api, db, token)
    record(
        scenario_id="T04",
        description="Expired (genuinely Keycloak-signed) access token",
        request="GET doc-alpha-eng with token past exp",
        expected_decision="401",
        actual_decision=str(r.status_code),
        expected_side_effects=0,
        actual_side_effects=effects,
        audit_events=decisions,
        attack=True,
    )
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Bearer")
    assert effects == 0 and decisions == 0


def test_t05_wrong_audience_tokens(api: httpx.Client, kc: Keycloak, db: Evidence, record: Any) -> None:
    agent_token = kc.client_token("agent-alpha")  # aud=aegis-mcp
    other_app = kc.password_token("alice", client="aegis-other-app")  # aud=other-service
    assert _parts(agent_token)[1]["aud"] == "aegis-mcp"
    assert _parts(other_app)[1]["aud"] == "other-service"
    results = [attempt(api, db, t) for t in (agent_token, other_app)]
    record(
        scenario_id="T05",
        description="Tokens issued for another audience (MCP agent token; other app)",
        request="GET doc-alpha-eng with aud=aegis-mcp and aud=other-service tokens",
        expected_decision="401",
        actual_decision=",".join(sorted({str(r.status_code) for r, _, _ in results})),
        expected_side_effects=0,
        actual_side_effects=sum(e for _, e, _ in results),
        audit_events=sum(d for _, _, d in results),
        attack=True,
    )
    for r, effects, decisions in results:
        assert r.status_code == 401
        assert effects == 0 and decisions == 0


def test_t06_forged_tokens(api: httpx.Client, kc: Keycloak, db: Evidence, record: Any) -> None:
    real = kc.password_token("alice")
    header, claims = _parts(real)
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged: dict[str, str] = {}

    # 1. Re-signed with attacker key but Keycloak's kid, claiming to be bob.
    forged["attacker_key_same_kid"] = jwt.encode(
        {**claims, "sub": "11111111-1111-4111-8111-000000000002"},
        attacker,
        algorithm="RS256",
        headers={"kid": header["kid"]},
    )
    # 2. Payload tampered, original signature kept.
    h, p, s = real.split(".")
    tampered = dict(claims, sub="11111111-1111-4111-8111-000000000002")
    forged["tampered_payload"] = f"{h}.{b64url(json.dumps(tampered).encode())}.{s}"
    # 3. alg=none.
    forged["alg_none"] = (
        b64url(json.dumps({"alg": "none", "typ": "JWT", "kid": header["kid"]}).encode())
        + "."
        + b64url(json.dumps(claims).encode())
        + "."
    )
    # 4. HS256 signed with Keycloak's PUBLIC key as the HMAC secret (key confusion).
    jwk = next(k for k in kc.jwks()["keys"] if k["kid"] == header["kid"])
    pem = RSAAlgorithm.from_jwk(json.dumps(jwk)).public_bytes(  # type: ignore[union-attr]
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hs_head = b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": header["kid"]}).encode())
    hs_body = b64url(json.dumps(claims).encode())
    sig = hmac.new(pem, f"{hs_head}.{hs_body}".encode(), hashlib.sha256).digest()
    forged["hs256_key_confusion"] = f"{hs_head}.{hs_body}.{b64url(sig)}"
    # 5. Unknown kid (self-made key set).
    forged["unknown_kid"] = jwt.encode(claims, attacker, algorithm="RS256", headers={"kid": "attacker-kid"})
    # 6. Signature stripped.
    forged["signature_stripped"] = f"{h}.{p}."
    # 7. Self-issued token from a different issuer.
    forged["wrong_issuer"] = jwt.encode(
        {**claims, "iss": "http://localhost:8080/realms/evil"},
        attacker,
        algorithm="RS256",
        headers={"kid": header["kid"]},
    )

    outcomes = {name: attempt(api, db, tok) for name, tok in forged.items()}
    record(
        scenario_id="T06",
        description=f"Forged/invalid-signature tokens ({len(forged)} variants)",
        request="GET doc-alpha-eng with " + ", ".join(forged),
        expected_decision="401",
        actual_decision=",".join(sorted({str(r.status_code) for r, _, _ in outcomes.values()})),
        expected_side_effects=0,
        actual_side_effects=sum(e for _, e, _ in outcomes.values()),
        audit_events=sum(d for _, _, d in outcomes.values()),
        attack=True,
    )
    for name, (r, effects, decisions) in outcomes.items():
        assert r.status_code == 401, name
        assert effects == 0 and decisions == 0, name


def test_missing_and_non_bearer_credentials(api: httpx.Client, db: Evidence) -> None:
    mark = db.mark()
    assert api.get(f"/api/v1/resources/{TARGET}").status_code == 401
    assert (
        api.get(f"/api/v1/resources/{TARGET}", headers={"Authorization": "Basic YWxpY2U6eA=="}).status_code
        == 401
    )
    assert db.side_effects(mark) == 0


def test_id_token_not_accepted_as_access_token(api: httpx.Client, kc: Keycloak, db: Evidence) -> None:
    resp = kc.http.post(
        "http://localhost:8080/realms/aegis/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "aegis-cli",
            "username": "alice",
            "password": "alice-demo-pw",
            "scope": "openid",
        },
    )
    id_token = resp.json().get("id_token")
    if id_token is None:
        pytest.fail("Keycloak did not issue an ID token for scope=openid")
    r, effects, _ = attempt(api, db, id_token)
    assert r.status_code == 401 and effects == 0
