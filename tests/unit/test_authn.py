"""JWT validation unit tests with locally generated keys and a mocked JWKS endpoint."""

from __future__ import annotations

import asyncio
import base64
import json
import time
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from aegis.authn import JwksCache, JwtVerifier, TokenValidationError, bearer_from_header

ISS = "http://idp.test/realms/aegis"


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(key: rsa.RSAPrivateKey, kid: str, **extra: str) -> dict[str, Any]:
    d = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    d.update({"kid": kid, "use": "sig", "alg": "RS256", **extra})
    return d


class FakeIdp:
    def __init__(self) -> None:
        self.keys: list[dict[str, Any]] = []
        self.jwks_hits = 0
        self.issuer = ISS

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": self.issuer, "jwks_uri": f"{ISS}/certs"})
        if request.url.path.endswith("/certs"):
            self.jwks_hits += 1
            return httpx.Response(200, json={"keys": self.keys})
        return httpx.Response(404)


def _claims(**over: Any) -> dict[str, Any]:
    now = int(time.time())
    c = {
        "iss": ISS,
        "aud": "aegis-api",
        "sub": "u-1",
        "azp": "aegis-cli",
        "typ": "Bearer",
        "iat": now,
        "exp": now + 300,
        "jti": "j-1",
        "scope": "",
    }
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def _sign(key: rsa.RSAPrivateKey, claims: dict[str, Any], kid: str = "k1", alg: str = "RS256") -> str:
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


@pytest.fixture
def env() -> Any:
    idp = FakeIdp()
    key = _key()
    idp.keys = [_jwk(key, "k1")]
    client = httpx.AsyncClient(transport=httpx.MockTransport(idp.handler))
    cache = JwksCache(issuer=ISS, discovery_base=ISS, client=client, min_refresh_seconds=30)
    verifier = JwtVerifier(
        jwks=cache,
        issuer=ISS,
        audience="aegis-api",
        allowed_clients=frozenset({"aegis-cli"}),
        conflicting_audiences=frozenset({"aegis-mcp"}),
    )
    return idp, key, cache, verifier


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def reason(verifier: JwtVerifier, token: str) -> str:
    with pytest.raises(TokenValidationError) as ei:
        run(verifier.verify(token))
    return ei.value.reason


def test_valid_token(env: Any) -> None:
    _, key, _, verifier = env
    vt = run(verifier.verify(_sign(key, _claims())))
    assert vt.subject == "u-1"
    assert vt.client_id == "aegis-cli"
    assert vt.audience == ("aegis-api",)


def test_expired(env: Any) -> None:
    _, key, _, v = env
    assert reason(v, _sign(key, _claims(exp=int(time.time()) - 5))) == "TOKEN_EXPIRED"


def test_not_yet_valid(env: Any) -> None:
    _, key, _, v = env
    assert reason(v, _sign(key, _claims(nbf=int(time.time()) + 600))) == "TOKEN_NOT_YET_VALID"


def test_wrong_audience(env: Any) -> None:
    _, key, _, v = env
    assert reason(v, _sign(key, _claims(aud="aegis-mcp"))) == "WRONG_AUDIENCE"
    assert reason(v, _sign(key, _claims(aud="other-service"))) == "WRONG_AUDIENCE"


def test_multi_audience_token_for_two_services_rejected(env: Any) -> None:
    _, key, _, v = env
    assert reason(v, _sign(key, _claims(aud=["aegis-api", "aegis-mcp"]))) == "WRONG_AUDIENCE"


def test_wrong_issuer(env: Any) -> None:
    _, key, _, v = env
    assert reason(v, _sign(key, _claims(iss="http://evil.test/realms/aegis"))) == "WRONG_ISSUER"


def test_missing_required_claims(env: Any) -> None:
    _, key, _, v = env
    assert reason(v, _sign(key, _claims(exp=None))) == "INVALID_TOKEN"
    assert reason(v, _sign(key, _claims(sub=None))) == "INVALID_TOKEN"


def test_wrong_token_type(env: Any) -> None:
    _, key, _, v = env
    assert reason(v, _sign(key, _claims(typ="ID"))) == "WRONG_TOKEN_TYPE"
    assert reason(v, _sign(key, _claims(typ="Refresh"))) == "WRONG_TOKEN_TYPE"


def test_client_not_allowed(env: Any) -> None:
    _, key, _, v = env
    assert reason(v, _sign(key, _claims(azp="agent-alpha"))) == "CLIENT_NOT_ALLOWED"
    assert reason(v, _sign(key, _claims(azp=None))) == "CLIENT_NOT_ALLOWED"


def test_forged_signature_other_key_same_kid(env: Any) -> None:
    _, _, _, v = env
    attacker = _key()
    assert reason(v, _sign(attacker, _claims(), kid="k1")) == "INVALID_SIGNATURE"


def test_tampered_payload(env: Any) -> None:
    _, key, _, v = env
    token = _sign(key, _claims())
    h, p, s = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(p + "=="))
    payload["sub"] = "admin"
    p2 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    assert reason(v, f"{h}.{p2}.{s}") == "INVALID_SIGNATURE"


def test_alg_none_rejected(env: Any) -> None:
    _, _, _, v = env
    token = jwt.encode(_claims(), key=None, algorithm="none", headers={"kid": "k1"})
    assert reason(v, token) == "DISALLOWED_ALGORITHM"


def test_hs256_key_confusion_rejected(env: Any) -> None:
    _, key, _, v = env
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "kid": "k1", "typ": "JWT"}).encode()
    ).rstrip(b"=")
    body = base64.urlsafe_b64encode(json.dumps(_claims()).encode()).rstrip(b"=")
    import hashlib
    import hmac

    sig = hmac.new(pem, header + b"." + body, hashlib.sha256).digest()
    token = (header + b"." + body + b"." + base64.urlsafe_b64encode(sig).rstrip(b"=")).decode()
    assert reason(v, token) == "DISALLOWED_ALGORITHM"


def test_malformed_and_missing_kid(env: Any) -> None:
    _, key, _, v = env
    assert reason(v, "not-a-jwt") == "MALFORMED_TOKEN"
    assert reason(v, "") == "MALFORMED_TOKEN"
    assert reason(v, "a" * 9000) == "MALFORMED_TOKEN"
    no_kid = jwt.encode(_claims(), key, algorithm="RS256")
    assert reason(v, no_kid) == "MISSING_KEY_ID"


def test_unknown_kid_refresh_is_rate_limited(env: Any) -> None:
    idp, _, cache, v = env
    attacker = _key()
    assert reason(v, _sign(attacker, _claims(), kid="forged-1")) == "UNKNOWN_SIGNING_KEY"
    hits_after_first = idp.jwks_hits
    for i in range(20):
        assert reason(v, _sign(attacker, _claims(), kid=f"forged-{i + 2}")) == "UNKNOWN_SIGNING_KEY"
    assert idp.jwks_hits == hits_after_first  # no refresh storm


def test_key_rotation_picks_up_new_kid(env: Any) -> None:
    idp, key, cache, v = env
    run(v.verify(_sign(key, _claims())))
    new_key = _key()
    idp.keys = [_jwk(key, "k1"), _jwk(new_key, "k2")]
    cache._last_refresh = float("-inf")  # simulate refresh window elapsed
    vt = run(v.verify(_sign(new_key, _claims(), kid="k2")))
    assert vt.subject == "u-1"


def test_rotated_out_key_rejected_after_refresh(env: Any) -> None:
    idp, key, cache, v = env
    new_key = _key()
    idp.keys = [_jwk(new_key, "k2")]
    run(cache.refresh())
    assert reason(v, _sign(key, _claims(), kid="k1")) == "UNKNOWN_SIGNING_KEY"


def test_jwks_ignores_unusable_keys(env: Any) -> None:
    idp, key, cache, v = env
    idp.keys = [_jwk(key, "enc1", use="enc"), _jwk(key, "hs", alg="HS256")]
    run(cache.refresh())
    assert reason(v, _sign(key, _claims(), kid="enc1")) == "UNKNOWN_SIGNING_KEY"


def test_discovery_issuer_mismatch_fails_closed() -> None:
    idp = FakeIdp()
    idp.issuer = "http://evil.test/realms/aegis"
    key = _key()
    idp.keys = [_jwk(key, "k1")]
    client = httpx.AsyncClient(transport=httpx.MockTransport(idp.handler))
    cache = JwksCache(issuer=ISS, discovery_base=ISS, client=client)
    v = JwtVerifier(jwks=cache, issuer=ISS, audience="aegis-api", allowed_clients=frozenset({"aegis-cli"}))
    assert reason(v, _sign(key, _claims())) == "JWKS_UNAVAILABLE"


def test_jwks_unreachable_fails_closed() -> None:
    def down(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    client = httpx.AsyncClient(transport=httpx.MockTransport(down))
    cache = JwksCache(issuer=ISS, discovery_base=ISS, client=client)
    v = JwtVerifier(jwks=cache, issuer=ISS, audience="aegis-api", allowed_clients=frozenset({"aegis-cli"}))
    assert reason(v, _sign(_key(), _claims())) == "JWKS_UNAVAILABLE"


def test_bearer_header_parsing() -> None:
    assert bearer_from_header("Bearer abc") == "abc"
    assert bearer_from_header("bearer abc") == "abc"
    assert bearer_from_header("Basic abc") is None
    assert bearer_from_header("Bearer ") is None
    assert bearer_from_header(None) is None
