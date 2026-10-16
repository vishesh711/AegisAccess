"""OIDC access-token validation against Keycloak (signature, alg, iss, aud, exp, nbf, typ, azp).

Design notes
* Only RS256 is accepted. ``alg`` values such as ``none`` or ``HS256`` are rejected before any key
  lookup, which also defeats RSA-public-key-as-HMAC-secret confusion.
* Keys come from the issuer's JWKS (discovered via ``.well-known/openid-configuration`` whose
  ``issuer`` must equal the configured issuer exactly). Unknown ``kid`` triggers one refresh,
  rate-limited so forged ``kid`` values cannot be used to hammer Keycloak.
* Token claims are used for *authentication only*. Tenant, roles and agent permissions are
  resolved from the database (see ``identity.py``).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from jwt import PyJWK

ALLOWED_ALGORITHMS = ("RS256",)
MAX_TOKEN_BYTES = 8192


class TokenValidationError(Exception):
    """Raised for any authentication failure. ``reason`` is a stable, non-sensitive code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class JwksUnavailableError(TokenValidationError):
    def __init__(self) -> None:
        super().__init__("JWKS_UNAVAILABLE")


@dataclass(frozen=True, slots=True)
class VerifiedToken:
    issuer: str
    subject: str
    client_id: str  # azp
    audience: tuple[str, ...]
    expires_at: int
    token_id: str | None
    scopes: tuple[str, ...]


def _usable_signing_key(jwk_dict: dict[str, Any]) -> PyJWK | None:
    if jwk_dict.get("kty") != "RSA":
        return None
    if jwk_dict.get("use", "sig") != "sig":
        return None
    if jwk_dict.get("alg", "RS256") not in ALLOWED_ALGORITHMS:
        return None
    if not isinstance(jwk_dict.get("kid"), str):
        return None
    try:
        return PyJWK(jwk_dict, algorithm="RS256")
    except (jwt.PyJWKError, jwt.InvalidKeyError, ValueError, TypeError):
        return None


class JwksCache:
    """Async JWKS cache with discovery, issuer pinning and rate-limited refresh."""

    def __init__(
        self,
        *,
        issuer: str,
        discovery_base: str,
        client: httpx.AsyncClient,
        min_refresh_seconds: float = 30.0,
    ) -> None:
        self._issuer = issuer
        self._discovery_base = discovery_base.rstrip("/")
        self._client = client
        self._min_refresh = min_refresh_seconds
        self._keys: dict[str, PyJWK] = {}
        self._jwks_uri: str | None = None
        self._last_refresh = float("-inf")
        self._lock = asyncio.Lock()
        self.refresh_count = 0

    async def _discover(self) -> str:
        resp = await self._client.get(f"{self._discovery_base}/.well-known/openid-configuration")
        resp.raise_for_status()
        meta = resp.json()
        if not isinstance(meta, dict) or meta.get("issuer") != self._issuer:
            raise JwksUnavailableError()
        uri = meta.get("jwks_uri")
        if not isinstance(uri, str):
            raise JwksUnavailableError()
        return uri

    async def refresh(self) -> None:
        try:
            if self._jwks_uri is None:
                self._jwks_uri = await self._discover()
            resp = await self._client.get(self._jwks_uri)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise JwksUnavailableError() from exc
        keys: dict[str, PyJWK] = {}
        for raw in data.get("keys", []) if isinstance(data, dict) else []:
            if isinstance(raw, dict) and (k := _usable_signing_key(raw)) is not None:
                keys[raw["kid"]] = k
        self._keys = keys
        self._last_refresh = time.monotonic()
        self.refresh_count += 1

    async def get_key(self, kid: str) -> PyJWK:
        key = self._keys.get(kid)
        if key is not None:
            return key
        async with self._lock:
            key = self._keys.get(kid)
            if key is not None:
                return key
            # Refresh at most once per ``min_refresh`` window (unknown-kid flood protection).
            if time.monotonic() - self._last_refresh >= self._min_refresh or not self._keys:
                await self.refresh()
            key = self._keys.get(kid)
        if key is None:
            raise TokenValidationError("UNKNOWN_SIGNING_KEY")
        return key

    async def ready(self) -> bool:
        try:
            if not self._keys:
                await self.refresh()
        except TokenValidationError:
            return False
        return bool(self._keys)


class JwtVerifier:
    def __init__(
        self,
        *,
        jwks: JwksCache,
        issuer: str,
        audience: str,
        allowed_clients: frozenset[str],
        conflicting_audiences: frozenset[str] = frozenset(),
        leeway_seconds: int = 0,
    ) -> None:
        self._jwks = jwks
        self._issuer = issuer
        self._audience = audience
        self._allowed_clients = allowed_clients
        # A token that is ALSO valid for another AegisAccess service is rejected: one token must
        # never authorize two services (no multi-audience tokens, no passthrough).
        self._conflicting = conflicting_audiences
        self._leeway = leeway_seconds

    @property
    def audience(self) -> str:
        return self._audience

    async def verify(self, token: str) -> VerifiedToken:
        if not token or len(token) > MAX_TOKEN_BYTES:
            raise TokenValidationError("MALFORMED_TOKEN")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenValidationError("MALFORMED_TOKEN") from exc
        alg = header.get("alg")
        if alg not in ALLOWED_ALGORITHMS:
            raise TokenValidationError("DISALLOWED_ALGORITHM")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenValidationError("MISSING_KEY_ID")
        key = await self._jwks.get_key(kid)
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key.key,
                algorithms=list(ALLOWED_ALGORITHMS),
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": ["exp", "iat", "iss", "aud", "sub"], "verify_signature": True},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenValidationError("TOKEN_EXPIRED") from exc
        except jwt.ImmatureSignatureError as exc:
            raise TokenValidationError("TOKEN_NOT_YET_VALID") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenValidationError("WRONG_AUDIENCE") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenValidationError("WRONG_ISSUER") from exc
        except jwt.InvalidSignatureError as exc:
            raise TokenValidationError("INVALID_SIGNATURE") from exc
        except jwt.PyJWTError as exc:
            raise TokenValidationError("INVALID_TOKEN") from exc

        # Keycloak marks access tokens ``typ: Bearer``; ID / refresh tokens are rejected.
        if claims.get("typ") != "Bearer":
            raise TokenValidationError("WRONG_TOKEN_TYPE")
        azp = claims.get("azp")
        if not isinstance(azp, str) or azp not in self._allowed_clients:
            raise TokenValidationError("CLIENT_NOT_ALLOWED")
        sub = claims["sub"]
        if not isinstance(sub, str) or not sub:
            raise TokenValidationError("INVALID_TOKEN")
        aud = claims["aud"]
        audiences = (aud,) if isinstance(aud, str) else tuple(str(a) for a in aud)
        if self._conflicting.intersection(audiences):
            raise TokenValidationError("WRONG_AUDIENCE")
        scope = claims.get("scope", "")
        return VerifiedToken(
            issuer=self._issuer,
            subject=sub,
            client_id=azp,
            audience=audiences,
            expires_at=int(claims["exp"]),
            token_id=claims.get("jti") if isinstance(claims.get("jti"), str) else None,
            scopes=tuple(scope.split()) if isinstance(scope, str) else (),
        )


def bearer_from_header(value: str | None) -> str | None:
    if not value:
        return None
    scheme, _, credential = value.partition(" ")
    if scheme.lower() != "bearer" or not credential.strip():
        return None
    return credential.strip()
