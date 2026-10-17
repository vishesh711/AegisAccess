"""Authorization code + PKCE (RFC 7636) login against Keycloak, for the demo personas.

This does what a browser does: it opens the authorization endpoint, submits Keycloak's own login form,
follows the redirect to the loopback ``redirect_uri`` (RFC 8252), checks ``state``, and redeems the code
with the ``code_verifier``. Used by ``scripts/pkce_login.py`` and the hardened-profile tests. It never
prints or logs tokens.
"""

from __future__ import annotations

import base64
import hashlib
import html
import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

import httpx

_FORM_ACTION = re.compile(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', re.S)


def pkce_pair() -> tuple[str, str]:
    """(code_verifier, S256 code_challenge)."""
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=")
    return verifier, challenge.decode("ascii")


@dataclass
class LoginResult:
    status: str  # "ok" | "authorize_error" | "login_failed" | "token_error"
    access_token: str | None = field(default=None, repr=False)
    error: str | None = None
    scope: str | None = None


def login(
    http: httpx.Client,
    *,
    issuer: str,
    client_id: str,
    redirect_uri: str,
    username: str,
    password: str,
    scope: str = "openid",
    challenge_method: str | None = "S256",
    send_verifier: bool = True,
    wrong_verifier: bool = False,
) -> LoginResult:
    """The flag arguments exist so tests can show the server refusing each PKCE shortcut."""
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(24)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
    }
    if challenge_method == "S256":
        params |= {"code_challenge": challenge, "code_challenge_method": "S256"}
    elif challenge_method == "plain":
        params |= {"code_challenge": verifier, "code_challenge_method": "plain"}
    page = http.get(f"{issuer}/protocol/openid-connect/auth", params=params, follow_redirects=False)
    if page.status_code in (302, 303):
        query = parse_qs(urlsplit(page.headers.get("location", "")).query)
        return LoginResult("authorize_error", error=(query.get("error") or ["redirect"])[0])
    match = _FORM_ACTION.search(page.text)
    if page.status_code != 200 or match is None:
        return LoginResult("authorize_error", error=f"http_{page.status_code}")
    sent = http.post(
        html.unescape(match.group(1)),
        data={"username": username, "password": password, "credentialId": ""},
        follow_redirects=False,
    )
    location = sent.headers.get("location", "")
    if sent.status_code not in (302, 303) or not location.startswith(redirect_uri):
        return LoginResult("login_failed", error=f"http_{sent.status_code}")
    query = parse_qs(urlsplit(location).query)
    if query.get("state") != [state] or "code" not in query:
        return LoginResult("login_failed", error=(query.get("error") or ["state_mismatch"])[0])
    form = {
        "grant_type": "authorization_code",
        "code": query["code"][0],
        "redirect_uri": redirect_uri,
        "client_id": client_id,
    }
    if send_verifier:
        form["code_verifier"] = pkce_pair()[0] if wrong_verifier else verifier
    token = http.post(f"{issuer}/protocol/openid-connect/token", data=form)
    body = token.json()
    if token.status_code != 200:
        return LoginResult("token_error", error=str(body.get("error")))
    return LoginResult("ok", access_token=body["access_token"], scope=body.get("scope"))
