"""Derive the hardened realm import from the demo realm (written to .build/keycloak/, git-ignored).

Changes: sslRequired=all, and no client may use the resource-owner password grant (humans log in with
authorization code + PKCE through `aegis-web`). Everything else (users, ids, scopes, token exchange) is
identical, so the same authorization behaviour is exercised.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "infra" / "keycloak" / "aegis-realm.json"
OUT = ROOT / ".build" / "keycloak" / "aegis-realm-hardened.json"


def harden(realm: dict) -> dict:  # type: ignore[type-arg]
    realm = json.loads(json.dumps(realm))
    realm["sslRequired"] = "all"
    for client in realm.get("clients", []):
        client["directAccessGrantsEnabled"] = False
    return realm


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(harden(json.loads(SRC.read_text())), indent=2) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
