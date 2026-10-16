"""Minimal, checksum-verified SQL migration runner (runs as the schema owner role).

Usage: python scripts/migrate.py [up|down N|status]
DSN from AEGIS_OWNER_DATABASE_URL (dummy local default).
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import psycopg

MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"
DEFAULT_DSN = "postgresql://aegis_owner:dummy-aegis-owner-pw@127.0.0.1:5432/aegis"  # pragma: allowlist secret


def _dsn() -> str:
    return os.environ.get("AEGIS_OWNER_DATABASE_URL", DEFAULT_DSN)


def _ups() -> list[Path]:
    return sorted(MIGRATIONS.glob("*.up.sql"))


def _digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _ensure_table(conn: psycopg.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())"
    )


def up() -> int:
    with psycopg.connect(_dsn(), autocommit=False) as conn:
        _ensure_table(conn)
        applied = dict(conn.execute("SELECT version, sha256 FROM schema_migrations").fetchall())
        count = 0
        for path in _ups():
            version = path.name.removesuffix(".up.sql")
            digest = _digest(path)
            if version in applied:
                if applied[version] != digest:
                    print(f"ERROR: applied migration {version} was modified (checksum mismatch)")
                    return 2
                continue
            with conn.transaction():
                conn.execute(path.read_text())  # type: ignore[call-overload]
                conn.execute(
                    "INSERT INTO schema_migrations (version, sha256) VALUES (%s, %s)", (version, digest)
                )
            print(f"applied {version}")
            count += 1
        conn.commit()
        print(f"migrations up to date ({count} applied this run, {len(_ups())} total)")
    return 0


def down(steps: int) -> int:
    with psycopg.connect(_dsn()) as conn:
        _ensure_table(conn)
        versions = [r[0] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version DESC")]
        for version in versions[:steps]:
            path = MIGRATIONS / f"{version}.down.sql"
            with conn.transaction():
                conn.execute(path.read_text())  # type: ignore[call-overload]
                conn.execute("DELETE FROM schema_migrations WHERE version = %s", (version,))
            print(f"reverted {version}")
    return 0


def status() -> int:
    with psycopg.connect(_dsn()) as conn:
        _ensure_table(conn)
        applied = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
    for path in _ups():
        v = path.name.removesuffix(".up.sql")
        print(f"{'[x]' if v in applied else '[ ]'} {v}")
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "up"
    if cmd == "up":
        sys.exit(up())
    if cmd == "down":
        sys.exit(down(int(sys.argv[2]) if len(sys.argv) > 2 else 1))
    if cmd == "status":
        sys.exit(status())
    print(__doc__)
    sys.exit(64)
