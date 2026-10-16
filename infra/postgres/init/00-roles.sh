#!/bin/sh
# Creates the migration owner and the least-privilege runtime role (DEMO passwords from env).
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v owner_pw="$AEGIS_OWNER_PASSWORD" -v app_pw="$AEGIS_APP_PASSWORD" <<'SQL'
CREATE ROLE aegis_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE aegis_app LOGIN PASSWORD :'app_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE DATABASE aegis OWNER aegis_owner;
REVOKE ALL ON DATABASE aegis FROM PUBLIC;
GRANT CONNECT ON DATABASE aegis TO aegis_owner, aegis_app;
SQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname aegis <<'SQL'
ALTER SCHEMA public OWNER TO aegis_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
